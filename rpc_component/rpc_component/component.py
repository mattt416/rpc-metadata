from collections import defaultdict
from copy import deepcopy
from functools import total_ordering
from itertools import groupby, takewhile
from operator import attrgetter, eq, ge, gt, le, lt, ne
import os
import re
from tempfile import TemporaryDirectory

import git
from schema import SchemaError
import yaml

from rpc_component.schemata import (
    constraint_key, component_metadata_schema, component_requirements_schema,
    component_schema, component_single_version_schema, branch_constraint_regex,
    branch_constraints_schema, version_constraint_regex, version_regex,
    version_key,
)

REQUIREMENTS_FILENAME = "component_requirements.yml"


class Component(yaml.YAMLObject):
    schema = component_schema

    def __init__(
            self, name, repo_url, is_product, releases=None, directory=None
            ):
        self.name = name
        self.repo_url = repo_url
        self.is_product = is_product
        self.releases = []
        for release in releases or []:
            self.create_release(**release)
        self.directory = directory
        self._orig_state = None

    def create_release(self, version, sha, series):
        release = Release(self, version, sha, series)
        return release

    def add_release(self, release):
        version = release.version
        try:
            self.get_release(version)
        except ComponentError:
            releases = self.releases + [release]
            self.releases = sorted(releases)
        else:
            raise ComponentError(
                "Release with version {v} already exists.".format(v=version)
            )

    def get_release(self, version, predecessor=False):
        if predecessor:
            pred = None
            for r in self.releases:
                if r.version == version:
                    if pred:
                        release = pred
                        break
                    else:
                        raise ComponentError(
                            "Release with version {v} does not have a "
                            "predecessor.".format(v=version)
                        )
                else:
                    pred = r
            else:
                raise ComponentError(
                    "Release with version {v} does not exist".format(v=version)
                )
        else:
            for release in self.releases:
                if release.version == version:
                    break
            else:
                raise ComponentError(
                    "Release with version {v} does not exist".format(v=version)
                )

        return release

    def difference(self, other):
        """Return difference, where in self but not in other."""
        def _difference(a, b):
            """In a but not b"""
            diff = {}
            for k, av in a.items():
                try:
                    bv = b[k]
                except KeyError:
                    diff[k] = av
                else:
                    if av == bv:
                        continue
                    elif k == "releases":
                        release_pairs = defaultdict(lambda: [{}, {}])
                        for r in av:
                            release_pairs[r["series"]][0] = r
                        for r in bv:
                            release_pairs[r["series"]][1] = r

                        value_diff = []
                        for avv, bvv in release_pairs.values():
                            sub_value_diff = _difference(avv, bvv)
                            if sub_value_diff:
                                value_diff.append(sub_value_diff)

                        if value_diff:
                            diff[k] = value_diff
                    elif isinstance(av, dict):
                        value_diff = _difference(av, bv)
                        if value_diff:
                            diff[k] = value_diff
                    elif isinstance(av, list):
                        value_diff = []
                        for avv in av:
                            if avv not in bv:
                                value_diff.append(avv)

                        if value_diff:
                            diff[k] = value_diff
                    else:
                        diff[k] = av

            return diff
        return _difference(self.to_dict(), other.to_dict())

    @property
    def _is_changed(self):
        current_state = vars(self).copy()
        del current_state["_orig_state"]
        return current_state != self._orig_state

    def to_dict(self):
        component = {
            "name": self.name,
            "repo_url": self.repo_url,
            "is_product": self.is_product,
            "releases": [
                {
                    "series": s, "versions": [
                        {"version": v.version, "sha": v.sha} for v in vs
                    ]
                }
                for s, vs in groupby(self.releases, attrgetter("series"))
            ],
        }
        return self.schema.validate(component)

    yaml_tag = ""

    @classmethod
    def to_yaml(cls, representer, data):
            return representer.represent_dict(data.to_dict())

    @classmethod
    def from_file(cls, component_name, component_directory):
        filename = "{name}.yml".format(name=component_name)
        filepath = os.path.join(component_directory, filename)

        try:
            component_data = cls.schema.validate(load_data(filepath))
        except FileNotFoundError:
            raise ComponentError(
                "Component '{name}' could not be found.".format(
                    name=component_name,
                )
            )
        else:
            component_data["releases"] = [
                dict(release, series=series["series"])
                for series in component_data["releases"]
                for release in series["versions"]
            ]
            component = cls(directory=component_directory, **component_data)
            component._orig_state = deepcopy(vars(component))
            del component._orig_state["_orig_state"]

        return component

    def to_file(self):
        if self._is_changed:
            filename = "{name}.yml".format(name=self.name)
            filepath = os.path.join(self.directory, filename)
            if self._orig_state:
                orig_name = self._orig_state["name"]
            else:
                orig_name = None
            if orig_name and self.name != orig_name:
                old_filename = "{name}.yml".format(name=orig_name)
                old_filepath = os.path.join(self.directory or "", old_filename)
            else:
                old_filepath = None

            save_data(filepath, self.to_dict(), old_filepath)


@total_ordering
class Release(yaml.YAMLObject):
    regex = version_regex
    schema = component_single_version_schema

    def __init__(self, component, version, sha, series):
        self.component = component
        self.version = version
        self.sha = sha
        self.series = series
        self.component.add_release(self)

    def __str__(self):
        return self.version

    def __eq__(self, other):
        return str(self) == str(other)

    def __lt__(self, other):
        return version_key(self.version) < version_key(other.version)

    yaml_tag = ""

    def to_dict(self):
        release = self.component.to_dict()
        del release["releases"]
        release["release"] = {
            "series": self.series,
            "version": self.version,
            "sha": self.sha,
        }
        return self.schema.validate(release)

    @classmethod
    def to_yaml(cls, representer, data):
            return representer.represent_dict(data.to_dict())


class ComponentError(Exception):
    pass


def load_data(filepath):
    with open(filepath) as f:
        data = yaml.safe_load(f)

    return data


def save_data(filepath, data, old_filepath=None, header=None):
    with open(filepath, "w") as f:
        enc_data = yaml.dump(data, default_flow_style=False)
        if header:
            o = "# {comment}\n{data}".format(comment=header, data=enc_data)
        else:
            o = enc_data
        f.write(o)

    if old_filepath:
        os.remove(old_filepath)


def load_all_components(component_dir, repo_dir, commitish):
    repo = git.Repo(repo_dir)
    start_ref = repo.head.commit

    repo.head.reference = repo.commit(commitish)
    repo.head.reset(index=True, working_tree=True)

    components = []
    for cf in os.listdir(component_dir):
        name = cf[:-4]
        components.append(Component.from_file(name, component_dir))

    repo.head.reference = repo.commit(start_ref)
    repo.head.reset(index=True, working_tree=True)

    return components


def load_requirements(directory):
    filepath = os.path.join(directory, REQUIREMENTS_FILENAME)

    try:
        data = load_data(filepath)
    except FileNotFoundError:
        data = {"dependencies": []}
    return component_requirements_schema.validate(data)


def save_requirements(requirements, directory):
    filepath = os.path.join(directory, REQUIREMENTS_FILENAME)

    data = component_requirements_schema.validate(requirements)
    save_data(
        filepath,
        data,
        header=(
            "Do not modify by hand. This file is automatically generated from"
            " the required dependencies and the constraints specified for"
            " them."
        ),
    )


def set_dependency(existing, name, constraints=None):
    dependencies = deepcopy(existing)

    for dependency in dependencies["dependencies"]:
        if dependency["name"] == name:
            dependency["constraints"] = constraints
            break
    else:
        dependencies["dependencies"].append(
            {
                "name": name,
                "constraints": constraints,
            }
        )

    return component_metadata_schema.validate(dependencies)


def build_constraint_checker(constraints):
    op_map = {
        "==": eq,
        "!=": ne,
        ">=": ge,
        "<=": le,
        ">": gt,
        "<": lt,
    }

    def check_constraint(fn, constraint):
        c_key = tuple(
            takewhile(
                lambda x: x is not None,
                constraint_key(constraint)
            )
        )

        def inner(version):
            return fn(
                constraint_key(version)[:len(c_key)],
                c_key
            )
        return inner

    checks = []
    for constraint in constraints:
        constraint_match = re.match(version_constraint_regex, constraint)
        checks.append(
            check_constraint(
                op_map[constraint_match.group("comparison_operator")],
                constraint_match.group("version"),
            )
        )

    return lambda v: all(c(v) for c in checks)


def requirement_from_version_constraints(component, constraints):
    meets_constraints = build_constraint_checker(constraints)
    for release in reversed(component.releases):
        if meets_constraints(release.version):
            requirement = {
                "name": component.name,
                "ref": release.version,
                "ref_type": "tag",
                "repo_url": component.repo_url,
                "sha": release.sha,
                "version": release.version,
            }
            break
    else:
        raise Exception(
            (
                "The component '{c_name}' has no version matching the "
                "constraints '{cs}'."
            ).format(c_name=component.name, cs=constraints)
        )

    return requirement


def requirement_from_branch_constraints(component, constraints):
    constraint = constraints.pop()
    assert len(constraints) == 0

    constraint_match = re.match(branch_constraint_regex, constraint)
    branch_name = constraint_match.group("branch_name")
    with TemporaryDirectory() as tmp_dir:
        repo = git.Repo.clone_from(
            component.repo_url, tmp_dir, branch=branch_name
        )
        sha = repo.head.commit.hexsha

    requirement = {
        "name": component.name,
        "ref": branch_name,
        "ref_type": "branch",
        "repo_url": component.repo_url,
        "sha": sha,
        "version": None
    }

    return requirement


def update_requirements(metadata, component_dir):
    requirements = {"dependencies": []}
    for dependency in metadata["dependencies"]:
        component = Component.from_file(dependency["name"], component_dir)
        constraints = dependency["constraints"]
        try:
            branch_constraints_schema.validate(constraints)
        except SchemaError:
            requirement = requirement_from_version_constraints(
                component,
                constraints
            )
        else:
            requirement = requirement_from_branch_constraints(
                component,
                constraints
            )

        requirements["dependencies"].append(requirement)

    return component_requirements_schema.validate(requirements)


def download_requirements(requirements, dl_base_dir):
    for requirement in requirements:
        repo_dir = os.path.join(dl_base_dir, requirement["name"])
        try:
            repo = git.Repo(repo_dir)
        except git.exc.NoSuchPathError:
            repo = git.Repo.clone_from(requirement["repo_url"], repo_dir)
        else:
            repo.remote("origin").fetch()

        repo.head.reference = repo.commit(requirement["sha"])
        repo.head.reset(index=True, working_tree=True)


def commit_changes(repo_dir, files, message):
    repo = git.Repo(repo_dir)
    repo.git.add(files)
    repo.git.commit(message=message)


def git_http_to_ssh(url):
    match = re.match(
        r"https?://github.com/"
        r"(?P<owner>[a-zA-Z0-9]+-?[a-zA-Z0-9]+)/"
        r"(?P<name>[a-zA-Z0-9_-]+)(.git)?",
        url
    )

    ssh_url = "git@github.com:{owner}/{name}.git".format(
        owner=match.group("owner"), name=match.group("name")
    )

    return ssh_url
