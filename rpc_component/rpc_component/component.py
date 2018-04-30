#!/usr/bin/env python3

import argparse
from collections import defaultdict
from copy import deepcopy
from itertools import takewhile
from operator import eq, ge, gt, le, lt, ne
import os
import re
import sys
from tempfile import TemporaryDirectory

import git
from schema import SchemaError
import yaml

from rpc_component.schemata import (
    comparison_added_component_schema, comparison_added_version_schema,
    constraint_key, component_metadata_schema, component_requirements_schema,
    component_schema, component_single_version_schema, branch_constraint_regex,
    branch_constraints_schema, repo_url_schema, version_constraint_regex,
    version_id_schema, version_sha_schema,
)

METADATA_FILENAME = "component_metadata.yml"
REQUIREMENTS_FILENAME = "component_requirements.yml"


class ComponentError(Exception):
    pass


def load_data(filepath, schema):
    try:
        with open(filepath) as f:
            raw_data = yaml.safe_load(f)
    except FileNotFoundError:
        data = None
    else:
        data = schema.validate(raw_data)

    return data


def save_data(filepath, data, schema, old_filepath=None):
    validated_data = schema.validate(data)
    with open(filepath, "w") as f:
        yaml.dump(validated_data, f, default_flow_style=False)

    if old_filepath:
        os.remove(old_filepath)


def load_component(name, directory):
    filename = "{name}.yml".format(name=name)
    filepath = os.path.join(directory, filename)

    return load_data(filepath, component_schema)


def load_all_components(component_dir, repo_dir, commitish):
    repo = git.Repo(repo_dir)
    start_ref = repo.head.commit

    repo.head.reference = repo.commit(commitish)
    repo.head.reset(index=True, working_tree=True)

    components = []
    for cf in os.listdir(component_dir):
        name = cf[:-4]
        components.append(load_component(name, component_dir))

    repo.head.reference = repo.commit(start_ref)
    repo.head.reset(index=True, working_tree=True)

    return components


def save_component(component, directory, old_component_name=None):
    filename = "{name}.yml".format(name=component["name"])
    filepath = os.path.join(directory, filename)

    if old_component_name:
        old_filename = "{name}.yml".format(name=old_component_name)
        old_filepath = os.path.join(directory, old_filename)
    else:
        old_filepath = None

    save_data(filepath, component, component_schema, old_filepath)


def load_metadata(directory):
    filepath = os.path.join(directory, METADATA_FILENAME)

    return load_data(filepath, component_metadata_schema)


def save_metadata(metadata, directory):
    filepath = os.path.join(directory, METADATA_FILENAME)

    save_data(filepath, metadata, component_metadata_schema)


def load_requirements(directory):
    filepath = os.path.join(directory, REQUIREMENTS_FILENAME)

    return load_data(filepath, component_requirements_schema)


def save_requirements(requirements, directory):
    filepath = os.path.join(directory, REQUIREMENTS_FILENAME)

    save_data(filepath, requirements, component_requirements_schema)


def add_component(name, repo_url, is_product):
    component = {
        "name": name,
        "repo_url": repo_url,
        "is_product": is_product,
        "releases": [],
    }

    return component_schema.validate(component)


def update_component(existing, name=None, repo_url=None, is_product=None):
    component = deepcopy(existing)
    new = {
        k: v
        for k, v in (
            ("name", name),
            ("repo_url", repo_url),
            ("is_product", is_product)
        )
        if v is not None
    }

    component.update(**new)

    return component_schema.validate(component)


def component_difference(a, b):
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
                    sub_value_diff = component_difference(avv, bvv)
                    if sub_value_diff:
                        value_diff.append(sub_value_diff)

                if value_diff:
                    diff[k] = value_diff
            elif isinstance(av, dict):
                value_diff = component_difference(av, bv)
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


def update_releases(component, series_name, version, sha):
    component = deepcopy(component)
    release = {
        "version": version,
        "sha": sha,
    }

    for r in component["releases"]:
        if r["series"] == series_name:
            series_versions = r["versions"]
            break
    else:
        series_versions = []
        component["releases"].append(
            {
                "series": series_name,
                "versions": series_versions,
            }
        )

    series_versions.append(release)

    return component_schema.validate(component)


def set_dependency(existing, name, constraints=None):
    if existing:
        dependencies = deepcopy(existing)
    else:
        dependencies = {"dependencies": []}

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
                constraint_key({"version": constraint})
            )
        )

        def inner(version):
            return fn(
                constraint_key({"version": version})[:len(c_key)],
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
    versions = reversed(
        [
            version
            for series in component["releases"]
            for version in series["versions"]
        ]
    )
    for version in versions:
        if meets_constraints(version["version"]):
            requirement = {
                "name": component["name"],
                "ref": version["version"],
                "ref_type": "tag",
                "repo_url": component["repo_url"],
                "sha": version["sha"],
                "version": version["version"],
            }
            break
    else:
        raise Exception(
            (
                "The component '{c_name}' has no version matching the "
                "constraints '{cs}'."
            ).format(c_name=component["name"], cs=constraints)
        )

    return requirement


def requirement_from_branch_constraints(component, constraints):
    constraint = constraints.pop()
    assert len(constraints) == 0

    constraint_match = re.match(branch_constraint_regex, constraint)
    branch_name = constraint_match.group("branch_name")
    with TemporaryDirectory() as tmp_dir:
        repo = git.Repo.clone_from(
            component["repo_url"], tmp_dir, branch=branch_name
        )
        sha = repo.head.commit.hexsha

    requirement = {
        "name": component["name"],
        "ref": branch_name,
        "ref_type": "branch",
        "repo_url": component["repo_url"],
        "sha": sha,
        "version": None
    }

    return requirement


def update_requirements(metadata, component_dir):
    requirements = {"dependencies": []}
    for dependency in metadata["dependencies"]:
        component = load_component(dependency["name"], component_dir)
        if not component:
            raise ComponentError(
                "Dependency '{name}' does not exist.".format(
                    name=dependency["name"],
                )
            )
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


def update_releases_repo(repo_url):
    repo_dir = os.path.expanduser("~/.rpc_component/releases")
    try:
        repo = git.Repo(repo_dir)
    except git.exc.NoSuchPathError:
        os.makedirs(repo_dir, exist_ok=True)
        repo = git.Repo.clone_from(repo_url, repo_dir, branch="master")
    else:
        repo.head.reset(index=True, working_tree=True)
        repo.heads.master.checkout()
        repo.remote("origin").pull()

    return repo_dir


def commit_changes(repo_dir, message):
    repo = git.Repo(repo_dir)
    repo.git.add(all=True)
    repo.git.commit(message=message)


def get_version_series(component, version):
    for release in component["releases"]:
        if version in release["versions"]:
            series = release["series"]
            break
    else:
        raise ComponentError("Version does not exist")

    return series


def parse_args(args):
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--releases-dir",
        help=(
            "Path to releases repo. If not specified, it is cloned from "
            "`--releases-repo`."
        ),
    )
    parser.add_argument(
        "--releases-repo",
        default="https://github.com/rcbops/releases",
        help=(
                "The repository to clone if `--releases-dir` is not specified "
                "and no previous clone exists."
        ),
    )

    subparsers = parser.add_subparsers(dest="subparser")
    subparsers.required = True

    c_parser = subparsers.add_parser("component")
    c_parser.add_argument(
        "--component-name",
        required=True,
        help="The component name.",
    )

    c_subparser = c_parser.add_subparsers(dest="component_subparser")
    c_subparser.required = True

    ca_parser = c_subparser.add_parser("add")
    ca_parser.add_argument(
        "--repo-url",
        type=repo_url_schema.validate,
        required=True,
        help="Component repository URL.",
    )
    ca_parser.add_argument("--is-product", action="store_true", default=False)

    cu_parser = c_subparser.add_parser("update")
    cu_parser.add_argument(
        "--repo-url",
        type=repo_url_schema.validate,
        required=True,
        help="Component repository URL.",
    )
    cu_parser.add_argument("--is-product", action="store_true", default=False)
    cu_parser.add_argument(
        "--new-name",
        help="Used to change the name of a component.",
    )

    r_parser = subparsers.add_parser("release")
    r_parser.add_argument(
        "--component-name",
        required=True,
        help="The component name.",
    )

    r_parser.add_argument(
        "--version",
        type=version_id_schema.validate,
        required=True,
        help="The version identifier for the new release, e.g. 1.0.0.",
    )
    r_parser.add_argument(
        "--sha",
        type=version_sha_schema.validate,
        required=True,
        help="The hash of the commit to be tagged with the specified version.",
    )
    r_parser.add_argument(
        "--series-name",
        required=True,
        help="The name of the major release to which the version belongs.",
    )

    dep_parser = subparsers.add_parser("dependency")
    dep_parser.add_argument("--dependency-dir", default="./")

    dep_subparsers = dep_parser.add_subparsers(dest="dependency_subparser")
    dep_subparsers.required = True

    req_parser = dep_subparsers.add_parser(
        "update-requirements",
        help=(
            "Generate a list of dependency requirements, pinned to specific "
            "versions/commits."
        ),
    )

    sd_parser = dep_subparsers.add_parser("set-dependency")
    sd_parser.add_argument(
        "--name",
        required=True,
        help="The name of the component dependency.",
    )
    sd_parser.add_argument(
        "--constraint",
        action="append",
        dest="constraints",
        help=(
            "A constraint limits the requirements generated from dependencies "
            "to specific versions or branches."
        ),
    )

    dl_parser = dep_subparsers.add_parser("download-requirements")
    dl_parser.add_argument("--download-dir", default="./")

    com_parser = subparsers.add_parser("compare")
    com_parser.add_argument(
        "--from",
        required=True,
        help="Git commitish.",
    )
    com_parser.add_argument(
        "--to",
        required=True,
        help="Git commitish.",
    )
    com_parser.add_argument(
        "--verify",
        choices=["version", "registration"],
    )

    return vars(parser.parse_args(args))


def main():
    raw_args = sys.argv[1:]
    try:
        kwargs = parse_args(raw_args)

        subparser = kwargs.pop("subparser")

        releases_repo = kwargs.pop("releases_repo")
        releases_dir = os.path.expanduser(kwargs.pop("releases_dir") or "")
        if not releases_dir:
            releases_dir = update_releases_repo(repo_url=releases_repo)

        components_dir = os.path.join(releases_dir, "components")
        os.makedirs(components_dir, exist_ok=True)

        if subparser == "component":
            component_name = kwargs.pop("component_name")
            existing_component = load_component(component_name, components_dir)

            component_subparser = kwargs.pop("component_subparser")
            if component_subparser == "add":
                if existing_component:
                    raise ComponentError("The component already exists.")
                updated_component = add_component(
                    name=component_name, **kwargs
                )
            elif component_subparser == "update":
                if not existing_component:
                    raise ComponentError(
                        "Component '{name}' does not exist.".format(
                            name=component_name,
                        )
                    )
                new_component_name = kwargs["new_name"]
                updated_component = update_component(
                    existing_component, name=new_component_name, **kwargs
                )
            else:
                raise ComponentError(
                    "The component subparser '{sp}' is not recognised.".format(
                        sp=subparser,
                    )
                )

            if updated_component != existing_component:
                if existing_component:
                    if updated_component["name"] != existing_component["name"]:
                        old_name = existing_component["name"]
                    else:
                        old_name = None
                else:
                    old_name = None
                save_component(updated_component, components_dir, old_name)

                msg = "{change} component {name}".format(
                    change=component_subparser.capitalize(),
                    name=updated_component["name"],
                )

                commit_changes(releases_dir, msg)
        elif subparser == "release":
            component_name = kwargs.pop("component_name")
            existing_component = load_component(component_name, components_dir)
            if not existing_component:
                raise ComponentError(
                    "Component '{name}' does not exist.".format(
                        name=component_name,
                    )
                )

            updated_component = update_releases(existing_component, **kwargs)

            if updated_component != existing_component:
                save_component(updated_component, components_dir)
                msg = "Add component {name} release {version}".format(
                    name=updated_component["name"],
                    version=kwargs["version"],
                )

                commit_changes(releases_dir, msg)
        elif subparser == "dependency":
            dependency_dir = kwargs.pop("dependency_dir")
            metadata = load_metadata(dependency_dir)

            dependency_subparser = kwargs.pop("dependency_subparser")
            if dependency_subparser == "set-dependency":
                data = set_dependency(metadata, **kwargs)
                if data != metadata:
                    save_metadata(data, dependency_dir)
                    msg = "Set component dependency {name}".format(
                        name=kwargs["name"],
                    )

                    commit_changes(dependency_dir, msg)
            elif dependency_subparser == "update-requirements":
                existing_requirements = load_requirements(dependency_dir)
                requirements = update_requirements(metadata, components_dir)
                if existing_requirements != requirements:
                    save_requirements(requirements, dependency_dir)
                    msg = "Update component dependency requirements"
                    commit_changes(dependency_dir, msg)
            elif dependency_subparser == "download-requirements":
                requirements = load_requirements(dependency_dir)
                download_requirements(
                    requirements["dependencies"], kwargs["download_dir"]
                )
        elif subparser == "compare":
            from_ = load_all_components(components_dir, releases_dir, kwargs["from"])
            to = load_all_components(components_dir, releases_dir, kwargs["to"])
            to_compare = defaultdict(lambda: [{}, {}])
            for c in from_:
                to_compare[c["name"]][0] = c
            for c in to:
                to_compare[c["name"]][1] = c
            comparison = {}
            for name, (f, t) in to_compare.items():
                deleted = component_difference(f, t)
                added = component_difference(t, f)
                if added or deleted:
                    comparison[name] = {"added": added, "deleted": deleted}

            comparison_yaml = yaml.dump(comparison, default_flow_style=False)
            if kwargs["verify"] == "version":
                try:
                    comparison_added_version_schema.validate(comparison)
                except SchemaError as e:
                    raise ComponentError(
                        "The changes from `{f}` to `{t}` do not represent the "
                        "addition of a new release version.\nValidation error:"
                        "\n{e}\nChanges found:\n{c}".format(
                            f=kwargs["from"],
                            t=kwargs["to"],
                            e=e,
                            c=comparison_yaml,
                        )
                    )
                else:
                    name, data = comparison.popitem()
                    version = data["added"]["releases"][0]["versions"][0]
                    component = [c for c in to if c["name"] == name][0]
                    comp_version = component_single_version_schema.validate(
                        {
                            "name": name,
                            "repo_url": component["repo_url"],
                            "is_product": component["is_product"],
                            "release": {
                                "series": get_version_series(
                                    component, version
                                ),
                                "version": version,
                            },
                        }
                    )
                    output = yaml.dump(comp_version, default_flow_style=False)
            elif kwargs["verify"] == "registration":
                try:
                    comparison_added_component_schema.validate(comparison)
                except SchemaError as e:
                    raise ComponentError(
                        "The changes from `{f}` to `{t}` do not represent the "
                        "registration of a new component.\nValidation error:"
                        "\n{e}\nChanges found:\n{c}".format(
                            f=kwargs["from"],
                            t=kwargs["to"],
                            e=e,
                            c=comparison_yaml,
                        )
                    )
                else:
                    output = comparison_yaml
            else:
                output = comparison_yaml

            print(output, end="")
        else:
            raise ComponentError(
                "The subparser '{sp}' is not recognised.".format(sp=subparser)
            )
    except SchemaError as e:
        error_message = e.code
    except ComponentError as e:
        error_message = e
    else:
        error_message = None
    sys.exit(error_message)


if __name__ == "__main__":
    main()
