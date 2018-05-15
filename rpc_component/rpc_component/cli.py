#!/usr/bin/env python3

import argparse
from collections import defaultdict
from copy import deepcopy
import os
import sys

import git
from schema import SchemaError
import yaml

from rpc_component import component as c_lib
from rpc_component import schemata as s_lib


def component(releases_dir, components_dir, subparser, **kwargs):
    os.makedirs(components_dir, exist_ok=True)
    component_name = kwargs.pop("component_name")

    if subparser == "get":
        component = c_lib.Component.from_file(
            component_name, components_dir
        )
    elif subparser == "add":
        try:
            component = c_lib.Component.from_file(
                component_name, components_dir
            )
        except c_lib.ComponentError:
            component = c_lib.Component(
                name=component_name, directory=components_dir, **kwargs
            )
        else:
            raise c_lib.ComponentError(
                "Component '{name}' already exists.".format(
                    name=component_name,
                )
            )
    elif subparser == "update":
        component = c_lib.Component.from_file(
            component_name, components_dir
        )
        if kwargs["new_name"]:
            component.name = kwargs["new_name"]
        if kwargs["repo_url"]:
            component.repo_url = kwargs["repo_url"]
        if "is_product" in kwargs:
            component.is_product = kwargs["is_product"]
    else:
        raise c_lib.ComponentError(
            "The component subparser '{sp}' is not recognised.".format(
                sp=subparser,
            )
        )

    if component._is_changed:
        component.to_file()
        msg = "{change} component {name}".format(
            change=subparser.capitalize(),
            name=component.name,
        )

        c_lib.commit_changes(releases_dir, components_dir, msg)

    return component


def release(releases_dir, components_dir, **kwargs):
    component_name = kwargs.pop("component_name")
    subparser = kwargs.pop("release_subparser")
    component = c_lib.Component.from_file(
        component_name, components_dir
    )
    if subparser == "get":
        release = component.get_release(kwargs["version"], kwargs["pred"])
    elif subparser == "add":
        release = component.create_release(
            version=kwargs["version"],
            sha=kwargs["sha"],
            series=kwargs["series_name"]
        )

        if component._is_changed:
            component.to_file()
            msg = "Add component {name} release {version}".format(
                name=component.name,
                version=release.version,
            )
            c_lib.commit_changes(releases_dir, components_dir, msg)
    else:
        raise c_lib.ComponentError(
            "The release subparser '{sp}' is not recognised.".format(
                sp=subparser,
            )
        )

    return release


def compare(releases_dir, components_dir, **kwargs):
    from_ = c_lib.load_all_components(
        components_dir, releases_dir, kwargs["from"]
    )
    to = c_lib.load_all_components(
        components_dir, releases_dir, kwargs["to"]
    )
    to_compare = defaultdict(lambda: [{}, {}])
    for c in from_:
        to_compare[c.name][0] = c
    for c in to:
        to_compare[c.name][1] = c
    comparison = {}
    for name, (f, t) in to_compare.items():
        if f and not t:
            deleted = f.to_dict()
            added = {}
        elif t and not f:
            deleted = {}
            added = t.to_dict()
        else:
            deleted = f.difference(t)
            added = t.difference(f)
        if added or deleted:
            comparison[name] = {"added": added, "deleted": deleted}

    comparison_yaml = yaml.dump(comparison, default_flow_style=False)
    if kwargs["verify"] == "release":
        try:
            s_lib.comparison_added_version_schema.validate(comparison)
        except SchemaError as e:
            raise c_lib.ComponentError(
                "The changes from `{f}` to `{t}` do not represent the "
                "addition of a new release.\nValidation error:"
                "\n{e}\nChanges found:\n{c}".format(
                    f=kwargs["from"],
                    t=kwargs["to"],
                    e=e,
                    c=comparison_yaml,
                )
            )
        else:
            name, data = comparison.popitem()
            version = data["added"]["releases"][0]["versions"][0]["version"]
            component = [c for c in to if c.name == name][0]
            output = component.get_release(version)
    elif kwargs["verify"] == "registration":
        try:
            s_lib.comparison_added_component_schema.validate(comparison)
        except SchemaError as e:
            raise c_lib.ComponentError(
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
            name, _ = comparison.popitem()
            component = [c for c in to if c.name == name][0]
            output = component
    else:
        output = comparison

    return output


def dependency(components_dir, **kwargs):
    dependency_dir = kwargs.pop("dependency_dir")
    metadata_filename = "component_metadata.yml"
    filepath = os.path.join(dependency_dir, metadata_filename)
    new_metadata = {"dependencies": []}
    try:
        metadata = c_lib.load_data(filepath)
    except FileNotFoundError:
        metadata = deepcopy(new_metadata)
    metadata = s_lib.component_metadata_schema.validate(metadata)

    subparser = kwargs.pop("dependency_subparser")
    if subparser == "set-dependency":
        data = c_lib.set_dependency(metadata, **kwargs)
        if data != metadata or data == new_metadata:
            c_lib.save_data(
                filepath,
                s_lib.component_metadata_schema.validate(data)
            )
            msg = "Set component dependency {name}".format(
                name=kwargs["name"],
            )

            c_lib.commit_changes(dependency_dir, metadata_filename, msg)
    elif subparser == "update-requirements":
        existing_requirements = c_lib.load_requirements(dependency_dir)
        requirements = c_lib.update_requirements(metadata, components_dir)
        if existing_requirements != requirements:
            c_lib.save_requirements(requirements, dependency_dir)
            msg = "Update component dependency requirements"
            c_lib.commit_changes(
                dependency_dir, c_lib.REQUIREMENTS_FILENAME, msg
            )
    elif subparser == "download-requirements":
        requirements = c_lib.load_requirements(dependency_dir)
        c_lib.download_requirements(
            requirements["dependencies"], kwargs["download_dir"]
        )
    else:
        raise c_lib.ComponentError(
            "The dependency subparser '{sp}' is not recognised.".format(
                sp=subparser,
            )
        )


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

    cg_parser = subparsers.add_parser("get")
    cg_parser.add_argument(
        "--component-name",
        required=True,
        help="The component name.",
    )

    ca_parser = subparsers.add_parser("add")
    ca_parser.add_argument(
        "--component-name",
        required=True,
        help="The component name.",
    )
    ca_parser.add_argument(
        "--repo-url",
        type=s_lib.repo_url_schema.validate,
        required=True,
        help="Component repository URL.",
    )
    ca_parser.add_argument("--is-product", action="store_true", default=False)

    cu_parser = subparsers.add_parser("update")
    cu_parser.add_argument(
        "--component-name",
        required=True,
        help="The component name.",
    )
    cu_parser.add_argument(
        "--repo-url",
        type=s_lib.repo_url_schema.validate,
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
    r_subparser = r_parser.add_subparsers(dest="release_subparser")
    r_subparser.required = True

    rg_parser = r_subparser.add_parser("get")
    rg_parser.add_argument(
        "--version",
        help="Get a single version.",
        required=True,
    )
    rg_parser.add_argument(
        "--pred",
        default=False,
        action="store_true",
        help="Get the predecessor of a single version.",
    )

    ra_parser = r_subparser.add_parser("add")
    ra_parser.add_argument(
        "--version",
        type=s_lib.version_id_schema.validate,
        required=True,
        help="The version identifier for the new release, e.g. 1.0.0.",
    )
    ra_parser.add_argument(
        "--sha",
        type=s_lib.version_sha_schema.validate,
        required=True,
        help="The hash of the commit to be tagged with the specified version.",
    )
    ra_parser.add_argument(
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
        choices=["release", "registration"],
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

        if subparser in ("get", "add", "update"):
            resp = component(
                releases_dir, components_dir, subparser, **kwargs
            )
        elif subparser == "release":
            resp = release(releases_dir, components_dir, **kwargs)
        elif subparser == "dependency":
            resp = dependency(components_dir, **kwargs)
        elif subparser == "compare":
            resp = compare(releases_dir, components_dir, **kwargs)
        else:
            raise c_lib.ComponentError(
                "The subparser '{sp}' is not recognised.".format(sp=subparser)
            )
    except SchemaError as e:
        error_message = e.code
    except c_lib.ComponentError as e:
        error_message = e
    else:
        error_message = None
        if resp is not None:
            print(yaml.dump(resp, default_flow_style=False), end="")

    sys.exit(error_message)


if __name__ == "__main__":
    main()
