from functools import partial
import re

from schema import And, Or, Regex, Schema


def sorted_versions(versions):
    return sorted(versions, key=version_key)


def is_sorted_versions(versions):
    return versions == sorted_versions(versions)


def is_value_unique(key):
    def fn(data):
        values = [v[key] for v in data]
        return len(values) == len(set(values))
    fn.__name__ = "is_{value}_unique".format(value=key)
    return fn


def is_version_ids_unique(releases):
    is_version_unique = is_value_unique("version")
    return is_version_unique((v for r in releases for v in r["versions"]))


def is_series_names_unique(releases):
    series = [r["series"] for r in releases]
    return len(series) == len(set(series))


sha_regex = r"^[0-9a-f]{40}$"
version_regex = (
    r"^(?P<version>r?"
    r"(?P<major>[0-9]+)\."
    r"(?P<minor>[0-9]+)\."
    r"(?P<patch>[0-9]+)"
    r"(-(?P<a_or_b>alpha|beta)\."
    r"(?P<a_b_version>[0-9]+))?)$"
)

version_id_schema = Regex(version_regex)
version_sha_schema = Regex(sha_regex)
version_schema = Schema(
    {
        "version": version_id_schema,
        "sha": version_sha_schema,
    },
)
comparison_added_version_schema = Schema(
    And(
        {
            And(str, len): {
                "added": {
                    "releases": And(
                        [
                            {
                                "versions": And(
                                    [version_schema],
                                    lambda vs: len(vs) == 1,
                                ),
                            }
                        ],
                        lambda rs: len(rs) == 1,
                    )
                },
                "deleted": {},
            }
        },
        lambda cs: len(cs) == 1,
    )
)

repo_url_schema = Regex(r"^https://github.com/.+")

comparison_operator_regex = r"(?P<comparison_operator>(=|!)=|(<|>)=?)"
constraint_regex = (
    r"(?P<version>r?(?P<major>[0-9]+)"
    r"(\.(?P<minor>[0-9]+)"
    r"(\.(?P<patch>[0-9]+)"
    r"(-(?P<a_or_b>alpha|beta)\."
    r"(?P<a_b_version>[0-9]+))?)?)?)"
)
version_constraint_regex = r"^version{op}{version}$".format(
    op=comparison_operator_regex,
    version=constraint_regex,
)
branch_constraint_regex = r"^branch==(?P<branch_name>.+)$"
branch_constraints_schema = And(
    [Regex(branch_constraint_regex)],
    lambda cs: len(cs) == 1,
)

constraints_schema = Or(
    [Regex(version_constraint_regex)],
    branch_constraints_schema,
)

component_single_version_schema = Schema(
    {
        "name": And(str, len),
        "repo_url": repo_url_schema,
        "is_product": bool,
        "release": {
            "series": And(str, len),
            "version": version_schema,
        },
    }
)

component_schema = Schema(
    {
        "name": And(str, len),
        "repo_url": repo_url_schema,
        "is_product": bool,
        "releases": And(
            [
                {
                    "series": And(str, len),
                    "versions": And(
                        [
                            version_schema,
                        ],
                        is_sorted_versions,
                    ),
                },
            ],
            is_value_unique("series"),
            is_version_ids_unique,
        ),
    }
)

component_metadata_schema = Schema(
    {
        "dependencies": And(
            [
                {
                    "name": And(str, len),
                    "constraints": constraints_schema,
                },
            ],
            is_value_unique("name"),
        ),
    }
)

component_requirements_schema = Schema(
    {
        "dependencies": And(
            [
                {
                    "name": And(str, len),
                    "ref": Or(And(str, len), None),
                    "ref_type": Or(lambda r: r in ("branch", "tag"), None),
                    "repo_url": repo_url_schema,
                    "sha": version_sha_schema,
                    "version": Or(version_id_schema, None),
                }
            ],
            is_value_unique("name"),
        ),
    }
)


def _version_key(version, regex=None):
    version_id = version["version"]
    a_b_map = {
        "alpha": 0,
        "beta": 1,
        None: 2,
    }

    def int_or_none(x): return x if x is None else int(x)

    v = re.match(regex, version_id)
    major = int(v.group("major"))
    minor = int_or_none(v.group("minor"))
    patch = int_or_none(v.group("patch"))
    a_or_b = a_b_map[v.group("a_or_b")]
    a_b_version = int(v.group("a_b_version") or 0)

    return (major, minor, patch, a_or_b, a_b_version)


version_key = partial(_version_key, regex=version_regex)
constraint_key = partial(_version_key, regex=constraint_regex)
