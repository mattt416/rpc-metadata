import unittest
from unittest.mock import PropertyMock, patch

import yaml

import rpc_component.component as c
import rpc_component.schemata as schemata


class TestUpdateRequirements(unittest.TestCase):

    def test_requirement_from_version_constraints(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "0.0.1",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                },
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000001",
                    "series": "first",
                },
                {
                    "version": "1.0.1",
                    "sha": "0000000000000000000000000000000000000002",
                    "series": "first",
                },
                {
                    "version": "1.1.0",
                    "sha": "0000000000000000000000000000000000000003",
                    "series": "first",
                },
                {
                    "version": "1.1.1",
                    "sha": "0000000000000000000000000000000000000004",
                    "series": "first",
                },
                {
                    "version": "2.0.0-alpha.1",
                    "sha": "0000000000000000000000000000000000000005",
                    "series": "first",
                },
                {
                    "version": "2.0.0-beta.1",
                    "sha": "0000000000000000000000000000000000000006",
                    "series": "first",
                },
                {
                    "version": "2.0.0-beta.2",
                    "sha": "0000000000000000000000000000000000000007",
                    "series": "first",
                },
                {
                    "version": "2.0.0",
                    "sha": "0000000000000000000000000000000000000008",
                    "series": "first",
                },
                {
                    "version": "10.0.0",
                    "sha": "0000000000000000000000000000000000000009",
                    "series": "first",
                },
            ],
        )
        self.assertTrue(
            schemata.component_schema.validate(component.to_dict())
        )
        constraints_test_cases = (
            {"constraints": [], "expected_version": "10.0.0"},
            {"constraints": ["version<10.0.0"], "expected_version": "2.0.0"},
            {"constraints": ["version<2"], "expected_version": "1.1.1"},
            {"constraints": ["version<1.1"], "expected_version": "1.0.1"},
            {"constraints": ["version<=1.1"], "expected_version": "1.1.1"},
            {
                "constraints": ["version<2.0.0-beta.1"],
                "expected_version": "2.0.0-alpha.1"
            },
        )
        for test_case in constraints_test_cases:
            calculated_requirement = c.requirement_from_version_constraints(
                component, test_case["constraints"]
            )
            self.assertEqual(
                test_case["expected_version"],
                calculated_requirement["version"]
            )


class TestRelease(unittest.TestCase):

    def setUp(self):
        self.component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
        )

    def tearDown(self):
        del self.component

    def test_release_added(self):
        release = c.Release(
            self.component,
            "1.0.0",
            "0000000000000000000000000000000000000000",
            "first",
        )
        self.assertEqual(release, self.component.get_release(release.version))

    def test_str_is_version(self):
        self.assertEqual(
            "1.0.0",
            str(c.Release(self.component, "1.0.0", "", ""))
        )

    def test_ordering(self):
        versions = ("1.1.10", "1.0.0", "2.0.0", "1.1.2", "1.1.0")
        sorted_versions = ("1.0.0", "1.1.0", "1.1.2", "1.1.10", "2.0.0")
        releases = (c.Release(self.component, v, "", "") for v in versions)
        sorted_releases = sorted(releases)
        self.assertEqual(sorted_versions, tuple(map(str, sorted_releases)))

    def test_dict(self):
        release = c.Release(
            self.component,
            "1.0.0",
            "0000000000000000000000000000000000000000",
            "first",
        )

        expected = {
            "is_product": False,
            "name": "test1",
            "release": {
                "series": "first",
                "sha": "0000000000000000000000000000000000000000",
                "version": "1.0.0",
            },
            "repo_url": "https://github.com/rcbops/test1",
        }

        self.assertEqual(expected, release.to_dict())

    def test_yaml(self):
        release = c.Release(
            self.component,
            "1.0.0",
            "0000000000000000000000000000000000000000",
            "first",
        )

        release_yaml = yaml.dump(release, default_flow_style=False)

        expected = (
            "is_product: false\n"
            "name: test1\n"
            "release:\n"
            "  series: first\n"
            "  sha: '0000000000000000000000000000000000000000'\n"
            "  version: 1.0.0\n"
            "repo_url: https://github.com/rcbops/test1\n"
        )

        self.assertEqual(expected, release_yaml)


class TestComponent(unittest.TestCase):

    def test_create_without_releases(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
        )
        self.assertEqual([], component.releases)

    def test_create_with_release(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
        )
        self.assertEqual(1, len(component.releases))

    def test_create_release(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
        )
        version = "1.0.0"
        sha = "0000000000000000000000000000000000000000"
        series = "first"
        release = component.create_release(
            version=version, sha=sha, series=series
        )
        self.assertIsInstance(release, c.Release)
        self.assertEqual(release, component.get_release(release.version))

    def test_get_release(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                },
                {
                    "version": "1.1.0",
                    "sha": "0000000000000000000000000000000000000001",
                    "series": "first",
                },
            ],
        )
        release = component.get_release("1.1.0")
        self.assertIsInstance(release, c.Release)
        self.assertEqual("1.1.0", release.version)

        release_pred = component.get_release("1.1.0", predecessor=True)
        self.assertIsInstance(release_pred, c.Release)
        self.assertEqual("1.0.0", release_pred.version)

    def test_difference(self):
        component_pred = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
        )

        component_succ = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                },
                {
                    "version": "1.1.0",
                    "sha": "0000000000000000000000000000000000000001",
                    "series": "first",
                }
            ],
        )

        expected_diff_from_pred = {
            "releases": [
                {
                    "versions": [
                        {
                            "version": "1.1.0",
                            "sha": "0000000000000000000000000000000000000001",
                        },
                    ],
                }
            ],
        }
        self.assertEqual(
            expected_diff_from_pred,
            component_succ.difference(component_pred)
        )

        expected_diff_from_succ = {}
        self.assertEqual(
            expected_diff_from_succ,
            component_pred.difference(component_succ)
        )

    def test_is_changed_when_new(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
        )

        self.assertTrue(component._is_changed)
        component.create_release(
            version="1.1.0",
            sha="0000000000000000000000000000000000000001",
            series="first",
        )
        self.assertTrue(component._is_changed)

    @patch("rpc_component.component.load_data")
    def test_is_changed_from_file(self, load_data):
        load_data.return_value = {
            "is_product": False,
            "name": "test1",
            "releases": [
                {
                    "series": "first",
                    "versions": [
                        {
                            "sha": "0000000000000000000000000000000000000000",
                            "version": "1.0.0",
                        },
                    ],
                },
            ],
            "repo_url": "https://github.com/rcbops/test1",
        }
        component = c.Component.from_file("test1", ".")
        self.assertFalse(component._is_changed)
        component.create_release(
            version="1.1.0",
            sha="0000000000000000000000000000000000000001",
            series="first",
        )
        self.assertTrue(component._is_changed)

    def test_dict(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
        )

        expected = {
            "is_product": False,
            "name": "test1",
            "releases": [
                {
                    "series": "first",
                    "versions": [
                        {
                            "sha": "0000000000000000000000000000000000000000",
                            "version": "1.0.0",
                        },
                    ],
                },
            ],
            "repo_url": "https://github.com/rcbops/test1",
        }

        self.assertEqual(expected, component.to_dict())

    def test_yaml(self):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
        )

        component_yaml = yaml.dump(component, default_flow_style=False)

        expected = (
            "is_product: false\n"
            "name: test1\n"
            "releases:\n"
            "- series: first\n"
            "  versions:\n"
            "  - sha: '0000000000000000000000000000000000000000'\n"
            "    version: 1.0.0\n"
            "repo_url: https://github.com/rcbops/test1\n"
        )

        self.assertEqual(expected, component_yaml)

    @patch("rpc_component.component.load_data")
    def test_from_file(self, load_data):
        c_data = {
            "is_product": False,
            "name": "test1",
            "repo_url": "https://github.com/rcbops/test1",
            "_is_changed": False,
        }
        r_data = {
            "version": "1.0.0",
            "sha": "0000000000000000000000000000000000000000",
            "series": "first",
        }
        load_data.return_value = {
            "is_product": c_data["is_product"],
            "name": c_data["name"],
            "releases": [
                {
                    "series": r_data["series"],
                    "versions": [
                        {
                            "sha": r_data["sha"],
                            "version": r_data["version"],
                        },
                    ],
                },
            ],
            "repo_url": c_data["repo_url"],
        }
        component = c.Component.from_file("test1", ".")
        for attr, value in c_data.items():
            self.assertEqual(value, getattr(component, attr))
        self.assertEqual(1, len(component.releases))
        release = component.releases[0]
        for attr, value in r_data.items():
            self.assertEqual(value, getattr(release, attr))

    @patch.object(c.Component, "_is_changed", new_callable=PropertyMock)
    @patch("rpc_component.component.save_data")
    def test_to_file(self, save_data, is_changed):
        component = c.Component(
            name="test1",
            repo_url="https://github.com/rcbops/test1",
            is_product=False,
            releases=[
                {
                    "version": "1.0.0",
                    "sha": "0000000000000000000000000000000000000000",
                    "series": "first",
                }
            ],
            directory=".",
        )
        is_changed.return_value = False
        component.to_file()
        save_data.assert_not_called()
        is_changed.return_value = True
        component.to_file()
        save_data.assert_called_once()
