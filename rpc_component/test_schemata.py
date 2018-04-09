import unittest

import rpc_component.schemata as schemata


sorted_versions = [
    {
        "version": "0.0.1",
        "sha": "0000000000000000000000000000000000000000",
    },
    {
        "version": "1.0.0",
        "sha": "0000000000000000000000000000000000000001",
    },
    {
        "version": "1.0.1",
        "sha": "0000000000000000000000000000000000000002",
    },
    {
        "version": "1.1.0",
        "sha": "0000000000000000000000000000000000000003",
    },
    {
        "version": "1.1.1",
        "sha": "0000000000000000000000000000000000000004",
    },
    {
        "version": "2.0.0-alpha.1",
        "sha": "0000000000000000000000000000000000000005",
    },
    {
        "version": "2.0.0-beta.1",
        "sha": "0000000000000000000000000000000000000006",
    },
    {
        "version": "2.0.0-beta.2",
        "sha": "0000000000000000000000000000000000000007",
    },
    {
        "version": "2.0.0",
        "sha": "0000000000000000000000000000000000000008",
    },
    {
        "version": "10.0.0",
        "sha": "0000000000000000000000000000000000000009",
    },
]

unsorted_versions = [
    {
        "version": "1.1.1",
        "sha": "0000000000000000000000000000000000000004",
    },
    {
        "version": "1.0.0",
        "sha": "0000000000000000000000000000000000000001",
    },
    {
        "version": "2.0.0-beta.1",
        "sha": "0000000000000000000000000000000000000006",
    },
    {
        "version": "0.0.1",
        "sha": "0000000000000000000000000000000000000000",
    },
    {
        "version": "1.0.1",
        "sha": "0000000000000000000000000000000000000002",
    },
    {
        "version": "2.0.0-beta.2",
        "sha": "0000000000000000000000000000000000000007",
    },
    {
        "version": "1.1.0",
        "sha": "0000000000000000000000000000000000000003",
    },
    {
        "version": "10.0.0",
        "sha": "0000000000000000000000000000000000000009",
    },
    {
        "version": "2.0.0",
        "sha": "0000000000000000000000000000000000000008",
    },
    {
        "version": "2.0.0-alpha.1",
        "sha": "0000000000000000000000000000000000000005",
    },
]


class TestValidationFunctions(unittest.TestCase):
    def test_sorted_versions(self):
        self.assertNotEqual(sorted_versions, unsorted_versions)
        self.assertEqual(
            sorted_versions,
            schemata.sorted_versions(unsorted_versions)
        )

    def test_is_sorted_versions(self):
        self.assertTrue(schemata.is_sorted_versions(sorted_versions))
        self.assertFalse(schemata.is_sorted_versions(unsorted_versions))

    def test_is_value_unique(self):
        unique = [
            {"key": 1},
            {"key": 2},
            {"key": 3},
        ]
        not_unique = [
            {"key": 1},
            {"key": 1},
            {"key": 3},
        ]
        self.assertTrue(schemata.is_value_unique("key")(unique))
        self.assertFalse(schemata.is_value_unique("key")(not_unique))


class TestSchemaValidation(unittest.TestCase):
    def test_component_requirements_schema(self):
        minimal = {"dependencies": []}
        with_deps = {
            "dependencies": [
                {
                    "name": "dep0",
                    "ref": "1.0.0",
                    "ref_type": "tag",
                    "repo_url": "https://github.com/rcbops/example-dep-0",
                    "sha": "0000000000000000000000000000000000000002",
                    "version": "1.0.0",
                },
                {
                    "name": "dep1",
                    "ref": "some-branch",
                    "ref_type": "branch",
                    "repo_url": "https://github.com/rcbops/example-dep-1",
                    "sha": "0000000000000000000000000000000000001000",
                    "version": None,
                },
            ]
        }

        self.assertTrue(
            schemata.component_requirements_schema.validate(minimal)
        )
        self.assertTrue(
            schemata.component_requirements_schema.validate(with_deps)
        )

    def test_component_metadata_schema(self):
        minimal = {"dependencies": []}
        with_deps = {
            "dependencies": [
                {
                    "name": "dep0",
                    "constraints": ["version<2.0.0"],
                },
                {
                    "name": "dep1",
                    "constraints": ["branch==some-branch"],
                },
                {
                    "name": "dep2",
                    "constraints": [],
                },
            ]
        }

        self.assertTrue(
            schemata.component_metadata_schema.validate(minimal)
        )
        self.assertTrue(
            schemata.component_metadata_schema.validate(with_deps)
        )

    def test_component_schema(self):
        minimal = {
            "name": "component0",
            "repo_url": "https://github.com/rcbops/example-component0",
            "is_product": False,
            "releases": [],
        }
        with_release = {
            "name": "component1",
            "repo_url": "https://github.com/rcbops/example-component1",
            "is_product": False,
            "releases": [
                {
                    "series": "first",
                    "versions": [
                        {
                            "version": "1.0.0",
                            "sha": "0000000000000000000000000000000000000000",
                        },
                    ],
                },
            ],
        }

        self.assertTrue(
            schemata.component_schema.validate(minimal)
        )
        self.assertTrue(
            schemata.component_schema.validate(with_release)
        )

    def test_constraints_schema(self):
        minimal = []
        valid_version_constraints = [
            "version<2",
            "version<1.1",
            "version<1.1.0",
            "version<=1.1.0",
            "version==1.1.0",
            "version!=1.1.0",
            "version>1.1.0",
            "version>=1.1.0",
        ]
        valid_branch_constraints = [
            "branch==test",
        ]
        self.assertEqual([], schemata.constraints_schema.validate(minimal))
        self.assertTrue(
            schemata.constraints_schema.validate(valid_version_constraints)
        )
        self.assertTrue(
            schemata.constraints_schema.validate(valid_branch_constraints)
        )
