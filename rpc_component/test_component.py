import unittest

import rpc_component.component as c
import rpc_component.schemata as schemata


class TestUpdateRequirements(unittest.TestCase):

    def test_requirement_from_version_constraints(self):
        component = {
            "name": "component0",
            "repo_url": "https://github.com/rcbops/example-component0",
            "is_product": False,
            "releases": [
                {
                    "series": "first",
                    "versions": [
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
                    ],
                },
            ],
        }
        self.assertTrue(schemata.component_schema.validate(component))
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
