from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scope = load_script("ci_change_scope", "ci-change-scope.py")
workflows = load_script("verify_workflows", "verify-workflows.py")


class ActionReferenceTests(unittest.TestCase):
    def test_accepts_consistent_allowlisted_commit_pins(self) -> None:
        pin = "a" * 40
        contents = {
            "ci.yml": f"uses: actions/checkout@{pin}\n",
            "release.yml": f"uses: actions/checkout@{pin} # v7\n",
        }
        self.assertEqual(workflows.action_reference_errors(contents), [])

    def test_rejects_floating_action_reference(self) -> None:
        errors = workflows.action_reference_errors(
            {"ci.yml": "uses: actions/checkout@v7\n"}
        )
        self.assertTrue(any("full commit SHA" in error for error in errors))

    def test_rejects_unreviewed_action(self) -> None:
        errors = workflows.action_reference_errors(
            {"ci.yml": f"uses: example/unreviewed@{'b' * 40}\n"}
        )
        self.assertTrue(any("unreviewed external action" in error for error in errors))

    def test_rejects_inconsistent_pins(self) -> None:
        errors = workflows.action_reference_errors(
            {
                "ci.yml": f"uses: actions/checkout@{'a' * 40}\n",
                "release.yml": f"uses: actions/checkout@{'b' * 40}\n",
            }
        )
        self.assertTrue(any("one consistent commit SHA" in error for error in errors))


class ChangeScopeTests(unittest.TestCase):
    def test_workflow_and_documentation_changes_are_fast(self) -> None:
        self.assertFalse(
            scope.requires_native(
                [
                    ".github/workflows/ci.yml",
                    "renovate.json",
                    "docs/release-automation.md",
                ]
            )
        )

    def test_source_and_lockfile_changes_require_native_gates(self) -> None:
        self.assertTrue(scope.requires_native(["ui/src/App.svelte"]))
        self.assertTrue(scope.requires_native(["Cargo.lock"]))

    def test_empty_diff_fails_safe(self) -> None:
        self.assertTrue(scope.requires_native([]))


if __name__ == "__main__":
    unittest.main()
