"""Check the release workflow locally with Python, PyYAML and Bash."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml


class ReleaseWorkflowTest(unittest.TestCase):
    def test_publish_prerelease_and_retry(self):
        root = Path(__file__).resolve().parents[2]
        steps = yaml.safe_load((root / ".github/workflows/release.yml").read_text("utf-8"))["jobs"]["release"]["steps"]
        publish = next(step["run"] for step in steps if "gh release create" in step.get("run", ""))
        mock = """
gh() {
    [[ $1 == release && $3 == "$TAG" ]] || return 9
    local action=$2 flag
    shift 3
    for flag in "$@"; do
        if [[ $flag == --prerelease ]]; then action+=" prerelease"; fi
    done
    echo "$action" >> calls
    case "$action" in
        view) [[ $* == '--json isPrerelease --jq .isPrerelease' && $EXISTING != absent ]] && echo "$EXISTING" ;;
        'edit prerelease') [[ $EDIT_FAIL == no ]] ;;
        *) return 0 ;;
    esac
}
"""
        for tag, existing, fail, expected in [
            ("v1.2.3-rc.1+build", "absent", False, ["view", "create prerelease"]),
            ("v1.2.3-rc.1", "false", False, ["view", "edit prerelease", "upload"]),
            ("v1.2.3-rc.1", "true", False, ["view", "upload"]),
            ("v1.2.3--alpha", "absent", False, ["view", "create prerelease"]),
            ("v1.2.3", "absent", False, ["view", "create"]),
            ("v1.2.3+build-1", "absent", False, ["view", "create"]),
            ("v1.2.3", "true", False, ["view", "upload"]),
            ("v1.2.3-rc.1", "false", True, ["view", "edit prerelease"]),
        ]:
            with self.subTest(tag=tag, existing=existing, fail=fail), tempfile.TemporaryDirectory() as directory:
                result = subprocess.run([shutil.which("bash"), "-ec", mock + publish], cwd=directory,
                                        env={**os.environ, "TAG": tag, "EXISTING": existing,
                                             "EDIT_FAIL": "yes" if fail else "no", "GITHUB_REPOSITORY": "test/netos"},
                                        capture_output=True)
                self.assertEqual(result.returncode == 0, not fail, result.stderr)
                self.assertEqual((Path(directory) / "calls").read_text().splitlines(), expected)

    def test_tag_is_data_throughout_release(self):
        root = Path(__file__).resolve().parents[2]
        workflow = yaml.safe_load((root / ".github/workflows/release.yml").read_text("utf-8"))
        job = workflow["jobs"]["release"]
        steps = job["steps"]
        for step in steps:
            for expression in re.findall(r"\$\{\{(.*?)\}\}", step.get("run", ""), re.DOTALL):
                self.assertNotRegex(expression.lower(), r"\b(tag|ref|ref_name)\b")
        self.assertEqual(job["env"]["TAG"], "${{ inputs.tag || github.ref_name }}")
        checkout = next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(steps[checkout]["with"]["ref"], "refs/tags/${{ env.TAG }}")
        guard = next(s["run"] for s in steps[:checkout] if "run" in s)
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        for tag, valid in [("v0.1", True), ("v1.2.3-rc.1+build", True),
                           ("", False), ("two words", False), ("line\nbreak", False),
                           ("v1'quote", False), ("-option", False), ("v1/part", False)]:
            with self.subTest(tag=tag):
                result = subprocess.run([bash, "-ec", guard], env={**os.environ, "TAG": tag},
                                        capture_output=True)
                self.assertEqual(result.returncode, 0 if valid else 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
