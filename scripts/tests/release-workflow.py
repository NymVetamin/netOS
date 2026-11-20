"""Check the release workflow locally with Python, PyYAML and Bash."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

import yaml


class ReleaseWorkflowTest(unittest.TestCase):
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
