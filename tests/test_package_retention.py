"""Check package cleanup without touching release artifacts."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PackageRetentionTest(unittest.TestCase):
    def test_only_two_newest_packages_and_checksums_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [f'clashx-rs-0.1.0-20260920.00000{i}-macos27-arm64.pkg' for i in range(4)]
            for name in reversed(names):
                (root / name).touch()
                (root / (name + '.sha256')).touch()
            unrelated = ['other.pkg', '.gitignore', 'clashx-rs-not-a-release.pkg']
            for name in unrelated:
                (root / name).touch()
            subprocess.run([sys.executable, str(ROOT / 'scripts/prune-macos-packages.py'), directory], check=True,
                           capture_output=True)
            self.assertEqual({p.name for p in root.iterdir()},
                             set(unrelated + names[2:] + [name + '.sha256' for name in names[2:]]))
