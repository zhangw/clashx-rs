"""Keep the two newest timestamped macOS packages and their checksum files."""
from pathlib import Path
import re
import sys


def prune(directory):
    pattern = re.compile(r'clashx-rs-.+-(\d{8}\.\d{6})-macos\d+-arm64\.pkg')
    packages = []
    for path in Path(directory).iterdir():
        match = pattern.fullmatch(path.name)
        if match and path.is_file() and not path.is_symlink():
            packages.append((match.group(1), path.name, path))
    for _, _, path in sorted(packages, reverse=True)[2:]:
        path.unlink()
        path.with_suffix('.pkg.sha256').unlink(missing_ok=True)
        print(f'Removed old installer: {path.name}')


if __name__ == '__main__':
    prune(sys.argv[1])
