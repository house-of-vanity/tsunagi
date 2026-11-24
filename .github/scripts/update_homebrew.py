"""Update the tap's formula and cask for a verified macOS release archive."""

import argparse
import re
from pathlib import Path

VERSION = r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}"
SHA256 = r"[0-9a-f]{64}"


def update_tap(tap: Path, tag: str, checksum: str) -> None:
    if not re.fullmatch(f"v{VERSION}", tag):
        raise ValueError("expected a stable vMAJOR.MINOR.PATCH release")
    if not re.fullmatch(SHA256, checksum):
        raise ValueError("expected a SHA-256 digest")

    version = tag[1:]
    updates = {}
    for filename, version_field, hash_field in (
        ("Formula/tsunagi.rb", "VERSION = ", "SHA256 = "),
        ("Casks/tsunagi-gui.rb", "version ", "sha256 "),
    ):
        path = tap / filename
        original = path.read_text()
        version_pattern = rf'^(  {version_field}")({VERSION})(")$'
        hash_pattern = rf'^(  {hash_field}")({SHA256})(")$'
        current = re.findall(version_pattern, original, re.MULTILINE)
        if len(current) != 1 or len(re.findall(hash_pattern, original, re.MULTILINE)) != 1:
            raise ValueError(f"expected one version and one SHA-256 in {filename}")
        if tuple(map(int, version.split("."))) < tuple(map(int, current[0][1].split("."))):
            print(f"Skipping older release {tag}: {filename} already has {current[0][1]}")
            return
        updated = re.sub(version_pattern, rf"\g<1>{version}\g<3>", original, flags=re.MULTILINE)
        updated = re.sub(hash_pattern, rf"\g<1>{checksum}\g<3>", updated, flags=re.MULTILINE)
        updates[path] = (original, updated)

    for path, (original, updated) in updates.items():
        if updated != original:
            path.write_text(updated)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tap", type=Path)
    parser.add_argument("tag")
    parser.add_argument("checksum")
    args = parser.parse_args()
    try:
        update_tap(args.tap, args.tag, args.checksum)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
