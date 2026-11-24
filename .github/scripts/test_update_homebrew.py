import tempfile
import unittest
from pathlib import Path

from update_homebrew import update_tap


class UpdateTapTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tap = Path(directory.name)
        self.formula = self.tap / "Formula/tsunagi.rb"
        self.cask = self.tap / "Casks/tsunagi-gui.rb"
        self.formula.parent.mkdir()
        self.cask.parent.mkdir()
        self.old_hash = "a" * 64
        self.new_hash = "b" * 64
        self.formula.write_text(f'  VERSION = "1.9.0"\n  SHA256 = "{self.old_hash}"\n')
        self.cask.write_text(f'  version "1.9.0"\n  sha256 "{self.old_hash}"\n')

    def test_updates_both_packages_and_allows_retry(self):
        for _ in range(2):
            update_tap(self.tap, "v1.10.0", self.new_hash)
            self.assertEqual(self.formula.read_text(), f'  VERSION = "1.10.0"\n  SHA256 = "{self.new_hash}"\n')
            self.assertEqual(self.cask.read_text(), f'  version "1.10.0"\n  sha256 "{self.new_hash}"\n')

    def test_older_release_does_not_replace_either_package(self):
        before = self.formula.read_bytes(), self.cask.read_bytes()
        update_tap(self.tap, "v1.8.9", self.new_hash)
        self.assertEqual((self.formula.read_bytes(), self.cask.read_bytes()), before)

    def test_invalid_release_or_cask_leaves_formula_untouched(self):
        before = self.formula.read_bytes()
        with self.assertRaises(ValueError):
            update_tap(self.tap, "v1.10.0-rc.1", self.new_hash)
        with self.assertRaises(ValueError):
            update_tap(self.tap, "v1.10.0", "invalid")
        self.cask.write_text('  version "1.9.0"\n')
        with self.assertRaises(ValueError):
            update_tap(self.tap, "v1.10.0", self.new_hash)
        self.assertEqual(self.formula.read_bytes(), before)
