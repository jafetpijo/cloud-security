"""Tests for the folder growth detector. Run with:  python3 -m unittest -v"""
import os
import tempfile
import time
import unittest
from pathlib import Path

import detector_crecimiento as g

MB = g.MB


class TestGrowth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name) / "data"
        self.folder.mkdir()
        (self.folder / "a.bin").write_bytes(b"x" * MB)
        self.state_file = str(Path(self.tmp.name) / "state.json")

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, threshold=1):
        return g.main(["--path", str(self.folder), "--state", self.state_file,
                       "--threshold", str(threshold)])

    def test_first_run_saves_reference(self):
        self.assertEqual(self.run_check(), g.EXIT_OK)
        self.assertTrue(Path(self.state_file).is_file())

    def test_small_change_is_ok(self):
        self.run_check()
        (self.folder / "b.bin").write_bytes(b"x" * 1000)
        self.assertEqual(self.run_check(), g.EXIT_OK)

    def test_big_growth_alerts_and_lists_file(self):
        state = {}
        results, state = g.check_folders([str(self.folder)], state, 1, time.time() - 60)
        (self.folder / "dump.zip").write_bytes(b"x" * 2 * MB)
        results, _ = g.check_folders([str(self.folder)], state, 1, time.time())
        self.assertEqual(results[0]["severity"], "HIGH")
        self.assertTrue(results[0]["changed_files"][0]["file"].endswith("dump.zip"))

    def test_big_drop_alerts(self):
        (self.folder / "big.bin").write_bytes(b"x" * 3 * MB)
        self.run_check()
        os.remove(self.folder / "big.bin")
        self.assertEqual(self.run_check(), g.EXIT_ALERTS)

    def test_symlinks_are_skipped(self):
        os.symlink(self.folder / "a.bin", self.folder / "link.bin")
        total, _ = g.scan_folder(self.folder)
        self.assertEqual(total, MB)


class TestMain(unittest.TestCase):
    def test_missing_folder_is_error(self):
        self.assertEqual(g.main(["--path", "does/not/exist"]), g.EXIT_ERROR)

    def test_demo_finds_alerts(self):
        self.assertEqual(g.main(["--demo", "--threshold", "1"]), g.EXIT_ALERTS)


if __name__ == "__main__":
    unittest.main()
