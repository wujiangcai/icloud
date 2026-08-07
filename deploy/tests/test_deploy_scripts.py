import importlib.machinery
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_script(name: str, relative_path: str):
    path = REPO_ROOT / relative_path
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class BackupGuardTests(unittest.TestCase):
    def setUp(self):
        self.module = load_script(
            f"backup_guard_{id(self)}", "deploy/backup/icloud-code-platform-backup"
        )
        self.module.subprocess.run = lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, "ok", ""
        )
        self.module.R2_MONITOR_COMMAND = Path("/bin/true")

    def monitor(self, total_bytes: int, class_a: int = 100, class_b: int = 100):
        return {
            "hard_limit_reached": False,
            "storage": {
                "total_bytes": total_bytes,
                "hard_limit_bytes": 8_000_000_000,
            },
            "operations": {
                "class_a": class_a,
                "hard_class_a": 900_000,
                "class_b": class_b,
                "hard_class_b": 9_000_000,
            },
        }

    def test_blocks_projected_storage_above_hard_limit(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            (snapshot / "payload").write_bytes(b"x" * 200_000)
            self.module.R2_MONITOR_PATH = root / "monitor.json"
            self.module.R2_MONITOR_PATH.write_text(
                json.dumps(self.monitor(7_999_900_001)), encoding="utf-8"
            )
            self.assertFalse(self.module.remote_backup_allowed(snapshot))

    def test_allows_normal_usage(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            (snapshot / "payload").write_bytes(b"x" * 200_000)
            self.module.R2_MONITOR_PATH = root / "monitor.json"
            self.module.R2_MONITOR_PATH.write_text(
                json.dumps(self.monitor(1_500_000)), encoding="utf-8"
            )
            self.assertTrue(self.module.remote_backup_allowed(snapshot))

    def test_blocks_operation_hard_limit(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            snapshot = root / "snapshot"
            snapshot.mkdir()
            self.module.R2_MONITOR_PATH = root / "monitor.json"
            self.module.R2_MONITOR_PATH.write_text(
                json.dumps(self.monitor(1_500_000, class_a=900_000)), encoding="utf-8"
            )
            self.assertFalse(self.module.remote_backup_allowed(snapshot))


class BudgetAlertTests(unittest.TestCase):
    def setUp(self):
        self.module = load_script(
            f"budget_alert_{id(self)}",
            "deploy/monitor/configure-cloudflare-budget-alert",
        )

    def test_normalizes_threshold(self):
        self.assertEqual(self.module.normalize_threshold("0.010"), "0.01")

    def test_rejects_non_positive_threshold(self):
        with self.assertRaises(ValueError):
            self.module.normalize_threshold("0")


if __name__ == "__main__":
    unittest.main()
