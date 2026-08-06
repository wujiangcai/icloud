#!/usr/bin/env python3
"""Run the recurring Hide My Email generation job.

The first successful run creates four aliases. Later successful runs create
five aliases. The state is kept under ``icloud-code-api/data`` so a scheduled
task can be restarted without losing its place.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
API_DIR = ROOT / "icloud-code-api"
GENERATOR_DIR = ROOT / "hidemyemail-generator"
GENERATOR_PYTHON = GENERATOR_DIR / ".venv" / "Scripts" / "python.exe"
GENERATOR_SCRIPT = API_DIR / "generate_and_import.py"
DATA_DIR = API_DIR / "data"
STATE_PATH = DATA_DIR / "hme_schedule_state.json"
LOCK_PATH = DATA_DIR / "hme_schedule.lock"
LOG_PATH = DATA_DIR / "hme_schedule.log"
LOCK_STALE_SECONDS = 2 * 60 * 60
_lock_descriptor: int | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_state() -> dict[str, object]:
    if not STATE_PATH.exists():
        return {"completed_runs": 0}
    try:
        value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"completed_runs": 0}
    return value if isinstance(value, dict) else {"completed_runs": 0}


def write_state(state: dict[str, object]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(STATE_PATH)


def _lock_pid() -> int | None:
    try:
        content = LOCK_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    match = re.search(r"(?m)^pid=(\d+)\s*$", content)
    return int(match.group(1)) if match else None


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # On Windows os.kill(pid, 0) reports a range of Win32 errors for
        # an already exited process. PermissionError is handled above;
        # an ordinary OSError here is treated as not running. Avoid a
        # ctypes probe because it can hang in restricted environments.
        return False
    return True


def acquire_lock() -> bool:
    global _lock_descriptor
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            descriptor = os.open(
                LOCK_PATH,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            try:
                pid = _lock_pid()
                age = max(0.0, time.time() - LOCK_PATH.stat().st_mtime)
                # A live owner is authoritative even after a long run.  Old
                # versions only checked mtime, so one slow job could be
                # mistaken for a stale lock forever after the next launch.
                if pid is not None and _pid_is_running(pid):
                    return False
                if pid is None and age <= LOCK_STALE_SECONDS:
                    return False
                LOCK_PATH.unlink()
            except OSError:
                return False
            continue

        try:
            os.write(descriptor, f"pid={os.getpid()}\nstarted={now_iso()}\n".encode("utf-8"))
            os.fsync(descriptor)
        except OSError:
            os.close(descriptor)
            try:
                LOCK_PATH.unlink()
            except FileNotFoundError:
                pass
            raise
        _lock_descriptor = descriptor
        return True


def release_lock() -> None:
    global _lock_descriptor
    descriptor = _lock_descriptor
    _lock_descriptor = None
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        LOCK_PATH.unlink()
    except FileNotFoundError:
        pass


def safe_log_text(text: str) -> str:
    """Keep generated addresses and API credentials out of the scheduler log."""
    text = re.sub(
        r"[A-Za-z0-9._%+\-]+@icloud\.com",
        "<alias>@icloud.com",
        text,
        flags=re.IGNORECASE,
    )
    return re.sub(
        r'("(?:api_key|credential)"\s*:\s*")[^"]*',
        r'\1<redacted>',
        text,
        flags=re.IGNORECASE,
    )


def append_log(text: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as handle:
        handle.write(safe_log_text(text))
        if not text.endswith("\n"):
            handle.write("\n")


def terminate_process_tree(process: subprocess.Popen[str]) -> None:
    """Stop a timed-out generator and any browser children it started."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
            if process.poll() is not None:
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        process.kill()
    except OSError:
        pass


def run_once(
    *,
    initial_count: int,
    recurring_count: int,
    success_delay: int,
    failure_delay: int,
    max_failures: int,
    timeout_minutes: int,
    force_count: int | None = None,
) -> int:
    if not acquire_lock():
        append_log(f"[{now_iso()}] skipped: another scheduled run is active")
        return 0

    try:
        state = read_state()
        try:
            completed_runs = max(0, int(state.get("completed_runs", 0)))
        except (TypeError, ValueError):
            completed_runs = 0
        count = (
            force_count
            if force_count is not None
            else (initial_count if completed_runs == 0 else recurring_count)
        )
        if count < 1:
            append_log(f"[{now_iso()}] error: count must be at least 1")
            return 2

        if not GENERATOR_PYTHON.exists():
            append_log(f"[{now_iso()}] error: Python runtime not found: {GENERATOR_PYTHON}")
            return 2
        if not GENERATOR_SCRIPT.exists():
            append_log(f"[{now_iso()}] error: generator script not found: {GENERATOR_SCRIPT}")
            return 2

        command = [
            str(GENERATOR_PYTHON),
            str(GENERATOR_SCRIPT),
            "--count",
            str(count),
            "--success-delay",
            str(max(0, success_delay)),
            "--failure-delay",
            str(max(0, failure_delay)),
        ]
        append_log(
            f"[{now_iso()}] starting run: count={count}, completed_runs={completed_runs}\n"
        )
        environment = {
            **os.environ,
            "HME_MAX_FAILURES": str(max(0, max_failures)),
        }
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if os.name == "nt"
            else 0
        )
        process = subprocess.Popen(
            command,
            cwd=str(API_DIR),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        try:
            output, _ = process.communicate(timeout=max(1, timeout_minutes) * 60)
        except subprocess.TimeoutExpired:
            terminate_process_tree(process)
            try:
                output, _ = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                output, _ = process.communicate()
            append_log(
                f"[{now_iso()}] timed out after {timeout_minutes} minutes\n"
                + (output or "")
            )
            return 1

        append_log(output or "")
        if process.returncode != 0:
            append_log(f"[{now_iso()}] run failed: exit={process.returncode}\n")
            return process.returncode

        state.update(
            {
                "completed_runs": completed_runs + 1,
                "last_count": count,
                "last_success_at": now_iso(),
            }
        )
        write_state(state)
        append_log(f"[{now_iso()}] run completed successfully\n")
        return 0
    finally:
        release_lock()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run scheduled iCloud Hide My Email generation"
    )
    parser.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--initial-count", type=int, default=4)
    parser.add_argument("--recurring-count", type=int, default=5)
    parser.add_argument("--success-delay", type=int, default=240)
    parser.add_argument("--failure-delay", type=int, default=600)
    parser.add_argument("--max-failures", type=int, default=3)
    parser.add_argument("--timeout-minutes", type=int, default=27)
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Run a one-off fixed count without changing the first/recurring rule",
    )
    args = parser.parse_args()
    return run_once(
        initial_count=args.initial_count,
        recurring_count=args.recurring_count,
        success_delay=args.success_delay,
        failure_delay=args.failure_delay,
        max_failures=args.max_failures,
        timeout_minutes=args.timeout_minutes,
        force_count=args.count,
    )


if __name__ == "__main__":
    raise SystemExit(main())
