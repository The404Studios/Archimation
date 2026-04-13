#!/usr/bin/env python3
"""
Automation Engine - Unit tests.

Tests task lifecycle, capabilities reporting, quick execution,
history tracking, and task cancellation without requiring
a running system or external services.
"""

import asyncio
import sys
import time
from pathlib import Path

# Add daemon to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "ai-control" / "daemon"))

from automation import AutomationEngine, TaskStatus, StepType

passed = 0
failed = 0


def test(name, condition):
    global passed, failed
    print(f"  {name:55s}", end=" ")
    if condition:
        print("\033[32mPASS\033[0m")
        passed += 1
    else:
        print("\033[31mFAIL\033[0m")
        failed += 1


# ------------------------------------------------------------------
# Capabilities
# ------------------------------------------------------------------

def test_capabilities_has_step_types():
    engine = AutomationEngine()
    caps = engine.get_capabilities()
    test("capabilities contains step_types", "step_types" in caps)


def test_capabilities_step_types_content():
    engine = AutomationEngine()
    caps = engine.get_capabilities()
    step_types = caps["step_types"]
    test("shell in step_types", "shell" in step_types)
    test("exec in step_types", "exec" in step_types)
    test("file_write in step_types", "file_write" in step_types)
    test("service in step_types", "service" in step_types)
    test("python in step_types", "python" in step_types)
    test("condition in step_types", "condition" in step_types)


def test_capabilities_features():
    engine = AutomationEngine()
    caps = engine.get_capabilities()
    test("features key present", "features" in caps)
    test("shell_commands in features", "shell_commands" in caps["features"])
    test("full_system_access in features", "full_system_access" in caps["features"])


def test_capabilities_max_concurrent():
    engine = AutomationEngine(max_concurrent=5)
    caps = engine.get_capabilities()
    test("max_concurrent_tasks = 5", caps["max_concurrent_tasks"] == 5)


def test_capabilities_initial_counters():
    engine = AutomationEngine()
    caps = engine.get_capabilities()
    test("running_tasks starts at 0", caps["running_tasks"] == 0)
    test("total_tasks starts at 0", caps["total_tasks"] == 0)


# ------------------------------------------------------------------
# Task listing (empty state)
# ------------------------------------------------------------------

def test_list_tasks_empty():
    engine = AutomationEngine()
    tasks = engine.list_tasks()
    test("list_tasks on new engine is empty", tasks == [])


def test_list_tasks_with_filter_empty():
    engine = AutomationEngine()
    tasks = engine.list_tasks(status="running")
    test("list_tasks with status filter is empty", tasks == [])


# ------------------------------------------------------------------
# History
# ------------------------------------------------------------------

def test_history_empty():
    engine = AutomationEngine()
    history = engine.get_history()
    test("history on new engine is empty", history == [])


def test_history_bounded():
    engine = AutomationEngine()
    # Manually add entries beyond limit
    engine._max_history = 10
    for i in range(25):
        engine._record_history(f"t-{i}", "test", "desc", "completed", {})
    test("history respects max_history", len(engine._history) <= 10)


def test_history_count_parameter():
    engine = AutomationEngine()
    for i in range(20):
        engine._record_history(f"t-{i}", "test", "desc", "completed", {})
    history = engine.get_history(count=5)
    test("get_history(count=5) returns 5", len(history) == 5)
    test("get_history returns most recent", history[-1]["task_id"] == "t-19")


def test_history_records_fields():
    engine = AutomationEngine()
    engine._record_history("abc", "my-task", "a description", "completed", {"extra": 42})
    h = engine.get_history(count=1)[0]
    test("history entry has task_id", h["task_id"] == "abc")
    test("history entry has name", h["name"] == "my-task")
    test("history entry has description", h["description"] == "a description")
    test("history entry has status", h["status"] == "completed")
    test("history entry has timestamp", "timestamp" in h)
    test("history entry has extra fields", h.get("extra") == 42)


# ------------------------------------------------------------------
# get_task (unknown)
# ------------------------------------------------------------------

def test_get_task_unknown():
    engine = AutomationEngine()
    result = engine.get_task("nonexistent-id")
    test("get_task for unknown id returns None", result is None)


# ------------------------------------------------------------------
# submit_quick (runs actual echo command)
# ------------------------------------------------------------------

def test_submit_quick():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(engine.submit_quick("echo hello", timeout=10))
        test("submit_quick returns task_id", "task_id" in result)
        test("submit_quick success=True for echo", result["success"] is True)
        test("submit_quick stdout contains hello", "hello" in result.get("stdout", ""))
        test("submit_quick returncode is 0", result.get("returncode") == 0)
    finally:
        loop.close()


def test_submit_quick_failure():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(engine.submit_quick("false", timeout=10))
        test("submit_quick success=False for false", result["success"] is False)
        test("submit_quick returncode non-zero", result.get("returncode") != 0)
    finally:
        loop.close()


def test_submit_quick_records_history():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(engine.submit_quick("echo test", timeout=10))
        history = engine.get_history()
        test("submit_quick adds history entry", len(history) == 1)
        test("history entry name is 'quick'", history[0]["name"] == "quick")
    finally:
        loop.close()


# ------------------------------------------------------------------
# submit_task (multi-step)
# ------------------------------------------------------------------

def test_submit_task():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        steps = [
            {"type": "shell", "params": {"command": "echo step1"}, "name": "first"},
            {"type": "shell", "params": {"command": "echo step2"}, "name": "second"},
        ]
        task_id = loop.run_until_complete(engine.submit_task("test-task", steps))
        test("submit_task returns task_id string", isinstance(task_id, str) and len(task_id) > 0)

        # Give it a moment to finish
        loop.run_until_complete(asyncio.sleep(1))

        info = engine.get_task(task_id)
        test("get_task returns dict", info is not None)
        test("task has correct steps_total", info["steps_total"] == 2)
        test("task completed both steps", info["steps_completed"] == 2)
        test("task status is completed", info["status"] == "completed")
        test("task has output list", isinstance(info["output"], list))
        test("task output has 2 entries", len(info["output"]) == 2)
        test("task has duration_ms", info["duration_ms"] >= 0)
    finally:
        loop.close()


def test_submit_task_step_failure():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        steps = [
            {"type": "shell", "params": {"command": "echo ok"}},
            {"type": "shell", "params": {"command": "false"}},  # will fail
            {"type": "shell", "params": {"command": "echo should-not-run"}},
        ]
        task_id = loop.run_until_complete(engine.submit_task("fail-task", steps))
        loop.run_until_complete(asyncio.sleep(1))

        info = engine.get_task(task_id)
        test("failing step stops task", info["status"] == "failed")
        test("only 2 steps completed (stopped at failure)", info["steps_completed"] == 2)
    finally:
        loop.close()


def test_submit_task_continue_on_error():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        steps = [
            {"type": "shell", "params": {"command": "false"}, "continue_on_error": True},
            {"type": "shell", "params": {"command": "echo still-running"}},
        ]
        task_id = loop.run_until_complete(engine.submit_task("continue-task", steps))
        loop.run_until_complete(asyncio.sleep(1))

        info = engine.get_task(task_id)
        test("continue_on_error lets task proceed", info["status"] == "completed")
        test("all steps completed", info["steps_completed"] == 2)
    finally:
        loop.close()


def test_list_tasks_after_submit():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        steps = [{"type": "shell", "params": {"command": "echo hi"}}]
        loop.run_until_complete(engine.submit_task("listed-task", steps))
        loop.run_until_complete(asyncio.sleep(1))

        tasks = engine.list_tasks()
        test("list_tasks shows submitted task", len(tasks) == 1)
        test("listed task has task_id", "task_id" in tasks[0])
        test("listed task has status", "status" in tasks[0])
    finally:
        loop.close()


def test_list_tasks_status_filter():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        steps = [{"type": "shell", "params": {"command": "echo done"}}]
        loop.run_until_complete(engine.submit_task("filter-task", steps))
        loop.run_until_complete(asyncio.sleep(1))

        completed = engine.list_tasks(status="completed")
        running = engine.list_tasks(status="running")
        test("filter by completed finds task", len(completed) == 1)
        test("filter by running finds nothing", len(running) == 0)
    finally:
        loop.close()


# ------------------------------------------------------------------
# cancel_task
# ------------------------------------------------------------------

def test_cancel_nonexistent():
    engine = AutomationEngine()
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(engine.cancel_task("no-such-task"))
        test("cancel nonexistent returns error", result["success"] is False)
    finally:
        loop.close()


# ------------------------------------------------------------------
# Enums
# ------------------------------------------------------------------

def test_task_status_enum():
    test("PENDING value", TaskStatus.PENDING.value == "pending")
    test("RUNNING value", TaskStatus.RUNNING.value == "running")
    test("COMPLETED value", TaskStatus.COMPLETED.value == "completed")
    test("FAILED value", TaskStatus.FAILED.value == "failed")
    test("CANCELLED value", TaskStatus.CANCELLED.value == "cancelled")


def test_step_type_enum():
    test("SHELL value", StepType.SHELL.value == "shell")
    test("EXEC value", StepType.EXEC.value == "exec")
    test("FILE_WRITE value", StepType.FILE_WRITE.value == "file_write")
    test("FILE_READ value", StepType.FILE_READ.value == "file_read")
    test("SERVICE value", StepType.SERVICE.value == "service")
    test("PACKAGE value", StepType.PACKAGE.value == "package")
    test("HTTP value", StepType.HTTP.value == "http")
    test("PYTHON value", StepType.PYTHON.value == "python")
    test("WAIT value", StepType.WAIT.value == "wait")
    test("NOTIFY value", StepType.NOTIFY.value == "notify")
    test("CONDITION value", StepType.CONDITION.value == "condition")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    print("=== Automation Engine Unit Tests ===\n")

    print("-- Capabilities --")
    test_capabilities_has_step_types()
    test_capabilities_step_types_content()
    test_capabilities_features()
    test_capabilities_max_concurrent()
    test_capabilities_initial_counters()

    print("\n-- Task Listing (empty) --")
    test_list_tasks_empty()
    test_list_tasks_with_filter_empty()

    print("\n-- History --")
    test_history_empty()
    test_history_bounded()
    test_history_count_parameter()
    test_history_records_fields()

    print("\n-- Get Task (unknown) --")
    test_get_task_unknown()

    print("\n-- Quick Execution --")
    test_submit_quick()
    test_submit_quick_failure()
    test_submit_quick_records_history()

    print("\n-- Multi-Step Tasks --")
    test_submit_task()
    test_submit_task_step_failure()
    test_submit_task_continue_on_error()
    test_list_tasks_after_submit()
    test_list_tasks_status_filter()

    print("\n-- Cancel --")
    test_cancel_nonexistent()

    print("\n-- Enums --")
    test_task_status_enum()
    test_step_type_enum()

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
