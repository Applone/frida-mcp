"""Tests for the Frida MCP server against the mocked frida module."""

import pytest

from conftest import fake_device
from frida_mcp import server


@pytest.fixture(autouse=True)
def fresh_sessions():
    server.sessions = server.SessionManager()
    yield
    server.sessions = server.SessionManager()


def test_enumerate_devices():
    devices = server.enumerate_devices()
    assert devices == [{"id": "usb-1", "name": "Test Phone", "type": "usb"}]


def test_get_device():
    assert server.get_device("usb-1")["name"] == "Test Phone"
    with pytest.raises(ValueError):
        server.get_device("missing")


def test_get_usb_device():
    assert server.get_usb_device()["id"] == "usb-1"


def test_get_local_device():
    assert server.get_local_device()["id"] == "usb-1"


def test_enumerate_processes_defaults_to_usb():
    procs = server.enumerate_processes()
    assert {"pid": 1234, "name": "com.example.app"} in procs


def test_enumerate_processes_by_device_id():
    procs = server.enumerate_processes(device_id="usb-1")
    assert len(procs) == 2


def test_get_process_by_name():
    found = server.get_process_by_name("EXAMPLE")
    assert found == {"found": True, "pid": 1234, "name": "com.example.app"}
    assert server.get_process_by_name("nope")["found"] is False


def test_attach_returns_session_id():
    result = server.attach_to_process(1234)
    assert result["success"] is True
    assert result["session_id"].startswith("session_")


def test_spawn_resume_kill():
    # Test auto_attach=True (default)
    spawned = server.spawn_process("com.example.app")
    assert spawned["pid"] == 4321
    assert "session_id" in spawned
    assert fake_device.spawned[-1] == ("com.example.app", [])

    resumed = server.resume_process(4321)
    assert resumed["success"] is True
    assert resumed["pid"] == 4321
    assert resumed["session_id"] == spawned["session_id"]
    assert fake_device.resumed[-1] == 4321

    assert server.kill_process(4321) == {"success": True, "pid": 4321}
    assert fake_device.killed[-1] == 4321

    # Test auto_attach=False
    spawned_no_attach = server.spawn_process("com.example.app", auto_attach=False)
    assert spawned_no_attach == {"pid": 4321}
    resumed_no_attach = server.resume_process(4321)
    assert resumed_no_attach["success"] is True
    assert resumed_no_attach["pid"] == 4321
    assert "session_id" in resumed_no_attach


def test_execute_in_session_one_shot():
    session_id = server.attach_to_process(1234)["session_id"]
    result = server.execute_in_session(session_id, "console.log('hello'); 40 + 2")
    assert result["status"] == "success"
    assert result["result"] == "42"
    assert result["initial_logs"] == ["hello"]
    assert result["script_unloaded"] is True
    script = fake_device.session.scripts[-1]
    assert script.unloaded is True
    assert "40 + 2" in script.source


def test_execute_in_session_keep_alive_and_messages():
    session_id = server.attach_to_process(1234)["session_id"]
    result = server.execute_in_session(session_id, "var x = 1", keep_alive=True)
    assert result["status"] == "success"
    assert result["script_unloaded"] is False
    script = fake_device.session.scripts[-1]
    assert script.unloaded is False

    messages = server.get_session_messages(session_id)
    assert messages["status"] == "success"
    kinds = [m["payload"].get("kind") for m in messages["messages"]]
    assert "hook_hit" in kinds

    drained = server.get_session_messages(session_id)
    assert drained["messages_retrieved"] == 0


def test_execute_in_unknown_session():
    with pytest.raises(ValueError):
        server.execute_in_session("nope", "1")
    with pytest.raises(ValueError):
        server.get_session_messages("nope")


def test_detach_session():
    session_id = server.attach_to_process(1234)["session_id"]
    server.execute_in_session(session_id, "1", keep_alive=True)
    assert server.detach_session(session_id)["status"] == "success"
    assert fake_device.session.detached is True
    assert fake_device.session.scripts[-1].unloaded is True
    with pytest.raises(ValueError):
        server.detach_session(session_id)


def test_resources():
    assert "16.0.0-test" in server.get_version()
    assert "Test Phone" in server.list_devices_resource()
    assert "com.example.app" in server.list_processes_resource()
