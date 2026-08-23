"""Frida MCP server.

Exposes Frida dynamic instrumentation capabilities as MCP tools and resources.
All device access goes through DeviceManager so it can be mocked in tests.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Annotated, Any, Dict, List, Optional

import frida
from fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("frida")


class SessionManager:
    """Tracks attached Frida sessions, their scripts and message queues."""

    def __init__(self) -> None:
        self._sessions: Dict[str, frida.core.Session] = {}
        self._scripts: Dict[str, List[frida.core.Script]] = {}
        self._messages: Dict[str, List[Dict[str, Any]]] = {}
        self._locks: Dict[str, threading.Lock] = {}

    def create(self, session: frida.core.Session) -> str:
        session_id = f"session_{id(session)}_{int(time.time() * 1000)}"
        self._sessions[session_id] = session
        self._scripts[session_id] = []
        self._messages[session_id] = []
        self._locks[session_id] = threading.Lock()
        return session_id

    def get(self, session_id: str) -> frida.core.Session:
        if session_id not in self._sessions:
            raise ValueError(f"Session '{session_id}' not found")
        return self._sessions[session_id]

    def lock(self, session_id: str) -> threading.Lock:
        return self._locks[session_id]

    def append_message(self, session_id: str, message: Dict[str, Any]) -> None:
        with self._locks[session_id]:
            self._messages[session_id].append(message)

    def drain_messages(self, session_id: str) -> List[Dict[str, Any]]:
        self.get(session_id)
        with self._locks[session_id]:
            messages = list(self._messages[session_id])
            self._messages[session_id].clear()
        return messages

    def track_script(self, session_id: str, script: frida.core.Script) -> None:
        self._scripts[session_id].append(script)

    def close(self, session_id: str) -> None:
        if session_id not in self._sessions:
            raise ValueError(f"Session '{session_id}' not found")
        for script in self._scripts.pop(session_id, []):
            try:
                script.unload()
            except frida.InvalidOperationError:
                pass
        session = self._sessions.pop(session_id)
        session.detach()
        self._messages.pop(session_id, None)
        self._locks.pop(session_id, None)


sessions = SessionManager()


def _device(device_id: Optional[str]) -> frida.core.Device:
    if device_id:
        return frida.get_device(device_id)
    return frida.get_usb_device()


_DEVICE_ID_DESC = "Device ID to target. If omitted, the first USB device is used."


@mcp.tool()
def enumerate_devices() -> List[Dict[str, Any]]:
    """List all devices known to Frida (local, USB, remote)."""
    return [
        {"id": d.id, "name": d.name, "type": d.type} for d in frida.enumerate_devices()
    ]


@mcp.tool()
def get_device(
    device_id: Annotated[str, Field(description="ID of the device to look up")],
) -> Dict[str, Any]:
    """Get information about a single device by ID."""
    try:
        d = frida.get_device(device_id)
    except frida.InvalidArgumentError:
        raise ValueError(f"Device with ID '{device_id}' not found")
    return {"id": d.id, "name": d.name, "type": d.type}


@mcp.tool()
def get_usb_device() -> Dict[str, Any]:
    """Get information about the first attached USB device."""
    try:
        d = frida.get_usb_device()
    except frida.InvalidArgumentError:
        raise ValueError("No USB device found")
    return {"id": d.id, "name": d.name, "type": d.type}


@mcp.tool()
def get_local_device() -> Dict[str, Any]:
    """Get information about the local device."""
    d = frida.get_local_device()
    return {"id": d.id, "name": d.name, "type": d.type}


@mcp.tool()
def enumerate_processes(
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> List[Dict[str, Any]]:
    """List all processes running on the target device."""
    return [
        {"pid": p.pid, "name": p.name} for p in _device(device_id).enumerate_processes()
    ]


@mcp.tool()
def get_process_by_name(
    name: Annotated[
        str, Field(description="Process name or substring, case-insensitive")
    ],
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> Dict[str, Any]:
    """Find a process by (partial, case-insensitive) name."""
    for p in _device(device_id).enumerate_processes():
        if name.lower() in p.name.lower():
            return {"found": True, "pid": p.pid, "name": p.name}
    return {"found": False, "error": f"Process '{name}' not found"}


@mcp.tool()
def attach_to_process(
    pid: Annotated[int, Field(description="PID to attach to")],
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> Dict[str, Any]:
    """Attach to a process. Returns a session_id usable with other session tools."""
    session = _device(device_id).attach(pid)
    session_id = sessions.create(session)
    return {"success": True, "pid": pid, "session_id": session_id}


@mcp.tool()
def spawn_process(
    program: Annotated[
        str, Field(description="Program path or application identifier to spawn")
    ],
    args: Annotated[
        Optional[List[str]], Field(description="Arguments for the program")
    ] = None,
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> Dict[str, Any]:
    """Spawn a program in suspended state. Use resume_process to start it."""
    pid = _device(device_id).spawn(program, args=args or [])
    return {"pid": pid}


@mcp.tool()
def resume_process(
    pid: Annotated[int, Field(description="PID of a spawned (suspended) process")],
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> Dict[str, Any]:
    """Resume a process previously started with spawn_process."""
    _device(device_id).resume(pid)
    return {"success": True, "pid": pid}


@mcp.tool()
def kill_process(
    pid: Annotated[int, Field(description="PID to kill")],
    device_id: Annotated[Optional[str], Field(description=_DEVICE_ID_DESC)] = None,
) -> Dict[str, Any]:
    """Kill a process on the target device."""
    _device(device_id).kill(pid)
    return {"success": True, "pid": pid}


_EXECUTION_WRAPPER = """
(function() {
    var initialLogs = [];
    var originalLog = console.log;
    console.log = function() {
        var args = Array.prototype.slice.call(arguments);
        var logMsg = args.map(function(arg) {
            return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
        }).join(' ');
        initialLogs.push(logMsg);
        originalLog.apply(console, arguments);
    };
    var scriptResult, scriptError;
    try {
        scriptResult = eval({code});
    } catch (e) {
        scriptError = { message: e.toString(), stack: e.stack };
    }
    console.log = originalLog;
    send({
        type: 'execution_receipt',
        result: scriptError ? undefined : (scriptResult !== undefined ? String(scriptResult) : 'undefined'),
        error: scriptError,
        initial_logs: initialLogs
    });
})();
"""


@mcp.tool()
def execute_in_session(
    session_id: Annotated[
        str, Field(description="Session ID returned by attach_to_process")
    ],
    javascript_code: Annotated[
        str,
        Field(
            description="JavaScript to evaluate in the target process. Can use Frida's JS API (Interceptor, Memory, Module, rpc, ...)."
        ),
    ],
    keep_alive: Annotated[
        bool,
        Field(
            description="If true, the script stays loaded (for hooks/RPC); retrieve async messages with get_session_messages."
        ),
    ] = False,
) -> Dict[str, Any]:
    """Execute JavaScript code inside an attached session."""
    session = sessions.get(session_id)

    wrapped = _EXECUTION_WRAPPER.replace("{code}", json.dumps(javascript_code))
    receipt: List[Dict[str, Any]] = []

    def on_receipt(message: Dict[str, Any], data: Any) -> None:
        if (
            message["type"] == "send"
            and message["payload"].get("type") == "execution_receipt"
        ):
            receipt.append(message["payload"])
        elif message["type"] == "error":
            receipt.append(
                {"script_error": message.get("description"), "details": message}
            )

    def on_persistent(message: Dict[str, Any], data: Any) -> None:
        sessions.append_message(
            session_id,
            {
                "type": message["type"],
                "payload": message.get("payload"),
            },
        )

    try:
        script = session.create_script(wrapped)
    except frida.InvalidOperationError as e:
        raise ValueError(f"Frida operation error (session may be detached): {e}")

    script.on("message", on_persistent if keep_alive else on_receipt)
    script.load()

    if keep_alive:
        sessions.track_script(session_id, script)
        return {
            "status": "success",
            "script_unloaded": False,
            "message": "Script loaded persistently. Use get_session_messages to retrieve asynchronous messages.",
        }

    time.sleep(0.2)
    try:
        script.unload()
    except frida.InvalidOperationError:
        pass

    if not receipt:
        return {
            "status": "nodata",
            "script_unloaded": True,
            "message": "Script loaded but sent no initial messages.",
        }

    payload = receipt[0]
    if "script_error" in payload:
        return {
            "status": "error",
            "error": "Script execution error",
            "details": payload["script_error"],
            "script_unloaded": True,
        }
    if payload.get("error"):
        return {
            "status": "error",
            "error": payload["error"]["message"],
            "stack": payload["error"].get("stack"),
            "initial_logs": payload.get("initial_logs", []),
            "script_unloaded": True,
        }
    return {
        "status": "success",
        "result": payload.get("result"),
        "initial_logs": payload.get("initial_logs", []),
        "script_unloaded": True,
    }


@mcp.tool()
def get_session_messages(
    session_id: Annotated[
        str, Field(description="Session ID returned by attach_to_process")
    ],
) -> Dict[str, Any]:
    """Retrieve and clear messages sent by persistent scripts in a session."""
    messages = sessions.drain_messages(session_id)
    return {
        "status": "success",
        "session_id": session_id,
        "messages_retrieved": len(messages),
        "messages": messages,
    }


@mcp.tool()
def detach_session(
    session_id: Annotated[
        str, Field(description="Session ID returned by attach_to_process")
    ],
) -> Dict[str, Any]:
    """Detach a session and unload all of its persistent scripts."""
    sessions.close(session_id)
    return {"status": "success", "session_id": session_id}


@mcp.resource("frida://version")
def get_version() -> str:
    """Frida version information."""
    return f"Frida version: {frida.__version__}"


@mcp.resource("frida://devices")
def list_devices_resource() -> str:
    """Human-readable list of connected devices."""
    lines = [
        f"- {d.name} (id={d.id}, type={d.type})" for d in frida.enumerate_devices()
    ]
    return "Connected devices:\n" + "\n".join(lines)


@mcp.resource("frida://processes")
def list_processes_resource() -> str:
    """Human-readable list of processes on the USB device."""
    lines = [
        f"- {p.name} (pid={p.pid})"
        for p in frida.get_usb_device().enumerate_processes()
    ]
    return "Processes on USB device:\n" + "\n".join(lines)
