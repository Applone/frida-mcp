"""Shared test fixtures: a fake `frida` module installed in sys.modules
before any test module imports frida_mcp.server."""

import sys
import types
from typing import Callable, List, Optional


class FakeProcess:
    def __init__(self, pid: int, name: str) -> None:
        self.pid = pid
        self.name = name


class FakeScript:
    def __init__(self, source: str) -> None:
        self.source = source
        self.handlers: List[Callable] = []
        self.loaded = False
        self.unloaded = False

    def on(self, event: str, handler: Callable) -> None:
        assert event == "message"
        self.handlers.append(handler)

    def load(self) -> None:
        self.loaded = True
        receipt = {
            "type": "execution_receipt",
            "result": "42",
            "error": None,
            "initial_logs": ["hello"],
        }
        hook_hit = {"kind": "hook_hit", "detail": "x"}
        for handler in self.handlers:
            handler({"type": "send", "payload": receipt}, None)
            handler({"type": "send", "payload": hook_hit}, None)

    def unload(self) -> None:
        self.unloaded = True


class FakeSession:
    def __init__(self) -> None:
        self.detached = False
        self.scripts: List[FakeScript] = []

    def create_script(self, source: str) -> FakeScript:
        script = FakeScript(source)
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        self.detached = True


class FakeDevice:
    id = "usb-1"
    name = "Test Phone"
    type = "usb"

    def __init__(self) -> None:
        self.spawned: List = []
        self.resumed: List[int] = []
        self.killed: List[int] = []
        self.session = FakeSession()

    def enumerate_processes(self) -> List[FakeProcess]:
        return [FakeProcess(1, "init"), FakeProcess(1234, "com.example.app")]

    def attach(self, pid: int) -> FakeSession:
        return self.session

    def spawn(self, program: str, args: Optional[List[str]] = None) -> int:
        self.spawned.append((program, args))
        return 4321

    def resume(self, pid: int) -> None:
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


fake_device = FakeDevice()


class InvalidArgumentError(Exception):
    pass


class InvalidOperationError(Exception):
    pass


def _get_device(device_id: str) -> FakeDevice:
    if device_id == "usb-1":
        return fake_device
    raise InvalidArgumentError(f"Device with ID {device_id} not found")


fake_frida = types.ModuleType("frida")
fake_frida.__version__ = "16.0.0-test"
fake_frida.InvalidArgumentError = InvalidArgumentError
fake_frida.InvalidOperationError = InvalidOperationError
fake_frida.enumerate_devices = lambda: [fake_device]
fake_frida.get_device = _get_device
fake_frida.get_usb_device = lambda: fake_device
fake_frida.get_local_device = lambda: fake_device

sys.modules["frida"] = fake_frida
