#!/usr/bin/env python3
"""
Command line entry point specifically for Claude Desktop integration.

This script is designed to be the target of the command in claude_desktop_config.json.
It sets up a basic Frida MCP server with STDIO transport for Claude to communicate with.
"""

import sys
import frida
from mcp.server.fastmcp import FastMCP, Context
from typing import Dict, List, Optional, Any, Union
import threading
import time

# Create the MCP server
mcp = FastMCP("Frida")

# Global dictionary to store scripts and their messages
# This allows us to retrieve messages from scripts after they've been created
_scripts = {}
_script_messages = {}
_message_locks = {}


@mcp.tool()
def enumerate_processes() -> List[Dict[str, Any]]:
    """List all processes running on the system.
    
    Returns:
        A list of process information dictionaries containing:
        - pid: Process ID
        - name: Process name
    """
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    return [{"pid": process.pid, "name": process.name} for process in processes]


@mcp.tool()
def enumerate_devices() -> List[Dict[str, Any]]:
    """List all devices connected to the system.
    
    Returns:
        A list of device information dictionaries containing:
        - id: Device ID
        - name: Device name
        - type: Device type
    """
    devices = frida.enumerate_devices()
    return [
        {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
        for device in devices
    ]


@mcp.tool()
def get_device(device_id: str) -> Dict[str, Any]:
    """Get a device by its ID.
    
    Args:
        device_id: The ID of the device to get
        
    Returns:
        Information about the device
    """
    try:
        device = frida.get_device(device_id)
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
    except frida.InvalidArgumentError:
        raise ValueError(f"Device with ID {device_id} not found")


@mcp.tool()
def get_usb_device() -> Dict[str, Any]:
    """Get the USB device connected to the system.
    
    Returns:
        Information about the USB device
    """
    try:
        device = frida.get_usb_device()
        return {
            "id": device.id,
            "name": device.name,
            "type": device.type,
        }
    except frida.InvalidArgumentError:
        raise ValueError("No USB device found")


@mcp.tool()
def get_process_by_name(name: str) -> dict:
    """Find a process by name."""
    device = frida.get_local_device()
    for proc in device.enumerate_processes():
        if name.lower() in proc.name.lower():
            return {"pid": proc.pid, "name": proc.name, "found": True}
    return {"found": False, "error": f"Process '{name}' not found"}


@mcp.tool()
def attach_to_process(pid: int) -> dict:
    """Attach to a process by ID."""
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        return {
            "pid": pid,
            "success": True,
            "is_detached": False  # New session is not detached
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def spawn_process(program: str, args: Optional[List[str]] = None, 
               device_id: Optional[str] = None) -> Dict[str, Any]:
    """Spawn a program.
    
    Args:
        program: The program to spawn
        args: Optional arguments for the program
        device_id: Optional device ID
        
    Returns:
        Information about the spawned process
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_local_device()
            
        pid = device.spawn(program, args=args or [])
        
        return {"pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to spawn {program}: {str(e)}")


@mcp.tool()
def resume_process(pid: int, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Resume a process by ID.
    
    Args:
        pid: The ID of the process to resume
        device_id: Optional device ID
        
    Returns:
        Status information
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_local_device()
            
        device.resume(pid)
        
        return {"success": True, "pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to resume process {pid}: {str(e)}")


@mcp.tool()
def kill_process(pid: int, device_id: Optional[str] = None) -> Dict[str, Any]:
    """Kill a process by ID.
    
    Args:
        pid: The ID of the process to kill
        device_id: Optional device ID
        
    Returns:
        Status information
    """
    try:
        if device_id:
            device = frida.get_device(device_id)
        else:
            device = frida.get_local_device()
            
        device.kill(pid)
        
        return {"success": True, "pid": pid}
    except Exception as e:
        raise ValueError(f"Failed to kill process {pid}: {str(e)}")


@mcp.resource("frida://version")
def get_version() -> str:
    """Get the Frida version."""
    return frida.__version__


@mcp.resource("frida://processes")
def get_processes_resource() -> str:
    """Get a list of all processes as a readable string."""
    device = frida.get_local_device()
    processes = device.enumerate_processes()
    return "\n".join([f"PID: {p.pid}, Name: {p.name}" for p in processes])


@mcp.resource("frida://devices")
def get_devices_resource() -> str:
    """Get a list of all devices as a readable string."""
    devices = frida.enumerate_devices()
    return "\n".join([f"ID: {d.id}, Name: {d.name}, Type: {d.type}" for d in devices])


@mcp.tool()
def create_interactive_session(process_id: int) -> Dict[str, Any]:
    """Create an interactive REPL-like session with a process.
    
    This returns a session ID that can be used with execute_in_session to run commands.
    
    Args:
        process_id: The ID of the process to attach to
        
    Returns:
        Information about the created session
    """
    try:
        # Attach to process
        device = frida.get_local_device()
        session = device.attach(process_id)
        
        # Generate a unique session ID
        session_id = f"session_{process_id}_{int(time.time())}"
        
        # Store the session
        _scripts[session_id] = session
        _script_messages[session_id] = []
        _message_locks[session_id] = threading.Lock()
        
        return {
            "status": "success",
            "process_id": process_id,
            "session_id": session_id,
            "message": f"Interactive session created for process {process_id}. Use execute_in_session to run JavaScript commands."
        }
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@mcp.tool()
def execute_in_session(session_id: str, javascript_code: str) -> Dict[str, Any]:
    """Execute JavaScript code in an interactive session.
    
    Args:
        session_id: The ID of the session to execute in
        javascript_code: The JavaScript code to execute
        
    Returns:
        The result of the execution
    """
    if session_id not in _scripts:
        raise ValueError(f"Session with ID {session_id} not found")
    
    session = _scripts[session_id]
    
    try:
        # For interactive use, we need to handle console.log output
        # and properly format the result
        
        # Wrap the code to capture console.log output and return values
        wrapped_code = f"""
        (function() {{
            // Capture console.log output
            var originalLog = console.log;
            var logs = [];
            
            console.log = function() {{
                var args = Array.prototype.slice.call(arguments);
                logs.push(args.map(function(arg) {{
                    return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
                }}).join(' '));
                originalLog.apply(console, arguments);
            }};
            
            // Execute the provided code
            var result;
            try {{
                result = eval({javascript_code!r});
            }} catch (e) {{
                send({{
                    type: 'error',
                    message: e.toString(),
                    stack: e.stack
                }});
                return;
            }}
            
            // Restore original console.log
            console.log = originalLog;
            
            // Send back the result and logs
            send({{
                type: 'result',
                result: result !== undefined ? result.toString() : 'undefined',
                logs: logs
            }});
        }})();
        """
        
        # Create a temporary script for this execution
        script = session.create_script(wrapped_code)
        
        # Store the results
        execution_results = []
        
        def on_message(message, data):
            if message["type"] == "send":
                execution_results.append(message["payload"])
            elif message["type"] == "error":
                execution_results.append({"error": message["description"]})
        
        script.on("message", on_message)
        
        # Load and wait for it to complete
        script.load()
        
        # Small wait to ensure messages are received
        time.sleep(0.1)
        
        # Format the result
        if execution_results:
            last_result = execution_results[-1]
            if "result" in last_result:
                result = {
                    "status": "success",
                    "result": last_result["result"],
                    "logs": last_result.get("logs", [])
                }
            elif "error" in last_result:
                result = {
                    "status": "error",
                    "error": last_result["error"],
                    "message": last_result.get("message", "")
                }
            else:
                result = {
                    "status": "success",
                    "raw_output": execution_results
                }
        else:
            result = {
                "status": "success",
                "result": "undefined",
                "logs": []
            }
        
        script.unload()
        
        return result
    
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


def main():
    """Run the CLI entry point for Claude Desktop integration."""
    mcp.run()


if __name__ == "__main__":
    main() 