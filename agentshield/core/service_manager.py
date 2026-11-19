"""
AgentShield Autonomous Background Service Manager.
Enables auto-start on system boot and auto-restart on crash across macOS (launchd) and Linux (systemd).
"""

import os
import sys
import shutil
import platform
import subprocess
import urllib.request
import json
from typing import Dict, Any

class ServiceManager:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.home = os.path.expanduser("~")
        self.log_dir = os.path.join(self.home, ".agentshield")
        os.makedirs(self.log_dir, exist_ok=True)

        self.bin_path = shutil.which("agentshield") or os.path.join(self.home, ".local", "bin", "agentshield")
        if not os.path.exists(self.bin_path):
            self.bin_path = sys.executable

        self.plist_path = os.path.join(self.home, "Library", "LaunchAgents", "com.agentshield.daemon.plist")
        self.systemd_path = os.path.join(self.home, ".config", "systemd", "user", "agentshield.service")

    def install(self) -> Dict[str, Any]:
        if "darwin" in self.os_type:
            # macOS launchd setup
            launch_agents_dir = os.path.dirname(self.plist_path)
            os.makedirs(launch_agents_dir, exist_ok=True)

            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.agentshield.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.bin_path}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{os.path.join(self.log_dir, "daemon.log")}</string>
    <key>StandardErrorPath</key>
    <string>{os.path.join(self.log_dir, "daemon.err")}</string>
</dict>
</plist>
"""
            with open(self.plist_path, "w", encoding="utf-8") as f:
                f.write(plist_content)

            try:
                subprocess.run(["launchctl", "unload", self.plist_path], capture_output=True)
                subprocess.run(["launchctl", "load", "-w", self.plist_path], check=True)
                return {
                    "success": True,
                    "service": "launchd",
                    "file": self.plist_path,
                    "message": "AgentShield background service installed. Auto-starts on boot and revives on crash."
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        elif "linux" in self.os_type:
            # Linux systemd user service setup
            systemd_dir = os.path.dirname(self.systemd_path)
            os.makedirs(systemd_dir, exist_ok=True)

            unit_content = f"""[Unit]
Description=AgentShield Autonomous AI Firewall Daemon
After=network.target

[Service]
ExecStart={self.bin_path} start
Restart=always
RestartSec=3
StandardOutput=append:{os.path.join(self.log_dir, "daemon.log")}
StandardError=append:{os.path.join(self.log_dir, "daemon.err")}

[Install]
WantedBy=default.target
"""
            with open(self.systemd_path, "w", encoding="utf-8") as f:
                f.write(unit_content)

            try:
                subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "--user", "enable", "--now", "agentshield.service"], check=True)
                return {
                    "success": True,
                    "service": "systemd",
                    "file": self.systemd_path,
                    "message": "AgentShield systemd service installed. Auto-starts on boot."
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        else:
            return {"success": False, "error": f"Unsupported OS for auto-service: {self.os_type}"}

    def status(self) -> Dict[str, Any]:
        # Probe health endpoint
        is_running = False
        uptime_info = None
        try:
            req = urllib.request.Request("http://127.0.0.1:8080/health", headers={"User-Agent": "AgentShield-Probe"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    is_running = True
                    uptime_info = json.loads(resp.read().decode("utf-8"))
        except Exception:
            is_running = False

        return {
            "running": is_running,
            "port": 8080,
            "auto_start_installed": os.path.exists(self.plist_path if "darwin" in self.os_type else self.systemd_path),
            "details": uptime_info or "Daemon not responding or stopped"
        }

    def uninstall(self) -> Dict[str, Any]:
        if "darwin" in self.os_type and os.path.exists(self.plist_path):
            subprocess.run(["launchctl", "unload", "-w", self.plist_path], capture_output=True)
            os.remove(self.plist_path)
            return {"success": True, "message": "AgentShield launchd service removed."}
        elif "linux" in self.os_type and os.path.exists(self.systemd_path):
            subprocess.run(["systemctl", "--user", "disable", "--now", "agentshield.service"], capture_output=True)
            os.remove(self.systemd_path)
            return {"success": True, "message": "AgentShield systemd service removed."}
        return {"success": True, "message": "Service was not installed."}
