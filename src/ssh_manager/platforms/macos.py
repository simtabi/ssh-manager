"""macOS strategy - Apple keychain, launchd, chmod, osascript. First-class."""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from ..util import proc
from .base import Platform

_PLIST_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args}
    </array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
    <key>RunAtLoad</key><false/>
</dict>
</plist>
"""


class MacOS(Platform):
    name = "macos"
    emits_use_keychain = True
    first_class = True

    def ssh_dir(self) -> Path:
        return Path.home() / ".ssh"

    def set_perms(self, path: Path, mode: int) -> None:
        os.chmod(path, mode)

    def install_scheduler(self, command: str, *, label: str = "ssh_manager.expiry") -> None:
        """Write + load a launchd agent that runs ``command`` daily at 09:00."""
        # shlex.split (not str.split) so a quoted, space-containing exe path stays
        # one launchd argument; XML-escape each token for the plist.
        args = "\n".join(f"        <string>{_xml_escape(tok)}</string>"
                         for tok in shlex.split(command))
        plist = _PLIST_TMPL.format(label=label, args=args)
        dest = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(plist, encoding="utf-8")
        os.chmod(dest, 0o644)
        # Reload if already present; ignore unload failure on first install.
        proc.run(["launchctl", "unload", str(dest)])
        proc.run_checked(["launchctl", "load", str(dest)])

    def notify(self, title: str, message: str) -> bool:
        """Post a desktop notification (terminal-notifier if present, else osascript)."""
        if proc.has("terminal-notifier"):
            proc.run(["terminal-notifier", "-title", title, "-message", message])
            return True
        if proc.has("osascript"):
            script = f'display notification {_q(message)} with title {_q(title)}'
            proc.run(["osascript", "-e", script])
            return True
        return False


def _q(text: str) -> str:
    """Quote a string for an AppleScript literal (newlines/tabs flattened
    they're invalid inside a single-line AppleScript string)."""
    flat = text.replace("\\", "\\\\").replace('"', '\\"')
    flat = flat.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return '"' + flat + '"'
