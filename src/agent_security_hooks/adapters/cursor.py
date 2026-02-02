"""Cursor adapter for hook communication.

Reference: https://cursor.com/docs/agent/hooks

Input format (beforeShellExecution):
{
    "command": "kubectl get pods",
    "cwd": "/path/to/project"
}

Input format (beforeReadFile):
{
    "file_path": "/path/to/file"
}

Input format (afterFileEdit):
{
    "file_path": "/path/to/file",
    "edits": [...]
}

Output format:
- Exit code 0: Allow
- Exit code 2: Block (equivalent to permission: "deny")
- JSON with "permission": "deny" or "continue": false
"""

import json
import os
import sys
from typing import Any

from ..validator import SecurityValidator, ValidationResult
from ..logger import AuditLogger, get_environment_context


class CursorAdapter:
    """Adapter for Cursor hook protocol."""

    # Map internal event names to Cursor event types
    EVENT_MAP = {
        "before-shell": "before_shell",
        "beforeShellExecution": "before_shell",
        "after-shell": "after_shell",
        "afterShellExecution": "after_shell",
        "before-read": "before_read",
        "beforeReadFile": "before_read",
        "after-edit": "after_edit",
        "afterFileEdit": "after_edit",
        "session-start": "session_start",
        "sessionStart": "session_start",
        "session-end": "session_end",
        "sessionEnd": "session_end",
        "before-mcp": "before_mcp",
        "beforeMCPExecution": "before_mcp",
        "after-mcp": "after_mcp",
        "afterMCPExecution": "after_mcp",
        "pre": "before_shell",  # Alias
        "post": "after_shell",  # Alias
    }

    def __init__(
        self,
        validator: SecurityValidator,
        logger: AuditLogger,
        debug: bool = False,
    ):
        """
        Initialize the Cursor adapter.
        
        Args:
            validator: Security validator instance.
            logger: Audit logger instance.
            debug: Enable debug output to stderr.
        """
        self.validator = validator
        self.logger = logger
        self.debug = debug

    def _debug(self, message: str) -> None:
        """Print debug message to stderr."""
        if self.debug:
            print(f"[DEBUG:cursor] {message}", file=sys.stderr)

    def _get_context(self) -> dict[str, str | None]:
        """Get Cursor-specific context from environment."""
        ctx = get_environment_context()
        ctx["project_dir"] = os.environ.get("CURSOR_PROJECT_DIR", ctx.get("project_dir"))
        ctx["user"] = os.environ.get("CURSOR_USER_EMAIL", ctx.get("user"))
        return ctx

    def handle(self, event: str, input_data: dict[str, Any]) -> int:
        """
        Handle a Cursor hook event.
        
        Args:
            event: The event type (e.g., "before-shell", "after-edit").
            input_data: JSON input from Cursor.
            
        Returns:
            Exit code (0 = allow, 2 = block).
        """
        event_type = self.EVENT_MAP.get(event, event)
        self._debug(f"Handling event: {event_type}")
        self._debug(f"Input: {json.dumps(input_data)}")

        if event_type == "before_shell":
            return self._handle_before_shell(input_data)
        elif event_type == "after_shell":
            return self._handle_after_shell(input_data)
        elif event_type == "before_read":
            return self._handle_before_read(input_data)
        elif event_type == "after_edit":
            return self._handle_after_edit(input_data)
        elif event_type in ("session_start", "session_end"):
            return self._handle_session(event_type, input_data)
        elif event_type in ("before_mcp", "after_mcp"):
            return self._handle_mcp(event_type, input_data)
        else:
            # SECURITY: Fail-secure - block unknown event types
            self._debug(f"Unknown event type: {event_type} - blocking for security")
            output = {
                "permission": "deny",
                "user_message": f"🛡️ Unknown event type: {event_type}",
            }
            print(json.dumps(output))
            return 2  # Block unknown events

    def _handle_before_shell(self, input_data: dict) -> int:
        """Handle beforeShellExecution events."""
        command = input_data.get("command", "")
        cwd = input_data.get("cwd", "")

        self._debug(f"Command: {command}")

        # Validate the command
        result = self.validator.validate_command(command)

        self._debug(f"Validation result: {result}")

        # Log the event
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="cursor",
            event_type="before_shell",
            command=command,
            decision=result.decision,
            reason=result.reason,
            matched_rules=result.matched_rules,
            severity=result.severity.value if result.severity else None,
            category=result.category,
            cwd=cwd,
            **ctx,
        )

        # Return appropriate response
        if result.decision == "block":
            output = {
                "permission": "deny",
                "user_message": f"🛡️ Blocked: {result.reason}",
            }
            print(json.dumps(output))
            return 2

        elif result.decision == "ask":
            output = {
                "permission": "deny",
                "user_message": f"⚠️ Confirmation required: {result.reason}",
            }
            print(json.dumps(output))
            return 2

        # Allow - output empty JSON or nothing
        print("{}")
        return 0

    def _handle_after_shell(self, input_data: dict) -> int:
        """Handle afterShellExecution events (logging only)."""
        command = input_data.get("command", "")
        exit_code = input_data.get("exit_code")
        stdout = input_data.get("stdout", "")
        stderr = input_data.get("stderr", "")

        # Log the completion
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="cursor",
            event_type="after_shell",
            command=command,
            exit_code=exit_code,
            stdout_length=len(stdout) if stdout else 0,
            stderr_length=len(stderr) if stderr else 0,
            **ctx,
        )

        return 0

    def _handle_before_read(self, input_data: dict) -> int:
        """Handle beforeReadFile events."""
        file_path = input_data.get("file_path", "")

        self._debug(f"File path: {file_path}")

        # Validate the file read
        result = self.validator.validate_file_read(file_path)

        self._debug(f"Validation result: {result}")

        # Log the event
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="cursor",
            event_type="before_read",
            file_path=file_path,
            decision=result.decision,
            reason=result.reason,
            matched_rules=result.matched_rules,
            category=result.category,
            **ctx,
        )

        if result.decision == "block":
            output = {
                "permission": "deny",
                "user_message": f"🛡️ Access denied: {result.reason}",
            }
            print(json.dumps(output))
            return 2

        print("{}")
        return 0

    def _handle_after_edit(self, input_data: dict) -> int:
        """Handle afterFileEdit events (logging only)."""
        file_path = input_data.get("file_path", "")
        edits = input_data.get("edits", [])

        # Log the edit
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="cursor",
            event_type="after_edit",
            file_path=file_path,
            edit_count=len(edits),
            **ctx,
        )

        return 0

    def _handle_session(self, event_type: str, input_data: dict) -> int:
        """Handle session start/end events."""
        session_id = input_data.get("session_id", "")
        
        ctx = self._get_context()
        ctx["session_id"] = session_id

        if event_type == "session_start":
            is_background = input_data.get("is_background_agent", False)
            composer_mode = input_data.get("composer_mode", "")
            
            self.logger.log_pre_execution(
                platform="cursor",
                event_type="session_start",
                decision="allow",
                is_background=is_background,
                composer_mode=composer_mode,
                **ctx,
            )
            
            # Can return environment variables or additional context
            output = {
                "continue": True,
            }
            print(json.dumps(output))

        else:  # session_end
            reason = input_data.get("reason", "")
            duration_ms = input_data.get("duration_ms", 0)
            
            self.logger.log_post_execution(
                platform="cursor",
                event_type="session_end",
                reason=reason,
                duration_ms=duration_ms,
                **ctx,
            )

        return 0

    def _handle_mcp(self, event_type: str, input_data: dict) -> int:
        """Handle MCP tool execution events."""
        server_name = input_data.get("serverName", "")
        tool_name = input_data.get("toolName", "")
        arguments = input_data.get("arguments", {})

        ctx = self._get_context()

        if event_type == "before_mcp":
            # Could validate MCP tool calls here
            self.logger.log_pre_execution(
                platform="cursor",
                event_type="before_mcp",
                tool_name=f"mcp:{server_name}:{tool_name}",
                decision="allow",
                mcp_arguments=str(arguments)[:500],
                **ctx,
            )
        else:
            self.logger.log_post_execution(
                platform="cursor",
                event_type="after_mcp",
                tool_name=f"mcp:{server_name}:{tool_name}",
                **ctx,
            )

        print("{}")
        return 0

