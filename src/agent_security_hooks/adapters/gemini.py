"""Gemini CLI adapter for hook communication.

Reference: https://geminicli.com/docs/hooks/

CRITICAL: Gemini CLI requires strict JSON output to stdout.
Any non-JSON text breaks parsing and defaults to "Allow".
All logging/debug output MUST go to stderr.

Input format (BeforeTool):
{
    "tool_name": "shell",
    "arguments": {"command": "kubectl get pods"}
}

Output format:
{
    "decision": "allow" | "deny",
    "reason": "..."
}
"""

import json
import os
import sys
from typing import Any

from ..validator import SecurityValidator, ValidationResult
from ..logger import AuditLogger, get_environment_context


class GeminiAdapter:
    """Adapter for Gemini CLI hook protocol."""

    # Map internal event names to Gemini event types
    EVENT_MAP = {
        "before": "before_tool",
        "before_tool": "before_tool",
        "BeforeTool": "before_tool",
        "after": "after_tool",
        "after_tool": "after_tool",
        "AfterTool": "after_tool",
        "before_agent": "before_agent",
        "BeforeAgent": "before_agent",
        "after_agent": "after_agent",
        "AfterAgent": "after_agent",
        "session_start": "session_start",
        "SessionStart": "session_start",
        "session_end": "session_end",
        "SessionEnd": "session_end",
        "pre": "before_tool",  # Alias
        "post": "after_tool",  # Alias
    }

    def __init__(
        self,
        validator: SecurityValidator,
        logger: AuditLogger,
        debug: bool = False,
    ):
        """
        Initialize the Gemini adapter.
        
        Args:
            validator: Security validator instance.
            logger: Audit logger instance.
            debug: Enable debug output to stderr.
        """
        self.validator = validator
        self.logger = logger
        self.debug = debug

    def _debug(self, message: str) -> None:
        """Print debug message to stderr (NEVER stdout for Gemini!)."""
        if self.debug:
            print(f"[DEBUG:gemini] {message}", file=sys.stderr)

    def _get_context(self) -> dict[str, str | None]:
        """Get context from environment."""
        return get_environment_context()

    def _output_json(self, data: dict) -> None:
        """
        Output JSON to stdout (the ONLY thing that should go to stdout).
        
        This is critical for Gemini CLI - any non-JSON breaks parsing.
        """
        # Use compact JSON (no pretty printing)
        print(json.dumps(data, separators=(",", ":")))

    def handle(self, event: str, input_data: dict[str, Any]) -> int:
        """
        Handle a Gemini CLI hook event.
        
        Args:
            event: The event type (e.g., "before", "after").
            input_data: JSON input from Gemini CLI.
            
        Returns:
            Exit code (0 = allow, non-zero = error).
        """
        event_type = self.EVENT_MAP.get(event, event)
        self._debug(f"Handling event: {event_type}")
        self._debug(f"Input: {json.dumps(input_data)}")

        if event_type == "before_tool":
            return self._handle_before_tool(input_data)
        elif event_type == "after_tool":
            return self._handle_after_tool(input_data)
        elif event_type == "before_agent":
            return self._handle_before_agent(input_data)
        elif event_type == "after_agent":
            return self._handle_after_agent(input_data)
        elif event_type == "session_start":
            return self._handle_session_start(input_data)
        elif event_type == "session_end":
            return self._handle_session_end(input_data)
        else:
            # SECURITY: Fail-secure - block unknown event types
            self._debug(f"Unknown event type: {event_type} - blocking for security")
            self._output_json({
                "decision": "deny",
                "reason": f"Unknown event type: {event_type}",
            })
            return 0  # Gemini uses JSON for decision, not exit code

    def _handle_before_tool(self, input_data: dict) -> int:
        """Handle BeforeTool events."""
        tool_name = input_data.get("tool_name", input_data.get("name", ""))
        # Gemini CLI uses tool_input, but also support arguments for testing
        arguments = input_data.get("tool_input", input_data.get("arguments", input_data.get("args", {})))

        # Determine operation type and extract relevant data
        command = ""
        file_path = ""
        operation = "shell"

        if tool_name in ("shell", "bash", "terminal", "run_command", "run_shell_command"):
            command = arguments.get("command", arguments.get("cmd", ""))
            operation = "shell"
        elif tool_name in ("read_file", "readFile", "read"):
            file_path = arguments.get("path", arguments.get("file_path", ""))
            operation = "read"
        elif tool_name in ("write_file", "writeFile", "write", "edit_file", "editFile"):
            file_path = arguments.get("path", arguments.get("file_path", ""))
            operation = "edit"
        else:
            # For unknown tools, try common command field names
            # Don't convert arbitrary dicts to string (security risk)
            command = (
                arguments.get("command", "")
                or arguments.get("cmd", "")
                or arguments.get("script", "")
            )
            if not command:
                self._debug(f"Unknown tool type with no command field: {tool_name}")

        self._debug(f"Tool: {tool_name}, Command: {command}, File: {file_path}")

        # Validate the operation
        result = self.validator.validate(
            command=command,
            file_path=file_path,
            operation=operation,
        )

        self._debug(f"Validation result: {result}")

        # Log the event
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="gemini",
            event_type="before_tool",
            tool_name=tool_name,
            command=command,
            file_path=file_path,
            decision=result.decision,
            reason=result.reason,
            matched_rules=result.matched_rules,
            severity=result.severity.value if result.severity else None,
            category=result.category,
            **ctx,
        )

        # Output JSON response (MUST be the only stdout output)
        # Per Gemini CLI docs: exit 0 = parse stdout JSON, exit 2 = use stderr as reason
        # We use exit 0 and rely on JSON decision field for blocking
        if result.decision == "block":
            self._output_json({
                "decision": "deny",
                "reason": result.reason,
            })
            return 0  # Exit 0 so Gemini parses the JSON decision
        elif result.decision == "ask":
            # Gemini doesn't have "ask" - treat as deny with informative message
            self._output_json({
                "decision": "deny",
                "reason": f"Confirmation required: {result.reason}",
            })
            return 0  # Exit 0 so Gemini parses the JSON decision
        else:
            self._output_json({
                "decision": "allow",
            })
            return 0

    def _handle_after_tool(self, input_data: dict) -> int:
        """Handle AfterTool events (logging only)."""
        tool_name = input_data.get("tool_name", input_data.get("name", ""))
        arguments = input_data.get("tool_input", input_data.get("arguments", input_data.get("args", {})))
        result = input_data.get("tool_response", input_data.get("result", {}))
        error = input_data.get("error")

        # Extract command if available
        command = arguments.get("command", arguments.get("cmd", ""))
        file_path = arguments.get("path", arguments.get("file_path", ""))

        # Determine exit code if available
        exit_code = None
        if isinstance(result, dict):
            exit_code = result.get("exit_code", result.get("exitCode"))

        # Log the completion
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="gemini",
            event_type="after_tool",
            tool_name=tool_name,
            command=command,
            file_path=file_path,
            exit_code=exit_code,
            has_error=error is not None,
            **ctx,
        )

        # Must output valid JSON
        self._output_json({})
        return 0

    def _handle_before_agent(self, input_data: dict) -> int:
        """Handle BeforeAgent events."""
        prompt = input_data.get("prompt", input_data.get("message", ""))

        # Log the agent start
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="gemini",
            event_type="before_agent",
            command=prompt[:500] if prompt else "",  # Truncate for logging
            decision="allow",
            **ctx,
        )

        # Allow by default
        self._output_json({"decision": "allow"})
        return 0

    def _handle_after_agent(self, input_data: dict) -> int:
        """Handle AfterAgent events."""
        response = input_data.get("prompt_response", input_data.get("response", input_data.get("output", "")))

        # Log the agent completion
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="gemini",
            event_type="after_agent",
            response_length=len(response) if response else 0,
            **ctx,
        )

        # Must output valid JSON
        self._output_json({})
        return 0

    def _handle_session_start(self, input_data: dict) -> int:
        """Handle SessionStart events (logging only)."""
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="gemini",
            event_type="session_start",
            decision="allow",
            **ctx,
        )

        self._output_json({"decision": "allow"})
        return 0

    def _handle_session_end(self, input_data: dict) -> int:
        """Handle SessionEnd events (logging only)."""
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="gemini",
            event_type="session_end",
            **ctx,
        )

        self._output_json({})
        return 0

