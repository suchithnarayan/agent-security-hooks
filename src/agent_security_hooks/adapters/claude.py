"""Claude Code adapter for hook communication.

Reference: https://code.claude.com/docs/en/hooks

Input format (PreToolUse):
{
    "tool_name": "Bash",
    "tool_input": {"command": "kubectl get pods"}
}

Output format:
- Exit code 0: Allow; stdout must be valid JSON (e.g. {}).
- Exit code 2: Block; stdout can contain hookSpecificOutput or decision/reason.
- PreToolUse: hookSpecificOutput with hookEventName "PreToolUse",
  permissionDecision ("deny"|"ask"), permissionDecisionReason.
- PermissionRequest: hookSpecificOutput with hookEventName "PermissionRequest",
  decision.behavior ("allow"|"deny"), decision.message (for deny).
"""

import json
import os
import sys
from typing import Any

from ..validator import SecurityValidator, ValidationResult
from ..logger import AuditLogger, get_environment_context


class ClaudeAdapter:
    """Adapter for Claude Code hook protocol."""

    # Map internal event names to Claude event types
    EVENT_MAP = {
        "pre": "pre_tool_use",
        "pre_tool_use": "pre_tool_use",
        "post": "post_tool_use",
        "post_tool_use": "post_tool_use",
        "prompt": "user_prompt_submit",
        "user_prompt_submit": "user_prompt_submit",
        "permission": "permission_request",
        "permission_request": "permission_request",
    }

    def __init__(
        self,
        validator: SecurityValidator,
        logger: AuditLogger,
        debug: bool = False,
    ):
        """
        Initialize the Claude adapter.
        
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
            print(f"[DEBUG:claude] {message}", file=sys.stderr)

    def _get_context(self) -> dict[str, str | None]:
        """Get Claude-specific context from environment."""
        ctx = get_environment_context()
        ctx["project_dir"] = os.environ.get("CLAUDE_PROJECT_DIR", ctx.get("project_dir"))
        return ctx

    def handle(self, event: str, input_data: dict[str, Any]) -> int:
        """
        Handle a Claude Code hook event.
        
        Args:
            event: The event type (e.g., "pre", "post").
            input_data: JSON input from Claude Code.
            
        Returns:
            Exit code (0 = allow, 2 = block).
        """
        event_type = self.EVENT_MAP.get(event, event)
        self._debug(f"Handling event: {event_type}")
        self._debug(f"Input: {json.dumps(input_data)}")

        if event_type in ("pre_tool_use", "permission_request"):
            return self._handle_pre_tool_use(event_type, input_data)
        elif event_type == "post_tool_use":
            return self._handle_post_tool_use(input_data)
        elif event_type == "user_prompt_submit":
            return self._handle_user_prompt(input_data)
        else:
            # SECURITY: Fail-secure - block unknown event types
            self._debug(f"Unknown event type: {event_type} - blocking for security")
            output = {
                "decision": "block",
                "reason": f"Unknown event type: {event_type}",
            }
            print(json.dumps(output))
            sys.stdout.flush()
            return 2  # Block unknown events

    def _handle_pre_tool_use(self, event_type: str, input_data: dict) -> int:
        """Handle PreToolUse or PermissionRequest events."""
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input") or {}
        
        # Extract command or file path based on tool type
        command = ""
        file_path = ""
        operation = "shell"

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            operation = "shell"
        elif tool_name in ("Read", "ReadFile"):
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            operation = "read"
        elif tool_name in ("Write", "Edit", "WriteFile", "EditFile"):
            file_path = tool_input.get("file_path", tool_input.get("path", ""))
            operation = "edit"
        else:
            # For unknown tools, try common command field names
            # Don't convert arbitrary dicts to string (security risk)
            command = (
                tool_input.get("command", "") 
                or tool_input.get("cmd", "") 
                or tool_input.get("script", "")
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
            platform="claude",
            event_type=event_type,
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

        # Return appropriate response (format depends on event type per Claude Code docs)
        if result.decision == "block":
            if event_type == "permission_request":
                output = {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": result.reason or "Blocked by security policy",
                        },
                    }
                }
            else:
                output = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": result.reason or "Blocked by security policy",
                    }
                }
            print(json.dumps(output))
            sys.stdout.flush()
            return 2  # Block exit code

        elif result.decision == "ask":
            if event_type == "permission_request":
                output = {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": f"Confirmation required: {result.reason}",
                        },
                    }
                }
            else:
                output = {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": f"Confirmation required: {result.reason}",
                    }
                }
            print(json.dumps(output))
            sys.stdout.flush()
            return 2

        # Allow - Claude Code parses stdout on exit 0; must output valid JSON
        print(json.dumps({}))
        sys.stdout.flush()
        return 0

    def _handle_post_tool_use(self, input_data: dict) -> int:
        """Handle PostToolUse events (logging only)."""
        tool_name = input_data.get("tool_name", "")
        tool_input = input_data.get("tool_input") or {}
        tool_output = input_data.get("tool_response") or input_data.get("tool_output") or {}
        
        # Extract relevant info
        command = ""
        file_path = ""
        exit_code = None

        if tool_name == "Bash":
            command = tool_input.get("command", "")
            # Try to get exit code from output
            if isinstance(tool_output, dict):
                exit_code = tool_output.get("exit_code")
            # Also check environment variable
            if exit_code is None:
                exit_code_str = os.environ.get("CLAUDE_TOOL_EXIT_CODE")
                if exit_code_str:
                    try:
                        exit_code = int(exit_code_str)
                    except ValueError:
                        pass
        elif tool_name in ("Read", "Write", "Edit", "ReadFile", "WriteFile", "EditFile"):
            file_path = tool_input.get("file_path", tool_input.get("path", ""))

        # Log the completion
        ctx = self._get_context()
        self.logger.log_post_execution(
            platform="claude",
            event_type="post_tool_use",
            tool_name=tool_name,
            command=command,
            file_path=file_path,
            exit_code=exit_code,
            **ctx,
        )

        # Claude Code parses stdout on exit 0; must output valid JSON
        print(json.dumps({}))
        sys.stdout.flush()
        return 0  # Always allow post-hooks

    def _handle_user_prompt(self, input_data: dict) -> int:
        """Handle UserPromptSubmit events."""
        prompt = input_data.get("prompt", "")
        
        # Could add prompt validation here (e.g., check for sensitive patterns)
        # For now, just log and allow
        ctx = self._get_context()
        self.logger.log_pre_execution(
            platform="claude",
            event_type="user_prompt_submit",
            command=prompt[:500],  # Truncate for logging
            decision="allow",
            **ctx,
        )

        # Claude Code parses stdout on exit 0; empty stdout causes parse error
        print(json.dumps({}))
        sys.stdout.flush()
        return 0

