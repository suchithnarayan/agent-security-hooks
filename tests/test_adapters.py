"""Tests for platform adapters."""

import json
import pytest
from io import StringIO
from unittest.mock import MagicMock, patch
from pathlib import Path

from agent_security_hooks.validator import SecurityValidator, ValidationResult, Severity
from agent_security_hooks.logger import AuditLogger
from agent_security_hooks.adapters import ClaudeAdapter, CursorAdapter, GeminiAdapter


@pytest.fixture
def config_path():
    """Get the path to the blacklist config."""
    return Path(__file__).parent.parent / "config" / "blacklist.yaml"


@pytest.fixture
def validator(config_path):
    """Create a validator."""
    return SecurityValidator(config_path)


@pytest.fixture
def logger(tmp_path):
    """Create a logger with temp directory."""
    return AuditLogger(log_dir=tmp_path, stderr_logging=False)


class TestClaudeAdapter:
    """Tests for Claude Code adapter."""

    def test_handle_safe_command(self, validator, logger, capsys):
        """Test that safe commands are allowed."""
        adapter = ClaudeAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        
        exit_code = adapter.handle("pre", input_data)
        
        assert exit_code == 0

    def test_handle_dangerous_command(self, validator, logger, capsys):
        """Test that dangerous commands are blocked."""
        adapter = ClaudeAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        
        exit_code = adapter.handle("pre", input_data)
        
        assert exit_code == 2
        
        # Check JSON output (PreToolUse uses hookSpecificOutput per Claude Code docs)
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "permissionDecisionReason" in output["hookSpecificOutput"]

    def test_handle_file_read(self, validator, logger, capsys):
        """Test file read validation."""
        adapter = ClaudeAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/app/.env"},
        }
        
        exit_code = adapter.handle("pre", input_data)
        
        assert exit_code == 2  # Should block .env files

    def test_handle_post_tool_use(self, validator, logger):
        """Test post tool use logging."""
        adapter = ClaudeAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_output": {"exit_code": 0},
        }
        
        exit_code = adapter.handle("post", input_data)
        
        assert exit_code == 0  # Post hooks always allow


class TestCursorAdapter:
    """Tests for Cursor adapter."""

    def test_handle_safe_command(self, validator, logger, capsys):
        """Test that safe commands are allowed."""
        adapter = CursorAdapter(validator=validator, logger=logger)
        
        input_data = {
            "command": "npm run build",
            "cwd": "/app",
        }
        
        exit_code = adapter.handle("before-shell", input_data)
        
        assert exit_code == 0
        
        # Check JSON output
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output == {}

    def test_handle_dangerous_command(self, validator, logger, capsys):
        """Test that dangerous commands are blocked."""
        adapter = CursorAdapter(validator=validator, logger=logger)
        
        input_data = {
            "command": "kubectl delete cluster my-cluster",
            "cwd": "/app",
        }
        
        exit_code = adapter.handle("before-shell", input_data)
        
        assert exit_code == 2
        
        # Check JSON output
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["permission"] == "deny"
        assert "Blocked" in output["user_message"]

    def test_handle_file_read(self, validator, logger, capsys):
        """Test file read validation."""
        adapter = CursorAdapter(validator=validator, logger=logger)
        
        input_data = {
            "file_path": "/app/secrets/api-key.txt",
        }
        
        exit_code = adapter.handle("before-read", input_data)
        
        assert exit_code == 2

    def test_handle_session_start(self, validator, logger, capsys):
        """Test session start handling."""
        adapter = CursorAdapter(validator=validator, logger=logger)
        
        input_data = {
            "session_id": "test-session-123",
            "is_background_agent": False,
            "composer_mode": "agent",
        }
        
        exit_code = adapter.handle("session-start", input_data)
        
        assert exit_code == 0
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["continue"] is True


class TestGeminiAdapter:
    """Tests for Gemini CLI adapter."""

    def test_handle_safe_command(self, validator, logger, capsys):
        """Test that safe commands are allowed."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "shell",
            "arguments": {"command": "ls -la"},
        }
        
        exit_code = adapter.handle("before", input_data)
        
        assert exit_code == 0
        
        # Check JSON output (must be valid JSON; Gemini uses "decision": "allow"|"deny")
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "allow"

    def test_handle_dangerous_command(self, validator, logger, capsys):
        """Test that dangerous commands are blocked."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "shell",
            "arguments": {"command": "terraform destroy"},
        }
        
        exit_code = adapter.handle("before", input_data)
        
        # Gemini always returns 0, decision is in JSON
        assert exit_code == 0
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "deny"
        assert "reason" in output

    def test_handle_file_read(self, validator, logger, capsys):
        """Test file read validation."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        input_data = {
            "tool_name": "read_file",
            "arguments": {"path": "/app/.env.production"},
        }
        
        exit_code = adapter.handle("before", input_data)
        
        assert exit_code == 0
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "deny"

    def test_output_is_valid_json(self, validator, logger, capsys):
        """Test that output is always valid JSON (critical for Gemini)."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        # Test various events
        events_and_inputs = [
            ("before", {"tool_name": "shell", "arguments": {"command": "ls"}}),
            ("after", {"tool_name": "shell", "result": {"exit_code": 0}}),
            ("before_agent", {"prompt": "Hello"}),
            ("after_agent", {"response": "Hi there"}),
        ]
        
        for event, input_data in events_and_inputs:
            adapter.handle(event, input_data)
            captured = capsys.readouterr()
            
            # Must be valid JSON
            try:
                json.loads(captured.out)
            except json.JSONDecodeError:
                pytest.fail(f"Invalid JSON output for event {event}: {captured.out}")

    def test_no_stderr_in_stdout(self, validator, logger, capsys):
        """Test that debug output goes to stderr, not stdout."""
        adapter = GeminiAdapter(validator=validator, logger=logger, debug=True)
        
        input_data = {
            "tool_name": "shell",
            "arguments": {"command": "ls"},
        }
        
        adapter.handle("before", input_data)
        
        captured = capsys.readouterr()
        
        # stdout should be pure JSON
        try:
            json.loads(captured.out)
        except json.JSONDecodeError:
            pytest.fail(f"stdout is not valid JSON: {captured.out}")
        
        # Debug output should be in stderr
        assert "[DEBUG:gemini]" in captured.err

    def test_handle_session_start(self, validator, logger, capsys):
        """Test SessionStart handling (must allow, not deny)."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        input_data = {
            "source": "startup",
            "session_id": "test-session-123",
        }
        
        exit_code = adapter.handle("session_start", input_data)
        
        assert exit_code == 0
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["decision"] == "allow"

    def test_handle_session_end(self, validator, logger, capsys):
        """Test SessionEnd handling."""
        adapter = GeminiAdapter(validator=validator, logger=logger)
        
        input_data = {
            "reason": "exit",
            "session_id": "test-session-123",
        }
        
        exit_code = adapter.handle("session_end", input_data)
        
        assert exit_code == 0
        
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        # SessionEnd outputs empty object or valid JSON
        assert isinstance(output, dict)
        json.loads(json.dumps(output))  # Must be serializable

