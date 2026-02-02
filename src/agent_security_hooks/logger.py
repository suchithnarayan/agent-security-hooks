"""Structured JSON audit logging for AI security hooks."""

import fcntl
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

# Security constants
MAX_COMMAND_LOG_LENGTH = 2000  # Maximum command length to log
MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100MB max log file size

# Patterns for sensitive data redaction
SENSITIVE_PATTERNS = [
    # Authorization headers
    (re.compile(r'(?i)(authorization:\s*bearer\s+)[^\s"\']+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(authorization:\s*basic\s+)[^\s"\']+'), r'\1[REDACTED]'),
    # API keys and tokens
    (re.compile(r'(?i)(api[_-]?key[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(token[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(secret[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    # Passwords
    (re.compile(r'(?i)(password[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(-p\s*)[^\s"\']+'), r'\1[REDACTED]'),  # mysql -p
    # AWS credentials
    (re.compile(r'(?i)(aws[_-]?secret[_-]?access[_-]?key[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(aws[_-]?access[_-]?key[_-]?id[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    # Private keys (base64-like patterns)
    (re.compile(r'(?i)(PRIVATE KEY-----\s*)[A-Za-z0-9+/=\s]+'), r'\1[REDACTED]'),
    # Connection strings
    (re.compile(r'(?i)(://[^:]+:)[^@]+(@)'), r'\1[REDACTED]\2'),
    # Generic key=value secrets
    (re.compile(r'(?i)(credentials?[=:\s]+)[^\s"\'&]+'), r'\1[REDACTED]'),
    # Webhooks
    (re.compile(r'https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'), r'https://hooks.slack.com/services/[REDACTED]'),
    (re.compile(r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9-]+'), r'https://discord.com/api/webhooks/[REDACTED]'),
]


def redact_sensitive_data(text: str) -> str:
    """
    Redact potential secrets from text.
    
    Args:
        text: Input text that may contain secrets.
        
    Returns:
        Text with sensitive data redacted.
    """
    if not text:
        return text
    
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    
    return result


def sanitize_for_log(text: str) -> str:
    """
    Sanitize text for safe logging (prevent log injection).
    
    Args:
        text: Input text to sanitize.
        
    Returns:
        Sanitized text safe for logging.
    """
    if not text:
        return text
    
    # Replace newlines, carriage returns, and other control characters
    # that could be used for log injection
    sanitized = text.replace('\n', '\\n')
    sanitized = sanitized.replace('\r', '\\r')
    sanitized = sanitized.replace('\x00', '')  # Remove null bytes
    
    return sanitized


def truncate_text(text: str, max_length: int = MAX_COMMAND_LOG_LENGTH) -> str:
    """
    Truncate text to maximum length.
    
    Args:
        text: Input text to truncate.
        max_length: Maximum allowed length.
        
    Returns:
        Truncated text with indicator if truncated.
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - 12] + "[TRUNCATED]"


@dataclass
class AuditEvent:
    """Represents a single audit log event."""
    timestamp: str
    event_type: Literal[
        "pre_tool_use", "post_tool_use", 
        "before_shell", "after_shell",
        "before_read", "after_edit",
        "before_tool", "after_tool",
        "session_start", "session_end"
    ]
    platform: Literal["claude", "cursor", "gemini"]
    tool_name: str = ""
    command: str = ""
    file_path: str = ""
    decision: Literal["allow", "block", "ask"] = "allow"
    reason: str = ""
    matched_rules: list[str] = field(default_factory=list)
    severity: str | None = None
    category: str | None = None
    exit_code: int | None = None
    session_id: str | None = None
    user: str | None = None
    project_dir: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values and empty collections."""
        data = asdict(self)
        # Remove empty/None values for cleaner logs
        return {k: v for k, v in data.items() if v is not None and v != "" and v != [] and v != {}}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))


class AuditLogger:
    """
    JSON Lines logger for audit events.
    
    Logs are written to daily files in the format: audit-YYYY-MM-DD.jsonl
    
    Security features:
    - Sensitive data redaction
    - Log injection prevention
    - Secure file permissions (0600)
    - File locking for concurrent access
    - Size limits and truncation
    """

    def __init__(
        self,
        log_dir: str | Path | None = None,
        stderr_logging: bool = False,
        redact_secrets: bool = True,
    ):
        """
        Initialize the audit logger.
        
        Args:
            log_dir: Directory for log files. Defaults to ~/.ai-security-hooks/logs/
            stderr_logging: If True, also log to stderr (useful for debugging).
            redact_secrets: If True, redact sensitive data from logs.
        """
        if log_dir is None:
            log_dir = Path.home() / ".agent-security-hooks" / "logs"
        
        self.log_dir = Path(log_dir)
        self.stderr_logging = stderr_logging
        self.redact_secrets = redact_secrets
        
        # Create log directory with secure permissions (0700)
        self.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Ensure directory has correct permissions even if it existed
        try:
            os.chmod(self.log_dir, 0o700)
        except OSError:
            pass  # May fail if not owner

    def _get_log_file(self) -> Path:
        """Get the log file path for today."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self.log_dir / f"audit-{today}.jsonl"

    def _get_timestamp(self) -> str:
        """Get current UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def _check_log_rotation(self, log_file: Path) -> None:
        """
        Check if log file needs rotation (size limit).
        
        Args:
            log_file: Path to the log file.
        """
        try:
            if log_file.exists() and log_file.stat().st_size > MAX_LOG_FILE_SIZE:
                # Rotate by renaming with timestamp
                rotate_name = log_file.with_suffix(
                    f".{datetime.now(timezone.utc).strftime('%H%M%S')}.jsonl"
                )
                log_file.rename(rotate_name)
        except OSError:
            pass  # Ignore rotation errors

    def _write_log_line(self, log_file: Path, log_line: str) -> None:
        """
        Write a log line with secure file handling.
        
        Args:
            log_file: Path to the log file.
            log_line: Line to write.
        """
        # Check for rotation before writing
        self._check_log_rotation(log_file)
        
        # Open with secure permissions (0600) and exclusive lock
        fd = os.open(
            str(log_file),
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600  # Secure permissions: owner read/write only
        )
        try:
            # Acquire exclusive lock for concurrent access safety
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                os.write(fd, (log_line + "\n").encode('utf-8'))
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _prepare_for_logging(self, text: str) -> str:
        """
        Prepare text for logging: truncate, sanitize, and optionally redact.
        
        Args:
            text: Input text to prepare.
            
        Returns:
            Prepared text safe for logging.
        """
        if not text:
            return text
        
        # Truncate long text
        result = truncate_text(text)
        
        # Sanitize for log injection prevention
        result = sanitize_for_log(result)
        
        # Redact sensitive data if enabled
        if self.redact_secrets:
            result = redact_sensitive_data(result)
        
        return result

    def log(self, event: AuditEvent) -> None:
        """
        Log an audit event.
        
        Args:
            event: The audit event to log.
        """
        # Ensure timestamp is set
        if not event.timestamp:
            event.timestamp = self._get_timestamp()

        # Prepare command and file_path for logging
        event.command = self._prepare_for_logging(event.command)
        event.file_path = self._prepare_for_logging(event.file_path)
        event.reason = self._prepare_for_logging(event.reason)
        
        # Sanitize extra fields
        if event.extra:
            event.extra = {
                k: self._prepare_for_logging(str(v)) if isinstance(v, str) else v
                for k, v in event.extra.items()
            }

        log_line = event.to_json()

        # Write to log file with security measures
        try:
            log_file = self._get_log_file()
            self._write_log_line(log_file, log_line)
        except Exception as e:
            # Don't fail the hook if logging fails
            if self.stderr_logging:
                print(f"[WARN] Failed to write audit log: {e}", file=sys.stderr)

        # Optionally write to stderr for debugging (also redacted)
        if self.stderr_logging:
            print(f"[AUDIT] {log_line}", file=sys.stderr)

    def log_pre_execution(
        self,
        platform: str,
        event_type: str,
        command: str = "",
        file_path: str = "",
        tool_name: str = "",
        decision: str = "allow",
        reason: str = "",
        matched_rules: list[str] | None = None,
        severity: str | None = None,
        category: str | None = None,
        session_id: str | None = None,
        user: str | None = None,
        project_dir: str | None = None,
        **extra,
    ) -> None:
        """
        Convenience method for logging pre-execution events.
        
        Args:
            platform: The AI platform (claude, cursor, gemini).
            event_type: The type of event being logged.
            command: The command being executed (if applicable).
            file_path: The file path (if applicable).
            tool_name: The name of the tool being used.
            decision: The security decision (allow, block, ask).
            reason: Reason for the decision.
            matched_rules: List of rule IDs that matched.
            severity: Severity level if blocked/asked.
            category: Category of the matched rule.
            session_id: Session identifier.
            user: User identifier.
            project_dir: Project directory path.
            **extra: Additional metadata to include.
        """
        event = AuditEvent(
            timestamp=self._get_timestamp(),
            event_type=event_type,
            platform=platform,
            tool_name=tool_name,
            command=command,
            file_path=file_path,
            decision=decision,
            reason=reason,
            matched_rules=matched_rules or [],
            severity=severity,
            category=category,
            session_id=session_id,
            user=user,
            project_dir=project_dir,
            extra=extra if extra else {},
        )
        self.log(event)

    def log_post_execution(
        self,
        platform: str,
        event_type: str,
        command: str = "",
        file_path: str = "",
        tool_name: str = "",
        exit_code: int | None = None,
        session_id: str | None = None,
        user: str | None = None,
        project_dir: str | None = None,
        **extra,
    ) -> None:
        """
        Convenience method for logging post-execution events.
        
        Args:
            platform: The AI platform (claude, cursor, gemini).
            event_type: The type of event being logged.
            command: The command that was executed.
            file_path: The file path (if applicable).
            tool_name: The name of the tool that was used.
            exit_code: The exit code of the command.
            session_id: Session identifier.
            user: User identifier.
            project_dir: Project directory path.
            **extra: Additional metadata to include.
        """
        event = AuditEvent(
            timestamp=self._get_timestamp(),
            event_type=event_type,
            platform=platform,
            tool_name=tool_name,
            command=command,
            file_path=file_path,
            exit_code=exit_code,
            session_id=session_id,
            user=user,
            project_dir=project_dir,
            extra=extra if extra else {},
        )
        self.log(event)


def get_environment_context() -> dict[str, str | None]:
    """
    Get context from environment variables set by AI tools.
    
    Returns:
        Dictionary with session_id, user, and project_dir from environment.
    """
    return {
        "session_id": os.environ.get("CURSOR_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID"),
        "user": os.environ.get("CURSOR_USER_EMAIL") or os.environ.get("USER"),
        "project_dir": (
            os.environ.get("CURSOR_PROJECT_DIR") 
            or os.environ.get("CLAUDE_PROJECT_DIR")
            or os.environ.get("PWD")
        ),
    }
