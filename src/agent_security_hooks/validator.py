"""Security pattern validator for AI tool operations."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml


def resolve_path_safely(file_path: str) -> tuple[str, str]:
    """
    Resolve a file path safely, handling symlinks.
    
    Args:
        file_path: The file path to resolve.
        
    Returns:
        Tuple of (original_path, resolved_path).
        If resolution fails, resolved_path equals original_path.
    """
    if not file_path:
        return file_path, file_path
    
    try:
        # Resolve symlinks to get the actual path
        resolved = str(Path(file_path).resolve())
        return file_path, resolved
    except (OSError, RuntimeError, ValueError):
        # If resolution fails, use original path
        return file_path, file_path


class Severity(str, Enum):
    """Severity levels for security rules."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Action(str, Enum):
    """Actions to take when a rule matches."""
    BLOCK = "block"
    ASK = "ask"
    ALLOW = "allow"


@dataclass
class Rule:
    """A security rule definition."""
    id: str
    pattern: str
    severity: Severity
    action: Action
    category: str
    message: str
    case_insensitive: bool = False
    _compiled: re.Pattern = field(default=None, repr=False, init=False)

    def __post_init__(self):
        """Compile the regex pattern."""
        flags = re.IGNORECASE if self.case_insensitive else 0
        self._compiled = re.compile(self.pattern, flags)

    def matches(self, text: str) -> bool:
        """Check if the rule matches the given text."""
        return bool(self._compiled.search(text))


@dataclass
class FilePattern:
    """A file pattern rule."""
    pattern: str
    category: str
    message: str
    _compiled: re.Pattern = field(default=None, repr=False, init=False)

    def __post_init__(self):
        """Compile the regex pattern."""
        self._compiled = re.compile(self.pattern)

    def matches(self, path: str) -> bool:
        """Check if the pattern matches the given path."""
        return bool(self._compiled.search(path))


@dataclass
class ValidationResult:
    """Result of validating a command or file operation."""
    decision: Literal["allow", "block", "ask"]
    reason: str = ""
    matched_rules: list[str] = field(default_factory=list)
    severity: Severity | None = None
    category: str | None = None


class SecurityValidator:
    """Validates commands and file operations against security rules."""

    def __init__(self, config_path: str | Path | None = None):
        """
        Initialize the validator with a blacklist configuration.
        
        Args:
            config_path: Path to the blacklist.yaml file. If None, uses default.
        """
        self.rules: list[Rule] = []
        self.file_block_patterns: list[FilePattern] = []
        self.file_ask_patterns: list[FilePattern] = []
        
        if config_path is None:
            # Try to find config in common locations
            possible_paths = [
                Path(__file__).parent.parent.parent.parent / "config" / "blacklist.yaml",
                Path.home() / ".config" / "agent-security-hooks" / "blacklist.yaml",
                Path("/etc/agent-security-hooks/blacklist.yaml"),
            ]
            for path in possible_paths:
                if path.exists():
                    config_path = path
                    break
        
        if config_path:
            self.load_config(config_path)

    def _compute_config_hash(self, config_path: Path) -> str:
        """
        Compute SHA-256 hash of config file for integrity verification.
        
        Args:
            config_path: Path to the config file.
            
        Returns:
            Hex string of SHA-256 hash.
        """
        sha256 = hashlib.sha256()
        with open(config_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _check_config_permissions(self, config_path: Path) -> None:
        """
        Check that config file has secure permissions.
        
        Args:
            config_path: Path to the config file.
            
        Raises:
            PermissionError: If config file is insecure.
        """
        try:
            st = config_path.stat()
        except OSError:
            # If we can't stat, we can't load anyway
            return

        # Check permissions: writable by group or others
        # S_IWGRP (0o020) and S_IWOTH (0o002)
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
             raise PermissionError(
                 f"Config file {config_path} is insecure. "
                 f"It is writable by group or others (mode {oct(st.st_mode)[-3:]}). "
                 f"Run 'chmod 644 {config_path}' to fix (readable by others for hooks, but not writable)."
             )

    def get_config_hash(self) -> str | None:
        """
        Get the hash of the loaded configuration.
        
        Returns:
            Config hash if loaded, None otherwise.
        """
        return getattr(self, '_config_hash', None)

    def load_config(self, config_path: str | Path) -> None:
        """
        Load rules from a YAML configuration file.
        
        Args:
            config_path: Path to the blacklist.yaml file.
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        # Compute config hash for integrity verification
        self._config_hash = self._compute_config_hash(config_path)
        self._config_path = config_path

        # Verify config permissions
        self._check_config_permissions(config_path)

        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Load command rules
        for rule_data in config.get("rules", []):
            rule = Rule(
                id=rule_data["id"],
                pattern=rule_data["pattern"],
                severity=Severity(rule_data["severity"]),
                action=Action(rule_data["action"]),
                category=rule_data["category"],
                message=rule_data["message"],
                case_insensitive=rule_data.get("case_insensitive", False),
            )
            self.rules.append(rule)

        # Load file patterns
        file_patterns = config.get("file_patterns", {})
        
        for pattern_data in file_patterns.get("block", []):
            self.file_block_patterns.append(FilePattern(
                pattern=pattern_data["pattern"],
                category=pattern_data["category"],
                message=pattern_data["message"],
            ))

        for pattern_data in file_patterns.get("ask", []):
            self.file_ask_patterns.append(FilePattern(
                pattern=pattern_data["pattern"],
                category=pattern_data["category"],
                message=pattern_data["message"],
            ))

    def validate_command(self, command: str) -> ValidationResult:
        """
        Validate a shell command against security rules.
        
        Args:
            command: The shell command to validate.
            
        Returns:
            ValidationResult with decision, reason, and matched rules.
        """
        if not command:
            return ValidationResult(decision="allow")

        # Check for blocking rules first (CRITICAL and HIGH severity blocks)
        block_matches: list[Rule] = []
        ask_matches: list[Rule] = []

        for rule in self.rules:
            if rule.matches(command):
                if rule.action == Action.BLOCK:
                    block_matches.append(rule)
                elif rule.action == Action.ASK:
                    ask_matches.append(rule)

        # Return block if any blocking rules matched
        if block_matches:
            # Sort by severity to get the most severe
            block_matches.sort(key=lambda r: list(Severity).index(r.severity))
            most_severe = block_matches[0]
            return ValidationResult(
                decision="block",
                reason=most_severe.message,
                matched_rules=[r.id for r in block_matches],
                severity=most_severe.severity,
                category=most_severe.category,
            )

        # Return ask if any ask rules matched
        if ask_matches:
            ask_matches.sort(key=lambda r: list(Severity).index(r.severity))
            most_severe = ask_matches[0]
            return ValidationResult(
                decision="ask",
                reason=most_severe.message,
                matched_rules=[r.id for r in ask_matches],
                severity=most_severe.severity,
                category=most_severe.category,
            )

        # No rules matched - allow
        return ValidationResult(decision="allow")

    def validate_file_read(self, file_path: str) -> ValidationResult:
        """
        Validate a file read operation.
        
        Args:
            file_path: The path of the file to be read.
            
        Returns:
            ValidationResult with decision and reason.
        """
        if not file_path:
            return ValidationResult(decision="allow")

        # Resolve symlinks to prevent TOCTOU attacks
        original_path, resolved_path = resolve_path_safely(file_path)
        
        # Check both original and resolved paths against block patterns
        for path in [original_path, resolved_path]:
            for pattern in self.file_block_patterns:
                if pattern.matches(path):
                    return ValidationResult(
                        decision="block",
                        reason=pattern.message,
                        matched_rules=[f"file_block:{pattern.pattern}"],
                        category=pattern.category,
                    )

        # Check both paths against ask patterns
        for path in [original_path, resolved_path]:
            for pattern in self.file_ask_patterns:
                if pattern.matches(path):
                    return ValidationResult(
                        decision="ask",
                        reason=pattern.message,
                        matched_rules=[f"file_ask:{pattern.pattern}"],
                        category=pattern.category,
                    )

        return ValidationResult(decision="allow")

    def validate_file_edit(self, file_path: str) -> ValidationResult:
        """
        Validate a file edit operation.
        
        Args:
            file_path: The path of the file to be edited.
            
        Returns:
            ValidationResult with decision and reason.
        """
        # File edits use the same patterns as reads but are generally more sensitive
        result = self.validate_file_read(file_path)
        
        # Upgrade ask to block for production config files during edit
        if result.decision == "ask" and result.category == "deployment":
            if re.search(r"prod|production", file_path, re.IGNORECASE):
                return ValidationResult(
                    decision="block",
                    reason="Production configuration files cannot be edited directly",
                    matched_rules=result.matched_rules,
                    category=result.category,
                )
        
        return result

    def validate(
        self,
        command: str | None = None,
        file_path: str | None = None,
        operation: Literal["read", "edit", "shell"] = "shell",
    ) -> ValidationResult:
        """
        Unified validation method.
        
        Args:
            command: Shell command to validate (for shell operations).
            file_path: File path to validate (for read/edit operations).
            operation: Type of operation being validated.
            
        Returns:
            ValidationResult with decision and details.
        """
        if operation == "shell" and command:
            return self.validate_command(command)
        elif operation == "read" and file_path:
            return self.validate_file_read(file_path)
        elif operation == "edit" and file_path:
            return self.validate_file_edit(file_path)
        
        return ValidationResult(decision="allow")

