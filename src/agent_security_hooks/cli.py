"""CLI entry point for Agent Security Hooks."""

import json
import os
import sys
from pathlib import Path

import click

from .validator import SecurityValidator
from .logger import AuditLogger, get_environment_context, redact_sensitive_data, truncate_text
from .adapters import ClaudeAdapter, CursorAdapter, GeminiAdapter

# Security constants
MAX_INPUT_SIZE = 1024 * 1024  # 1MB max input size
MAX_DEBUG_OUTPUT_LENGTH = 500  # Max length for debug output


def safe_debug_print(message: str, debug: bool = False) -> None:
    """
    Print debug message with sensitive data redaction.
    
    Args:
        message: The message to print.
        debug: Whether debug mode is enabled.
    """
    if not debug:
        return
    
    # Truncate and redact sensitive data
    safe_message = truncate_text(message, MAX_DEBUG_OUTPUT_LENGTH)
    safe_message = redact_sensitive_data(safe_message)
    print(f"[DEBUG] {safe_message}", file=sys.stderr)


# Detect platform from environment
def detect_platform() -> str | None:
    """Auto-detect the AI platform from environment variables."""
    if os.environ.get("CLAUDE_PROJECT_DIR") or os.environ.get("CLAUDE_TOOL_INPUT"):
        return "claude"
    if os.environ.get("CURSOR_PROJECT_DIR") or os.environ.get("CURSOR_VERSION"):
        return "cursor"
    # Gemini CLI doesn't set specific env vars, so it must be explicit
    return None


def get_config_path() -> Path | None:
    """Find the blacklist configuration file."""
    possible_paths = [
        # Project-local config
        Path.cwd() / ".agent-security-hooks" / "blacklist.yaml",
        Path.cwd() / "config" / "blacklist.yaml",
        # Package config (relative to this file)
        Path(__file__).parent.parent.parent.parent / "config" / "blacklist.yaml",
        # User config
        Path.home() / ".config" / "agent-security-hooks" / "blacklist.yaml",
        Path.home() / ".agent-security-hooks" / "blacklist.yaml",
        # System config
        Path("/etc/agent-security-hooks/blacklist.yaml"),
    ]
    
    for path in possible_paths:
        if path.exists():
            return path
    
    return None


@click.command()
@click.option(
    "--platform", "-p",
    type=click.Choice(["claude", "cursor", "gemini"]),
    help="AI platform (auto-detected if not specified)",
)
@click.option(
    "--event", "-e",
    type=str,
    required=True,
    help="Hook event type (e.g., pre, post, before-shell, after-edit)",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to blacklist.yaml configuration",
)
@click.option(
    "--log-dir", "-l",
    type=click.Path(),
    help="Directory for audit logs",
)
@click.option(
    "--debug", "-d",
    is_flag=True,
    help="Enable debug logging to stderr",
)
def main(
    platform: str | None,
    event: str,
    config: str | None,
    log_dir: str | None,
    debug: bool,
):
    """
    Agent Security Hooks - Validate and log AI tool operations.
    
    Reads JSON input from stdin, validates against security rules,
    logs the operation, and returns appropriate response.
    
    Exit codes:
      0 - Allow operation
      2 - Block operation
    """
    # Auto-detect platform if not specified
    if not platform:
        platform = detect_platform()
        if not platform:
            # Default to claude format if can't detect
            platform = "claude"
            safe_debug_print(f"Could not detect platform, defaulting to {platform}", debug)

    # Find config file
    config_path = Path(config) if config else get_config_path()
    if not config_path:
        print("⚠️  WARNING: No configuration file found!", file=sys.stderr)
        print("⚠️  All commands will be ALLOWED without security checks!", file=sys.stderr)
        print("⚠️  Install config: mkdir -p ~/.config/agent-security-hooks && cp config/blacklist.yaml ~/.config/agent-security-hooks/", file=sys.stderr)
        safe_debug_print("No config file found, using empty ruleset", debug)

    # Initialize components
    try:
        validator = SecurityValidator(config_path)
        if debug and config_path:
            # Don't expose full path in debug output
            safe_debug_print(f"Loaded config, {len(validator.rules)} rules", debug)
            if validator.get_config_hash():
                safe_debug_print(f"Config hash: {validator.get_config_hash()[:16]}...", debug)
    except Exception as e:
        # Don't expose full exception details (may contain paths)
        print("⚠️  ERROR: Failed to load config", file=sys.stderr)
        safe_debug_print(f"Config load error: {type(e).__name__}", debug)
        validator = SecurityValidator()  # Empty validator

    logger = AuditLogger(log_dir=log_dir, stderr_logging=debug)

    # Get the appropriate adapter
    adapters = {
        "claude": ClaudeAdapter,
        "cursor": CursorAdapter,
        "gemini": GeminiAdapter,
    }
    adapter_class = adapters[platform]
    adapter = adapter_class(validator=validator, logger=logger, debug=debug)

    # Read input from stdin with size limit (CVE-ASH-009)
    try:
        raw_input = sys.stdin.read(MAX_INPUT_SIZE + 1)
        
        # Check if input exceeds size limit
        if len(raw_input) > MAX_INPUT_SIZE:
            print("❌ Input size exceeds limit", file=sys.stderr)
            sys.exit(2)  # Block oversized input
        
        if not raw_input.strip():
            input_data = {}
        else:
            input_data = json.loads(raw_input)
    except json.JSONDecodeError as e:
        safe_debug_print(f"Invalid JSON input: {e}", debug)
        # For invalid input, block by default (fail-closed)
        sys.exit(2)

    # Process the hook event
    exit_code = adapter.handle(event=event, input_data=input_data)
    # Ensure stdout is flushed before exit so hook caller receives our JSON
    sys.stdout.flush()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

