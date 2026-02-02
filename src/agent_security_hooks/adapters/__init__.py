"""Platform-specific adapters for AI tool hooks."""

from .claude import ClaudeAdapter
from .cursor import CursorAdapter
from .gemini import GeminiAdapter

__all__ = [
    "ClaudeAdapter",
    "CursorAdapter",
    "GeminiAdapter",
]

