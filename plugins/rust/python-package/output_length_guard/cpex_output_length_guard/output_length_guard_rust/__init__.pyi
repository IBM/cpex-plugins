"""Type stubs for output_length_guard_rust Rust module."""

from typing import Any

class OutputLengthGuardEngine:
    """Rust-backed engine for Output Length Guard."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Initialize the engine with configuration.
        
        Args:
            config: Configuration dictionary
        """
        ...

def tool_post_invoke(self, result: Any, context: Any) -> Any:
        """Process tool after invocation.
        
        Args:
            result: Tool result
            context: Plugin context
            
        Returns:
            ToolPostInvokeResult
        """
        ...

__all__ = ["OutputLengthGuardEngine"]
