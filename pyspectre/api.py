"""Public API for PySpectre."""
from __future__ import annotations
from collections.abc import Callable
from pathlib import Path
from typing import Any
from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.execution.executor import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)
from pyspectre.reporting.formatters import format_result
def analyze(
    func: Callable,
    symbolic_args: dict[str, str] | None = None,
    *,
    max_paths: int = 1000,
    max_depth: int = 100,
    max_iterations: int = 10000,
    timeout: float = 60.0,
    verbose: bool = False,
    detect_division_by_zero: bool = True,
    detect_assertion_errors: bool = True,
    detect_index_errors: bool = True,
    detect_type_errors: bool = True,
    detect_overflow: bool = False,
) -> ExecutionResult:
    """
    Analyze a Python function for potential runtime errors.
    This is the main entry point for PySpectre. It performs symbolic execution
    on the given function and returns any issues found.
    Args:
        func: The function to analyze
        symbolic_args: Mapping of parameter names to their types.
                      Supported types: "int", "str", "list", "bool"
                      If not provided, all parameters default to "int"
        max_paths: Maximum number of paths to explore
        max_depth: Maximum recursion/call depth
        max_iterations: Maximum total iterations
        timeout: Timeout in seconds
        verbose: Print verbose output during analysis
        detect_division_by_zero: Check for division by zero
        detect_assertion_errors: Check for assertion failures
        detect_index_errors: Check for index out of bounds
        detect_type_errors: Check for type mismatches
        detect_overflow: Check for integer overflow (Python ints don't overflow,
                        but useful for bounded analysis)
    Returns:
        ExecutionResult containing issues, statistics, and coverage info
    Example:
        >>> def divide(x, y):
        ...     return x / y
        ...
        >>> result = analyze(divide, {"x": "int", "y": "int"})
        >>> if result.has_issues():
        ...     for issue in result.issues:
        ...         print(issue.format())
        >>> # Quick check with defaults
        >>> result = analyze(lambda x: 1/x)
        >>> print(len(result.issues))  # 1 - division by zero
    """
    config = ExecutionConfig(
        max_paths=max_paths,
        max_depth=max_depth,
        max_iterations=max_iterations,
        timeout_seconds=timeout,
        verbose=verbose,
        detect_division_by_zero=detect_division_by_zero,
        detect_assertion_errors=detect_assertion_errors,
        detect_index_errors=detect_index_errors,
        detect_type_errors=detect_type_errors,
        detect_overflow=detect_overflow,
    )
    executor = SymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args or {})
def analyze_code(
    code: str,
    symbolic_vars: dict[str, str] | None = None,
    **kwargs,
) -> ExecutionResult:
    """
    Analyze a code snippet for potential runtime errors.
    Args:
        code: Python source code to analyze
        symbolic_vars: Mapping of variable names to types
        **kwargs: Additional configuration options (see analyze())
    Returns:
        ExecutionResult with issues found
    Example:
        >>> code = '''
        ... def foo(x, y):
        ...     return x / y
        ... '''
        >>> result = analyze_code(code, {"x": "int", "y": "int"})
    """
    compiled = compile(code, "<string>", "exec")
    config = ExecutionConfig(**kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(compiled, symbolic_vars or {})
def analyze_file(
    filepath: str | Path,
    function_name: str,
    symbolic_args: dict[str, str] | None = None,
    **kwargs,
) -> ExecutionResult:
    """
    Analyze a function from a Python file.
    Args:
        filepath: Path to the Python file
        function_name: Name of the function to analyze
        symbolic_args: Mapping of parameter names to types
        **kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues found
    Example:
        >>> result = analyze_file("mymodule.py", "process_data", {"data": "list"})
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    source = filepath.read_text(encoding="utf-8")
    compiled = compile(source, str(filepath), "exec")
    namespace: dict[str, Any] = {}
    exec(compiled, namespace)
    if function_name not in namespace:
        raise ValueError(f"Function '{function_name}' not found in {filepath}")
    func = namespace[function_name]
    if not callable(func):
        raise ValueError(f"'{function_name}' is not a callable")
    analyze_kwargs = {
        k: v
        for k, v in kwargs.items()
        if k
        in [
            "max_paths",
            "max_depth",
            "max_iterations",
            "timeout",
            "verbose",
            "detect_division_by_zero",
            "detect_assertion_errors",
            "detect_index_errors",
            "detect_type_errors",
            "detect_overflow",
        ]
    }
    return analyze(func, symbolic_args, **analyze_kwargs)
def quick_check(func: Callable) -> list[Issue]:
    """
    Quick check a function for common issues.
    This is a convenience function for simple cases where you just want
    to know if there are any potential issues.
    Args:
        func: Function to check
    Returns:
        List of issues found (empty if none)
    Example:
        >>> issues = quick_check(lambda x: 1/x)
        >>> if issues:
        ...     print(f"Found {len(issues)} issues")
    """
    result = analyze(func, max_paths=100, max_iterations=500)
    return result.issues
def check_division_by_zero(func: Callable) -> list[Issue]:
    """
    Check specifically for division by zero issues.
    Args:
        func: Function to check
    Returns:
        List of division by zero issues
    """
    result = analyze(
        func,
        detect_division_by_zero=True,
        detect_assertion_errors=False,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
def check_assertions(func: Callable) -> list[Issue]:
    """
    Check specifically for assertion errors.
    Args:
        func: Function to check
    Returns:
        List of assertion error issues
    """
    result = analyze(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=True,
        detect_index_errors=False,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.ASSERTION_ERROR)
def check_index_errors(func: Callable) -> list[Issue]:
    """
    Check specifically for index out of bounds errors.
    Args:
        func: Function to check
    Returns:
        List of index error issues
    """
    result = analyze(
        func,
        detect_division_by_zero=False,
        detect_assertion_errors=False,
        detect_index_errors=True,
        detect_type_errors=False,
    )
    return result.get_issues_by_kind(IssueKind.INDEX_ERROR)
def format_issues(
    issues: list[Issue],
    format_type: str = "text",
) -> str:
    """
    Format a list of issues for display.
    Args:
        issues: List of issues to format
        format_type: Output format ("text", "json", "markdown")
    Returns:
        Formatted string
    """
    lines = []
    for i, issue in enumerate(issues, 1):
        if format_type == "json":
            import json
            lines.append(json.dumps(issue.to_dict(), indent=2))
        else:
            lines.append(f"[{i}] {issue.format()}")
    return "\n\n".join(lines)
check = analyze
scan = analyze_file
__all__ = [
    "analyze",
    "analyze_code",
    "analyze_file",
    "quick_check",
    "check_division_by_zero",
    "check_assertions",
    "check_index_errors",
    "format_issues",
    "format_result",
    "ExecutionResult",
    "ExecutionConfig",
    "Issue",
    "IssueKind",
    "check",
    "scan",
]