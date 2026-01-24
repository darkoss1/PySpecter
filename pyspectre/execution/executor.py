"""Main symbolic executor for PySpectre."""

from __future__ import annotations

import dis
import inspect
import types
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import (
    Any,
)

from pyspectre.analysis.detectors import DetectorRegistry, Issue, IssueKind, default_registry
from pyspectre.analysis.path_manager import (
    ExplorationStrategy,
    PathManager,
    create_path_manager,
)
from pyspectre.core.solver import ShadowSolver, is_satisfiable
from pyspectre.core.state import VMState
from pyspectre.core.types import SymbolicList, SymbolicString, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeDispatcher


@dataclass
class ExecutionConfig:
    """Configuration for symbolic execution."""

    max_paths: int = 1000
    max_depth: int = 100
    max_iterations: int = 10000
    timeout_seconds: float = 60.0
    strategy: ExplorationStrategy = ExplorationStrategy.DFS
    max_loop_iterations: int = 10
    unroll_loops: bool = True
    solver_timeout_ms: int = 5000
    use_incremental_solving: bool = True
    detect_division_by_zero: bool = True
    detect_assertion_errors: bool = True
    detect_index_errors: bool = True
    detect_type_errors: bool = True
    detect_overflow: bool = False
    verbose: bool = False
    collect_coverage: bool = True
    symbolic_args: dict[str, str] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of symbolic execution."""

    issues: list[Issue] = field(default_factory=list)
    paths_explored: int = 0
    paths_completed: int = 0
    paths_pruned: int = 0
    coverage: set[int] = field(default_factory=set)
    total_time_seconds: float = 0.0
    solver_time_seconds: float = 0.0
    function_name: str = ""
    source_file: str = ""

    def has_issues(self) -> bool:
        """Check if any issues were found."""
        return len(self.issues) > 0

    def get_issues_by_kind(self, kind: IssueKind) -> list[Issue]:
        """Get issues of a specific kind."""
        return [i for i in self.issues if i.kind == kind]

    def format_summary(self) -> str:
        """Format a summary of results."""
        lines = [
            "=== PySpectre Execution Results ===",
            f"Function: {self.function_name}",
            f"Paths explored: {self.paths_explored}",
            f"Paths completed: {self.paths_completed}",
            f"Coverage: {len(self.coverage)} bytecode instructions",
            f"Total time: {self.total_time_seconds:.2f}s",
            "",
        ]
        if self.issues:
            lines.append(f"Issues found: {len(self.issues)}")
            for issue in self.issues:
                lines.append("")
                lines.append(issue.format())
        else:
            lines.append("No issues found!")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "function_name": self.function_name,
            "source_file": self.source_file,
            "paths_explored": self.paths_explored,
            "paths_completed": self.paths_completed,
            "paths_pruned": self.paths_pruned,
            "coverage_size": len(self.coverage),
            "total_time_seconds": self.total_time_seconds,
            "issues": [i.to_dict() for i in self.issues],
        }


class SymbolicExecutor:
    """Main symbolic execution engine."""

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
    ):
        self.config = config or ExecutionConfig()
        self.detector_registry = detector_registry or default_registry
        self.dispatcher = OpcodeDispatcher()
        self.solver = ShadowSolver(timeout_ms=self.config.solver_timeout_ms)
        self._instructions: list[dis.Instruction] = []
        self._pc_to_line: dict[int, int] = {}
        self._worklist: PathManager = None
        self._issues: list[Issue] = []
        self._coverage: set[int] = set()
        self._visited_states: set[int] = set()
        self._paths_explored: int = 0
        self._paths_completed: int = 0
        self._paths_pruned: int = 0
        self._iterations: int = 0

    def execute_function(
        self,
        func: Callable,
        symbolic_args: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """
        Symbolically execute a function.
        Args:
            func: The function to analyze
            symbolic_args: Mapping of parameter names to types ("int", "str", "list", etc.)
        Returns:
            ExecutionResult with issues and statistics
        """
        import time

        start_time = time.time()
        self._reset()
        code = func.__code__
        self._instructions = list(dis.get_instructions(code))
        self._build_line_mapping(code)
        initial_state = self._create_initial_state(func, symbolic_args or {})
        self._worklist = create_path_manager(self.config.strategy)
        self._worklist.add_state(initial_state)
        self._execute_loop()
        end_time = time.time()
        result = ExecutionResult(
            issues=self._issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=end_time - start_time,
            function_name=func.__name__,
            source_file=code.co_filename,
        )
        return result

    def execute_code(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """
        Symbolically execute a code object.
        Args:
            code: The code object to analyze
            symbolic_vars: Mapping of variable names to types
        Returns:
            ExecutionResult with issues and statistics
        """
        import time

        start_time = time.time()
        self._reset()
        self._instructions = list(dis.get_instructions(code))
        self._build_line_mapping(code)
        initial_state = VMState()
        for name, type_hint in (symbolic_vars or {}).items():
            sym_val = self._create_symbolic_for_type(name, type_hint)
            initial_state.local_vars[name] = sym_val
        self._worklist = create_path_manager(self.config.strategy)
        self._worklist.add_state(initial_state)
        self._execute_loop()
        end_time = time.time()
        return ExecutionResult(
            issues=self._issues,
            paths_explored=self._paths_explored,
            paths_completed=self._paths_completed,
            paths_pruned=self._paths_pruned,
            coverage=self._coverage,
            total_time_seconds=end_time - start_time,
            function_name=code.co_name,
            source_file=code.co_filename,
        )

    def _reset(self) -> None:
        """Reset execution state."""
        self._instructions = []
        self._pc_to_line = {}
        self._issues = []
        self._coverage = set()
        self._visited_states = set()
        self._paths_explored = 0
        self._paths_completed = 0
        self._paths_pruned = 0
        self._iterations = 0

    def _build_line_mapping(self, code: types.CodeType) -> None:
        """Build mapping from PC to source line numbers."""
        last_line = None
        for i, instr in enumerate(self._instructions):
            if hasattr(instr, "positions") and instr.positions:
                line = instr.positions.lineno
                if line:
                    self._pc_to_line[i] = line
                    last_line = line
                elif last_line:
                    self._pc_to_line[i] = last_line
            elif instr.starts_line and isinstance(instr.starts_line, int):
                self._pc_to_line[i] = instr.starts_line
                last_line = instr.starts_line
            elif last_line:
                self._pc_to_line[i] = last_line

    def _create_initial_state(
        self,
        func: Callable,
        symbolic_args: dict[str, str],
    ) -> VMState:
        """Create initial VM state with symbolic arguments."""
        state = VMState()
        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
        except (ValueError, TypeError):
            params = list(func.__code__.co_varnames[: func.__code__.co_argcount])
        for param in params:
            type_hint = symbolic_args.get(param, "int")
            sym_val = self._create_symbolic_for_type(param, type_hint)
            state.local_vars[param] = sym_val
        return state

    def _create_symbolic_for_type(self, name: str, type_hint: str) -> Any:
        """Create a symbolic value of the given type."""
        type_hint = type_hint.lower()
        if type_hint in ("int", "integer"):
            val, constraint = SymbolicValue.symbolic(name)
            return val
        elif type_hint in ("str", "string"):
            val, constraint = SymbolicString.symbolic(name)
            return val
        elif type_hint in ("list", "array"):
            val, constraint = SymbolicList.symbolic(name)
            return val
        elif type_hint in ("bool", "boolean"):
            val, constraint = SymbolicValue.symbolic(name)
            return val
        elif type_hint in ("path", "pathlib.path"):
            val, constraint = SymbolicValue.symbolic_path(name)
            return val
        else:
            val, constraint = SymbolicValue.symbolic(name)
            return val

    def _execute_loop(self) -> None:
        """Main execution loop."""
        while not self._worklist.is_empty():
            if self._iterations >= self.config.max_iterations:
                if self.config.verbose:
                    print(f"Reached max iterations: {self.config.max_iterations}")
                break
            if self._paths_explored >= self.config.max_paths:
                if self.config.verbose:
                    print(f"Reached max paths: {self.config.max_paths}")
                break
            state = self._worklist.get_next_state()
            if state is None:
                break
            self._iterations += 1
            self._execute_step(state)

    def _execute_step(self, state: VMState) -> None:
        """Execute a single step (one instruction)."""
        if state.pc >= len(self._instructions):
            self._paths_completed += 1
            return
        if state.depth > self.config.max_depth:
            self._paths_pruned += 1
            return
        state_hash = self._hash_state(state)
        if state_hash in self._visited_states:
            self._paths_pruned += 1
            return
        else:
            self._visited_states.add(state_hash)
        instr = self._instructions[state.pc]
        self._coverage.add(state.pc)
        state.visited_pcs.add(state.pc)
        if not is_satisfiable(list(state.path_constraints)):
            self._paths_pruned += 1
            return
        self._run_detectors(state, instr)
        try:
            result = self.dispatcher.dispatch(instr, state)
        except Exception as e:
            if self.config.verbose:
                print(f"Execution error at PC {state.pc}: {e}")
            self._paths_pruned += 1
            return
        if result.issues:
            for issue in result.issues:
                issue.line_number = self._pc_to_line.get(state.pc)
                self._issues.append(issue)
        if result.terminal:
            self._paths_completed += 1
            return
        for new_state in result.new_states:
            new_state.depth = state.depth + 1
            self._worklist.add_state(new_state)
            self._paths_explored += 1

    def _run_detectors(self, state: VMState, instr: dis.Instruction) -> None:
        """Run enabled detectors on current state."""
        for detector in self.detector_registry.get_all():
            if detector is None:
                continue
            if detector.name == "division-by-zero" and not self.config.detect_division_by_zero:
                continue
            if detector.name == "assertion-error" and not self.config.detect_assertion_errors:
                continue
            if detector.name == "index-error" and not self.config.detect_index_errors:
                continue
            if detector.name == "type-error" and not self.config.detect_type_errors:
                continue
            if detector.name == "overflow" and not self.config.detect_overflow:
                continue
            issue = detector.check(state, instr, is_satisfiable)
            if issue:
                issue.line_number = self._pc_to_line.get(state.pc)
                self._issues.append(issue)

    def _hash_state(self, state: VMState) -> int:
        """Create a hash for loop detection."""
        return hash(
            (
                state.pc,
                len(state.path_constraints),
                len(state.stack),
                tuple(sorted(state.local_vars.keys())),
            )
        )


def analyze(
    func: Callable,
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs,
) -> ExecutionResult:
    """
    Analyze a function for potential issues.
    Args:
        func: Function to analyze
        symbolic_args: Mapping of parameter names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    Example:
        >>> def divide(x, y):
        ...     return x / y
        >>> result = analyze(divide, {"x": "int", "y": "int"})
        >>> print(result.issues)  # Division by zero issue
    """
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)


def analyze_code(
    code: str | types.CodeType,
    symbolic_vars: dict[str, str] | None = None,
    **config_kwargs,
) -> ExecutionResult:
    """
    Analyze code for potential issues.
    Args:
        code: Source code string or code object
        symbolic_vars: Mapping of variable names to types
        **config_kwargs: Additional configuration options
    Returns:
        ExecutionResult with issues and statistics
    """
    if isinstance(code, str):
        compiled = compile(code, "<string>", "exec")
        code = compiled
    config = ExecutionConfig(**config_kwargs)
    executor = SymbolicExecutor(config)
    return executor.execute_code(code, symbolic_vars)


def quick_check(func: Callable) -> list[Issue]:
    """
    Quick check a function for common issues.
    Args:
        func: Function to check
    Returns:
        List of issues found
    Example:
        >>> issues = quick_check(lambda x: 1/x)
        >>> print(issues[0].kind)  # IssueKind.DIVISION_BY_ZERO
    """
    result = analyze(func, max_paths=100, max_iterations=1000)
    return result.issues
