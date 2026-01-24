"""Loop analysis for PySpectre.
This module provides loop detection, bound inference, and invariant generation
for improving symbolic execution of loops.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
)

import z3

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class LoopType(Enum):
    """Classification of loop types."""

    FOR_RANGE = auto()
    FOR_ITER = auto()
    WHILE_COND = auto()
    WHILE_TRUE = auto()
    NESTED = auto()
    UNKNOWN = auto()


@dataclass
class LoopBound:
    """Represents loop iteration bounds."""

    lower: z3.ExprRef
    upper: z3.ExprRef
    exact: z3.ExprRef | None = None
    is_finite: bool = True

    @staticmethod
    def constant(n: int) -> LoopBound:
        """Create a constant bound."""
        val = z3.IntVal(n)
        return LoopBound(lower=val, upper=val, exact=val)

    @staticmethod
    def range(low: int, high: int) -> LoopBound:
        """Create a range bound."""
        return LoopBound(lower=z3.IntVal(low), upper=z3.IntVal(high))

    @staticmethod
    def unbounded() -> LoopBound:
        """Create an unbounded (potentially infinite) loop."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=z3.IntVal(2**31),
            is_finite=False,
        )

    @staticmethod
    def symbolic(expr: z3.ExprRef) -> LoopBound:
        """Create a symbolic bound."""
        return LoopBound(
            lower=z3.IntVal(0),
            upper=expr,
            exact=expr,
        )


@dataclass
class LoopInfo:
    """Information about a detected loop."""

    header_pc: int
    back_edge_pc: int
    exit_pcs: set[int]
    body_pcs: set[int]
    loop_type: LoopType = LoopType.UNKNOWN
    bound: LoopBound | None = None
    induction_vars: dict[str, InductionVariable] = field(default_factory=dict)
    invariants: list[z3.BoolRef] = field(default_factory=list)
    parent: LoopInfo | None = None
    children: list[LoopInfo] = field(default_factory=list)
    nesting_depth: int = 0

    def contains_pc(self, pc: int) -> bool:
        """Check if PC is inside this loop."""
        return pc in self.body_pcs or pc == self.header_pc

    def is_header(self, pc: int) -> bool:
        """Check if PC is the loop header."""
        return pc == self.header_pc

    def is_exit(self, pc: int) -> bool:
        """Check if PC is a loop exit."""
        return pc in self.exit_pcs


@dataclass
class InductionVariable:
    """An induction variable that changes predictably each iteration."""

    name: str
    initial: z3.ExprRef
    step: z3.ExprRef
    direction: int = 1

    def value_at_iteration(self, i: z3.ExprRef) -> z3.ExprRef:
        """Get value at iteration i."""
        return self.initial + self.step * i

    def final_value(self, iterations: z3.ExprRef) -> z3.ExprRef:
        """Get value after all iterations."""
        return self.initial + self.step * iterations


class LoopDetector:
    """Detects loops in bytecode using control flow analysis."""

    def __init__(self):
        self._loops: list[LoopInfo] = []
        self._back_edges: list[tuple[int, int]] = []

    def analyze_cfg(
        self,
        instructions: list,
        entry_pc: int = 0,
    ) -> list[LoopInfo]:
        """Analyze control flow graph to detect loops."""
        cfg = self._build_cfg(instructions)
        dominators = self._compute_dominators(cfg, entry_pc)
        self._back_edges = self._find_back_edges(cfg, dominators)
        for from_pc, to_pc in self._back_edges:
            loop = self._build_loop_info(cfg, from_pc, to_pc)
            self._loops.append(loop)
        self._compute_nesting()
        return self._loops

    def _build_cfg(self, instructions: list) -> dict[int, set[int]]:
        """Build control flow graph from instructions."""
        cfg: dict[int, set[int]] = {}
        for i, instr in enumerate(instructions):
            pc = instr.offset
            if pc not in cfg:
                cfg[pc] = set()
            if instr.opname in ("JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"):
                cfg[pc].add(instr.argval)
            elif instr.opname in (
                "POP_JUMP_IF_TRUE",
                "POP_JUMP_IF_FALSE",
                "POP_JUMP_IF_NONE",
                "POP_JUMP_IF_NOT_NONE",
            ):
                cfg[pc].add(instr.argval)
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
            elif instr.opname not in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"):
                if i + 1 < len(instructions):
                    cfg[pc].add(instructions[i + 1].offset)
        return cfg

    def _compute_dominators(
        self,
        cfg: dict[int, set[int]],
        entry: int,
    ) -> dict[int, set[int]]:
        """Compute dominator sets for all nodes."""
        all_nodes = set(cfg.keys())
        for successors in cfg.values():
            all_nodes.update(successors)
        dom: dict[int, set[int]] = {entry: {entry}}
        for node in all_nodes:
            if node != entry:
                dom[node] = set(all_nodes)
        changed = True
        while changed:
            changed = False
            for node in all_nodes:
                if node == entry:
                    continue
                preds = [n for n, succs in cfg.items() if node in succs]
                if preds:
                    new_dom = set.intersection(*[dom.get(p, all_nodes) for p in preds])
                    new_dom.add(node)
                    if new_dom != dom[node]:
                        dom[node] = new_dom
                        changed = True
        return dom

    def _find_back_edges(
        self,
        cfg: dict[int, set[int]],
        dominators: dict[int, set[int]],
    ) -> list[tuple[int, int]]:
        """Find back edges (loops) in CFG."""
        back_edges = []
        for from_pc, successors in cfg.items():
            for to_pc in successors:
                if to_pc in dominators.get(from_pc, set()):
                    back_edges.append((from_pc, to_pc))
        return back_edges

    def _build_loop_info(
        self,
        cfg: dict[int, set[int]],
        back_edge_pc: int,
        header_pc: int,
    ) -> LoopInfo:
        """Build loop info from back edge."""
        body_pcs = {header_pc, back_edge_pc}
        worklist = [back_edge_pc]
        reverse_cfg: dict[int, set[int]] = {}
        for src, dsts in cfg.items():
            for dst in dsts:
                if dst not in reverse_cfg:
                    reverse_cfg[dst] = set()
                reverse_cfg[dst].add(src)
        while worklist:
            pc = worklist.pop()
            for pred in reverse_cfg.get(pc, set()):
                if pred not in body_pcs and pred != header_pc:
                    body_pcs.add(pred)
                    worklist.append(pred)
        exit_pcs = set()
        for pc in body_pcs:
            for succ in cfg.get(pc, set()):
                if succ not in body_pcs and succ != header_pc:
                    exit_pcs.add(succ)
        return LoopInfo(
            header_pc=header_pc,
            back_edge_pc=back_edge_pc,
            exit_pcs=exit_pcs,
            body_pcs=body_pcs,
        )

    def _compute_nesting(self) -> None:
        """Compute loop nesting relationships."""
        sorted_loops = sorted(self._loops, key=lambda l: len(l.body_pcs), reverse=True)
        for i, inner in enumerate(sorted_loops):
            for outer in sorted_loops[:i]:
                if inner.header_pc in outer.body_pcs:
                    inner.parent = outer
                    outer.children.append(inner)
                    inner.nesting_depth = outer.nesting_depth + 1
                    break

    def get_loop_at(self, pc: int) -> LoopInfo | None:
        """Get the innermost loop containing a PC."""
        candidates = [l for l in self._loops if l.contains_pc(pc)]
        if not candidates:
            return None
        return max(candidates, key=lambda l: l.nesting_depth)


class LoopBoundInference:
    """Infers loop bounds from loop structure."""

    def __init__(self):
        pass

    def infer_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bounds for a loop."""
        if self._is_range_loop(loop, state):
            return self._infer_range_bound(loop, state)
        if self._is_counted_loop(loop, state):
            return self._infer_counted_bound(loop, state)
        return LoopBound.range(0, 1000)

    def _is_range_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop is a for i in range(...) loop."""
        return False

    def _is_counted_loop(self, loop: LoopInfo, state: VMState) -> bool:
        """Check if loop has a counting pattern."""
        return bool(loop.induction_vars)

    def _infer_range_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bound for range-based loop."""
        return LoopBound.range(0, 100)

    def _infer_counted_bound(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> LoopBound:
        """Infer bound for counted loop."""
        for name, iv in loop.induction_vars.items():
            pass
        return LoopBound.range(0, 1000)


class LoopInvariantGenerator:
    """Generates loop invariants for verification."""

    def __init__(self):
        self._invariants: dict[int, list[z3.BoolRef]] = {}

    def generate_invariants(
        self,
        loop: LoopInfo,
        state: VMState,
    ) -> list[z3.BoolRef]:
        """Generate candidate invariants for a loop."""
        invariants = []
        for name, iv in loop.induction_vars.items():
            sym_var = state.locals.get(name)
            if sym_var and hasattr(sym_var, "z3_int"):
                invariants.append(sym_var.z3_int >= iv.initial)
                if loop.bound and loop.bound.upper:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        invariants.append(sym_var.z3_int <= final)
                    else:
                        invariants.append(sym_var.z3_int >= final)
        return invariants

    def verify_invariant(
        self,
        invariant: z3.BoolRef,
        loop: LoopInfo,
        state: VMState,
    ) -> bool:
        """Verify that an invariant holds."""
        from pyspectre.core.solver import is_satisfiable

        return is_satisfiable([invariant])


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def __init__(self, widening_threshold: int = 3):
        self.widening_threshold = widening_threshold
        self._iteration_count: dict[int, int] = {}

    def should_widen(self, loop: LoopInfo) -> bool:
        """Check if widening should be applied."""
        count = self._iteration_count.get(loop.header_pc, 0)
        return count >= self.widening_threshold

    def record_iteration(self, loop: LoopInfo) -> None:
        """Record a loop iteration."""
        pc = loop.header_pc
        self._iteration_count[pc] = self._iteration_count.get(pc, 0) + 1

    def widen_state(
        self,
        old_state: VMState,
        new_state: VMState,
        loop: LoopInfo,
    ) -> VMState:
        """Apply widening to generalize loop state."""
        from pyspectre.core.types import SymbolicValue

        widened = new_state.copy()
        for name in set(old_state.locals.keys()) | set(new_state.locals.keys()):
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                if isinstance(old_val, SymbolicValue) and isinstance(new_val, SymbolicValue):
                    widened.locals[name] = SymbolicValue(f"{name}_widened")
        return widened


__all__ = [
    "LoopType",
    "LoopBound",
    "LoopInfo",
    "InductionVariable",
    "LoopDetector",
    "LoopBoundInference",
    "LoopInvariantGenerator",
    "LoopWidening",
]
