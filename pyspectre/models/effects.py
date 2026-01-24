"""
PySpectre Effect Tracking System - Phase 17
Tracks and manages side effects from function calls for symbolic execution.
Effect Categories:
- PURE: No side effects, result depends only on inputs
- READ: Reads external state (globals, files, etc.)
- WRITE: Writes to external state
- MUTATE: Mutates arguments in place
- IO: Performs I/O operations
- ALLOC: Allocates memory/resources
- EXCEPT: May raise exceptions
"""

from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Any

import z3


class Effect(Flag):
    """Effect flags that can be combined."""

    NONE = 0
    PURE = auto()
    READ_GLOBAL = auto()
    WRITE_GLOBAL = auto()
    READ_ARG = auto()
    MUTATE_ARG = auto()
    ALLOC = auto()
    IO_READ = auto()
    IO_WRITE = auto()
    MAY_RAISE = auto()
    NON_TERMINATING = auto()
    UNKNOWN = auto()
    IO = IO_READ | IO_WRITE
    GLOBAL = READ_GLOBAL | WRITE_GLOBAL
    SAFE = PURE | READ_ARG
    IMPURE = WRITE_GLOBAL | MUTATE_ARG | IO | ALLOC


@dataclass(frozen=True)
class EffectSignature:
    """
    Effect signature for a function.
    Describes what effects a function may have.
    """

    effects: Effect
    mutated_args: frozenset[int] = frozenset()
    read_globals: frozenset[str] = frozenset()
    written_globals: frozenset[str] = frozenset()
    may_raise: frozenset[str] = frozenset()

    @staticmethod
    def pure() -> "EffectSignature":
        """Create a pure effect signature."""
        return EffectSignature(effects=Effect.PURE)

    @staticmethod
    def unknown() -> "EffectSignature":
        """Create an unknown effect signature."""
        return EffectSignature(effects=Effect.UNKNOWN)

    @staticmethod
    def mutates(*arg_indices: int) -> "EffectSignature":
        """Create a signature that mutates specific arguments."""
        return EffectSignature(effects=Effect.MUTATE_ARG, mutated_args=frozenset(arg_indices))

    @staticmethod
    def io_read() -> "EffectSignature":
        """Create an I/O read signature."""
        return EffectSignature(effects=Effect.IO_READ)

    @staticmethod
    def io_write() -> "EffectSignature":
        """Create an I/O write signature."""
        return EffectSignature(effects=Effect.IO_WRITE)

    def is_pure(self) -> bool:
        """Check if the function is pure."""
        return self.effects == Effect.PURE or self.effects == Effect.NONE

    def is_safe(self) -> bool:
        """Check if the function has no impure effects."""
        return not (self.effects & Effect.IMPURE)

    def may_mutate(self) -> bool:
        """Check if the function may mutate state."""
        return bool(self.effects & (Effect.MUTATE_ARG | Effect.WRITE_GLOBAL))

    def has_io(self) -> bool:
        """Check if the function performs I/O."""
        return bool(self.effects & Effect.IO)

    def combine(self, other: "EffectSignature") -> "EffectSignature":
        """Combine two effect signatures (for sequential composition)."""
        return EffectSignature(
            effects=self.effects | other.effects,
            mutated_args=self.mutated_args | other.mutated_args,
            read_globals=self.read_globals | other.read_globals,
            written_globals=self.written_globals | other.written_globals,
            may_raise=self.may_raise | other.may_raise,
        )


@dataclass
class EffectTracker:
    """
    Tracks effects during symbolic execution.
    Used to accumulate effects across multiple operations.
    """

    accumulated: Effect = Effect.NONE
    mutated_addresses: set[Any] = field(default_factory=set)
    read_addresses: set[Any] = field(default_factory=set)
    written_globals: set[str] = field(default_factory=set)
    read_globals: set[str] = field(default_factory=set)
    io_operations: list[tuple[str, Any]] = field(default_factory=list)
    raised_exceptions: list[tuple[str, z3.BoolRef]] = field(default_factory=list)
    allocated_objects: list[Any] = field(default_factory=list)

    def record_pure(self):
        """Record a pure operation."""

    def record_mutation(self, address: Any, value: Any = None):
        """Record a mutation at an address."""
        self.accumulated |= Effect.MUTATE_ARG
        self.mutated_addresses.add(address)

    def record_read(self, address: Any):
        """Record a read from an address."""
        self.read_addresses.add(address)

    def record_global_read(self, name: str):
        """Record reading a global variable."""
        self.accumulated |= Effect.READ_GLOBAL
        self.read_globals.add(name)

    def record_global_write(self, name: str, value: Any = None):
        """Record writing a global variable."""
        self.accumulated |= Effect.WRITE_GLOBAL
        self.written_globals.add(name)

    def record_io(self, operation: str, target: Any = None):
        """Record an I/O operation."""
        if operation in ("read", "readline", "readlines", "recv", "input"):
            self.accumulated |= Effect.IO_READ
        else:
            self.accumulated |= Effect.IO_WRITE
        self.io_operations.append((operation, target))

    def record_allocation(self, obj: Any):
        """Record an object allocation."""
        self.accumulated |= Effect.ALLOC
        self.allocated_objects.append(obj)

    def record_exception(self, exc_type: str, condition: z3.BoolRef):
        """Record a potential exception."""
        self.accumulated |= Effect.MAY_RAISE
        self.raised_exceptions.append((exc_type, condition))

    def merge(self, other: "EffectTracker") -> "EffectTracker":
        """Merge effects from another tracker (for path merging)."""
        return EffectTracker(
            accumulated=self.accumulated | other.accumulated,
            mutated_addresses=self.mutated_addresses | other.mutated_addresses,
            read_addresses=self.read_addresses | other.read_addresses,
            written_globals=self.written_globals | other.written_globals,
            read_globals=self.read_globals | other.read_globals,
            io_operations=self.io_operations + other.io_operations,
            raised_exceptions=self.raised_exceptions + other.raised_exceptions,
            allocated_objects=self.allocated_objects + other.allocated_objects,
        )

    def to_signature(self) -> EffectSignature:
        """Convert tracked effects to a signature."""
        return EffectSignature(
            effects=self.accumulated,
            mutated_args=frozenset(),
            read_globals=frozenset(self.read_globals),
            written_globals=frozenset(self.written_globals),
            may_raise=frozenset(e[0] for e in self.raised_exceptions),
        )

    def is_pure(self) -> bool:
        """Check if all tracked operations were pure."""
        return self.accumulated == Effect.NONE or self.accumulated == Effect.PURE

    def clone(self) -> "EffectTracker":
        """Create an independent copy."""
        return EffectTracker(
            accumulated=self.accumulated,
            mutated_addresses=set(self.mutated_addresses),
            read_addresses=set(self.read_addresses),
            written_globals=set(self.written_globals),
            read_globals=set(self.read_globals),
            io_operations=list(self.io_operations),
            raised_exceptions=list(self.raised_exceptions),
            allocated_objects=list(self.allocated_objects),
        )


@dataclass
class EffectConstraint:
    """
    Constraint based on effects.
    Used to encode effect-related constraints in Z3.
    """

    effect: Effect
    condition: z3.BoolRef
    message: str = ""

    def to_z3(self) -> z3.BoolRef:
        """Get the Z3 constraint."""
        return self.condition


class EffectRegistry:
    """
    Registry of known function effect signatures.
    Maps function names to their effect signatures.
    """

    def __init__(self):
        self._signatures: dict[str, EffectSignature] = {}
        self._register_builtins()

    def _register_builtins(self):
        """Register effect signatures for builtins."""
        pure_builtins = [
            "len",
            "abs",
            "min",
            "max",
            "sum",
            "sorted",
            "reversed",
            "int",
            "float",
            "str",
            "bool",
            "list",
            "tuple",
            "dict",
            "set",
            "all",
            "any",
            "ord",
            "chr",
            "repr",
            "format",
            "hash",
            "isinstance",
            "issubclass",
            "type",
            "callable",
            "round",
            "pow",
            "divmod",
            "range",
            "enumerate",
            "zip",
            "map",
            "filter",
            "bin",
            "hex",
            "oct",
            "ascii",
            "id",
            "iter",
            "next",
            "frozenset",
            "bytes",
            "bytearray",
            "memoryview",
            "complex",
            "slice",
            "object",
            "super",
        ]
        for name in pure_builtins:
            self.register(name, EffectSignature.pure())
        self.register("print", EffectSignature(effects=Effect.IO_WRITE))
        self.register("input", EffectSignature(effects=Effect.IO_READ))
        self.register("open", EffectSignature(effects=Effect.IO | Effect.ALLOC))
        list_mutators = ["append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse"]
        for name in list_mutators:
            self.register(f"list.{name}", EffectSignature.mutates(0))
        dict_mutators = ["update", "pop", "popitem", "clear", "setdefault"]
        for name in dict_mutators:
            self.register(f"dict.{name}", EffectSignature.mutates(0))
        set_mutators = [
            "add",
            "remove",
            "discard",
            "pop",
            "clear",
            "update",
            "intersection_update",
            "difference_update",
            "symmetric_difference_update",
        ]
        for name in set_mutators:
            self.register(f"set.{name}", EffectSignature.mutates(0))
        self.register("setattr", EffectSignature.mutates(0))
        self.register("delattr", EffectSignature.mutates(0))
        self.register("exec", EffectSignature(effects=Effect.WRITE_GLOBAL | Effect.UNKNOWN))
        self.register("eval", EffectSignature(effects=Effect.READ_GLOBAL | Effect.MAY_RAISE))
        self.register("compile", EffectSignature(effects=Effect.ALLOC))
        may_raise = ["getattr", "hasattr", "delattr", "next"]
        for name in may_raise:
            existing = self.get(name) or EffectSignature.pure()
            self.register(name, EffectSignature(effects=existing.effects | Effect.MAY_RAISE))

    def register(self, name: str, signature: EffectSignature):
        """Register an effect signature for a function."""
        self._signatures[name] = signature

    def get(self, name: str) -> EffectSignature | None:
        """Get the effect signature for a function."""
        return self._signatures.get(name)

    def is_pure(self, name: str) -> bool:
        """Check if a function is known to be pure."""
        sig = self.get(name)
        return sig is not None and sig.is_pure()

    def may_mutate(self, name: str) -> bool:
        """Check if a function may mutate state."""
        sig = self.get(name)
        if sig is None:
            return True
        return sig.may_mutate()

    def has_io(self, name: str) -> bool:
        """Check if a function performs I/O."""
        sig = self.get(name)
        if sig is None:
            return False
        return sig.has_io()


EFFECT_REGISTRY = EffectRegistry()


class EffectAnalyzer:
    """
    Analyzes code for effects without execution.
    Static analysis to determine effect signatures.
    """

    def __init__(self, registry: EffectRegistry | None = None):
        self.registry = registry or EFFECT_REGISTRY

    def analyze_call(self, func_name: str, args: list[Any]) -> EffectSignature:
        """Analyze effects of a function call."""
        sig = self.registry.get(func_name)
        if sig is not None:
            return sig
        if "." in func_name:
            parts = func_name.split(".")
            if len(parts) == 2:
                type_name, method = parts
                method_sig = self.registry.get(f"{type_name}.{method}")
                if method_sig is not None:
                    return method_sig
        return EffectSignature.unknown()

    def analyze_assignment(self, target: Any) -> EffectSignature:
        """Analyze effects of an assignment."""
        return EffectSignature.pure()

    def analyze_attribute_access(
        self, obj: Any, attr: str, is_store: bool = False
    ) -> EffectSignature:
        """Analyze effects of attribute access."""
        if is_store:
            return EffectSignature.mutates(0)
        return EffectSignature(effects=Effect.READ_ARG)

    def analyze_subscript(self, obj: Any, index: Any, is_store: bool = False) -> EffectSignature:
        """Analyze effects of subscript access."""
        if is_store:
            return EffectSignature.mutates(0)
        return EffectSignature(effects=Effect.READ_ARG)


def havoc_value(type_hint: type | None = None, name: str = "havoc") -> Any:
    """
    Generate a havoc (unknown) value of the given type.
    Used for unknown function returns.
    """
    from pyspectre.core.symbolic_types import (
        SymbolicBool,
        SymbolicDict,
        SymbolicFloat,
        SymbolicInt,
        SymbolicList,
        SymbolicString,
        fresh_name,
    )

    var_name = fresh_name(name)
    if type_hint == int:
        return SymbolicInt(z3.Int(var_name))
    elif type_hint == bool:
        return SymbolicBool(z3.Bool(var_name))
    elif type_hint == float:
        return SymbolicFloat(z3.Real(var_name))
    elif type_hint == str:
        return SymbolicString(z3.String(var_name))
    elif type_hint == list:
        return SymbolicList(element_sort=z3.IntSort())
    elif type_hint == dict:
        return SymbolicDict(key_sort=z3.IntSort(), value_sort=z3.IntSort())
    else:
        return SymbolicInt(z3.Int(var_name))


def havoc_object(obj: Any, tracker: EffectTracker | None = None) -> Any:
    """
    Havoc an object's contents (make all fields unknown).
    Used after a function may have mutated an object.
    """
    from pyspectre.core.symbolic_types import SymbolicDict, SymbolicList, SymbolicSet

    if tracker:
        tracker.record_mutation(id(obj))
    if isinstance(obj, SymbolicList):
        return SymbolicList(element_sort=obj.element_sort)
    elif isinstance(obj, SymbolicDict):
        return SymbolicDict(key_sort=obj.key_sort, value_sort=obj.value_sort)
    elif isinstance(obj, SymbolicSet):
        return SymbolicSet(element_sort=obj.element_sort)
    return obj
