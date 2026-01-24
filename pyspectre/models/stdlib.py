"""
Extended Standard Library Models for PySpectre v1.2.
Provides symbolic models for commonly used stdlib modules:
- math: Mathematical functions (sqrt, ceil, floor, sin, cos, etc.)
- collections: Counter, defaultdict, deque, OrderedDict
- itertools: islice, chain, cycle, repeat, takewhile, dropwhile
- functools: reduce, partial
- os.path: exists, join, dirname, basename, isfile, isdir
- json: loads, dumps
- re: match, search, findall, sub
- datetime: date, time, datetime, timedelta
- random: random, randint, choice, shuffle
"""

from __future__ import annotations

import math as _math
from typing import TYPE_CHECKING, Any

import z3

from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pyspectre.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class MathSqrtModel(FunctionModel):
    """Model for math.sqrt()."""

    name = "sqrt"
    qualname = "math.sqrt"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)) and x >= 0:
            return ModelResult(value=SymbolicValue.from_const(_math.sqrt(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"sqrt_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int >= 0,
                    result.z3_real >= 0,
                    result.z3_real * result.z3_real == z3.ToReal(x.z3_int),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathCeilModel(FunctionModel):
    """Model for math.ceil()."""

    name = "ceil"
    qualname = "math.ceil"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.ceil(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"ceil_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int >= x.z3_int,
                    result.z3_int <= x.z3_int + 1,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathFloorModel(FunctionModel):
    """Model for math.floor()."""

    name = "floor"
    qualname = "math.floor"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.floor(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"floor_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int <= x.z3_int,
                    result.z3_int >= x.z3_int - 1,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathLogModel(FunctionModel):
    """Model for math.log()."""

    name = "log"
    qualname = "math.log"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        base = args[1] if len(args) > 1 else _math.e
        if isinstance(x, (int, float)) and x > 0:
            if isinstance(base, (int, float)) and base > 0:
                return ModelResult(value=SymbolicValue.from_const(_math.log(x, base)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"log_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int > 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathExpModel(FunctionModel):
    """Model for math.exp()."""

    name = "exp"
    qualname = "math.exp"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.exp(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"exp_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_real > 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathSinModel(FunctionModel):
    """Model for math.sin()."""

    name = "sin"
    qualname = "math.sin"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.sin(x)))
        result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= -1,
                result.z3_real <= 1,
            ],
        )


class MathCosModel(FunctionModel):
    """Model for math.cos()."""

    name = "cos"
    qualname = "math.cos"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.cos(x)))
        result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= -1,
                result.z3_real <= 1,
            ],
        )


class MathTanModel(FunctionModel):
    """Model for math.tan()."""

    name = "tan"
    qualname = "math.tan"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.tan(x)))
        result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathFabsModel(FunctionModel):
    """Model for math.fabs()."""

    name = "fabs"
    qualname = "math.fabs"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.fabs(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"fabs_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_real
                    == z3.If(z3.ToReal(x.z3_int) >= 0, z3.ToReal(x.z3_int), -z3.ToReal(x.z3_int)),
                    result.z3_real >= 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_float, result.z3_real >= 0]
        )


class MathGcdModel(FunctionModel):
    """Model for math.gcd()."""

    name = "gcd"
    qualname = "math.gcd"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        a, b = args[0], args[1]
        if isinstance(a, int) and isinstance(b, int):
            return ModelResult(value=SymbolicValue.from_const(_math.gcd(a, b)))
        result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if isinstance(a, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(a.z3_int >= 0, a.z3_int, -a.z3_int))
        if isinstance(b, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(b.z3_int >= 0, b.z3_int, -b.z3_int))
        return ModelResult(value=result, constraints=constraints)


class MathIsfiniteModel(FunctionModel):
    """Model for math.isfinite()."""

    name = "isfinite"
    qualname = "math.isfinite"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isfinite(x)))
        if isinstance(x, SymbolicValue) and hasattr(x, "is_int"):
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool, result.z3_bool == x.is_int],
            )
        result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsinfModel(FunctionModel):
    """Model for math.isinf()."""

    name = "isinf"
    qualname = "math.isinf"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isinf(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsnanModel(FunctionModel):
    """Model for math.isnan()."""

    name = "isnan"
    qualname = "math.isnan"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isnan(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class CounterModel(FunctionModel):
    """Model for collections.Counter()."""

    name = "Counter"
    qualname = "collections.Counter"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"counter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DefaultdictModel(FunctionModel):
    """Model for collections.defaultdict()."""

    name = "defaultdict"
    qualname = "collections.defaultdict"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"defaultdict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DequeModel(FunctionModel):
    """Model for collections.deque()."""

    name = "deque"
    qualname = "collections.deque"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"deque_{state.pc}")
        if args and isinstance(args[0], (list, tuple)):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == len(args[0])],
            )
        maxlen = kwargs.get("maxlen")
        if maxlen is not None and isinstance(maxlen, int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len >= 0, result.z3_len <= maxlen],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class OrderedDictModel(FunctionModel):
    """Model for collections.OrderedDict()."""

    name = "OrderedDict"
    qualname = "collections.OrderedDict"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"ordereddict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NamedtupleModel(FunctionModel):
    """Model for collections.namedtuple()."""

    name = "namedtuple"
    qualname = "collections.namedtuple"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"namedtuple_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsChainModel(FunctionModel):
    """Model for itertools.chain()."""

    name = "chain"
    qualname = "itertools.chain"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"chain_{state.pc}")
        total_len = z3.IntVal(0)
        for arg in args:
            if isinstance(arg, SymbolicList):
                total_len = total_len + arg.z3_len
            elif isinstance(arg, (list, tuple)):
                total_len = total_len + len(arg)
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == total_len],
        )


class ItertoolsIsliceModel(FunctionModel):
    """Model for itertools.islice()."""

    name = "islice"
    qualname = "itertools.islice"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"islice_{state.pc}")
        if len(args) >= 2:
            stop = args[1]
            if isinstance(stop, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len >= 0, result.z3_len <= stop],
                )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsCycleModel(FunctionModel):
    """Model for itertools.cycle()."""

    name = "cycle"
    qualname = "itertools.cycle"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"cycle_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsRepeatModel(FunctionModel):
    """Model for itertools.repeat()."""

    name = "repeat"
    qualname = "itertools.repeat"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"repeat_{state.pc}")
        if len(args) >= 2:
            times = args[1]
            if isinstance(times, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == times],
                )
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsTakewhileModel(FunctionModel):
    """Model for itertools.takewhile()."""

    name = "takewhile"
    qualname = "itertools.takewhile"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"takewhile_{state.pc}")
        if len(args) >= 2 and isinstance(args[1], SymbolicList):
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_len >= 0,
                    result.z3_len <= args[1].z3_len,
                ],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsDropwhileModel(FunctionModel):
    """Model for itertools.dropwhile()."""

    name = "dropwhile"
    qualname = "itertools.dropwhile"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dropwhile_{state.pc}")
        if len(args) >= 2 and isinstance(args[1], SymbolicList):
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_len >= 0,
                    result.z3_len <= args[1].z3_len,
                ],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsProductModel(FunctionModel):
    """Model for itertools.product()."""

    name = "product"
    qualname = "itertools.product"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"product_{state.pc}")
        product_len = z3.IntVal(1)
        for arg in args:
            if isinstance(arg, SymbolicList):
                product_len = product_len * arg.z3_len
            elif isinstance(arg, (list, tuple)):
                product_len = product_len * len(arg)
        repeat = kwargs.get("repeat", 1)
        if isinstance(repeat, int) and repeat > 1:
            for _ in range(repeat - 1):
                product_len = product_len * product_len
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == product_len],
        )


class ItertoolsPermutationsModel(FunctionModel):
    """Model for itertools.permutations()."""

    name = "permutations"
    qualname = "itertools.permutations"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"permutations_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsCombinationsModel(FunctionModel):
    """Model for itertools.combinations()."""

    name = "combinations"
    qualname = "itertools.combinations"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"combinations_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class FunctoolsReduceModel(FunctionModel):
    """Model for functools.reduce()."""

    name = "reduce"
    qualname = "functools.reduce"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"reduce_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsPartialModel(FunctionModel):
    """Model for functools.partial()."""

    name = "partial"
    qualname = "functools.partial"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"partial_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsLruCacheModel(FunctionModel):
    """Model for functools.lru_cache()."""

    name = "lru_cache"
    qualname = "functools.lru_cache"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"lru_cache_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathExistsModel(FunctionModel):
    """Model for os.path.exists()."""

    name = "exists"
    qualname = "os.path.exists"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"exists_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsfileModel(FunctionModel):
    """Model for os.path.isfile()."""

    name = "isfile"
    qualname = "os.path.isfile"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isfile_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsdirModel(FunctionModel):
    """Model for os.path.isdir()."""

    name = "isdir"
    qualname = "os.path.isdir"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isdir_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathJoinModel(FunctionModel):
    """Model for os.path.join()."""

    name = "join"
    qualname = "os.path.join"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if all(isinstance(a, str) for a in args):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.join(*args)))
        result, constraint = SymbolicString.symbolic(f"pathjoin_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathDirnameModel(FunctionModel):
    """Model for os.path.dirname()."""

    name = "dirname"
    qualname = "os.path.dirname"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.dirname(args[0])))
        result, constraint = SymbolicString.symbolic(f"dirname_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathBasenameModel(FunctionModel):
    """Model for os.path.basename()."""

    name = "basename"
    qualname = "os.path.basename"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.basename(args[0])))
        result, constraint = SymbolicString.symbolic(f"basename_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathSplitModel(FunctionModel):
    """Model for os.path.split()."""

    name = "split"
    qualname = "os.path.split"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            head, tail = os.path.split(args[0])
            return ModelResult(
                value=(
                    SymbolicString.from_const(head),
                    SymbolicString.from_const(tail),
                )
            )
        head, c1 = SymbolicString.symbolic(f"split_head_{state.pc}")
        tail, c2 = SymbolicString.symbolic(f"split_tail_{state.pc}")
        return ModelResult(value=(head, tail), constraints=[c1, c2])


class OsPathAbspathModel(FunctionModel):
    """Model for os.path.abspath()."""

    name = "abspath"
    qualname = "os.path.abspath"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"abspath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class JsonLoadsModel(FunctionModel):
    """Model for json.loads()."""

    name = "loads"
    qualname = "json.loads"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_loads_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class JsonDumpsModel(FunctionModel):
    """Model for json.dumps()."""

    name = "dumps"
    qualname = "json.dumps"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"json_dumps_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 2])


class JsonLoadModel(FunctionModel):
    """Model for json.load()."""

    name = "load"
    qualname = "json.load"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_load_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
        )


class JsonDumpModel(FunctionModel):
    """Model for json.dump()."""

    name = "dump"
    qualname = "json.dump"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"io": True},
        )


class ReMatchModel(FunctionModel):
    """Model for re.match()."""

    name = "match"
    qualname = "re.match"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"re_match_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReSearchModel(FunctionModel):
    """Model for re.search()."""

    name = "search"
    qualname = "re.search"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"re_search_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReFindallModel(FunctionModel):
    """Model for re.findall()."""

    name = "findall"
    qualname = "re.findall"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"re_findall_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ReSubModel(FunctionModel):
    """Model for re.sub()."""

    name = "sub"
    qualname = "re.sub"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"re_sub_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReSplitModel(FunctionModel):
    """Model for re.split()."""

    name = "split"
    qualname = "re.split"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"re_split_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class ReCompileModel(FunctionModel):
    """Model for re.compile()."""

    name = "compile"
    qualname = "re.compile"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"re_compile_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RandomRandomModel(FunctionModel):
    """Model for random.random()."""

    name = "random"
    qualname = "random.random"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"random_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= 0,
                result.z3_real < 1,
            ],
        )


class RandomRandintModel(FunctionModel):
    """Model for random.randint()."""

    name = "randint"
    qualname = "random.randint"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"randint_{state.pc}")
        constraints = [constraint, result.is_int]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, int):
                constraints.append(result.z3_int >= a)
            elif isinstance(a, SymbolicValue):
                constraints.append(result.z3_int >= a.z3_int)
            if isinstance(b, int):
                constraints.append(result.z3_int <= b)
            elif isinstance(b, SymbolicValue):
                constraints.append(result.z3_int <= b.z3_int)
        return ModelResult(value=result, constraints=constraints)


class RandomChoiceModel(FunctionModel):
    """Model for random.choice()."""

    name = "choice"
    qualname = "random.choice"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], (list, tuple)) and args[0]:
            result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if args and isinstance(args[0], SymbolicList):
            result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, args[0].z3_len > 0],
            )
        result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RandomShuffleModel(FunctionModel):
    """Model for random.shuffle()."""

    name = "shuffle"
    qualname = "random.shuffle"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class RandomSampleModel(FunctionModel):
    """Model for random.sample()."""

    name = "sample"
    qualname = "random.sample"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"sample_{state.pc}")
        if len(args) >= 2:
            k = args[1]
            if isinstance(k, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == k],
                )
            elif isinstance(k, SymbolicValue):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == k.z3_int],
                )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class RandomUniformModel(FunctionModel):
    """Model for random.uniform()."""

    name = "uniform"
    qualname = "random.uniform"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"uniform_{state.pc}")
        constraints = [constraint, result.is_float]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, (int, float)):
                constraints.append(result.z3_real >= a)
            if isinstance(b, (int, float)):
                constraints.append(result.z3_real <= b)
        return ModelResult(value=result, constraints=constraints)


class ExtendedStdlibRegistry:
    """Registry for extended stdlib models."""

    def __init__(self):
        self._models: dict[str, FunctionModel] = {}
        self._register_all()

    def _register_all(self):
        """Register all stdlib models."""
        math_models = [
            MathSqrtModel(),
            MathCeilModel(),
            MathFloorModel(),
            MathLogModel(),
            MathExpModel(),
            MathSinModel(),
            MathCosModel(),
            MathTanModel(),
            MathFabsModel(),
            MathGcdModel(),
            MathIsfiniteModel(),
            MathIsinfModel(),
            MathIsnanModel(),
        ]
        collections_models = [
            CounterModel(),
            DefaultdictModel(),
            DequeModel(),
            OrderedDictModel(),
            NamedtupleModel(),
        ]
        itertools_models = [
            ItertoolsChainModel(),
            ItertoolsIsliceModel(),
            ItertoolsCycleModel(),
            ItertoolsRepeatModel(),
            ItertoolsTakewhileModel(),
            ItertoolsDropwhileModel(),
            ItertoolsProductModel(),
            ItertoolsPermutationsModel(),
            ItertoolsCombinationsModel(),
        ]
        functools_models = [
            FunctoolsReduceModel(),
            FunctoolsPartialModel(),
            FunctoolsLruCacheModel(),
        ]
        ospath_models = [
            OsPathExistsModel(),
            OsPathIsfileModel(),
            OsPathIsdirModel(),
            OsPathJoinModel(),
            OsPathDirnameModel(),
            OsPathBasenameModel(),
            OsPathSplitModel(),
            OsPathAbspathModel(),
        ]
        json_models = [
            JsonLoadsModel(),
            JsonDumpsModel(),
            JsonLoadModel(),
            JsonDumpModel(),
        ]
        re_models = [
            ReMatchModel(),
            ReSearchModel(),
            ReFindallModel(),
            ReSubModel(),
            ReSplitModel(),
            ReCompileModel(),
        ]
        random_models = [
            RandomRandomModel(),
            RandomRandintModel(),
            RandomChoiceModel(),
            RandomShuffleModel(),
            RandomSampleModel(),
            RandomUniformModel(),
        ]
        all_models = (
            math_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
            + json_models
            + re_models
            + random_models
        )
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a model."""
        self._models[model.name] = model
        self._models[model.qualname] = model

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        return self._models.get(name)

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return sorted(set(m.name for m in self._models.values()))

    def list_modules(self) -> dict[str, list[str]]:
        """List models grouped by module."""
        modules = {}
        for model in self._models.values():
            if "." in model.qualname:
                module = model.qualname.rsplit(".", 1)[0]
            else:
                module = "builtins"
            if module not in modules:
                modules[module] = []
            if model.name not in modules[module]:
                modules[module].append(model.name)
        return {k: sorted(v) for k, v in sorted(modules.items())}


extended_stdlib_registry = ExtendedStdlibRegistry()


def get_stdlib_model(name: str) -> FunctionModel | None:
    """Get a stdlib model by name."""
    return extended_stdlib_registry.get(name)


def list_stdlib_models() -> list[str]:
    """List all stdlib models."""
    return extended_stdlib_registry.list_models()


def list_stdlib_modules() -> dict[str, list[str]]:
    """List stdlib models by module."""
    return extended_stdlib_registry.list_modules()
