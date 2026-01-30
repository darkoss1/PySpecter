"""Function call opcodes."""
from __future__ import annotations
import dis
import z3
from typing import TYPE_CHECKING
from pyspectre.core.solver import get_model, is_satisfiable
from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicObject,
    SymbolicString,
    SymbolicValue,
)
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler
from pyspectre.analysis.detectors import Issue, IssueKind
from pyspectre.core.solver import is_satisfiable, get_model
from pyspectre.models.builtins import default_model_registry
from pyspectre.models.stdlib import get_stdlib_model
if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher
@opcode_handler("PRECALL")
def handle_precall(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle setup before a function call."""
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("CALL", "CALL_FUNCTION", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX")
def handle_call(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls, applying models if available."""
    argc = int(instr.argval) if instr.argval else 0
    args = []
    for _ in range(argc):
        if state.stack:
            args.insert(0, state.pop())
    kwargs = {}
    kw_names = getattr(state, "pending_kw_names", None)
    if kw_names is not None:
        if len(args) >= len(kw_names):
            kw_vals = args[-len(kw_names) :]
            args = args[: -len(kw_names)]
            for k, v in zip(kw_names, kw_vals):
                kwargs[k] = v
        state.pending_kw_names = None
    if state.stack:
        receiver_or_null = state.pop()
    else:
        receiver_or_null = SymbolicNone()
    if state.stack:
        func_obj = state.pop()
    else:
        func_obj = SymbolicNone()
    if not isinstance(receiver_or_null, SymbolicNone):
        args.insert(0, receiver_or_null)
    model_name = getattr(func_obj, "model_name", None)
    model = None
    if model_name:
        model = default_model_registry.get(model_name) or get_stdlib_model(model_name)
    if model:
        result = model.apply(args, kwargs, state)
        opcode_res = OpcodeResult.continue_with(state)
        if result.side_effects and "potential_exception" in result.side_effects:
            exc = result.side_effects["potential_exception"]
            cond = exc.get("condition")
            full_cond = list(state.path_constraints)
            if cond is not None:
                full_cond.append(cond)
            if is_satisfiable(full_cond):
                issue = Issue(
                    kind=(
                        IssueKind.KEY_ERROR
                        if exc["type"] == "KeyError"
                        else (
                            IssueKind.INDEX_ERROR
                            if exc["type"] == "IndexError"
                            else IssueKind.TYPE_ERROR
                        )
                    ),
                    message=exc["message"],
                    constraints=full_cond,
                    model=get_model(full_cond),
                    pc=state.pc,
                )
                opcode_res.issues.append(issue)
        state.push(result.value)
        for constraint in result.constraints:
            state.add_constraint(constraint)
        state.pc += 1
        return opcode_res
    ret_val, type_constraint = SymbolicValue.symbolic(f"call_result_{state.pc}")
    state.push(ret_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("CALL_KW")
def handle_call_kw(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Handle function calls with keyword arguments."""
    """Handle function calls with keyword arguments."""
    argc = int(instr.argval) if instr.argval else 0
    args = []
    kw_names = None
    if state.stack:
        kw_names = state.pop()
    for _ in range(argc):
        if state.stack:
            args.insert(0, state.pop())
    if state.stack:
        receiver_or_null = state.pop()
    else:
        receiver_or_null = SymbolicNone()
    if state.stack:
        func_obj = state.pop()
    else:
        func_obj = SymbolicNone()
    if not isinstance(receiver_or_null, SymbolicNone):
        args.insert(0, receiver_or_null)
    model_name = getattr(func_obj, "model_name", None)
    model = None
    if model_name:
        model = default_model_registry.get(model_name) or get_stdlib_model(model_name)
    if model:
        kwargs = {}
        if kw_names and hasattr(kw_names, "value") and isinstance(kw_names.value, tuple):
            names = kw_names.value
            if len(names) <= len(args):
                kw_vals = args[-len(names) :]
                args = args[: -len(names)]
                for k, v in zip(names, kw_vals):
                    kwargs[k] = v
        result = model.apply(args, kwargs, state)
        state.push(result.value)
        for constraint in result.constraints:
            state.add_constraint(constraint)
        state.pc += 1
        return OpcodeResult.continue_with(state)
    ret_val, type_constraint = SymbolicValue.symbolic(f"call_kw_result_{state.pc}")
    state.push(ret_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("CALL_METHOD")
def handle_call_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle method calls."""
    argc = int(instr.argval) if instr.argval else 0
    for _ in range(argc):
        if state.stack:
            state.pop()
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    ret_val, type_constraint = SymbolicValue.symbolic(f"method_result_{state.pc}")
    state.push(ret_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("LOAD_METHOD", "LOAD_ATTR")
def handle_load_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load an attribute or method, checking heap memory for attributes."""
    try:
        if state.stack:
            obj = state.pop()
        else:
            obj = SymbolicNone()
        attr_name = str(instr.argval)
        push_null = False
        if hasattr(instr, "arg") and instr.arg is not None:
            if instr.arg & 1:
                push_null = True
        result_val = None
        type_name = "unknown"
        if isinstance(obj, SymbolicObject):
            if obj.address != -1:
                obj_state = state.memory.get(obj.address)
                if obj_state is None:
                    obj_state = {}
                    state.memory[obj.address] = obj_state
                if attr_name in obj_state:
                    result_val = obj_state[attr_name]
                else:
                    result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                    obj_state[attr_name] = result_val
                    state.add_constraint(type_constraint)
            else:
                addresses = list(obj.potential_addresses)
                if not addresses:
                    result_val, type_constraint = SymbolicValue.symbolic(f"{obj.name}.{attr_name}")
                    state.add_constraint(type_constraint)
                else:
                    values = []
                    for addr in addresses:
                        mem = state.memory.get(addr, {})
                        if attr_name in mem:
                            val = mem[attr_name]
                        else:
                            val, _ = SymbolicValue.symbolic(f"obj_{addr}.{attr_name}")
                            mem[attr_name] = val
                        values.append((addr, val))
                    if len(values) == 1:
                        result_val = values[0][1]
                    else:
                        base_addr, base_val = values[-1]
                        if not isinstance(base_val, SymbolicValue):
                            base_val = SymbolicValue.from_const(base_val)
                        merged_z3_int = base_val.z3_int
                        merged_z3_bool = base_val.z3_bool
                        merged_is_int = base_val.is_int
                        merged_is_bool = base_val.is_bool
                        for addr, val in reversed(values[:-1]):
                            if not isinstance(val, SymbolicValue):
                                val = SymbolicValue.from_const(val)
                            cond = obj.z3_addr == addr
                            merged_z3_int = z3.If(cond, val.z3_int, merged_z3_int)
                            merged_z3_bool = z3.If(cond, val.z3_bool, merged_z3_bool)
                            merged_is_int = z3.If(cond, val.is_int, merged_is_int)
                            merged_is_bool = z3.If(cond, val.is_bool, merged_is_bool)
                        result_val = SymbolicValue(
                            _name=f"{obj.name}.{attr_name}",
                            z3_int=merged_z3_int,
                            is_int=merged_is_int,
                            z3_bool=merged_z3_bool,
                            is_bool=merged_is_bool,
                        )
        elif isinstance(obj, SymbolicList):
            type_name = "list"
        elif isinstance(obj, SymbolicDict):
            type_name = "dict"
        elif isinstance(obj, SymbolicString):
            type_name = "str"
        else:
            obj_name = getattr(obj, "name", "") or getattr(obj, "_name", "")
            if "set" in obj_name.lower() or getattr(obj, "_type", "") == "set":
                type_name = "set"
        if result_val is None:
            result_val, type_constraint = SymbolicValue.symbolic(
                f"{getattr(obj, 'name', 'obj')}.{attr_name}"
            )
            setattr(result_val, "model_name", f"{type_name}.{attr_name}")
            state.add_constraint(type_constraint)
        state.push(result_val)
        if push_null:
            state.push(
                obj if isinstance(obj, SymbolicObject) or type_name != "unknown" else SymbolicNone()
            )
        state.pc += 1
        return OpcodeResult.continue_with(state)
    except Exception as e:
        print(f"DEBUG EXCEPTION in handle_load_method: {e}")
        raise e
@opcode_handler("STORE_ATTR")
def handle_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object, updating heap memory."""
    if state.stack:
        value = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    if state.stack:
        obj = state.pop()
    else:
        return OpcodeResult.error(
            Issue(IssueKind.RUNTIME_ERROR, "Stack underflow", [], None, state.pc)
        )
    attr_name = str(instr.argval)
    if isinstance(obj, SymbolicObject):
        if obj.address != -1:
            obj_state = state.memory.get(obj.address)
            if obj_state is None:
                obj_state = {}
                state.memory[obj.address] = obj_state
            obj_state[attr_name] = value
        else:
            pass
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("DELETE_ATTR")
def handle_delete_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete attribute from object."""
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("MAKE_FUNCTION")
def handle_make_function(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Create a function object."""
    if state.stack:
        state.pop()
    flags = int(instr.argval) if instr.argval else 0
    if flags & 0x01:
        if state.stack:
            state.pop()
    if flags & 0x02:
        if state.stack:
            state.pop()
    if flags & 0x04:
        if state.stack:
            state.pop()
    if flags & 0x08:
        if state.stack:
            state.pop()
    func_val = SymbolicValue(
        _name=f"function_{state.pc}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    state.push(func_val)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("LOAD_BUILD_CLASS")
def handle_load_build_class(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load __build_class__ builtin."""
    builtin_val = SymbolicValue(
        _name="__build_class__",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    state.push(builtin_val)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("PUSH_EXC_INFO")
def handle_push_exc_info_func(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Push exception info for exception handling."""
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("KW_NAMES")
def handle_kw_names(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Set up keyword argument names for next CALL (Python 3.11+)."""
    state.pending_kw_names = instr.argval
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("IMPORT_NAME")
def handle_import_name(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import a module (import x)."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    module_name = str(instr.argval) if instr.argval else "unknown_module"
    module_val = SymbolicValue(
        _name=f"module_{module_name}",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )
    setattr(module_val, "model_name", module_name)
    state.push(module_val)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("IMPORT_FROM")
def handle_import_from(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import attribute from module (from x import y)."""
    attr_name = str(instr.argval) if instr.argval else "unknown_attr"
    attr_val, type_constraint = SymbolicValue.symbolic(f"import_{attr_name}")
    setattr(attr_val, "model_name", attr_name)
    state.push(attr_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("IMPORT_STAR")
def handle_import_star(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Import all from module (from x import *)."""
    if state.stack:
        state.pop()
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("LOAD_SUPER_ATTR")
def handle_load_super_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load attribute from super() (Python 3.12+)."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    attr_name = str(instr.argval) if instr.argval else "unknown"
    attr_val, constraint = SymbolicValue.symbolic(f"super_{attr_name}")
    state.push(attr_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("LOAD_SUPER_METHOD", "LOAD_ZERO_SUPER_ATTR", "LOAD_ZERO_SUPER_METHOD")
def handle_load_super_variants(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Load method/attribute from super() variants (Python 3.12+)."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
    attr_name = str(instr.argval) if instr.argval else "unknown"
    method_val, constraint = SymbolicValue.symbolic(f"super_method_{attr_name}")
    state.push(method_val)
    state.add_constraint(constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)
@opcode_handler("SET_FUNCTION_ATTRIBUTE")
def handle_set_function_attribute(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Set function attribute (__name__, __doc__, etc.)."""
    if state.stack:
        state.pop()
    if state.stack:
        func = state.pop()
    else:
        func = SymbolicNone()
    state.push(func)
    state.pc += 1
    return OpcodeResult.continue_with(state)