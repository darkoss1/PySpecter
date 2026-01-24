"""Function call opcodes."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pyspectre.core.types import SymbolicNone, SymbolicValue
from pyspectre.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pyspectre.core.state import VMState
    from pyspectre.execution.dispatcher import OpcodeDispatcher


@opcode_handler("PRECALL")
def handle_precall(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Pre-call setup (Python 3.11)."""
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL", "CALL_FUNCTION", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX")
def handle_call(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Function call - pop args and push symbolic result."""
    argc = int(instr.argval) if instr.argval else 0
    for _ in range(argc):
        if state.stack:
            state.pop()
    if state.stack:
        state.pop()
    if state.stack and isinstance(state.peek(), SymbolicNone):
        state.pop()
    ret_val, type_constraint = SymbolicValue.symbolic(f"call_result_{state.pc}")
    state.push(ret_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_KW")
def handle_call_kw(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Function call with keyword arguments (Python 3.12+)."""
    argc = int(instr.argval) if instr.argval else 0
    if state.stack:
        state.pop()
    for _ in range(argc):
        if state.stack:
            state.pop()
    if state.stack:
        state.pop()
    if state.stack and isinstance(state.peek(), SymbolicNone):
        state.pop()
    ret_val, type_constraint = SymbolicValue.symbolic(f"call_kw_result_{state.pc}")
    state.push(ret_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("CALL_METHOD")
def handle_call_method(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Method call."""
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
    """Load method/attribute from object."""
    if state.stack:
        obj = state.pop()
    else:
        obj = SymbolicNone()
    attr_name = str(instr.argval)
    attr_val, type_constraint = SymbolicValue.symbolic(f"{getattr(obj, 'name', 'obj')}.{attr_name}")
    state.push(attr_val)
    state.add_constraint(type_constraint)
    state.pc += 1
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_ATTR")
def handle_store_attr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store attribute on object."""
    if state.stack:
        state.pop()
    if state.stack:
        state.pop()
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
        attr_value = state.pop()
    if state.stack:
        func = state.pop()
    else:
        func = SymbolicNone()
    state.push(func)
    state.pc += 1
    return OpcodeResult.continue_with(state)
