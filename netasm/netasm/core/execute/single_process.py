# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        single_process.py
# ##
# ##  Project:
# ##        NetASM: A Network Assembly Language for Programmable Dataplanes
# ##
# ##  Author:
# ##        Muhammad Shahbaz
# ##
# ##  Copyright notice:
# ##        Copyright (C) 2014 Princeton University
# ##      Network Operations and Internet Security Lab
# ##
# ##  Licence:
# ##        This file is a part of the NetASM development base package.
# ##
# ##        This file is free code: you can redistribute it and/or modify it under
# ##        the terms of the GNU Lesser General Public License version 2.1 as
# ##        published by the Free Software Foundation.
# ##
# ##        This package is distributed in the hope that it will be useful, but
# ##        WITHOUT ANY WARRANTY; without even the implied warranty of
# ##        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# ##        Lesser General Public License for more details.
# ##
# ##        You should have received a copy of the GNU Lesser General Public
# ##        License along with the NetASM source package.  If not, see
# ##        http://www.gnu.org/licenses/.

__author__ = 'shahbaz'

from copy import deepcopy
from Queue import Queue
from threading import Thread, Lock

from netasm.netasm.core.syntax import InstructionCollection as I, Policy
from netasm.netasm.core.common import get_reserved_fields, get_instruction_at_label as get_label
from netasm.netasm.core.utilities.profile import time_usage, do_cprofile
from netasm.netasm.core.execute import *


# TODO: add runtime errors' details.


lock = Lock()


class Table:
    def __init__(self, patterns):
        self.patterns = patterns


class Tables(dict):
    def __setitem__(self, table_id, table):
        dict.__setitem__(self, table_id, table)


class ExecuteDecls:
    def __init__(self, decls):
        # Declare tables
        self.tables = Tables()
        for table_id, table in decls.table_decls.iteritems():
            # generate pattern
            if isinstance(table.table_fields, syntax.TableFieldsCollection.SimpleFields):
                pattern = SimplePattern()
                for field, size in table.table_fields.iteritems():
                    pattern[field] = syntax.Value(0, size)

                # generate list of patterns
                patterns = SimplePatterns()
                for i in range(0, table.size):
                    patterns.insert(i, deepcopy(pattern))
            elif isinstance(table.table_fields, syntax.TableFieldsCollection.MatchFields):
                pattern = MatchPattern()
                for field, (size, _) in table.table_fields.iteritems():
                    pattern[field] = (syntax.Value(0, size), syntax.Mask(-1))

                # generate list of patterns
                patterns = MatchPatterns()
                for i in range(0, table.size):
                    patterns.insert(i, deepcopy(pattern))
            else:
                raise RuntimeError()

            self.tables[table_id] = Table(patterns)


def execute_LDt(state, tables, destinations, table_id, index):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table '''
    patterns = tables[table_id].patterns

    ''' Lookup pattern '''
    pattern = patterns[index_value.value]
    pattern_list = pattern.values()

    for i in range(0, len(destinations)):
        operand = destinations[i]

        if isinstance(operand, O.Field):
            state.header[operand.field].value = pattern_list[i].value
        else:
            raise RuntimeError()

    state.label = syntax.Label('')
    return state


# TODO: type system to ensure destinations and patterns must have the same order


def execute_STt(state, tables, table_id, index, sources):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table '''
    patterns = tables[table_id].patterns

    ''' Lookup pattern '''
    pattern = patterns[index_value.value]
    pattern_list = pattern.keys()

    if isinstance(sources, O.Operands_):
        for i in range(0, len(sources)):
            field = pattern_list[i]
            operand = sources[i]

            if isinstance(operand, O.Value):
                pattern[field].value = operand.value.value
            elif isinstance(operand, O.Field):
                pattern[field].value = state.header[operand.field].value
            else:
                raise RuntimeError()
    elif isinstance(sources, O.OperandsMasks_):
        for i in range(0, len(sources)):
            field = pattern_list[i]
            operand, mask = sources[i]

            if isinstance(operand, O.Value):
                pattern[field][0].value = operand.value.value
                pattern[field] = (pattern[field][0], mask)
            elif isinstance(operand, O.Field):
                pattern[field][0].value = state.header[operand.field].value
                pattern[field] = (pattern[field][0], mask)
            else:
                raise RuntimeError()
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


# TODO: type system to ensure destinations and patterns must have the same order


def execute_INCt(state, tables, table_id, index):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table '''
    patterns = tables[table_id].patterns

    ''' Lookup pattern '''
    pattern = patterns[index_value.value]

    for field in pattern:
        pattern[field].value += 1

    state.label = syntax.Label('')
    return state


def execute_LKt(state, tables, index, table_id, sources):
    values = []
    ''' Read sources values '''
    for source in sources:
        if isinstance(source, O.Value):
            values.append(source.value)
        elif isinstance(source, O.Field):
            values.append(state.header[source.field])
        else:
            raise RuntimeError()

    ''' Lookup table '''
    patterns = tables[table_id].patterns

    value = -1
    if isinstance(patterns, MatchPatterns):
        for i in range(0, len(patterns)):
            pattern_list = patterns[i].values()

            if len(pattern_list) != len(values):
                raise RuntimeError()

            if all(map((lambda (value, mask), source: value.value == (source.value & mask)),
                       pattern_list, values)):
                value = i
                break
    elif isinstance(patterns, SimplePatterns):
        for i in range(0, len(patterns)):
            pattern_list = patterns[i].values()

            if all(map((lambda value, source: value.value == source.value),
                       pattern_list, values)):
                value = i
                break
    else:
        raise RuntimeError()

    ''' Lookup index '''
    if isinstance(index, O.Field):
        state.header[index.field].value = value
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


# TODO: 1) type system to ensure destinations and patterns must have the same order
# TODO: 2) look into the -1 assignment issue


def _execute_CNC(state, tables, codes):
    for code in codes:
        state = _execute_Code(code, tables, state)
    return state


def _execute_ATM(state, tables, code):
    return _execute_Code(code, tables, state)


def _execute_SEQ(state, tables, code):
    return _execute_Code(code, tables, state)


def _next_Instruction(instructions, tables, state):
    # Read instruction at program counter
    instruction = instructions[state.pc]

    if isinstance(instruction, I.ID):
        state = execute_ID(state)
    elif isinstance(instruction, I.DRP):
        state = execute_DRP(state, instruction.reason)
    elif isinstance(instruction, I.CTR):
        state = execute_CTR(state, instruction.reason)
    elif isinstance(instruction, I.ADD):
        state = execute_ADD(state, instruction.field, instruction.size)
    elif isinstance(instruction, I.RMV):
        state = execute_RMV(state, instruction.field)
    elif isinstance(instruction, I.LD):
        state = execute_LD(state, instruction.destination, instruction.source)
    elif isinstance(instruction, I.ST):
        state = execute_ST(state, instruction.location, instruction.source)
    elif isinstance(instruction, I.OP):
        state = execute_OP(state, instruction.destination, instruction.left_source,
                           instruction.operator, instruction.right_source)
    elif isinstance(instruction, I.PUSH):
        state = execute_PUSH(state, instruction.location)
    elif isinstance(instruction, I.POP):
        state = execute_POP(state, instruction.location)
    elif isinstance(instruction, I.BR):
        state = execute_BR(state, instruction.left_source, instruction.operator,
                           instruction.right_source, instruction.label)
    elif isinstance(instruction, I.JMP):
        state = execute_JMP(state, instruction.label)
    elif isinstance(instruction, I.LBL):
        state = execute_LBL(state)
    elif isinstance(instruction, I.LDt):
        state = execute_LDt(state, tables, instruction.destinations, instruction.table_id, instruction.index)
    elif isinstance(instruction, I.STt):
        state = execute_STt(state, tables, instruction.table_id, instruction.index, instruction.sources)
    elif isinstance(instruction, I.INCt):
        state = execute_INCt(state, tables, instruction.table_id, instruction.index)
    elif isinstance(instruction, I.LKt):
        state = execute_LKt(state, tables, instruction.index, instruction.table_id, instruction.sources)
    elif isinstance(instruction, I.CRC):
        state = execute_CRC(state, instruction.destination, instruction.sources)
    elif isinstance(instruction, I.HSH):
        state = execute_HSH(state, instruction.destination, instruction.sources)
    elif isinstance(instruction, I.CNC):
        state = _execute_CNC(state, tables, instruction.codes)
    elif isinstance(instruction, I.ATM):
        state = _execute_ATM(state, tables, instruction.code)
    elif isinstance(instruction, I.SEQ):
        state = _execute_SEQ(state, tables, instruction.code)
    else:
        raise RuntimeError()

    if state.label == syntax.Label(''):
        state.pc += 1
    else:
        state.pc, _ = get_label(instructions, state.label)

    return state


def _execute_Instructions(instructions, tables, state):
    # Read instruction at program counter
    instruction = instructions[state.pc]

    # Check if HLT instruction
    if isinstance(instruction, I.HLT):
        state = execute_HLT(state)
    else:
        state = _next_Instruction(instructions, tables, state)
        state = _execute_Instructions(instructions, tables, state)

    return state


def _execute_Code(code, tables, state):
    # Save the current header and pc
    pc = state.pc
    header = state.header

    state.pc = 0
    state.header = Header()
    for field in code.argument_fields:
        state.header[field] = header[field]
    for field in get_reserved_fields():
        state.header[field] = header[field]

    # Execute instructions
    state = _execute_Instructions(code.instructions, tables, state)

    # Commit changes to the current header
    for field in code.argument_fields:
        header[field] = state.header[field]
    for field in get_reserved_fields():
        header[field] = state.header[field]

    state.pc = pc
    state.header = header

    return state


# Execute code with timing usage
@time_usage
def _execute_Code__time_usage(code, tables, state):
    return _execute_Code(code, tables, state)


# Execute code with profiling information
@do_cprofile
def _execute_Code__cprofile(code, tables, state):
    return _execute_Code(code, tables, state)


execute = _execute_Code


class Execute(Thread):
    def __init__(self, policy):
        super(Execute, self).__init__()

        self._execute_decls = ExecuteDecls(policy.decls)
        self._tables = self._execute_decls.tables
        self._code = policy.code
        self._input_interface = Queue()
        self._output_interface = Queue()

    def put(self, state):
        setattr(state, 'pc', 0)
        self._input_interface.put(state)

    def get(self):
        state = self._output_interface.get()
        del state.pc
        return state

    def stop(self):
        self._input_interface.put(None)
        self.join()

    def run(self):
        while True:
            try:
                state = self._input_interface.get()

                if state is None:
                    return

                state = execute(self._code, self._tables, state)
                self._output_interface.put(state)
            except KeyboardInterrupt:
                break

    def add_table_entry(self, id, index, entry):
        lock.acquire()
        if id in self._tables:
            self._tables[id].patterns.add_entry(index, entry)
        else:
            raise RuntimeError("No such table")
        lock.release()

    def del_table_entry(self, id, index):
        lock.acquire()
        if id in self._tables:
            self._tables[id].patterns.del_entry(index)
        else:
            raise RuntimeError("No such table")
        lock.release()

    def query_table_entry(self, id, index):
        lock.acquire()
        if id in self._tables:
            entry = self._tables[id].patterns.query_entry(index)
        else:
            raise RuntimeError("No such table")
        lock.release()
        return entry

    def query_table_list(self):
        list = []
        lock.acquire()
        for t in self._tables.keys():
            list.append(str(t))
        lock.release()
        return list
