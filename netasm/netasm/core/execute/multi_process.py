# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        multi_process.py
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
from functools import partial
from multiprocessing import Process

from multiprocessing.queues import SimpleQueue as Queue

from netasm.netasm.core.syntax import InstructionCollection as I, Policy
import netasm.netasm.core.graphs.control_flow_graph as cfg
from netasm.netasm.core.common import get_modified_fields, get_reserved_fields, get_modified_reserved_fields, \
    get_modified_locations
from netasm.netasm.core.execute import *


# TODO: add runtime errors' details.


class Table(Process):
    def __init__(self, patterns):
        super(Table, self).__init__()

        self.patterns = patterns
        self.input_interface = Queue()
        self.output_interfaces = {'': Queue()}

    def stop(self):
        self.input_interface.put(None)
        self.join()

    def run(self):
        while True:
            try:
                data = self.input_interface.get()

                if data is None:
                    return

                operation, items = data

                if operation == 'add_entry':
                    index, entry = items
                    self.patterns.add_entry(index, entry)
                elif operation == 'del_entry':
                    index = items
                    self.patterns.del_entry(index)
                elif operation == 'query_entry':
                    index = items
                    entry = self.patterns.query_entry(index)
                    self.output_interfaces[''].put(entry)
                elif operation == 'write':
                    index, pattern = items
                    self.patterns[index] = pattern
                elif operation == 'read':
                    index, instruction_id = items
                    pattern = self.patterns[index]
                    self.output_interfaces[instruction_id].put(pattern)
                elif operation == 'lookup':
                    values, instruction_id = items
                    value = -1
                    if isinstance(self.patterns, MatchPatterns):
                        for i in range(0, len(self.patterns)):
                            pattern_list = self.patterns[i].values()

                            if len(pattern_list) != len(values):
                                raise RuntimeError()

                            if all(map((lambda (value, mask), source: value.value == (source.value & mask)),
                                       pattern_list, values)):
                                value = i
                                break
                    elif isinstance(self.patterns, SimplePatterns):
                        for i in range(0, len(self.patterns)):
                            pattern_list = self.patterns[i].values()

                            if all(map((lambda value, source: value.value == source.value),
                                       pattern_list, values)):
                                value = i
                                break
                    else:
                        raise RuntimeError()
                    self.output_interfaces[instruction_id].put(value)
                else:
                    raise RuntimeError()
            except KeyboardInterrupt:
                break


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


def execute_LDt(state, table_interface, instruction, destinations, index):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table pattern '''
    table_interface.put(('read', (index_value.value, id(instruction))))
    pattern = table_interface.get()
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


def execute_STt(state, table_interface, instruction, index, sources):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table pattern '''
    table_interface.put(('read', (index_value.value, id(instruction))))
    pattern = table_interface.get()
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

    ''' Write back into the table '''
    table_interface.put(('write', (index_value.value, pattern)))

    state.label = syntax.Label('')
    return state


# TODO: type system to ensure destinations and patterns must have the same order


def execute_INCt(state, table_interface, instruction, index):
    index_value = None
    ''' Lookup index '''
    if isinstance(index, O.Value):
        index_value = index.value
    elif isinstance(index, O.Field):
        index_value = state.header[index.field]
    else:
        raise RuntimeError()

    ''' Lookup table pattern '''
    table_interface.put(('read', (index_value.value, id(instruction))))
    pattern = table_interface.get()

    for field in pattern:
        pattern[field].value += 1

    ''' Write back into the table '''
    table_interface.put(('write', (index_value.value, pattern)))

    state.label = syntax.Label('')
    return state


def execute_LKt(state, table_interface, instruction, index, sources):
    values = []
    ''' Read sources values '''
    for source in sources:
        if isinstance(source, O.Value):
            values.append(source.value)
        elif isinstance(source, O.Field):
            values.append(state.header[source.field])
        else:
            raise RuntimeError()

    ''' Lookup table index '''
    table_interface.put(('lookup', (values, id(instruction))))
    value = table_interface.get()

    ''' Lookup index '''
    if isinstance(index, O.Field):
        state.header[index.field].value = value
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


# TODO: 1) type system to ensure destinations and patterns must have the same order
# TODO: 2) look into the -1 assignment issue


class GroupProcess():
    def __init__(self, instruction, tables):
        self._instruction = instruction
        self._tables = tables
        self.input_interface = Queue()
        self.output_interfaces = {}

        self._instruction_pipelines = []
        self._is_atomic_enabled = False
        self._is_sequential_enabled = False
        self._is_concurrent_enabled = False

        self._setup()

    def _setup(self):
        if isinstance(self._instruction, I.ATM):
            self._code = self._instruction.code
            self._instruction_pipelines.append(Pipeline(self._code.instructions, self._tables))
            self._atomic_process = Process(target=self.run_atomic)
            self._is_atomic_enabled = True
        elif isinstance(self._instruction, I.SEQ):
            self._code = self._instruction.code
            self._instruction_pipelines.append(Pipeline(self._code.instructions, self._tables))
            self._sequential_ingress_process = Process(target=self.run_sequential_ingress)
            self._sequential_egress_process = Process(target=self.run_sequential_egress)
            self._metadata_queue = Queue()
            self._is_sequential_enabled = True
        elif isinstance(self._instruction, I.CNC):
            # Note: CNC can't have PUSH/POP instructions in its code blocks. They violate the concurrency invariant.
            self._codes = self._instruction.codes
            self._modified_locations = []
            self._modified_reserved_fields = []
            self._modified_fields = []
            for code in self._codes:
                self._instruction_pipelines.append(Pipeline(code.instructions, self._tables))
                self._modified_locations.append(get_modified_locations(code.instructions))
                self._modified_reserved_fields.append(get_modified_reserved_fields(code.instructions))
                self._modified_fields.append(get_modified_fields(code.instructions, code.argument_fields))
            self._concurrent_ingress_process = Process(target=self.run_concurrent_ingress)
            self._concurrent_egress_process = Process(target=self.run_concurrent_egress)
            self._metadata_queue = Queue()
            self._is_concurrent_enabled = True
        else:
            raise RuntimeError()

    def start(self):
        for instruction_pipeline in self._instruction_pipelines:
            instruction_pipeline.start()

        if self._is_atomic_enabled:
            self._atomic_process.start()
        elif self._is_sequential_enabled:
            self._sequential_ingress_process.start()
            self._sequential_egress_process.start()
        elif self._is_concurrent_enabled:
            self._concurrent_ingress_process.start()
            self._concurrent_egress_process.start()
        else:
            raise RuntimeError()

    def stop(self):
        self.input_interface.put(None)
        for instruction_pipeline in self._instruction_pipelines:
            instruction_pipeline.stop()

        if self._is_atomic_enabled:
            self._atomic_process.join()
        elif self._is_sequential_enabled:
            self._metadata_queue.put(None)
            self._sequential_ingress_process.join()
            self._sequential_egress_process.join()
        elif self._is_concurrent_enabled:
            self._metadata_queue.put(None)
            self._concurrent_ingress_process.join()
            self._concurrent_egress_process.join()
        else:
            raise RuntimeError()

    def run_atomic(self):
        instruction_pipeline = self._instruction_pipelines[0]

        while True:
            try:
                state = self.input_interface.get()

                # print 'atomic_group_process'

                if state is None:
                    return

                ''' Save the current header '''
                header = state.header

                state.header = Header()
                for field in self._code.argument_fields:
                    state.header[field] = header[field]
                for field in get_reserved_fields():
                    state.header[field] = header[field]

                ''' Process the pipeline '''
                instruction_pipeline.put(state)
                state = instruction_pipeline.get()

                ''' Commit changes to the current header '''
                for field in self._code.argument_fields:
                    header[field] = state.header[field]
                for field in get_reserved_fields():
                    header[field] = state.header[field]

                state.header = header

                self.output_interfaces[state.label].put(state)
            except KeyboardInterrupt:
                break

    def run_sequential_ingress(self):
        instruction_pipeline = self._instruction_pipelines[0]

        while True:
            try:
                state = self.input_interface.get()

                # print 'sequential_group_ingress_process'

                if state is None:
                    return

                ''' Save the current header '''
                header = state.header

                self._metadata_queue.put(header)

                state.header = Header()
                for field in self._code.argument_fields:
                    state.header[field] = header[field]
                for field in get_reserved_fields():
                    state.header[field] = header[field]

                instruction_pipeline.put(state)
            except KeyboardInterrupt:
                break

    def run_sequential_egress(self):
        instruction_pipeline = self._instruction_pipelines[0]

        while True:
            try:
                header = self._metadata_queue.get()

                # print 'sequential_group_egress_process'

                if header is None:
                    return

                state = instruction_pipeline.get()

                ''' Commit changes to the original header '''
                for field in self._code.argument_fields:
                    header[field] = state.header[field]
                for field in get_reserved_fields():
                    header[field] = state.header[field]

                state.header = header

                self.output_interfaces[state.label].put(state)
            except KeyboardInterrupt:
                break

    def run_concurrent_ingress(self):
        while True:
            try:
                state = self.input_interface.get()

                # print 'concurrent_group_ingress_process'

                if state is None:
                    return

                ''' Save the current header '''
                header = state.header

                self._metadata_queue.put(state)

                for i in range(len(self._instruction_pipelines)):
                    state.header = Header()
                    for field in self._codes[i].argument_fields:
                        state.header[field] = header[field]
                    for field in get_reserved_fields():
                        state.header[field] = header[field]

                    self._instruction_pipelines[i].put(state)
            except KeyboardInterrupt:
                break

    def run_concurrent_egress(self):
        while True:
            try:
                state = self._metadata_queue.get()

                # print 'concurrent_group_egress_process'

                if state is None:
                    return

                for i in range(len(self._instruction_pipelines)):
                    _state = self._instruction_pipelines[i].get()

                    ''' Commit changes to the original header '''
                    # Note: we assume that fields and locations are unique across different legs of CNC
                    for field in self._modified_fields[i]:
                        state.header[field] = _state.header[field]
                    for field in self._modified_reserved_fields[i]:
                        state.header[field] = _state.header[field]
                    for location in self._modified_locations[i]:
                        offset_value = location.offset.value
                        length_value = location.length.value
                        state.header.packet[offset_value.value:(offset_value.value + length_value.value)] = \
                            _state.packet[offset_value.value:(offset_value.value + length_value.value)]

                self.output_interfaces[state.label].put(state)
            except KeyboardInterrupt:
                break


class TableInterface:
    def __init__(self):
        self.input_interface = Queue()
        self.output_interface = None

    def put(self, data):
        self.output_interface.put(data)

    def get(self):
        return self.input_interface.get()


class PrimitiveProcess(Process):
    def __init__(self, instruction):
        super(PrimitiveProcess, self).__init__()
        # self.daemon = True

        self._instruction = instruction
        self.input_interface = Queue()
        self.output_interfaces = {}

        self._run = None
        if isinstance(self._instruction, I.ID):
            self._run = execute_ID
        elif isinstance(self._instruction, I.DRP):
            self._run = partial(execute_DRP,
                                reason=self._instruction.reason)
        elif isinstance(self._instruction, I.CTR):
            self._run = partial(execute_CTR,
                                reason=self._instruction.reason)
        elif isinstance(self._instruction, I.ADD):
            self._run = partial(execute_ADD,
                                field=self._instruction.field,
                                size=self._instruction.size)
        elif isinstance(self._instruction, I.RMV):
            self._run = partial(execute_RMV,
                                field=self._instruction.field)
        elif isinstance(self._instruction, I.LD):
            self._run = partial(execute_LD,
                                destination=self._instruction.destination,
                                source=self._instruction.source)
        elif isinstance(self._instruction, I.ST):
            self._run = partial(execute_ST,
                                location=self._instruction.location,
                                source=self._instruction.source)
        elif isinstance(self._instruction, I.OP):
            self._run = partial(execute_OP,
                                destination=self._instruction.destination,
                                left_source=self._instruction.left_source,
                                operator=self._instruction.operator,
                                right_source=self._instruction.right_source)
        elif isinstance(self._instruction, I.PUSH):
            self._run = partial(execute_PUSH,
                                location=self._instruction.location)
        elif isinstance(self._instruction, I.POP):
            self._run = partial(execute_POP,
                                location=self._instruction.location)
        elif isinstance(self._instruction, I.BR):
            self._run = partial(execute_BR,
                                left_source=self._instruction.left_source,
                                operator=self._instruction.operator,
                                right_source=self._instruction.right_source,
                                label=self._instruction.label)
        elif isinstance(self._instruction, I.JMP):
            self._run = partial(execute_JMP,
                                label=self._instruction.label)
        elif isinstance(self._instruction, I.LBL):
            self._run = execute_LBL
        elif isinstance(self._instruction, I.LDt):
            self.table_interface = TableInterface()
            self._run = partial(execute_LDt,
                                table_interface=self.table_interface,
                                instruction=self._instruction,
                                destinations=self._instruction.destinations,
                                index=self._instruction.index)
        elif isinstance(self._instruction, I.STt):
            self.table_interface = TableInterface()
            self._run = partial(execute_STt,
                                table_interface=self.table_interface,
                                instruction=self._instruction,
                                index=self._instruction.index,
                                sources=self._instruction.sources)
        elif isinstance(self._instruction, I.INCt):
            self.table_interface = TableInterface()
            self._run = partial(execute_INCt,
                                table_interface=self.table_interface,
                                instruction=self._instruction,
                                index=self._instruction.index)
        elif isinstance(self._instruction, I.LKt):
            self.table_interface = TableInterface()
            self._run = partial(execute_LKt,
                                table_interface=self.table_interface,
                                instruction=self._instruction,
                                index=self._instruction.index,
                                sources=self._instruction.sources)
        elif isinstance(self._instruction, I.CRC):
            self._run = partial(execute_CRC,
                                destination=self._instruction.destination,
                                sources=self._instruction.sources)
        elif isinstance(self._instruction, I.HSH):
            self._run = partial(execute_HSH,
                                destination=self._instruction.destination,
                                sources=self._instruction.sources)
        elif isinstance(self._instruction, I.HLT):
            self._run = execute_HLT
        else:
            raise RuntimeError()

    def stop(self):
        self.input_interface.put(None)
        self.join()

    def run(self):
        while True:
            try:
                state = self.input_interface.get()

                # print 'primitive_process'

                if state is None:
                    return

                state = self._run(state)

                self.output_interfaces[state.label].put(state)
            except KeyboardInterrupt:
                break


class Pipeline:
    def __init__(self, instructions, tables):
        self.instructions = instructions
        self.tables = tables

        self._input_interface = None
        self._output_interface = Queue()
        self._instructions = {}
        self._is_setup = False
        self._is_start = False

        self._setup()

    def _setup(self):
        flow_graph = cfg.generate(self.instructions)

        ''' Setting connections with in basic blocks '''
        for label, node in flow_graph.iteritems():
            if label == syntax.Label('$entry') or label == syntax.Label('$exit'):
                continue
            next_instruction = None
            for instruction in node.basic_block[::-1]:
                if (isinstance(instruction, I.ATM) or isinstance(instruction, I.SEQ) or
                        isinstance(instruction, I.CNC)):
                    self._instructions[instruction] = GroupProcess(instruction, self.tables)
                else:
                    self._instructions[instruction] = PrimitiveProcess(instruction)

                if next_instruction:
                    self._instructions[instruction].output_interfaces[syntax.Label('')] = \
                        self._instructions[next_instruction].input_interface

                next_instruction = instruction

        ''' Setting up connections across basic blocks '''
        for label, node in flow_graph.iteritems():
            last_instruction = node.basic_block[-1]
            for successor_label in node.successors:
                first_instruction = flow_graph[successor_label].basic_block[0]

                if label == syntax.Label('$entry'):
                    # if successor_label == Label('$exit'):
                    # self.input_interface = self.output_interface
                    # else:
                    self._input_interface = self._instructions[first_instruction].input_interface
                    # Note: this should always be no more than one
                else:
                    if successor_label == syntax.Label('$exit'):
                        self._instructions[last_instruction].output_interfaces[
                            syntax.Label('')] = self._output_interface
                    else:
                        if isinstance(last_instruction, I.BR) or isinstance(last_instruction, I.JMP):
                            if last_instruction.label == successor_label:
                                self._instructions[last_instruction].output_interfaces[last_instruction.label] = \
                                    self._instructions[first_instruction].input_interface
                            else:
                                self._instructions[last_instruction].output_interfaces[syntax.Label('')] = \
                                    self._instructions[first_instruction].input_interface
                        else:
                            self._instructions[last_instruction].output_interfaces[syntax.Label('')] = \
                                self._instructions[first_instruction].input_interface

        ''' Connect tables with instructions '''
        for instruction in self._instructions:
            if isinstance(instruction, I.LDt):
                table = self.tables[instruction.table_id]
                self._instructions[instruction].table_interface.output_interface = table.input_interface
                table.output_interfaces[id(instruction)] = \
                    self._instructions[instruction].table_interface.input_interface
            elif isinstance(instruction, I.STt):
                table = self.tables[instruction.table_id]
                self._instructions[instruction].table_interface.output_interface = table.input_interface
                table.output_interfaces[id(instruction)] = \
                    self._instructions[instruction].table_interface.input_interface
            elif isinstance(instruction, I.INCt):
                table = self.tables[instruction.table_id]
                self._instructions[instruction].table_interface.output_interface = table.input_interface
                table.output_interfaces[id(instruction)] = \
                    self._instructions[instruction].table_interface.input_interface
            elif isinstance(instruction, I.LKt):
                table = self.tables[instruction.table_id]
                self._instructions[instruction].table_interface.output_interface = table.input_interface
                table.output_interfaces[id(instruction)] = \
                    self._instructions[instruction].table_interface.input_interface

        self._is_setup = True

    def start(self):
        if not self._is_setup:
            raise RuntimeError()

        ''' Start the instructions '''
        for instruction in self._instructions:
            self._instructions[instruction].start()

        self._is_start = True

    def stop(self):
        if not self._is_start:
            raise RuntimeError()

        ''' Stop the instructions '''
        for instruction in self._instructions:
            self._instructions[instruction].stop()

        self._is_start = False

    def put(self, state):
        if not self._is_start:
            raise RuntimeError()

        if not state.header:
            pass

        self._input_interface.put(state)

    def get(self):
        if not self._is_start:
            raise RuntimeError()

        return self._output_interface.get()


class ExecuteInstructions:
    def __init__(self, instructions, tables):
        self.instructions = instructions
        self.tables = tables
        self._pipeline = Pipeline(self.instructions, self.tables)

    def start(self):
        self._pipeline.start()

    def stop(self):
        self._pipeline.stop()

    def put(self, state):
        self._pipeline.put(state)

    def get(self):
        return self._pipeline.get()


class Execute:
    def __init__(self, policy):
        self._execute_decls = ExecuteDecls(policy.decls)
        self._tables = self._execute_decls.tables

        self._execute_instructions = ExecuteInstructions(policy.code.instructions, self._tables)
        self.put = self._execute_instructions.put
        self.get = self._execute_instructions.get

    def start(self):
        self._execute_instructions.start()

        ''' Start tables '''
        for table in self._tables:
            self._tables[table].start()

    def stop(self):
        self._execute_instructions.stop()

        ''' Stop tables '''
        for table in self._tables:
            self._tables[table].stop()

    def add_table_entry(self, id, index, entry):
        self._tables[id].input_interface.put(('add_entry', (index, entry)))

    def del_table_entry(self, id, index):
        self._tables[id].input_interface.put(('del_entry', index))

    def query_table_entry(self, id, index):
        self._tables[id].input_interface.put(('query_entry', index))
        return self._tables[id].output_interfaces[''].get()

    def query_table_list(self):
        list = []
        for t in self._tables.keys():
            list.append(str(t))
        return list