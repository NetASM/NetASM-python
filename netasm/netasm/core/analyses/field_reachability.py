# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        field_reachability.py
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

# Note: reachability analysis just operates on fields

from netasm.netasm.core.syntax import InstructionCollection as I, OperandCollection as O
from netasm.netasm.core.graphs.control_flow_graph import Entry


class Use:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def field(instruction, argument_fields, exclude_list):
        operands = set()

        if any(map(lambda instruction_type: isinstance(instruction, instruction_type), exclude_list)):
            pass
        elif isinstance(instruction, Entry):
            # for field in argument_fields:
            # operands |= {field}
            # for field in get_reserved_fields():
            # operands |= {field}
            pass
        elif isinstance(instruction, I.ADD):
            operands |= {instruction.field.field}
        elif isinstance(instruction, I.LD):
            if isinstance(instruction.source, O.Field):
                operands |= {instruction.source.field}
            if isinstance(instruction.destination, O.Field):
                operands |= {instruction.destination.field}
        elif isinstance(instruction, I.ST):
            if isinstance(instruction.source, O.Field):
                operands |= {instruction.source.field}
            if isinstance(instruction.location, O.Location):
                if isinstance(instruction.location.location.offset, O.Field):
                    operands |= {instruction.location.location.offset.field}
                if isinstance(instruction.location.location.length, O.Field):
                    operands |= {instruction.location.location.length.field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.OP):
            if isinstance(instruction.left_source, O.Field):
                operands |= {instruction.left_source.field}
            if isinstance(instruction.right_source, O.Field):
                operands |= {instruction.right_source.field}
            if isinstance(instruction.destination, O.Field):
                operands |= {instruction.destination.field}
        elif isinstance(instruction, I.PUSH):
            if isinstance(instruction.location, O.Location):
                if isinstance(instruction.location.location.offset, O.Field):
                    operands |= {instruction.location.location.offset.field}
                if isinstance(instruction.location.location.length, O.Field):
                    operands |= {instruction.location.location.length.field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.POP):
            if isinstance(instruction.location, O.Location):
                if isinstance(instruction.location.location.offset, O.Field):
                    operands |= {instruction.location.location.offset.field}
                if isinstance(instruction.location.location.length, O.Field):
                    operands |= {instruction.location.location.length.field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.BR):
            if isinstance(instruction.left_source, O.Field):
                operands |= {instruction.left_source.field}
            if isinstance(instruction.right_source, O.Field):
                operands |= {instruction.right_source.field}
        elif isinstance(instruction, I.LDt):
            if isinstance(instruction.index, O.Field):
                operands |= {instruction.index.field}
            if isinstance(instruction.destinations, O.Operands__):
                for operand in instruction.destinations:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.STt):
            if isinstance(instruction.index, O.Field):
                operands |= {instruction.index.field}
            if isinstance(instruction.sources, O.Operands_):
                for operand in instruction.sources:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            elif isinstance(instruction.sources, O.OperandsMasks_):
                for operand, _ in instruction.sources:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.INCt):
            if isinstance(instruction.index, O.Field):
                operands |= {instruction.index.field}
        elif isinstance(instruction, I.LKt):
            if isinstance(instruction.sources, O.Operands_):
                for operand in instruction.sources:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            else:
                raise RuntimeError()
            if isinstance(instruction.index, O.Field):
                operands |= {instruction.index.field}
        elif isinstance(instruction, I.CRC):
            if isinstance(instruction.sources, O.Operands_):
                for operand in instruction.sources:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            else:
                raise RuntimeError()
            if isinstance(instruction.destination, O.Field):
                operands |= {instruction.destination.field}
        elif isinstance(instruction, I.HSH):
            if isinstance(instruction.sources, O.Operands_):
                for operand in instruction.sources:
                    if isinstance(operand, O.Field):
                        operands |= {operand.field}
            else:
                raise RuntimeError()
            if isinstance(instruction.destination, O.Field):
                operands |= {instruction.destination.field}
        elif isinstance(instruction, I.CNC):
            if isinstance(instruction.codes, I.Codes):
                for code in instruction.codes:
                    for field in code.argument_fields:
                        operands |= {field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.ATM):
            if isinstance(instruction.code, I.Code):
                for field in instruction.code.argument_fields:
                    operands |= {field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.SEQ):
            if isinstance(instruction.code, I.Code):
                for field in instruction.code.argument_fields:
                    operands |= {field}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.Instruction):
            pass
        else:
            raise RuntimeError()

        return operands


class Kill:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def field(instruction, argument_fields, exclude_list):
        operands = set()

        if any(map(lambda instruction_type: isinstance(instruction, instruction_type), exclude_list)):
            pass
        elif isinstance(instruction, I.RMV):
            operands |= {instruction.field.field}
        elif isinstance(instruction, I.Instruction):
            pass
        else:
            raise RuntimeError()

        return operands


# Propagate reachability information once at every node in the flow graph
def _step(flow_graph, ins, outs, argument_fields, exclude_list):
    use_ = Use.field
    kill_ = Kill.field

    for _, node in flow_graph.iteritems():
        previous_instruction = None

        for instruction in node.basic_block:
            _out = []
            if not previous_instruction:
                for n in node.predecessors:
                    last_instruction = flow_graph[n].basic_block[-1]
                    _out.append(outs[last_instruction])
            else:
                _out.append(outs[previous_instruction])
            previous_instruction = instruction

            _in = set.union(set(), *_out)
            _out = (use_(instruction, argument_fields, exclude_list) |
                    (_in - kill_(instruction, argument_fields, exclude_list)))
            ins[instruction] = _in
            outs[instruction] = _out


# Iterates until a fixed-point is reached
def _solve(flow_graph, ins, outs, argument_fields, exclude_list):
    _outs = outs.copy()
    _step(flow_graph, ins, _outs, argument_fields, exclude_list)

    if all(map(lambda i: outs[i] == _outs[i], outs.keys())):
        return ins, outs
    else:
        return _solve(flow_graph, ins, _outs, argument_fields, exclude_list)


# Compute field reachability in/out fields at every node in the control flow graph
def analyse(flow_graph, argument_fields, exclude_list):
    ins = {}
    outs = {}
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            ins[instruction] = set()
            outs[instruction] = set()
    return _solve(flow_graph, ins, outs, argument_fields, exclude_list)