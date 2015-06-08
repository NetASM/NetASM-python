# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        reaching_definitions.py
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

from netasm.netasm.core.syntax import InstructionCollection as I, OperandCollection as O
from netasm.netasm.core.common import is_reserved_field


class Gen:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def field(instruction, argument_fields, exclude_list):
        instructions = set()

        if any(map(lambda instruction_type: isinstance(instruction, instruction_type), exclude_list)):
            pass
        elif isinstance(instruction, I.ADD):
            instructions |= {instruction}
        elif isinstance(instruction, I.LD):
            if isinstance(instruction.destination, O.Field):
                instructions |= {instruction}
        elif isinstance(instruction, I.OP):
            if isinstance(instruction.destination, O.Field):
                instructions |= {instruction}
        elif isinstance(instruction, I.LDt):
            if isinstance(instruction.destinations, O.Operands_):
                for operand in instruction.destinations:
                    if isinstance(operand, O.Field):
                        instructions |= {instruction}
                        break
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.LKt):
            if isinstance(instruction.index, O.Field):
                instructions |= {instruction}
        elif isinstance(instruction, I.CRC):
            if isinstance(instruction.destination, O.Field):
                instructions |= {instruction}
        elif isinstance(instruction, I.HSH):
            if isinstance(instruction.destination, O.Field):
                instructions |= {instruction}
        elif isinstance(instruction, I.CNC):
            if isinstance(instruction.codes, I.Codes):
                for code in instruction.codes:
                    for _ in code.argument_fields:
                        instructions |= {instruction}
                        break
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.ATM):
            if isinstance(instruction.code, I.Code):
                for _ in instruction.code.argument_fields:
                    instructions |= {instruction}
                    break
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.SEQ):
            if isinstance(instruction.code, I.Code):
                for _ in instruction.code.argument_fields:
                    instructions |= {instruction}
                    break
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.Instruction):
            pass
        else:
            raise RuntimeError()

        return instructions


class Kill:
    def __init__(self):
        raise NotImplementedError

    @staticmethod
    def field(flow_graph, instruction, argument_fields, exclude_list):

        def defines(flow_graph, field, argument_fields):
            instructions = set()

            for _, node in flow_graph.iteritems():
                for instruction in node.basic_block:
                    if isinstance(instruction, I.ADD):
                        if instruction.field.field == field:
                            instructions |= {instruction}
                    elif isinstance(instruction, I.LD):
                        if isinstance(instruction.destination, O.Field):
                            if instruction.destination.field == field:
                                if not (is_reserved_field(field) or field in argument_fields):
                                    instructions |= {instruction}
                    elif isinstance(instruction, I.OP):
                        if isinstance(instruction.destination, O.Field):
                            if instruction.destination.field == field:
                                if not (is_reserved_field(field) or field in argument_fields):
                                    instructions |= {instruction}
                    elif isinstance(instruction, I.LDt):
                        if isinstance(instruction.destinations, O.Operands__):
                            for operand in instruction.destinations:
                                if isinstance(operand, O.Field):
                                    if operand.field == field:
                                        if not (is_reserved_field(field) or field in argument_fields):
                                            instructions |= {instruction}
                                            break
                        else:
                            raise RuntimeError()
                    elif isinstance(instruction, I.LKt):
                        if isinstance(instruction.index, O.Field):
                            if instruction.index.field == field:
                                if not (is_reserved_field(field) or field in argument_fields):
                                    instructions |= {instruction}
                    elif isinstance(instruction, I.CRC):
                        if isinstance(instruction.destination, O.Field):
                            if instruction.destination.field == field:
                                if not (is_reserved_field(field) or field in argument_fields):
                                    instructions |= {instruction}
                    elif isinstance(instruction, I.HSH):
                        if isinstance(instruction.destination, O.Field):
                            if instruction.destination.field == field:
                                if not (is_reserved_field(field) or field in argument_fields):
                                    instructions |= {instruction}
                    elif isinstance(instruction, I.CNC):
                        if isinstance(instruction.codes, I.Codes):
                            for code in instruction.codes:
                                for _field in code.argument_fields:
                                    if _field == field:
                                        if not (is_reserved_field(field) or field in argument_fields):
                                            instructions |= {instruction}
                                            break
                        else:
                            raise RuntimeError()
                    elif isinstance(instruction, I.ATM):
                        if isinstance(instruction.code, I.Code):
                            for _field in instruction.code.argument_fields:
                                if _field == field:
                                    if not (is_reserved_field(field) or field in argument_fields):
                                        instructions |= {instruction}
                                        break
                        else:
                            raise RuntimeError()
                    elif isinstance(instruction, I.SEQ):
                        if isinstance(instruction.code, I.Code):
                            for _field in instruction.code.argument_fields:
                                if _field == field:
                                    if not (is_reserved_field(field) or field in argument_fields):
                                        instructions |= {instruction}
                                        break
                        else:
                            raise RuntimeError()
                    elif isinstance(instruction, I.Instruction):
                        pass
                    else:
                        raise RuntimeError()

            return instructions

        instructions = set()

        if any(map(lambda instruction_type: isinstance(instruction, instruction_type), exclude_list)):
            pass
        elif isinstance(instruction, I.ADD):
            instructions |= defines(flow_graph, instruction.field.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.RMV):
            instructions |= defines(flow_graph, instruction.field.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.LD):
            if isinstance(instruction.destination, O.Field):
                instructions |= defines(flow_graph, instruction.destination.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.OP):
            if isinstance(instruction.destination, O.Field):
                instructions |= defines(flow_graph, instruction.destination.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.LDt):
            if isinstance(instruction.destinations, O.Operands_):
                for operand in instruction.destinations:
                    if isinstance(operand, O.Field):
                        instructions |= defines(flow_graph, operand.field, argument_fields) - {instruction}
                        # Note: a field can only be specified once in the destinations of LDt
        elif isinstance(instruction, I.LKt):
            if isinstance(instruction.index, O.Field):
                instructions |= defines(flow_graph, instruction.index.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.CRC):
            if isinstance(instruction.destination, O.Field):
                instructions |= defines(flow_graph, instruction.destination.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.HSH):
            if isinstance(instruction.destination, O.Field):
                instructions |= defines(flow_graph, instruction.destination.field, argument_fields) - {instruction}
        elif isinstance(instruction, I.CNC):
            if isinstance(instruction.codes, I.Codes):
                for code in instruction.codes:
                    for field in code.argument_fields:
                        instructions |= defines(flow_graph, field, argument_fields) - {instruction}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.ATM):
            if isinstance(instruction.code, I.Code):
                for field in instruction.code.argument_fields:
                    instructions |= defines(flow_graph, field, argument_fields) - {instruction}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.SEQ):
            if isinstance(instruction.code, I.Code):
                for field in instruction.code.argument_fields:
                    instructions |= defines(flow_graph, field, argument_fields) - {instruction}
            else:
                raise RuntimeError()
        elif isinstance(instruction, I.Instruction):
            pass
        else:
            raise RuntimeError()

        return instructions


# Propagate reaching-definitions information once at every node in the flow graph
def _step(flow_graph, ins, outs, argument_fields, exclude_list):
    gen_ = Gen.field
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
            _out = (gen_(instruction, argument_fields, exclude_list) |
                    (_in - kill_(flow_graph, instruction, argument_fields, exclude_list)))
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


# Compute reach-in/out fields/registers at every node in the flow graph
def analyse(flow_graph, argument_fields, exclude_list):
    ins = {}
    outs = {}
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            ins[instruction] = set()
            outs[instruction] = set()
    return _solve(flow_graph, ins, outs, argument_fields, exclude_list)