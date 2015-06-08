# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        add_code_motion.py
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
from netasm.netasm.core.graphs import control_flow_graph as cfg
from netasm.netasm.core.analyses import field_reachability as fr
from netasm.netasm.core.analyses import reaching_definitions as rd


def is_reserved_or_argument_field(field, argument_fields):
    return is_reserved_field(field) or (field in argument_fields)


def get_field_size(reach_def_in, field):
    for instruction in reach_def_in:
        if isinstance(instruction, I.ADD):
            if instruction.field.field == field:
                return instruction.size
    raise RuntimeError()


def _transform(code, exclude_list):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get reaching definitions information (for I.ADD only) '''
    reach_def_ins, reach_def_outs = rd.analyse(flow_graph, code.argument_fields,
                                               [I.LD, I.OP, I.LDt, I.LKt, I.CRC, I.HSH, I.CNC, I.ATM, I.SEQ])

    ''' Get field reachability information '''
    reach_ins, reach_outs = fr.analyse(flow_graph, code.argument_fields, exclude_list)

    ''' Cherry-pick dead instructions '''
    instruction_dict = {}
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.LD):
                instruction_dict[instruction] = []
                if isinstance(instruction.source, O.Field):
                    if is_reserved_or_argument_field(instruction.source.field, code.argument_fields):
                        pass
                    elif not (instruction.source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(
                            I.ADD(O.Field(instruction.source.field),
                                  get_field_size(reach_def_ins[instruction], instruction.source.field)))
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(
                            I.ADD(O.Field(instruction.destination.field),
                                  get_field_size(reach_def_ins[instruction], instruction.destination.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.ST):
                instruction_dict[instruction] = []
                if isinstance(instruction.source, O.Field):
                    if is_reserved_or_argument_field(instruction.source.field, code.argument_fields):
                        pass
                    elif not (instruction.source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(
                            I.ADD(O.Field(instruction.source.field),
                                  get_field_size(reach_def_ins[instruction], instruction.source.field)))
                if isinstance(instruction.location, O.Location):
                    if isinstance(instruction.location.location.offset, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.offset.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.offset.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.offset.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.offset.field)))
                    if isinstance(instruction.location.location.length, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.length.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.length.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.length.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.length.field)))
                else:
                    raise RuntimeError("invalid %s of location (%s). Should be %s."
                                       % (type(instruction.location), instruction.location, O.Location))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.OP):
                instruction_dict[instruction] = []
                if isinstance(instruction.left_source, O.Field):
                    if is_reserved_or_argument_field(instruction.left_source.field, code.argument_fields):
                        pass
                    elif not (instruction.left_source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.left_source.field),
                            get_field_size(reach_def_ins[instruction], instruction.left_source.field)))
                if isinstance(instruction.right_source, O.Field):
                    if is_reserved_or_argument_field(instruction.right_source.field, code.argument_fields):
                        pass
                    elif not (instruction.right_source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.right_source.field),
                            get_field_size(reach_def_ins[instruction], instruction.right_source.field)))
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.destination.field),
                            get_field_size(reach_def_ins[instruction], instruction.destination.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.PUSH):
                instruction_dict[instruction] = []
                if isinstance(instruction.location, O.Location):
                    if isinstance(instruction.location.location.offset, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.offset.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.offset.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.offset.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.offset.field)))
                    if isinstance(instruction.location.location.length, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.length.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.length.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.length.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.length.field)))
                else:
                    raise RuntimeError("invalid %s of location (%s). Should be %s."
                                       % (type(instruction.location), instruction.location, O.Location))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.POP):
                instruction_dict[instruction] = []
                if isinstance(instruction.location, O.Location):
                    if isinstance(instruction.location.location.offset, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.offset.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.offset.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.offset.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.offset.field)))
                    if isinstance(instruction.location.location.length, O.Field):
                        if is_reserved_or_argument_field(instruction.location.location.length.field,
                                                         code.argument_fields):
                            pass
                        elif not (instruction.location.location.length.field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(instruction.location.location.length.field),
                                get_field_size(reach_def_ins[instruction], instruction.location.location.length.field)))
                else:
                    raise RuntimeError("invalid %s of location (%s). Should be %s."
                                       % (type(instruction.location), instruction.location, O.Location))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.BR):
                instruction_dict[instruction] = []
                if isinstance(instruction.left_source, O.Field):
                    if is_reserved_or_argument_field(instruction.left_source.field, code.argument_fields):
                        pass
                    elif not (instruction.left_source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.left_source.field),
                            get_field_size(reach_def_ins[instruction], instruction.left_source.field)))
                if isinstance(instruction.right_source, O.Field):
                    if is_reserved_or_argument_field(instruction.right_source.field, code.argument_fields):
                        pass
                    elif not (instruction.right_source.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.right_source.field),
                            get_field_size(reach_def_ins[instruction], instruction.right_source.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.LDt):
                instruction_dict[instruction] = []
                if isinstance(instruction.index, O.Field):
                    if is_reserved_or_argument_field(instruction.index.field, code.argument_fields):
                        pass
                    elif not (instruction.index.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.index.field),
                            get_field_size(reach_def_ins[instruction], instruction.index.field)))
                if isinstance(instruction.destinations, O.Operands__):
                    for operand in instruction.destinations:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                else:
                    raise RuntimeError("invalid %s of destinations (%s). Should be %s."
                                       % (type(instruction.destinations), instruction.destinations, O.Operands__))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.STt):
                instruction_dict[instruction] = []
                if isinstance(instruction.index, O.Field):
                    if is_reserved_or_argument_field(instruction.index.field, code.argument_fields):
                        pass
                    elif not (instruction.index.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.index.field),
                            get_field_size(reach_def_ins[instruction], instruction.index.field)))
                if isinstance(instruction.sources, O.Operands_):
                    for operand in instruction.sources:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                elif isinstance(instruction.sources, O.OperandsMasks_):
                    for operand, _ in instruction.sources:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                else:
                    raise RuntimeError("invalid %s of sources (%s). Should be %s or %s."
                                       % (type(instruction.sources), instruction.sources,
                                          O.Operands_, O.OperandsMasks_))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.INCt):
                instruction_dict[instruction] = []
                if isinstance(instruction.index, O.Field):
                    if is_reserved_or_argument_field(instruction.index.field, code.argument_fields):
                        pass
                    elif not (instruction.index.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.index.field),
                            get_field_size(reach_def_ins[instruction], instruction.index.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.LKt):
                instruction_dict[instruction] = []
                if isinstance(instruction.sources, O.Operands_):
                    for operand in instruction.sources:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                else:
                    raise RuntimeError("invalid %s of sources (%s). Should be %s."
                                       % (type(instruction.sources), instruction.sources, O.Operands_))
                if isinstance(instruction.index, O.Field):
                    if is_reserved_or_argument_field(instruction.index.field, code.argument_fields):
                        pass
                    elif not (instruction.index.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.index.field),
                            get_field_size(reach_def_ins[instruction], instruction.index.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.CRC):
                instruction_dict[instruction] = []
                if isinstance(instruction.sources, O.Operands_):
                    for operand in instruction.sources:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                else:
                    raise RuntimeError("invalid %s of sources (%s). Should be %s."
                                       % (type(instruction.sources), instruction.sources, O.Operands_))
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.destination.field),
                            get_field_size(reach_def_ins[instruction], instruction.destination.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.HSH):
                instruction_dict[instruction] = []
                if isinstance(instruction.sources, O.Operands_):
                    for operand in instruction.sources:
                        if isinstance(operand, O.Field):
                            if is_reserved_or_argument_field(operand.field, code.argument_fields):
                                pass
                            elif not (operand.field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(operand.field),
                                    get_field_size(reach_def_ins[instruction], operand.field)))
                else:
                    raise RuntimeError("invalid %s of sources (%s). Should be %s."
                                       % (type(instruction.sources), instruction.sources, O.Operands_))
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in reach_ins[instruction]):
                        instruction_dict[instruction].append(I.ADD(
                            O.Field(instruction.destination.field),
                            get_field_size(reach_def_ins[instruction], instruction.destination.field)))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.CNC):
                instruction_dict[instruction] = []
                if isinstance(instruction.codes, I.Codes):
                    for _code in instruction.codes:
                        for field in _code.argument_fields:
                            if is_reserved_or_argument_field(field, code.argument_fields):
                                pass
                            elif not (field in reach_ins[instruction]):
                                instruction_dict[instruction].append(I.ADD(
                                    O.Field(field),
                                    get_field_size(reach_def_ins[instruction], field)))
                else:
                    raise RuntimeError("invalid %s of codes (%s). Should be %s."
                                       % (type(instruction.codes), instruction.codes, I.Codes))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.ATM):
                instruction_dict[instruction] = []
                if isinstance(instruction.code, I.Code):
                    for field in instruction.code.argument_fields:
                        if is_reserved_or_argument_field(field, code.argument_fields):
                            pass
                        elif not (field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(field),
                                get_field_size(reach_def_ins[instruction], field)))
                else:
                    raise RuntimeError("invalid %s of code (%s). Should be %s."
                                       % (type(instruction.code), instruction.code, I.Code))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]
            elif isinstance(instruction, I.SEQ):
                instruction_dict[instruction] = []
                if isinstance(instruction.code, I.Code):
                    for field in instruction.code.argument_fields:
                        if is_reserved_or_argument_field(field, code.argument_fields):
                            pass
                        elif not (field in reach_ins[instruction]):
                            instruction_dict[instruction].append(I.ADD(
                                O.Field(field),
                                get_field_size(reach_def_ins[instruction], field)))
                else:
                    raise RuntimeError("invalid %s of sources (%s). Should be %s."
                                       % (type(instruction.code), instruction.code, I.Code))
                if not instruction_dict[instruction]:
                    del instruction_dict[instruction]

    ''' Add new add instructions in the code '''
    for instruction, _instructions in instruction_dict.iteritems():
        index = instructions.index(instruction)
        for i in range(0, len(_instructions)):
            instructions.insert(index + i, _instructions[i])


def transform(code):
    _transform(code, [I.ADD])

    return code