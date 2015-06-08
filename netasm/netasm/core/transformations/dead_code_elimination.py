# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        dead_code_elimination.py
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

from copy import copy

from netasm.netasm.core.syntax import InstructionCollection as I, OperandCollection as O
from netasm.netasm.core.common import is_reserved_field
from netasm.netasm.core.graphs import control_flow_graph as cfg
from netasm.netasm.core.analyses import liveness as li
from netasm.netasm.core.analyses import field_usability as fu
from netasm.netasm.core.analyses import field_reachability as fr


def is_reserved_or_argument_field(field, argument_fields):
    return is_reserved_field(field) or (field in argument_fields)


# Transform using liveness analysis
def _phase_0(code):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get liveness information '''
    live_ins, live_outs = li.analyse(flow_graph, code.argument_fields, [I.ADD, I.RMV])

    ''' Cherry-pick dead instructions '''
    instruction_list = []
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            # I.ID
            # I.DRP
            # I.CTR
            # I.ADD
            # I.RMV
            if isinstance(instruction, I.LD):
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in live_outs[instruction]):
                        instruction_list.append(instruction)
            # I.ST
            elif isinstance(instruction, I.OP):
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in live_outs[instruction]):
                        instruction_list.append(instruction)
            # I.PUSH
            # I.POP
            # I.BR
            # I.JMP
            # I.LBL
            elif isinstance(instruction, I.LDt):
                check_list = []
                for destination in instruction.destinations:
                    if isinstance(destination, O.Field):
                        if is_reserved_or_argument_field(destination.field, code.argument_fields):
                            check_list.append(False)
                        else:
                            check_list.append(True if not (destination.field in live_outs[instruction]) else False)
                if check_list and all(check_list):
                    instruction_list.append(instruction)
            # I.STt
            # I.INCt
            elif isinstance(instruction, I.LKt):
                if isinstance(instruction.index, O.Field):
                    if is_reserved_or_argument_field(instruction.index.field, code.argument_fields):
                        pass
                    elif not (instruction.index.field in live_outs[instruction]):
                        instruction_list.append(instruction)
            elif isinstance(instruction, I.CRC):
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in live_outs[instruction]):
                        instruction_list.append(instruction)
            elif isinstance(instruction, I.HSH):
                if isinstance(instruction.destination, O.Field):
                    if is_reserved_or_argument_field(instruction.destination.field, code.argument_fields):
                        pass
                    elif not (instruction.destination.field in live_outs[instruction]):
                        instruction_list.append(instruction)
            # I.HLT
            # I.CNC
            # I.ATM
            # I.SEQ

            # TODO: add support for group instructions, above.

    ''' Remove dead instructions from the code '''
    for instruction in instruction_list:
        instructions.remove(instruction)


# Transform using field usability analysis for removing dead ADD instructions
def _phase_1(code):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get usability information '''
    use_ins, use_outs = fu.analyse(flow_graph, code.argument_fields, [I.RMV])

    ''' Cherry-pick dead instructions '''
    instruction_list = []
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.ADD):
                if is_reserved_or_argument_field(instruction.field.field, code.argument_fields):
                    pass
                elif not (instruction.field.field in use_outs[instruction]):
                    instruction_list.append(instruction)

    ''' Remove dead instructions from the code '''
    for instruction in instruction_list:
        instructions.remove(instruction)


# Transform using field reachability analysis for removing dead RMV instructions
def _phase_2(code):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get reachability information '''
    reach_ins, reach_outs = fr.analyse(flow_graph, code.argument_fields, [I.ADD])

    ''' Cherry-pick dead instructions '''
    instruction_list = []
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.RMV):
                if is_reserved_or_argument_field(instruction.field.field, code.argument_fields):
                    pass
                elif not (instruction.field.field in reach_ins[instruction]):
                    instruction_list.append(instruction)

    ''' Remove dead instructions from the code '''
    for instruction in instruction_list:
        instructions.remove(instruction)


def transform(code):
    while True:
        ''' Iterate till fixed-point is reached '''
        instructions = copy(code.instructions)

        _phase_0(code)
        _phase_1(code)
        _phase_2(code)

        if set(instructions) == set(code.instructions):
            return code