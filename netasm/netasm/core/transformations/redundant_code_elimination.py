# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        redundant_code_elimination.py
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

from netasm.netasm.core.syntax import InstructionCollection as I
from netasm.netasm.core.common import is_reserved_field, get_add_instruction_count, get_rmv_instruction_count
from netasm.netasm.core.graphs import control_flow_graph as cfg
from netasm.netasm.core.analyses import field_usability as fu
from netasm.netasm.core.analyses import field_reachability as fr


def is_reserved_or_argument_field(field, argument_fields):
    return is_reserved_field(field) or (field in argument_fields)


# Transform using field reachability analysis for removing redundant ADD instructions
def _phase_0(code):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get reachability information '''
    reach_ins, reach_outs = fr.analyse(flow_graph, code.argument_fields, [])

    ''' Cherry-pick dead instructions '''
    instruction_list = []
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.ADD):
                if is_reserved_or_argument_field(instruction.field.field, code.argument_fields):
                    pass
                else:
                    if get_add_instruction_count(code.instructions, instruction.field.field) < 2:
                        pass
                    elif not (instruction.field.field in reach_ins[instruction]):
                        instruction_list.append(instruction)

    ''' Remove dead instructions from the code '''
    for instruction in instruction_list:
        instructions.remove(instruction)


# Transform using field usability analysis for removing redundant RMV instructions
def _phase_1(code):
    instructions = code.instructions

    ''' Generate flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get usability information '''
    use_ins, use_outs = fu.analyse(flow_graph, code.argument_fields, [])

    ''' Cherry-pick dead instructions '''
    instruction_list = []
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.RMV):
                if is_reserved_or_argument_field(instruction.field.field, code.argument_fields):
                    pass
                else:
                    if get_rmv_instruction_count(code.instructions, instruction.field.field) < 2:
                        pass
                    elif not (instruction.field.field in use_outs[instruction]):
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

        if set(instructions) == set(code.instructions):
            return code