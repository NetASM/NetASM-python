# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        basic_blocks.py
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

from netasm.netasm.core.syntax import InstructionCollection as I
from netasm.netasm.core.common import get_instruction_at_label


def _find_leaders(instructions):
    leaders_set = set()

    for i in range(0, len(instructions)):
        instruction = instructions[i]

        ''' The first instruction is always a leader '''
        if not leaders_set:
            leaders_set |= {instruction}

        if (isinstance(instruction, I.BR) or
                isinstance(instruction, I.JMP)):
            ''' The instruction following BR/JMP is a leader '''
            if (i + 1) < len(instructions):
                leaders_set |= {instructions[i + 1]}
            else:
                raise RuntimeError

            ''' The target instruction of BR/JMP is a leader '''
            j, _ = get_instruction_at_label(instructions, instruction.label)
            if (j + 1) < len(instructions):
                leaders_set |= {instructions[j + 1]}
            else:
                raise RuntimeError

    return leaders_set


def generate(instructions):
    leaders = _find_leaders(instructions)

    basic_block_list = None
    basic_blocks_list = []

    for instruction in instructions:
        if instruction in leaders:
            basic_block_list = [instruction]
            basic_blocks_list.append(basic_block_list)
        else:
            basic_block_list.append(instruction)

    return basic_blocks_list