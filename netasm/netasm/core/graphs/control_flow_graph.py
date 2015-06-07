# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        control_flow_graph.py
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

import uuid

from netasm.netasm.core import syntax as syntax
from netasm.netasm.core.syntax import InstructionCollection as I
from netasm.netasm.core.graphs import basic_blocks as bb


class Node:
    def __init__(self, basic_block, predecessors, successors):
        self.basic_block = basic_block
        self.predecessors = predecessors
        self.successors = successors


def _next_label(instruction):
    if isinstance(instruction, I.LBL):
        return instruction.label
    elif isinstance(instruction, I.Instruction):
        return syntax.Label('$' + str(uuid.uuid1().hex))
    else:
        raise RuntimeError


def _successors(instruction, next_label):
    if isinstance(instruction, I.BR):
        return [next_label, instruction.label]
    elif isinstance(instruction, I.JMP):
        return [instruction.label]
    elif isinstance(instruction, I.HLT):
        return []
    elif isinstance(instruction, I.Instruction):
        return [next_label]
    else:
        raise RuntimeError


class Entry(I.Instruction):
    pass


class Exit(I.Instruction):
    pass


def generate(instructions):
    flow_graph = {}

    basic_blocks = bb.generate(instructions)

    entry_label = syntax.Label('$entry')
    first_label = current_label = syntax.Label('$' + str(uuid.uuid1().hex))
    exit_label = syntax.Label('$exit')
    last_label = None

    flow_graph[entry_label] = Node([Entry()], [], [first_label])
    flow_graph[exit_label] = Node([Exit()], [], [])

    for basic_block in basic_blocks:
        instruction = basic_block[-1]
        next_label = _next_label(instruction)
        flow_graph[current_label] = Node(basic_block, [], _successors(instruction, next_label))
        if isinstance(instruction, I.HLT):
            last_label = current_label
        current_label = next_label

    flow_graph[last_label].successors.append(exit_label)

    # Remove redundant label instructions
    label_list = []
    for label, node in flow_graph.iteritems():
        instruction_list = []
        for instruction in node.basic_block:
            if isinstance(instruction, I.LBL):
                instruction_list.append(instruction)
        for instruction in instruction_list:
            node.basic_block.remove(instruction)
        if len(node.basic_block) == 0:
            label_list.append(label)
    for label in label_list:
        del flow_graph[label]

    for label, node in flow_graph.iteritems():
        for successor_label in node.successors:
            flow_graph[successor_label].predecessors.append(label)

    return flow_graph

    # TODO: work on the graph traversals (reverse-post-order and vice versa)