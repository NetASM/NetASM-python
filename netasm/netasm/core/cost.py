# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        cost.py
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

from copy import deepcopy as copy

from netasm.netasm.core.common import is_reserved_field
from netasm.netasm.core import syntax as syntax
from netasm.netasm.core.syntax import InstructionCollection as I, OperandCollection as O, OperatorCollection as Op
from netasm.netasm.core.graphs import control_flow_graph as cfg
from netasm.netasm.core.analyses import field_reachability as fr
from netasm.netasm.core.analyses import reaching_definitions as rd
from netasm.netasm.core.utilities.profile import time_usage


def is_reserved_or_argument_field(field, argument_fields):
    return is_reserved_field(field) or (field in argument_fields)


def get_field_size(reach_def_in, field):
    for instruction in reach_def_in:
        if isinstance(instruction, I.ADD):
            if instruction.field.field == field:
                return instruction.size


def get_header_size(reach_in, reach_def_in, argument_fields):
    area = 0
    for field in reach_in:
        if not is_reserved_or_argument_field(field, argument_fields):
            area += get_field_size(reach_def_in, field)
    return area


class PatternsCollection:
    def __init__(self):
        raise NotImplementedError()

    class Pattern(dict):
        pass

    class MatchPattern(Pattern):
        def __setitem__(self, field, (size, match_type)):
            dict.__setitem__(self, field, (size, match_type))

        def __getitem__(self, field):
            return dict.__getitem__(self, field)

    class SimplePattern(Pattern):
        def __setitem__(self, field, size):
            dict.__setitem__(self, field, size)

        def __getitem__(self, field):
            return dict.__getitem__(self, field)

    class Patterns(list):
        pass

    class MatchPatterns(Patterns):
        def __init__(self, *args):
            for arg in args:
                list.append(self, arg)

        def __setitem__(self, index, pattern):
            list.__setitem__(self, index, pattern)

        def __getitem__(self, index):
            return list.__getitem__(self, index)

    class SimplePatterns(Patterns):
        def __init__(self, *args):
            for arg in args:
                list.append(self, arg)

        def __setitem__(self, index, pattern):
            list.__setitem__(self, index, pattern)

        def __getitem__(self, index):
            return list.__getitem__(self, index)


class Tables(dict):
    def __setitem__(self, table_id, (patterns, size, table_type)):
        dict.__setitem__(self, table_id, (patterns, size, table_type))


class State:
    def __init__(self, tables, area, latency):
        self.tables = tables
        self.area = area
        self.latency = latency


def cost_Decls(decls, state):
    patterns = None
    ''' Declare tables '''
    for table_id, table in decls.table_decls.iteritems():
        ''' Generate pattern '''
        if isinstance(table.table_fields, syntax.TableFieldsCollection.SimpleFields):
            pattern = PatternsCollection.SimplePattern()
            area = 0
            for field, size in table.table_fields.iteritems():
                pattern[field] = size
                area += size
            if table.table_type == syntax.TableTypeCollection.RAM:
                state.area += area * table.size
            elif table.table_type == syntax.TableTypeCollection.CAM:
                state.area += area * table.size * 2

            ''' Generate list of patterns '''
            patterns = PatternsCollection.SimplePatterns()
            for i in range(0, table.size):
                patterns.insert(i, copy(pattern))
        elif isinstance(table.table_fields, syntax.TableFieldsCollection.MatchFields):
            pattern = PatternsCollection.MatchPattern()
            area = 0
            for field, (size, match_type) in table.table_fields.iteritems():
                pattern[field] = (size, match_type)
                if match_type == syntax.MatchTypeCollection.Binary:
                    area += size * 2
                # elif match_type == syntax.MatchTypeCollection.Ternary:
                # area += size * 3
                else:
                    raise RuntimeError("invalid match type (%s)." % match_type)
            if table.table_type == syntax.TableTypeCollection.RAM:
                state.area += area * table.size
            elif table.table_type == syntax.TableTypeCollection.CAM:
                state.area += area * table.size * 2

            ''' Generate list of patterns '''
            patterns = PatternsCollection.MatchPatterns()
            for i in range(0, table.size):
                patterns.insert(i, copy(pattern))

        ''' Add table in the state '''
        state.tables[table_id] = (patterns, table.size, table.table_type)


def cost_Code(code, state):
    argument_fields = code.argument_fields
    instructions = code.instructions

    ''' Generate control flow graph '''
    flow_graph = cfg.generate(instructions)

    ''' Get reaching definitions information (for I.ADD only) '''
    reach_def_ins, reach_def_outs = rd.analyse(flow_graph, [],
                                               [I.LD, I.OP, I.LDt, I.LKt, I.CRC, I.HSH, I.CNC, I.ATM, I.SEQ])

    ''' Get field reachability information '''
    reach_ins, reach_outs = fr.analyse(flow_graph, [],
                                       [I.LD, I.OP, I.LDt, I.LKt, I.CRC, I.HSH, I.CNC, I.ATM, I.SEQ])

    instruction_dict = {}
    for _, node in flow_graph.iteritems():
        for instruction in node.basic_block:
            if isinstance(instruction, I.ID):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.DRP):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.CTR):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.ADD):
                pass
            elif isinstance(instruction, I.RMV):
                pass
            elif isinstance(instruction, I.LD):
                if isinstance(instruction.source, O.Value) or isinstance(instruction.source, O.Field):
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields)
                    state.latency += 1
                elif isinstance(instruction.source, O.Location):
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 2
                    state.latency += 2
            elif isinstance(instruction, I.ST):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.OP):
                if not (instruction.operator == Op.Mul or instruction.operator == Op.Div):
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields)
                    state.latency += 1
                else:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 2
                    state.latency += 2
            elif isinstance(instruction, I.PUSH):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.POP):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.BR):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.JMP):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.LBL):
                pass
            elif isinstance(instruction, I.LDt):
                _, _, table_type = state.tables[instruction.table_id]

                if table_type == syntax.TableTypeCollection.RAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 3
                    state.latency += 3
                else:
                    raise RuntimeError("invalid table type (%s)." % table_type)
                    # Note:
                    # 1) tables are not added in the "area" cost as they will incur a one time cost for the
                    # whole program
                    # 2) it only operates on RAM type
            elif isinstance(instruction, I.STt):
                _, _, table_type = state.tables[instruction.table_id]

                if table_type == syntax.TableTypeCollection.RAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 3
                    state.latency += 3
                # elif table_type == syntax.TableTypeCollection.HSH:
                # latency += 2
                elif table_type == syntax.TableTypeCollection.CAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 4
                    state.latency += 4
                else:
                    raise RuntimeError("invalid table type (%s)." % table_type)
            elif isinstance(instruction, I.INCt):
                _, _, table_type = state.tables[instruction.table_id]
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)

                if table_type == syntax.TableTypeCollection.RAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 3
                    state.latency += 3
                else:
                    raise RuntimeError("invalid table type (%s)." % table_type)
            elif isinstance(instruction, I.LKt):
                _, _, table_type = state.tables[instruction.table_id]

                if table_type == syntax.TableTypeCollection.RAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 3
                    state.latency += 3
                # elif table_type == syntax.TableTypeCollection.HSH:
                # latency += 2
                elif table_type == syntax.TableTypeCollection.CAM:
                    state.area += get_header_size(reach_ins[instruction],
                                                  reach_def_ins[instruction],
                                                  argument_fields) * 4
                    state.latency += 4
                else:
                    raise RuntimeError("invalid table type (%s)." % table_type)
            elif isinstance(instruction, I.CRC):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.HSH):
                state.area += get_header_size(reach_ins[instruction],
                                              reach_def_ins[instruction],
                                              argument_fields)
                state.latency += 1
            elif isinstance(instruction, I.CNC):
                for code in instruction.codes:
                    cost_Code(code, state)
            elif isinstance(instruction, I.ATM):
                cost_Code(instruction.code, state)
            elif isinstance(instruction, I.SEQ):
                cost_Code(instruction.code, state)


def cost_Policy(policy):
    state = State(Tables(), 0, 0)

    # Note: reserved fields and root-level argument fields are not included as they remain constant for all policies

    ''' Cost of declarations '''
    cost_Decls(policy.decls, state)

    ''' Cost of code '''
    cost_Code(policy.code, state)

    return state.area, state.latency


@time_usage
def cost_Policy__time_usage(policy):
    return cost_Policy(policy)
