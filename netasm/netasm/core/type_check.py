# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        type_check.py
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

# TODO: still in progress ...

__author__ = 'shahbaz'

from copy import deepcopy

from bitstring import BitArray

from netasm.netasm.core import syntax
from netasm.netasm.core.syntax import OperandCollection as O, OperatorCollection as Op, InstructionCollection as I
from netasm.netasm.core.common import is_reserved_field, is_special_field, get_reserved_fields, \
    get_instruction_at_label as get_label
from netasm.netasm.core.utilities.profile import time_usage

labels = None


class Header(dict):
    def __setitem__(self, field, size):
        if isinstance(field, syntax.Field):
            pass
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, syntax.Field))
        if isinstance(size, syntax.Size):
            pass
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, syntax.Size))
        dict.__setitem__(self, field, size)


class Packet(BitArray):
    pass


class Pattern(dict):
    pass


class MatchPattern(Pattern):
    def __setitem__(self, field, (size, match_type)):
        if isinstance(field, syntax.Field):
            pass
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, syntax.Field))
        if isinstance(size, syntax.Size):
            pass
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, syntax.Size))
        if isinstance(match_type, syntax.MatchTypeCollection.MatchType):
            pass
        else:
            raise TypeError("invalid %s of match type (%s). Should be %s."
                            % (type(match_type), match_type, syntax.MatchTypeCollection.MatchType))
        dict.__setitem__(self, field, (size, match_type))

    def __getitem__(self, field):
        if isinstance(field, syntax.Field):
            return dict.__getitem__(self, field)
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, syntax.Field))


class SimplePattern(Pattern):
    def __setitem__(self, field, size):
        if isinstance(field, syntax.Field):
            pass
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, syntax.Field))
        if isinstance(size, syntax.Size):
            pass
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, syntax.Size))
        dict.__setitem__(self, field, size)

    def __getitem__(self, field):
        if isinstance(field, syntax.Field):
            return dict.__getitem__(self, field)
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, syntax.Field))


# class Patterns(list):
#     pass
#
#
# class MatchPatterns(Patterns):
#     def __init__(self, *args):
#         super(Patterns, self).__init__()
#
#         for arg in args:
#             if isinstance(arg, MatchPattern):
#                 list.append(self, arg)
#             else:
#                 raise TypeError("TypeError(%s): invalid pattern type." % "MatchPatterns")
#
#     def __setitem__(self, index, pattern):
#         if isinstance(pattern, MatchPattern):
#             list.__setitem__(self, index, pattern)
#         else:
#             raise TypeError("TypeError(%s): invalid pattern type." % "MatchPatterns")
#
#     def __getitem__(self, index):
#         return list.__getitem__(self, index)
#
#
# class SimplePatterns(Patterns):
#     def __init__(self, *args):
#         super(Patterns, self).__init__()
#
#         for arg in args:
#             if isinstance(arg, SimplePattern):
#                 list.append(self, arg)
#             else:
#                 raise TypeError("TypeError(%s): invalid pattern type." % "SimplePatterns")
#
#     def __setitem__(self, index, pattern):
#         if isinstance(pattern, SimplePattern):
#             list.__setitem__(self, index, pattern)
#         else:
#             raise TypeError("TypeError(%s): invalid pattern type." % "SimplePatterns")
#
#     def __getitem__(self, index):
#         return list.__getitem__(self, index)


class Table:
    def __init__(self, pattern, size, table_type):
        if isinstance(pattern, Pattern):
            self.patterns = pattern
        else:
            raise TypeError("invalid %s of pattern (%s). Should be %s."
                            % (type(pattern), pattern, Pattern))
        if isinstance(size, syntax.Size):
            self.size = size
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, syntax.Size))
        if isinstance(table_type, syntax.TableTypeCollection.TableType):
            self.table_type = table_type
        else:
            raise TypeError("invalid %s of table type (%s). Should be %s."
                            % (type(table_type), table_type, syntax.TableTypeCollection.TableType))


class Tables(dict):
    def __setitem__(self, table_id, table):
        if isinstance(table_id, syntax.TableId):
            pass
        else:
            raise TypeError("invalid %s of table id (%s). Should be %s."
                            % (type(table_id), table_id, syntax.TableId))
        if isinstance(table, Table):
            pass
        else:
            raise TypeError("invalid %s of table (%s). Should be %s."
                            % (type(table), table, Table))
        dict.__setitem__(self, table_id, table)


class Labels(list):
    def __init__(self, *args):
        for arg in args:
            if isinstance(arg, syntax.Label):
                list.append(self, arg)
            else:
                raise TypeError("invalid %s of argument (%s). Should be %s."
                                % (type(arg), arg, syntax.Label))

    def __setitem__(self, index, label):
        if isinstance(label, syntax.Label):
            list.__setitem__(self, index, label)
        else:
            raise TypeError("invalid %s of label (%s). Should be %s."
                            % (type(label), label, syntax.Label))

    def __getitem__(self, index):
        return list.__getitem__(self, index)


class Context:
    def __init__(self, header, packet, reason=syntax.Reason('', ''), labels=Labels(), extra=None):
        if isinstance(header, Header):
            self.header = header
        else:
            raise TypeError("invalid %s of header (%s). Should be %s."
                            % (type(header), header, Header))
        if isinstance(packet, Packet):
            self.packet = packet
        else:
            raise TypeError("invalid %s of packet (%s). Should be %s."
                            % (type(packet), packet, Packet))
        if isinstance(reason, syntax.Reason):
            self.reason = reason
        else:
            raise TypeError("invalid %s of reason (%s). Should be %s."
                            % (type(reason), reason, syntax.Reason))
        if isinstance(labels, Labels):
            self.labels = labels
        else:
            raise TypeError("invalid %s of labels (%s). Should be %s."
                            % (type(labels), labels, Labels))
        self.extra = extra


def type_check_ID(context):
    context.labels = Labels(syntax.Label(''))


def type_check_DRP(context, reason):
    if isinstance(reason, syntax.Reason):
        pass
    else:
        raise TypeError("invalid %s of reason (%s). Should be %s."
                        % (type(reason), reason, syntax.Reason))

    if syntax.Field('DRP') in context.header:
        # if context.header[syntax.Field('DRP')] == syntax.Size(1):
        #     pass
        # else:
        #     raise TypeError("TypeError(%s): invalid '%s' field size (%i), should be of size (1)." %
        #                     ("DRP", "DRP", context.header[syntax.Field('DRP')]))
        pass
    else:
        raise TypeError("field (%s) is not present in the header." % "DRP")

    context.labels = Labels(syntax.Label(''))


def type_check_CTR(context, reason):
    if isinstance(reason, syntax.Reason):
        pass
    else:
        raise TypeError("invalid %s of reason (%s). Should be %s."
                        % (type(reason), reason, syntax.Reason))

    if syntax.Field('CTR') in context.header:
        # if context.header[syntax.Field('CTR')] == syntax.Size(1):
        #     pass
        # else:
        #     raise TypeError("TypeError(%s): invalid '%s' field size (%i), should be of size (1)." %
        #                     ("CTR", "CTR", context.header[syntax.Field('CTR')]))
        pass
    else:
        raise TypeError("field (%s) is not present in the header." % "CTR")

    context.labels = Labels(syntax.Label(''))


def type_check_ADD(context, field, size):
    if not is_reserved_field(field.field):
        if field.field not in context.header:
            context.header[field.field] = size
        else:
            raise TypeError("field (%s) is already present in the header." % str(field.field))
    else:
        raise TypeError("field (%s) is a reserved field." % str(field.field))

    context.labels = Labels(syntax.Label(''))


def type_check_RMV(context, field):
    if not is_reserved_field(field.field):
        if field.field in context.header:
            del context.header[field.field]
        else:
            raise TypeError("field (%s) is not present in the header." % str(field.field))
    else:
        raise TypeError("field (%s) is a reserved field." % str(field.field))

    context.labels = Labels(syntax.Label(''))


def type_check_LD(context, destination, source):
    destination_size = None
    ''' Lookup destination operand '''
    if isinstance(destination, O.Field):
        if not is_special_field(destination.field):
            if destination.field in context.header:
                destination_size = context.header[destination.field]
            else:
                raise TypeError("destination field (%s) is not present in the header."
                                % str(destination.field))
        else:
            raise TypeError("destination field (%s) is a special field."
                            % str(destination.field))
    else:
        raise TypeError("invalid %s of destination (%s). Should be %s."
                        % (type(destination), destination, O.Field))

    source_size = None
    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        source_size = source.value.size
    elif isinstance(source, O.Field):
        if not is_special_field(source.field):
            if source.field in context.header:
                source_size = context.header[source.field]
            else:
                raise TypeError("source field (%s) is not present in the header."
                                % str(source.field))
        else:
            raise TypeError("source field (%s) is a special field." % str(source.field))
    elif isinstance(source, O.Location):
        offset = source.location.offset
        if isinstance(offset, O.Value):
            pass
        elif isinstance(offset, O.Field):
            if not is_special_field(offset.field):
                if offset.field in context.header:
                    pass
                else:
                    raise TypeError("source location's offset field (%s) is not present in the header."
                                    % str(offset.field))
            else:
                raise TypeError("source location's offset field (%s) is a special field."
                                % str(offset.field))
        else:
            raise TypeError("invalid %s of source location's offset (%s). Should be either %s or %s."
                            % (type(offset), offset, O.Value, O.Field))
        source_size = destination_size
    else:
        raise TypeError("invalid %s of source (%s). Should be %s, %s, or %s."
                        % (type(source), source, O.Value, O.Field, O.Location))

    ''' Compare sizes '''
    if source_size <= destination_size:
        pass
    else:
        raise TypeError("source (%s) size (%s) should be less than destination (%s) size (%s)."
                        % (source, source_size, destination, destination_size))

    context.labels = Labels(syntax.Label(''))


def type_check_ST(context, location, source):
    source_size = None
    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        source_size = source.value.size
    elif isinstance(source, O.Field):
        if not is_special_field(source.field):
            if source.field in context.header:
                source_size = context.header[source.field]
            else:
                raise TypeError("source field (%s) is not present in the header."
                                % str(source.field))
        else:
            raise TypeError("source field (%s) is a special field."
                            % str(source.field))
    else:
        raise TypeError("invalid %s of source (%s). Should be either %s or %s."
                        % (type(source), source, O.Value, O.Field))

    ''' Store in the packet '''
    location_size = None
    if isinstance(location, O.Location):
        offset = location.location.offset
        if isinstance(offset, O.Value):
            pass
        elif isinstance(offset, O.Field):
            if not is_special_field(offset.field):
                if offset.field in context.header:
                    pass
                else:
                    raise TypeError(
                        "destination location's offset field (%s) is not present in the header."
                        % str(offset.field))
            else:
                raise TypeError("destination location's offset field (%s) is a special field."
                                % str(offset.field))
        else:
            raise TypeError("invalid %s of destination location's offset (%s). Should be %s or %s."
                            % (type(offset), offset, O.Value, O.Field))
        location_size = source_size
    else:
        raise TypeError("invalid %s of location (%s). Should be %s."
                        % (type(location), location, O.Location))

    ''' Compare sizes '''
    if source_size <= location_size:
        pass
    else:
        raise TypeError("source (%s) size (%s) should be less than location (%s) size (%s)."
                        % (source, source_size, location, location_size))

    context.labels = Labels(syntax.Label(''))


def type_check_OP(context, destination, left_source, operator, right_source):
    left_size = None
    ''' Lookup left_source operand '''
    if isinstance(left_source, O.Value):
        left_size = left_source.value.size
    elif isinstance(left_source, O.Field):
        if not is_special_field(left_source.field):
            if left_source.field in context.header:
                left_size = context.header[left_source.field]
            else:
                raise TypeError("left source field (%s) is not present in the header."
                                % str(left_source.field))
        else:
            raise TypeError("left source field (%s) is a special field."
                            % str(left_source.field))
    else:
        raise TypeError("invalid %s of left source (%s). Should be %s or %s."
                        % (type(left_source), left_source, O.Value, O.Field))

    ''' Lookup right_source operand '''
    right_size = None
    if isinstance(right_source, O.Value):
        right_size = right_source.value.size
    elif isinstance(right_source, O.Field):
        if not is_special_field(right_source.field):
            if right_source.field in context.header:
                right_size = context.header[right_source.field]
            else:
                raise TypeError("right source field (%s) is not present in the header."
                                % str(right_source.field))
        else:
            raise TypeError("right source field (%s) is a special field."
                            % str(right_source.field))
    else:
        raise TypeError("invalid %s of right source (%s). Should be %s or %s."
                        % (type(right_source), right_source, O.Value, O.Field))

    ''' Operate on the values '''
    if isinstance(operator, Op.ArithmeticBitwiseOperator):
        pass
    else:
        raise TypeError("invalid %s of operator (%s). Should be %s."
                        % (type(operator), operator, Op.ArithmeticBitwiseOperator))

    ''' Lookup destination operand '''
    destination_size = None
    if isinstance(destination, O.Field):
        if not is_special_field(destination.field):
            if destination.field in context.header:
                destination_size = context.header[destination.field]
            else:
                raise TypeError("destination field (%s) is not present in the header."
                                % str(destination.field))
        else:
            raise TypeError("destination field (%s) is a special field."
                            % str(destination.field))
    else:
        raise TypeError("invalid %s of destination (%s). Should be %s."
                        % (type(destination), destination, O.Field))

    # TODO: make proper comparisons using the operator types (i.e., mul operator requires double desintation size)

    ''' Compare sizes '''
    if left_size <= destination_size:
        pass
    else:
        raise TypeError("left source (%s) size (%s) should be less than destination (%s) size (%s)."
                        % (left_source, left_size, destination, destination_size))
    if right_size <= destination_size:
        pass
    else:
        raise TypeError("right source (%s) size (%s) should be less than destination (%s) size (%s)."
                        % (right_source, right_size, destination, destination_size))

    context.labels = Labels(syntax.Label(''))


def type_check_PUSH(context, location, source):
    source_size = None
    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        source_size = source.value.size
    elif isinstance(source, O.Field):
        if not is_special_field(source.field):
            if source.field in context.header:
                source_size = context.header[source.field]
            else:
                raise TypeError("source field (%s) is not present in the header."
                                % str(source.field))
        else:
            raise TypeError("source field (%s) is a special field."
                            % str(source.field))
    else:
        raise TypeError("invalid %s of source (%s). Should be either %s or %s."
                        % (type(source), source, O.Value, O.Field))

    ''' lookup location operand '''
    location_size = None
    if isinstance(location, O.Location):
        offset = location.location.offset
        if isinstance(offset, O.Value):
            pass
        elif isinstance(offset, O.Field):
            if not is_special_field(offset.field):
                if offset.field in context.header:
                    pass
                else:
                    raise TypeError(
                        "location's offset field (%s) is not present in the header."
                        % str(offset.field))
            else:
                raise TypeError("location's offset field (%s) is a special field."
                                % str(offset.field))
        else:
            raise TypeError("invalid %s of location's offset (%s). Should be either %s or %s."
                            % (type(offset), offset, O.Value, O.Field))
        location_size = source_size
    else:
        raise TypeError("invalid %s of location (%s). Should be %s."
                        % (type(location), location, O.Location))

    ''' Compare sizes '''
    if source_size <= location_size:
        pass
    else:
        raise TypeError("source (%s) size (%s) should be less than location (%s) size (%s)."
                        % (source, source_size, location, location_size))

    context.labels = Labels(syntax.Label(''))


def type_check_POP(context, destination, location):
    destination_size = None
    ''' Lookup destination operand '''
    if isinstance(destination, O.Field):
        if not is_special_field(destination.field):
            if destination.field in context.header:
                destination_size = context.header[destination.field]
            else:
                raise TypeError("destination field (%s) is not present in the header."
                                % str(destination.field))
        else:
            raise TypeError("destination field (%s) is a special field."
                            % str(destination.field))
    else:
        raise TypeError("invalid %s of destination (%s). Should be %s."
                        % (type(destination), destination, O.Field))

    location_size = None
    ''' Lookup source operand '''
    if isinstance(location, O.Location):
        offset = location.location.offset
        if isinstance(offset, O.Value):
            pass
        elif isinstance(offset, O.Field):
            if not is_special_field(offset.field):
                if offset.field in context.header:
                    pass
                else:
                    raise TypeError(
                        "location's offset field (%s) is not present in the header."
                        % str(offset.field))
            else:
                raise TypeError("location's offset field (%s) is a special field."
                                % str(offset.field))
        else:
            raise TypeError("invalid %s of location's offset (%s). Should be either %s or %s."
                            % (type(offset), offset, O.Value, O.Location))
        location_size = destination_size
    else:
        raise TypeError("invalid %s of location (%s). Should be %s."
                        % (type(location), location, O.Location))

    ''' Compare sizes '''
    if location_size <= destination_size:
        pass
    else:
        raise TypeError("location (%s) size (%s) should be less than destination (%s) size (%s)."
                        % (location, location_size, destination, destination_size))

    context.labels = Labels(syntax.Label(''))


# TODO: track packet size using PUSH/POP functions. (This comes under dynamic type checking.)


def type_check_BR(context, left_source, operator, right_source, label):
    pass
    ''' Lookup left_source operand '''
    if isinstance(left_source, O.Value):
        pass
    elif isinstance(left_source, O.Field):
        if not is_special_field(left_source.field):
            if left_source.field in context.header:
                pass
            else:
                raise TypeError(
                    "left source field (%s) is not present in the header."
                    % str(left_source.field))
        else:
            raise TypeError("left source field (%s) is a special field."
                            % str(left_source.field))
    else:
        raise TypeError("invalid %s of left source (%s). Should be either %s or %s."
                        % (type(left_source), left_source, O.Value, O.Field))

    ''' Lookup right_source operand '''
    if isinstance(right_source, O.Value):
        pass
    elif isinstance(right_source, O.Field):
        if not is_special_field(right_source.field):
            if right_source.field in context.header:
                pass
            else:
                raise TypeError(
                    "right source field (%s) is not present in the header."
                    % str(right_source.field))
        else:
            raise TypeError("right source field (%s) is a special field."
                            % str(right_source.field))
    else:
        raise TypeError("invalid %s of right source (%s). Should be either %s or %s."
                        % (type(right_source), right_source, O.Value, O.Field))

    if isinstance(operator, Op.ComparisonOperator):
        pass
    else:
        raise TypeError("invalid %s of operator (%s). Should be %s."
                        % (type(operator), operator, Op.ComparisonOperator))

    ''' Update program counter '''
    if not isinstance(label, syntax.Label):
        raise TypeError("invalid %s of label (%s). Should be %s."
                        % (type(label), label, syntax.Label))

    # TODO: check this using the forwards and backwards label check
    # if label in labels:
    #     pass
    # else:
    #     raise TypeError("TypeError(%s): label (%s) doesn't exist" % ("BR", str(label)))

    context.labels = Labels(label, syntax.Label(''))


def type_check_JMP(context, label):
    if not isinstance(label, syntax.Label):
        raise TypeError("invalid %s of label (%s). Should be %s."
                        % (type(label), label, syntax.Label))

    # TODO: check this using the forwards and backwards label check
    # if label in labels:
    #     pass
    # else:
    #     raise TypeError("TypeError(%s): label (%s) doesn't exist" % ("JMP", str(label)))

    context.labels = Labels(label)


def type_check_LBL(context, label):
    if not isinstance(label, syntax.Label):
        raise TypeError("invalid %s of label (%s). Should be %s."
                        % (type(label), label, syntax.Label))

    # TODO: check this using the forwards and backwards label check
    # if label in labels:
    #     pass
    # else:
    #     raise TypeError("TypeError(%s): label (%s) doesn't exist" % ("JMP", str(label)))

    context.labels = Labels(syntax.Label(''))


def type_check_HLT(context):
    context.labels = Labels(syntax.Label(''))


# ### Load table instruction ###
# def costLDt(state, destinations, table_id, index):
# if not isinstance(table_id, TableId): raise TypeError()
#     _, _, table_type = state.tables[table_id]
#
#     state.area += getHeaderSize(state.header)
#
#     if isinstance(table_type, TableTypeCollection.RAM):
#         state.latency += 1
#     else:
#         raise TypeError()
# # Note: tables are not added in the "area" cost as they will incur a one time cost for the whole program
# #       it only operates on RAM type
#
#
# ### Store table instruction ###
# def costSTt(state, table_id, index, sources):
#     if not isinstance(table_id, TableId): raise TypeError()
#     _, _, table_type = state.tables[table_id]
#
#     state.area += getHeaderSize(state.header)
#
#     if isinstance(table_type, TableTypeCollection.RAM):
#         state.latency += 1
#     elif isinstance(table_type, TableTypeCollection.HSH):
#         state.latency += 2
#     elif isinstance(table_type, TableTypeCollection.CAM):
#         state.latency += 3
#     else:
#         raise TypeError()
#
#
# ### Increment table instruction ###
# def costINCt(state, table_id, index):
#     if not isinstance(table_id, TableId): raise TypeError()
#     _, _, table_type = state.tables[table_id]
#
#     state.area += getHeaderSize(state.header)
#
#     if isinstance(table_type, TableTypeCollection.RAM):
#         state.latency += 1
#     else:
#         raise TypeError()
# # Note: it only operates on RAM type
#
#
# ### Lookup table instruction ###
# def costLKt(state, index, table_id, sources):
#     if not isinstance(table_id, TableId): raise TypeError()
#     _, _, table_type = state.tables[table_id]
#
#     state.area += getHeaderSize(state.header)
#
#     if isinstance(table_type, TableTypeCollection.RAM):
#         state.latency += 1
#     elif isinstance(table_type, TableTypeCollection.HSH):
#         state.latency += 2
#     elif isinstance(table_type, TableTypeCollection.CAM):
#         state.latency += 3
#     else:
#         raise TypeError()
#
#
# ### Checksum instruction ###
# def costCRC(state, destination, sources):
#     state.area += getHeaderSize(state.header)
#     state.latency += 1
#
#
# ### Hash instruction ###
# def costHSH(state, destination, sources):
#     state.area += getHeaderSize(state.header)
#     state.latency += 1
#
#
# def type_check_CNC(context, tables, codes):
#     pass


def type_check_ATM(context, tables, code):
    type_check_Code(code, tables, context)


def type_check_SEQ(context, tables, code):
    type_check_Code(code, tables, context)


def type_check_Decls(decls):
    if not isinstance(decls, syntax.Decls):
        raise TypeError("invalid %s of declarations (%s). Should be %s."
                        % (type(decls), decls, syntax.Decls))

    # Declare tables
    tables = Tables()
    for table_id, table in decls.table_decls.iteritems():
        if isinstance(table.table_fields, syntax.TableFieldsCollection.SimpleFields):
            pattern = SimplePattern()
            for field, size in table.table_fields.iteritems():
                pattern[field] = size
        elif isinstance(table.table_fields, syntax.TableFieldsCollection.MatchFields):
            pattern = MatchPattern()
            for field, (size, match_type) in table.table_fields.iteritems():
                pattern[field] = (size, match_type)
        else:
            raise TypeError("invalid %s of pattern (%s). Should be either %s or %s."
                            % (type(table.table_fields), table.table_fields,
                               syntax.TableFieldsCollection.SimpleFields,
                               syntax.TableFieldsCollection.MatchFields))

        tables[table_id] = Table(pattern, table.size, table.table_type)

    return tables


def next_Instruction(instructions, tables, context):
    # Read instruction at program counter
    instruction = instructions[context.pc]

    if isinstance(instruction, I.ID):
        type_check_ID(context)
    elif isinstance(instruction, I.DRP):
        type_check_DRP(context, instruction.reason)
    elif isinstance(instruction, I.CTR):
        type_check_CTR(context, instruction.reason)
    elif isinstance(instruction, I.ADD):
        type_check_ADD(context, instruction.field, instruction.size)
    elif isinstance(instruction, I.RMV):
        type_check_RMV(context, instruction.field)
    elif isinstance(instruction, I.LD):
        type_check_LD(context, instruction.destination, instruction.source)
    elif isinstance(instruction, I.ST):
        type_check_ST(context, instruction.location, instruction.source)
    elif isinstance(instruction, I.OP):
        type_check_OP(context, instruction.destination, instruction.left_source,
                      instruction.operator, instruction.right_source)
    elif isinstance(instruction, I.PUSH):
        type_check_PUSH(context, instruction.location)
    elif isinstance(instruction, I.POP):
        type_check_POP(context, instruction.location)
    elif isinstance(instruction, I.BR):
        type_check_BR(context, instruction.left_source, instruction.operator,
                      instruction.right_source, instruction.label)
    elif isinstance(instruction, I.JMP):
        type_check_JMP(context, instruction.label)
    elif isinstance(instruction, I.LBL):
        type_check_LBL(context, instruction.label)
    elif isinstance(instruction, I.LDt):
        # type_check_LDt(context, tables, instruction.destinations, instruction.table_id, instruction.index)
        pass
    elif isinstance(instruction, I.STt):
        # type_check_STt(context, tables, instruction.table_id, instruction.index, instruction.sources)
        pass
    elif isinstance(instruction, I.INCt):
        # type_check_INCt(context, tables, instruction.table_id, instruction.index)
        pass
    elif isinstance(instruction, I.LKt):
        # type_check_LKt(context, tables, instruction.index, instruction.table_id, instruction.sources)
        pass
    elif isinstance(instruction, I.CRC):
        # type_check_CRC(context, instruction.destination, instruction.sources)
        pass
    elif isinstance(instruction, I.HSH):
        # type_check_HSH(context, instruction.destination, instruction.sources)
        pass
    elif isinstance(instruction, I.CNC):
        # type_check_CNC(context, tables, instruction.codes)
        pass
    elif isinstance(instruction, I.ATM):
        type_check_ATM(context, tables, instruction.code)
    elif isinstance(instruction, I.SEQ):
        type_check_SEQ(context, tables, instruction.code)
    else:
        raise TypeError("invalid %s of instruction (%s). Should be %s."
                        % (type(instruction), instruction, I.Instruction))


def type_check_Instruction(instructions, tables, context):
    # Read instruction at program counter
    instruction = instructions[context.pc]

    # Check if HLT instruction
    if isinstance(instruction, I.HLT):
        type_check_HLT(context)
    else:
        next_Instruction(instructions, tables, context)

        if len(context.labels) == 1:
            if context.labels[0] == syntax.Label(''):
                context.pc += 1
            else:
                context.pc, _ = get_label(instructions, context.labels[0])
            type_check_Instruction(instructions, tables, context)
        elif len(context.labels) == 2:
            if context.labels[0] != '':
                pass
            else:
                raise TypeError("taken-branch label (%s) can't be empty."
                                % (context.labels[0]))
            if context.labels[1] == '':
                pass
            else:
                raise TypeError("not-taken-branch label (%s) must be empty."
                                % (context.labels[1]))

            # type check taken-branch
            contextT = deepcopy(context)
            contextT.pc, _ = get_label(instructions, context.labels[0])
            type_check_Instruction(instructions, tables, contextT)

            # type check not-taken-branch
            context.pc += 1
            type_check_Instruction(instructions, tables, context)
        else:
            raise TypeError("invalid labels (%s) count."
                            % context.labels)


def type_check_Code(code, tables, context):
    pc = context.pc
    header = context.header

    context.pc = 0
    context.header = Header()
    for field in code.argument_fields:
        context.header[field] = header[field]
    for field in get_reserved_fields():
        context.header[field] = header[field]

    # Type check instructions
    type_check_Instruction(code.instructions, tables, context)

    # Commit changes to the current header
    for field in code.argument_fields:
        header[field] = context.header[field]
    for field in get_reserved_fields():
        header[field] = context.header[field]

    context.pc = pc
    context.header = header


def type_check_Policy(policy, ports):
    if not isinstance(policy, syntax.Policy):
        raise TypeError("invalid %s of policy (%s). Should be %s."
                        % (type(policy), policy, syntax.Policy))

    if not isinstance(ports, int):
        raise TypeError("invalid %s of ports (%s). Should be %s."
                        % (type(ports), ports, int))

    ''' Create empty context '''
    context = Context(Header(), Packet())

    ''' Add reserved fields '''
    context.header[syntax.Field('inport_bitmap')] = syntax.Size(ports)
    context.header[syntax.Field('outport_bitmap')] = syntax.Size(ports)
    context.header[syntax.Field('bit_length')] = syntax.Size(ports)
    context.header[syntax.Field('DRP')] = syntax.Size(1)
    context.header[syntax.Field('CTR')] = syntax.Size(1)
    setattr(context, 'pc', 0)

    ''' Type check declarations '''
    tables = type_check_Decls(policy.decls)

    ''' Type check code '''
    type_check_Code(policy.code, tables, context)

    ''' Remove local context attributes '''
    del context.pc


@time_usage
def type_check_Policy__time_usage(policy, ports):
    return type_check_Policy(policy, ports)
