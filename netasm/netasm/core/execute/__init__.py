# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        __init__.py
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

from bitstring import BitArray

from netasm.netasm.core import syntax
from netasm.netasm.core.syntax import OperandCollection as O
from netasm.netasm.core.utilities.algorithms import crc16


class Header(dict):
    def __setitem__(self, field, value):
        dict.__setitem__(self, field, value)


class Packet(BitArray):
    pass


class Pattern(dict):
    pass


class MatchPattern(Pattern):
    def __setitem__(self, field, (value, mask)):
        dict.__setitem__(self, field, (value, mask))

    def __getitem__(self, field):
        return dict.__getitem__(self, field)


class SimplePattern(Pattern):
    def __setitem__(self, field, value):
        dict.__setitem__(self, field, value)

    def __getitem__(self, field):
        return dict.__getitem__(self, field)


class Patterns(list):
    pass


class MatchPatterns(Patterns):
    def __init__(self, *args):
        super(Patterns, self).__init__()

        for arg in args:
            list.append(self, arg)

    def __setitem__(self, index, pattern):
        list.__setitem__(self, index, pattern)

    def __getitem__(self, index):
        return list.__getitem__(self, index)

    def add_entry(self, index, entry):
        if index > len(self):
            raise RuntimeError()

        pattern = list.__getitem__(self, index)

        if len(entry) > 0:
            for field, value in entry.iteritems():
                if not (isinstance(value, tuple) and len(value) == 2):
                    raise RuntimeError()

                field = syntax.Field(field)
                if field not in pattern:
                    raise RuntimeError()

                pattern[field][0].value = value[0]
                pattern[field] = (pattern[field][0], syntax.Mask(value[1]))

    def del_entry(self, index):
        if index > len(self):
            raise RuntimeError()

        pattern = list.__getitem__(self, index)

        for field, (value, mask) in pattern.iteritems():
            value.value = 0
            pattern[field] = (value, syntax.Mask(-1))

    def query_entry(self, index):
        pattern = list.__getitem__(self, index)

        entry = {}
        for field, (value, mask) in pattern.iteritems():
            entry[str(field)] = {'value': (value.value, int(value.size)),
                                 'mask': int(mask)}
        return entry


class SimplePatterns(Patterns):
    def __init__(self, *args):
        super(Patterns, self).__init__()

        for arg in args:
            list.append(self, arg)

    def __setitem__(self, index, pattern):
        list.__setitem__(self, index, pattern)

    def __getitem__(self, index):
        return list.__getitem__(self, index)

    def add_entry(self, index, entry):
        if index > len(self):
            raise RuntimeError()

        pattern = list.__getitem__(self, index)

        if len(entry) > 0:
            for field, value in entry.iteritems():
                field = syntax.Field(field)
                if field not in pattern:
                    raise RuntimeError()

                pattern[field].value = value

    def del_entry(self, index):
        if index > len(self):
            raise RuntimeError()

        pattern = list.__getitem__(self, index)

        for _, value in pattern.iteritems():
            value.value = 0

    def query_entry(self, index):
        pattern = list.__getitem__(self, index)

        entry = {}
        for field, value in pattern.iteritems():
            entry[str(field)] = {'value': (value.value, int(value.size))}
        return entry


class State:
    def __init__(self, header, packet, reason=syntax.Reason('', ''), label=syntax.Label(''), extra=None):
        self.header = header
        self.packet = packet
        self.reason = reason
        self.label = label
        self.extra = extra


def execute_ID(state):
    state.label = syntax.Label('')
    return state


def execute_DRP(state, reason):
    state.reason = reason
    value = state.header[syntax.Field('DRP')]
    value.value = 1

    state.label = syntax.Label('')
    return state


def execute_CTR(state, reason):
    state.reason = reason
    value = state.header[syntax.Field('CTR')]
    value.value = 1

    state.label = syntax.Label('')
    return state


def execute_ADD(state, field, size):
    state.header[field.field] = syntax.Value(0, size)

    state.label = syntax.Label('')
    return state


def execute_RMV(state, field):
    del state.header[field.field]

    state.label = syntax.Label('')
    return state


def execute_LD(state, destination, source):
    size = None
    ''' Validate destination operand '''
    if isinstance(destination, O.Field):
        size = state.header[destination.field].size
    else:
        raise RuntimeError()

    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        state.header[destination.field].value = source.value.value
    elif isinstance(source, O.Field):
        state.header[destination.field].value = state.header[source.field].value
    elif isinstance(source, O.Location):
        offset = source.location.offset
        if isinstance(offset, O.Value):
            offset_value = offset.value
        elif isinstance(offset, O.Field):
            offset_value = state.header[offset.field]
        else:
            raise RuntimeError()

        state.header[destination.field].value = int(state.packet[offset_value.value:(offset_value.value + size)].uint)
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def execute_ST(state, location, source):
    value = None
    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        value = source.value
    elif isinstance(source, O.Field):
        value = state.header[source.field]
    else:
        raise RuntimeError()

    ''' Store in the packet '''
    if isinstance(location, O.Location):
        offset = location.location.offset
        if isinstance(offset, O.Value):
            offset_value = offset.value
        elif isinstance(offset, O.Field):
            offset_value = state.header[offset.field]
        else:
            raise RuntimeError()

        state.packet[offset_value.value:(offset_value.value + value.size)] = value.value
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def operate(left_value, operator, right_value):
    if operator == syntax.OperatorCollection.Add:
        value = left_value.value + right_value.value
    elif operator == syntax.OperatorCollection.Sub:
        value = left_value.value - right_value.value
    elif operator == syntax.OperatorCollection.Mul:
        value = left_value.value * right_value.value
    elif operator == syntax.OperatorCollection.Div:
        value = left_value.value / right_value.value
    elif operator == syntax.OperatorCollection.And:
        value = left_value.value & right_value.value
    elif operator == syntax.OperatorCollection.Or:
        value = left_value.value | right_value.value
    elif operator == syntax.OperatorCollection.Xor:
        value = left_value.value ^ right_value.value
    else:
        raise RuntimeError()

    return syntax.Value(value,
                 syntax.Size(left_value.size if left_value.size > right_value.size else right_value.size))


def execute_OP(state, destination, left_source, operator, right_source):
    left_value = None
    ''' Lookup left_source operand '''
    if isinstance(left_source, O.Value):
        left_value = left_source.value
    elif isinstance(left_source, O.Field):
        left_value = state.header[left_source.field]
    else:
        raise RuntimeError()

    right_value = None
    ''' Lookup right_source operand '''
    if isinstance(right_source, O.Value):
        right_value = right_source.value
    elif isinstance(right_source, O.Field):
        right_value = state.header[right_source.field]
    else:
        raise RuntimeError()

    ''' Operate on the values '''
    value = operate(left_value, operator, right_value)

    ''' Lookup destination operand '''
    if isinstance(destination, O.Field):
        state.header[destination.field] = value
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def execute_PUSH(state, location, source):
    value = None
    ''' Lookup source operand '''
    if isinstance(source, O.Value):
        value = source.value
    elif isinstance(source, O.Field):
        value = state.header[source.field]
    else:
        raise RuntimeError()

    if isinstance(location, O.Location):
        ''' Lookup offset '''
        offset = location.location.offset
        if isinstance(offset, O.Value):
            offset_value = offset.value
        elif isinstance(offset, O.Field):
            offset_value = state.header[offset.field]
        else:
            raise RuntimeError()

        state.packet.insert(BitArray(length=value.size), offset_value.value)
        state.packet[offset_value.value:(offset_value.value + value.size)] = value.value
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def execute_POP(state, destination, location):
    size = None
    ''' Validate destination operand '''
    if isinstance(destination, O.Field):
        size = state.header[destination.field].size
    else:
        raise RuntimeError()

    if isinstance(location, O.Location):
        ''' Lookup offset '''
        offset = location.location.offset
        if isinstance(offset, O.Value):
            offset_value = offset.value
        elif isinstance(offset, O.Field):
            offset_value = state.header[offset.field]
        else:
            raise RuntimeError()

        state.header[destination.field].value = int(state.packet[offset_value.value:(offset_value.value + size)].uint)
        del state.packet[offset_value.value:(offset_value.value + size)]
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def compare(left_value, operator, right_value):
    if operator == syntax.OperatorCollection.Eq:
        value = left_value.value == right_value.value
    elif operator == syntax.OperatorCollection.Neq:
        value = left_value.value != right_value.value
    elif operator == syntax.OperatorCollection.Lt:
        value = left_value.value < right_value.value
    elif operator == syntax.OperatorCollection.Gt:
        value = left_value.value > right_value.value
    elif operator == syntax.OperatorCollection.Le:
        value = left_value.value <= right_value.value
    elif operator == syntax.OperatorCollection.Ge:
        value = left_value.value >= right_value.value
    else:
        raise RuntimeError()

    return value


def execute_BR(state, left_source, operator, right_source, label):
    left_value = None
    ''' Lookup left_source operand '''
    if isinstance(left_source, O.Value):
        left_value = left_source.value
    elif isinstance(left_source, O.Field):
        left_value = state.header[left_source.field]
    else:
        raise RuntimeError()

    right_value = None
    ''' Lookup right_source operand '''
    if isinstance(right_source, O.Value):
        right_value = right_source.value
    elif isinstance(right_source, O.Field):
        right_value = state.header[right_source.field]
    else:
        raise RuntimeError()

    ''' Update program counter '''
    if compare(left_value, operator, right_value):
        state.label = label
    else:
        state.label = syntax.Label('')

    return state


def execute_JMP(state, label):
    state.label = label
    return state


def execute_LBL(state):
    state.label = syntax.Label('')
    return state


def execute_CRC(state, destination, sources):
    offset = 0
    ba = BitArray()
    for source in sources:
        ''' Lookup source '''
        if isinstance(source, O.Value):
            value = source.value
        elif isinstance(source, O.Field):
            value = state.header[source.field]
        else:
            raise RuntimeError()

        length = value.size
        ba[offset:(offset + length)] = value.value
        offset += length

    ''' Compute CRC and store it in the destination '''
    if isinstance(destination, O.Field):
        state.header[destination.field].value = crc16(ba.bytes)

    state.label = syntax.Label('')
    return state


def execute_HSH(state, destination, sources):
    value = None
    offset = 0
    ba = BitArray()
    for source in sources:
        if isinstance(source, O.Value):
            value = source.value
        elif isinstance(source, O.Field):
            value = state.header[source.field]
        else:
            raise RuntimeError()

        length = value.size
        ba[offset:(offset + length)] = value.value
        offset += length

    ''' Compute hash and store it in the destination '''
    if isinstance(destination, O.Field):
        state.header[destination.field].value = hash(ba.uint)
    else:
        raise RuntimeError()

    state.label = syntax.Label('')
    return state


def execute_HLT(state):
    state.label = syntax.Label('')
    return state
