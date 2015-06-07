# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        common.py
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

from netasm.netasm.core.syntax import *
from netasm.netasm.core.syntax import InstructionCollection as I, OperandCollection as O


SPECIAL_FIELDS = [Field('DRP'),
                  Field('CTR')]


RESERVED_FIELDS = [Field('inport_bitmap'),
                   Field('outport_bitmap'),
                   Field('bit_length')] + SPECIAL_FIELDS


def get_modified_locations(instructions):
    modified_offsets = []

    for instruction in instructions:
        if isinstance(instruction, I.ST):
            modified_offsets.append(instruction.location.location)
        elif isinstance(instruction, I.ATM):
            modified_offsets.extend(get_modified_locations(instruction.code.instructions))
        elif isinstance(instruction, I.SEQ):
            modified_offsets.extend(get_modified_locations(instruction.code.instructions))
        elif isinstance(instruction, I.CNC):
            for code in instruction.codes:
                modified_offsets.extend(get_modified_locations(code.instructions))

    # TODO: optimize by finding overlapping offset/length pairs and eliminate them

    return modified_offsets


def get_modified_reserved_fields(instructions):
    modified_reserved_fields = set()

    for instruction in instructions:
        if isinstance(instruction, I.DRP):
            modified_reserved_fields |= {Field('DRP')}
        elif isinstance(instruction, I.CTR):
            modified_reserved_fields |= {Field('CTR')}
        elif isinstance(instruction, I.LD):
            if isinstance(instruction.destination, O.Field):
                if is_reserved_field(instruction.destination.field):
                    modified_reserved_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.OP):
            if isinstance(instruction.destination, O.Field):
                if is_reserved_field(instruction.destination.field):
                    modified_reserved_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.LDt):
            if isinstance(instruction.destinations, O.Operands__):
                for operand in instruction.destinations:
                    if isinstance(operand, O.Field):
                        if is_reserved_field(operand.field):
                            modified_reserved_fields |= {operand.field}
            else:
                raise TypeError("invalid %s of destinations (%s). Should be %s."
                                % (type(instruction.destinations), instruction.destinations, O.Operands__))
        elif isinstance(instruction, I.LKt):
            if isinstance(instruction.index, O.Field):
                if is_reserved_field(instruction.index.field):
                    modified_reserved_fields |= {instruction.index.field}
        elif isinstance(instruction, I.CRC):
            if isinstance(instruction.destination, O.Field):
                if is_reserved_field(instruction.destination.field):
                    modified_reserved_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.HSH):
            if isinstance(instruction.destination, O.Field):
                if is_reserved_field(instruction.destination.field):
                    modified_reserved_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.ATM):
            modified_reserved_fields |= get_modified_reserved_fields(instruction.code.instructions)
        elif isinstance(instruction, I.SEQ):
            modified_reserved_fields |= get_modified_reserved_fields(instruction.code.instructions)
        elif isinstance(instruction, I.CNC):
            for code in instruction.codes:
                modified_reserved_fields |= get_modified_reserved_fields(code.instructions)

    return modified_reserved_fields


def get_modified_fields(instructions, fields):
    modified_fields = set()

    for instruction in instructions:
        if isinstance(instruction, I.LD):
            if isinstance(instruction.destination, O.Field):
                if instruction.destination.field in fields:
                    modified_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.OP):
            if isinstance(instruction.destination, O.Field):
                if instruction.destination.field in fields:
                    modified_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.LDt):
            if isinstance(instruction.destinations, O.Operands__):
                for operand in instruction.destinations:
                    if isinstance(operand, O.Field):
                        if operand.field in fields:
                            modified_fields |= {operand.field}
            else:
                raise TypeError("invalid %s of destinations (%s). Should be %s."
                                % (type(instruction.destinations), instruction.destinations, O.Operands__))
        elif isinstance(instruction, I.LKt):
            if isinstance(instruction.index, O.Field):
                if instruction.index.field in fields:
                    modified_fields |= {instruction.index.field}
        elif isinstance(instruction, I.CRC):
            if isinstance(instruction.destination, O.Field):
                if instruction.destination.field in fields:
                    modified_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.HSH):
            if isinstance(instruction.destination, O.Field):
                if instruction.destination.field in fields:
                    modified_fields |= {instruction.destination.field}
        elif isinstance(instruction, I.ATM):
            modified_fields |= get_modified_fields(instruction.code.instructions, fields)
        elif isinstance(instruction, I.SEQ):
            modified_fields |= get_modified_fields(instruction.code.instructions, fields)
        elif isinstance(instruction, I.CNC):
            for code in instruction.codes:
                modified_fields |= get_modified_fields(code.instructions, fields)

    return modified_fields


def get_add_instruction_count(instructions, field):
    count = 0
    for instruction in instructions:
        if isinstance(instruction, I.ADD):
            if instruction.field.field == field:
                count += 1
    return count


def get_rmv_instruction_count(instructions, field):
    count = 0
    for instruction in instructions:
        if isinstance(instruction, I.RMV):
            if instruction.field.field == field:
                count += 1
    return count


def get_instruction_at_label(instructions, label):
    i = 0
    for instruction in instructions:
        if isinstance(instruction, I.LBL):
            if instruction.label == label:
                return i, instruction
        i += 1

    raise TypeError("invalid label (%s)." % label)


def is_special_field(field):
    return True if field in SPECIAL_FIELDS else False


def is_reserved_field(field):
    return True if field in RESERVED_FIELDS else False


def get_reserved_fields():
    return Fields(*RESERVED_FIELDS)


# Note: port numbers start from 1
def ports_to_bitmap(*args):
    bitmap = 0
    if isinstance(args[0], list):
        for port in args[0]:
            bitmap |= 1 << (port - 1)
    else:
        for port in args:
            bitmap |= 1 << (port - 1)
    return bitmap


def bitmap_to_ports(bitmap):
    ports = []
    bitmap_string = bin(bitmap)[2:][::-1]
    for i in range(0, len(bitmap_string)):
        if int(bitmap_string[i]) == 1:
            ports.append(i + 1)
    return ports