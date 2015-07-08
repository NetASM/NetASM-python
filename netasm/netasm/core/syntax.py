# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        syntax.py
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


def singleton(f):
    return f()


class Size(int):
    def __repr__(self):
        return 'Size(' + str(self) + ')'


class Value:
    def __init__(self, value, size):
        if isinstance(value, int):
            self.value = value
        else:
            raise TypeError("invalid %s of value (%s). Should be %s."
                            % (type(value), value, int))
        if isinstance(size, Size):
            self.size = size
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, Size))

    def __repr__(self):
        return 'Value(' + repr(self.value) + ',' + repr(self.size) + ')'


class Field(str):
    def __repr__(self):
        return "Field('" + str(self) + "')"


class Fields(list):
    def __init__(self, *args):
        for arg in args:
            if isinstance(arg, Field):
                list.append(self, arg)
            else:
                raise TypeError("invalid %s of argument (%s). Should be %s."
                                % (type(arg), arg, Field))

    def __setitem__(self, index, field):
        if isinstance(field, Field):
            list.__setitem__(self, index, field)
        else:
            raise TypeError("invalid %s of field (%s). Should be %s."
                            % (type(field), field, Field))

    def __getitem__(self, index):
        return list.__getitem__(self, index)

    def __repr__(self):
        return "Fields('" + "','".join(self) + "')"


class Mask(int):
    def __repr__(self):
        return 'Mask(' + str(self) + ')'


class Label(str):
    def __repr__(self):
        return "Label('" + str(self) + "')"


class Reason:
    def __init__(self, reason, description):
        if isinstance(reason, str):
            self.reason = reason
        else:
            raise TypeError("invalid %s of reason (%s). Should be %s."
                            % (type(reason), reason, str))
        if isinstance(description, str):
            self.description = description
        else:
            raise TypeError("invalid %s of description (%s). Should be %s."
                            % (type(description), description, str))

    def __repr__(self):
        return "Reason('" + self.reason + "','" + self.description + "')"


class OperatorCollection:
    def __init__(self):
        raise NotImplementedError

    class ArithmeticBitwiseOperator:
        def __repr__(self):
            return "OperatorCollection.ArithmeticBitwiseOperator()"

    @singleton
    class Add(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Add"

    @singleton
    class Sub(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Sub"

    @singleton
    class Mul(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Mul"

    @singleton
    class Div(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Div"

    @singleton
    class And(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.And"

    @singleton
    class Or(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Or"

    @singleton
    class Xor(ArithmeticBitwiseOperator):
        def __repr__(self):
            return "OperatorCollection.Xor"

    class ComparisonOperator:
        def __repr__(self):
            return "OperatorCollection.ComparisonOperator()"

    @singleton
    class Eq(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Eq"

    @singleton
    class Neq(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Neq"

    @singleton
    class Lt(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Lt"

    @singleton
    class Gt(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Gt"

    @singleton
    class Le(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Le"

    @singleton
    class Ge(ComparisonOperator):
        def __repr__(self):
            return "OperatorCollection.Ge"


class OperandCollection:
    def __init__(self):
        raise NotImplementedError

    class Operand:
        def __repr__(self):
            return "OperandCollection.Operand()"

    class Location(Operand):
        def __init__(self, location):
            if isinstance(location, Location):
                self.location = location
            else:
                raise TypeError("invalid %s of location (%s). Should be %s."
                                % (type(location), location, Location))

        def __repr__(self):
            return "OperandCollection.Location(" + repr(self.location) + ")"

    class Operand_(Operand):
        def __repr__(self):
            return "OperandCollection.Operand_()"

    class Operands_(list):
        def __init__(self, *args):
            for arg in args:
                if isinstance(arg, OperandCollection.Operand_):
                    list.append(self, arg)
                else:
                    raise TypeError("invalid %s of argument (%s). Should be %s."
                                    % (type(arg), arg, OperandCollection.Operand_))

        def __setitem__(self, index, operand):
            if isinstance(operand, OperandCollection.Operand_):
                list.__setitem__(self, index, operand)
            else:
                raise TypeError("invalid %s of operand (%s). Should be %s."
                                % (type(operand), operand, OperandCollection.Operand_))

        def __getitem__(self, index):
            return list.__getitem__(self, index)

        def __repr__(self):
            _repr = "OperandCollection.Operands_("

            __repr = ""
            for operand in self:
                __repr += repr(operand) + ","
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class OperandsMasks_(list):
        def __init__(self, *args):
            for arg in args:
                (operand, mask) = arg
                if isinstance(operand, OperandCollection.Operand_):
                    pass
                else:
                    raise TypeError("invalid %s of operand (%s). Should be %s."
                                    % (type(operand), operand, OperandCollection.Operand_))
                if isinstance(mask, Mask):
                    pass
                else:
                    raise TypeError("invalid %s of mask (%s). Should be %s."
                                    % (type(mask), mask, Mask))
                list.append(self, arg)

        def __setitem__(self, index, (operand, mask)):
            if isinstance(operand, OperandCollection.Operand_):
                pass
            else:
                raise TypeError("invalid %s of operand (%s). Should be %s."
                                % (type(operand), operand, OperandCollection.Operand_))
            if isinstance(mask, Mask):
                pass
            else:
                raise TypeError("invalid %s of mask (%s). Should be %s."
                                % (type(mask), mask, Mask))
            list.__setitem__(self, index, (operand, mask))

        def __getitem__(self, index):
            return list.__getitem__(self, index)

        def __repr__(self):
            _repr = "OperandCollection.OperandsMasks_("

            __repr = ""
            for operand, mask in self:
                __repr += "(" + repr(operand) + "," + repr(mask) + "),"
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class Value(Operand_):
        def __init__(self, value):
            if isinstance(value, Value):
                self.value = value
            else:
                raise TypeError("invalid %s of value (%s). Should be %s."
                                % (type(value), value, Value))

        def __repr__(self):
            return "OperandCollection.Value(" + repr(self.value) + ")"

    class Operand__(Operand_):
        def __repr__(self):
            return "OperandCollection.Operand__()"

    class Operands__(list):
        def __init__(self, *args):
            for arg in args:
                if isinstance(arg, OperandCollection.Operand__):
                    list.append(self, arg)
                else:
                    raise TypeError("invalid %s of argument (%s). Should be %s."
                                    % (type(arg), arg, OperandCollection.Operand__))

        def __setitem__(self, index, operand):
            if isinstance(operand, OperandCollection.Operand__):
                list.__setitem__(self, index, operand)
            else:
                raise TypeError("invalid %s of argument (%s). Should be %s."
                                % (type(operand), operand, OperandCollection.Operand__))

        def __getitem__(self, index):
            return list.__getitem__(self, index)

        def __repr__(self):
            _repr = "OperandCollection.Operands__("

            __repr = ""
            for operand in self:
                __repr += repr(operand) + ","
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class Field(Operand__):
        def __init__(self, field):
            if isinstance(field, Field):
                self.field = field
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))

        def __repr__(self):
            return "OperandCollection.Field(" + repr(self.field) + ")"


class Location:
    def __init__(self, offset):
        if isinstance(offset, OperandCollection.Operand_):
            self.offset = offset
        else:
            raise TypeError("invalid %s of offset (%s). Should be %s."
                            % (type(offset), offset, OperandCollection.Operand_))
        # if isinstance(length, OperandCollection.Operand_):
        #     self.length = length
        # else:
        #     raise TypeError("invalid %s of length (%s). Should be %s."
        #                     % (type(length), length, OperandCollection.Operand_))

    def __repr__(self):
        return "Location(" + repr(self.offset) + ")"


class TableId(str):
    def __repr__(self):
        return "TableId('" + str(self) + "')"


class MatchTypeCollection:
    def __init__(self):
        raise NotImplementedError

    class MatchType:
        def __repr__(self):
            return "MatchTypeCollection.MatchType()"

    @singleton
    class Binary(MatchType):
        def __repr__(self):
            return "MatchTypeCollection.Binary"

    @singleton
    class Ternary(MatchType):
        def __repr__(self):
            return "MatchTypeCollection.Ternary"


class TableFieldsCollection:
    def __init__(self):
        raise NotImplementedError

    class TableFields(dict):
        def __init__(self):
            raise NotImplementedError

    class MatchFields(TableFields):
        def __init__(self):
            pass

        def __setitem__(self, field, (size, match_type)):
            if isinstance(field, Field):
                pass
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))
            if isinstance(size, Size):
                pass
            else:
                raise TypeError("invalid %s of size (%s). Should be %s."
                                % (type(size), size, Size))
            if isinstance(match_type, MatchTypeCollection.MatchType):
                pass
            else:
                raise TypeError("invalid %s of match type (%s). Should be %s."
                                % (type(match_type), match_type, MatchTypeCollection.MatchType))
            dict.__setitem__(self, field, (size, match_type))

        def __getitem__(self, field):
            if isinstance(field, Field):
                return dict.__getitem__(self, field)
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))

        def __repr__(self):
            _repr = "TableFieldsCollection.MatchFields("

            __repr = ""
            for field, (size, match_type) in self.iteritems():
                __repr += "(" + repr(field) + ":" + "(" + repr(size) + "," + repr(match_type) + ")),"
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class SimpleFields(TableFields):
        def __init__(self):
            pass

        def __setitem__(self, field, size):
            if isinstance(field, Field):
                pass
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))
            if isinstance(size, Size):
                pass
            else:
                raise TypeError("invalid %s of size (%s). Should be %s."
                                % (type(size), size, Size))
            dict.__setitem__(self, field, size)

        def __getitem__(self, field):
            if isinstance(field, Field):
                return dict.__getitem__(self, field)
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))

        def __repr__(self):
            _repr = "TableFieldsCollection.SimpleFields("

            __repr = ""
            for field, size in self.iteritems():
                __repr += "(" + repr(field) + ":" + repr(size) + "),"
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr


class TableTypeCollection:
    def __init__(self):
        raise NotImplementedError

    class TableType:
        def __repr__(self):
            return "TableTypeCollection.TableType()"

    @singleton
    class CAM(TableType):
        def __repr__(self):
            return "TableTypeCollection.CAM"

    @singleton
    class RAM(TableType):
        def __repr__(self):
            return "TableTypeCollection.RAM"

    @singleton
    class HSH(TableType):
        def __repr__(self):
            return "TableTypeCollection.HSH"


class Table:
    def __init__(self, table_fields, size, table_type):
        if isinstance(table_fields, TableFieldsCollection.TableFields):
            self.table_fields = table_fields
        else:
            raise TypeError("invalid %s of table fields (%s). Should be %s."
                            % (type(table_fields), table_fields, TableFieldsCollection.TableFields))
        if isinstance(size, Size):
            self.size = size
        else:
            raise TypeError("invalid %s of size (%s). Should be %s."
                            % (type(size), size, Size))
        if isinstance(table_type, TableTypeCollection.TableType):
            self.table_type = table_type
        else:
            raise TypeError("invalid %s of table type (%s). Should be %s."
                            % (type(table_type), table_type, TableTypeCollection.TableType))

    def __repr__(self):
        return "Table(" + repr(self.table_fields) + "," + repr(self.size) + "," + repr(self.table_type) + ")"


class TableDecls(dict):
    def __setitem__(self, table_id, table):
        if isinstance(table_id, TableId):
            pass
        else:
            raise TypeError("invalid %s of table id (%s). Should be %s."
                            % (type(table_id), table_id, TableId))
        if isinstance(table, Table):
            pass
        else:
            raise TypeError("invalid %s of table (%s). Should be %s."
                            % (type(table), table, Table))
        dict.__setitem__(self, table_id, table)

    def __getitem__(self, table_id):
        if isinstance(table_id, TableId):
            return dict.__getitem__(self, table_id)
        else:
            raise TypeError("invalid %s of table id (%s). Should be %s."
                            % (type(table_id), table_id, TableId))

    def __repr__(self):
        _repr = "TableDecls("

        __repr = ""
        for table_id, table in self.iteritems():
            __repr += "(" + repr(table_id) + ":" + repr(table) + "),"
        if __repr:
            __repr = __repr[:-1]

        _repr += _repr + ")"
        return _repr


class Decls:
    def __init__(self, table_decls=TableDecls()):
        if isinstance(table_decls, TableDecls):
            self.table_decls = table_decls
        else:
            raise TypeError("invalid %s of table declarations (%s). Should be %s."
                            % (type(table_decls), table_decls, TableDecls))

    def __repr__(self):
        return "Decls(" + repr(self.table_decls) + ")"


class InstructionCollection:
    def __init__(self):
        raise NotImplementedError

    class Instruction:
        pass

    class Instructions(list):
        def __init__(self, *args):
            for arg in args:
                if isinstance(arg, InstructionCollection.Instruction):
                    list.append(self, arg)
                else:
                    raise TypeError("invalid %s of argument (%s). Should be %s."
                                    % (type(arg), arg, InstructionCollection.Instruction))

        def __setitem__(self, index, instruction):
            if isinstance(instruction, InstructionCollection.Instruction):
                list.__setitem__(self, index, instruction)
            else:
                raise TypeError("invalid %s of instruction (%s). Should be %s."
                                % (type(instruction), instruction, InstructionCollection.Instruction))

        def __getitem__(self, index):
            return list.__getitem__(self, index)

        def __repr__(self):
            _repr = "InstructionCollection.Instructions("

            __repr = ""
            for instruction in self:
                __repr += repr(instruction) + ","
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class Code:
        def __init__(self, argument_fields, instructions):
            if isinstance(argument_fields, Fields):
                self.argument_fields = argument_fields
            else:
                raise TypeError("invalid %s of arguments fields (%s). Should be %s."
                                % (type(argument_fields), argument_fields, Fields))
            if isinstance(instructions, InstructionCollection.Instructions):
                self.instructions = instructions
            else:
                raise TypeError("invalid %s of instructions (%s). Should be %s."
                                % (type(instructions), instructions, InstructionCollection.Instructions))

        def __repr__(self):
            return "InstructionCollection.Code(" + repr(self.argument_fields) + "," + repr(self.instructions) + ")"

    class Codes(list):
        def __init__(self, *args):
            for arg in args:
                if isinstance(arg, InstructionCollection.Code):
                    list.append(self, arg)
                else:
                    raise TypeError("invalid %s of argument (%s). Should be %s."
                                    % (type(arg), arg, InstructionCollection.Code))

        def __setitem__(self, index, code):
            if isinstance(code, InstructionCollection.Code):
                list.__setitem__(self, index, code)
            else:
                raise TypeError("invalid %s of code (%s). Should be %s."
                                % (type(code), code, InstructionCollection.Code))

        def __getitem__(self, index):
            return list.__getitem__(self, index)

        def __repr__(self):
            _repr = "InstructionCollection.Codes("

            __repr = ""
            for code in self:
                __repr += repr(code) + ","
            if __repr:
                __repr = __repr[:-1]

            _repr += __repr + ")"
            return _repr

    class ID(Instruction):
        def __repr__(self):
            return "InstructionCollection.ID()"

    class DRP(Instruction):
        def __init__(self, reason=Reason('', '')):
            if isinstance(reason, Reason):
                self.reason = reason
            else:
                raise TypeError("invalid %s of reason (%s). Should be %s."
                                % (type(reason), reason, Reason))

        def __repr__(self):
            return "InstructionCollection.DRP(" + repr(self.reason) + ")"

    class CTR(Instruction):
        def __init__(self, reason=Reason('', '')):
            if isinstance(reason, Reason):
                self.reason = reason
            else:
                raise TypeError("invalid %s of reason (%s). Should be %s."
                                % (type(reason), reason, Reason))

        def __repr__(self):
            return "InstructionCollection.CTR(" + repr(self.reason) + ")"

    class ADD(Instruction):
        def __init__(self, field, size):
            if isinstance(field, OperandCollection.Field):
                self.field = field
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, OperandCollection.Field))
            if isinstance(size, Size):
                self.size = size
            else:
                raise TypeError("invalid %s of size (%s). Should be %s."
                                % (type(size), size, Size))

        def __repr__(self):
            return "InstructionCollection.ADD(" + repr(self.field) + "," + repr(self.size) + ")"

    class RMV(Instruction):
        def __init__(self, field):
            if isinstance(field, OperandCollection.Field):
                self.field = field
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(field), field, Field))

        def __repr__(self):
            return "InstructionCollection.RMV(" + repr(self.field) + ")"

    class LD(Instruction):
        def __init__(self, destination, source):
            if isinstance(destination, OperandCollection.Operand__):
                self.destination = destination
            else:
                raise TypeError("invalid %s of destination (%s). Should be %s."
                                % (type(destination), destination, OperandCollection.Operand__))
            if isinstance(source, OperandCollection.Operand):
                self.source = source
            else:
                raise TypeError("invalid %s of source (%s). Should be %s."
                                % (type(source), source, OperandCollection.Operand))

        def __repr__(self):
            return "InstructionCollection.LD(" + repr(self.destination) + "," + repr(self.source) + ")"

    class ST(Instruction):
        def __init__(self, location, source):
            if isinstance(location, OperandCollection.Location):
                self.location = location
            else:
                raise TypeError("invalid %s of location (%s). Should be %s."
                                % (type(location), location, OperandCollection.Location))
            if isinstance(source, OperandCollection.Operand_):
                self.source = source
            else:
                raise TypeError("invalid %s of source (%s). Should be %s."
                                % (type(source), source, OperandCollection.Operand_))

        def __repr__(self):
            return "InstructionCollection.ST(" + repr(self.location) + "," + repr(self.source) + ")"

    class OP(Instruction):
        def __init__(self, destination, left_source, operator, right_source):
            if isinstance(destination, OperandCollection.Operand__):
                self.destination = destination
            else:
                raise TypeError("invalid %s of destination (%s). Should be %s."
                                % (type(destination), destination, OperandCollection.Operand__))
            if isinstance(left_source, OperandCollection.Operand_):
                self.left_source = left_source
            else:
                raise TypeError("invalid %s of left source (%s). Should be %s."
                                % (type(left_source), left_source, OperandCollection.Operand_))
            if isinstance(operator, OperatorCollection.ArithmeticBitwiseOperator):
                self.operator = operator
            else:
                raise TypeError("invalid %s of operator (%s). Should be %s."
                                % (type(operator), operator, OperatorCollection.ArithmeticBitwiseOperator))
            if isinstance(right_source, OperandCollection.Operand_):
                self.right_source = right_source
            else:
                raise TypeError("invalid %s of right source (%s). Should be %s."
                                % (type(right_source), right_source, OperandCollection.Operand_))

        def __repr__(self):
            return "InstructionCollection.OP(" + repr(self.destination) + "," + repr(self.left_source) + \
                   "," + repr(self.operator) + "," + repr(self.right_source) + ")"

    class PUSH(Instruction):
        def __init__(self, location, source):
            if isinstance(location, OperandCollection.Location):
                self.location = location
            else:
                raise TypeError("invalid %s of location (%s). Should be %s."
                                % (type(location), location, OperandCollection.Location))
            if isinstance(source, OperandCollection.Operand_):
                self.field = source
            else:
                raise TypeError("invalid %s of field (%s). Should be %s."
                                % (type(source), source, OperandCollection.Operand_))

        def __repr__(self):
            return "InstructionCollection.PUSH(" + repr(self.location) + "," + repr(self.field) + ")"

    class POP(Instruction):
        def __init__(self, destination, location):
            if isinstance(destination, OperandCollection.Operand__):
                self.destination = destination
            else:
                raise TypeError("invalid %s of destination (%s). Should be %s."
                                % (type(destination), destination, OperandCollection.Operand__))
            if isinstance(location, OperandCollection.Location):
                self.location = location
            else:
                raise TypeError("invalid %s of location (%s). Should be %s."
                                % (type(location), location, OperandCollection.Location))

        def __repr__(self):
            return "InstructionCollection.POP(" + repr(self.destination) + "," + repr(self.location) + ")"

    class BR(Instruction):
        def __init__(self, left_source, operator, right_source, label):
            if isinstance(left_source, OperandCollection.Operand_):
                self.left_source = left_source
            else:
                raise TypeError("invalid %s of left source (%s). Should be %s."
                                % (type(left_source), left_source, OperandCollection.Operand_))
            if isinstance(operator, OperatorCollection.ComparisonOperator):
                self.operator = operator
            else:
                raise TypeError("invalid %s of operator (%s). Should be %s."
                                % (type(operator), operator, OperatorCollection.ComparisonOperator))
            if isinstance(right_source, OperandCollection.Operand_):
                self.right_source = right_source
            else:
                raise TypeError("invalid %s of right source (%s). Should be %s."
                                % (type(right_source), right_source, OperandCollection.Operand_))
            if isinstance(label, Label):
                self.label = label
            else:
                raise TypeError("invalid %s of label (%s). Should be %s."
                                % (type(label), label, Label))

        def __repr__(self):
            return "InstructionCollection.BR(" + repr(self.left_source) + "," + \
                   repr(self.operator) + "," + repr(self.right_source) + "," + repr(self.label) + ")"

    class JMP(Instruction):
        def __init__(self, label):
            if isinstance(label, Label):
                self.label = label
            else:
                raise TypeError("invalid %s of label (%s). Should be %s."
                                % (type(label), label, Label))

        def __repr__(self):
            return "InstructionCollection.JMP(" + repr(self.label) + ")"

    class LBL(Instruction):
        def __init__(self, label):
            if isinstance(label, Label):
                self.label = label
            else:
                raise TypeError("invalid %s of label (%s). Should be %s."
                                % (type(label), label, Label))

        def __repr__(self):
            return "InstructionCollection.LBL(" + repr(self.label) + ")"

    class LDt(Instruction):
        def __init__(self, destinations, table_id, index):
            if isinstance(destinations, OperandCollection.Operands__):
                self.destinations = destinations
            else:
                raise TypeError("invalid %s of destinations (%s). Should be %s."
                                % (type(destinations), destinations, OperandCollection.Operands__))
            if isinstance(table_id, TableId):
                self.table_id = table_id
            else:
                raise TypeError("invalid %s of table id (%s). Should be %s."
                                % (type(table_id), table_id, TableId))
            if isinstance(index, OperandCollection.Operand_):
                self.index = index
            else:
                raise TypeError("invalid %s of index (%s). Should be %s."
                                % (type(index), index, OperandCollection.Operand_))

        def __repr__(self):
            return "InstructionCollection.LDt(" + repr(self.destinations) + "," + repr(self.table_id) + "," \
                   + repr(self.index) + ")"

    class STt(Instruction):
        def __init__(self, table_id, index, sources):
            if isinstance(table_id, TableId):
                self.table_id = table_id
            else:
                raise TypeError("invalid %s of table id (%s). Should be %s."
                                % (type(table_id), table_id, TableId))
            if isinstance(index, OperandCollection.Operand_):
                self.index = index
            else:
                raise TypeError("invalid %s of index (%s). Should be %s."
                                % (type(index), index, OperandCollection.Operand_))
            if isinstance(sources, OperandCollection.Operands_):
                self.sources = sources
            elif isinstance(sources, OperandCollection.OperandsMasks_):
                self.sources = sources
            else:
                raise TypeError("invalid %s of sources (%s). Should be either %s or %s."
                                % (type(sources), sources, OperandCollection.Operands_,
                                   OperandCollection.OperandsMasks_))

        def __repr__(self):
            return "InstructionCollection.STt(" + repr(self.table_id) + "," + repr(self.index) + "," \
                   + repr(self.sources) + ")"

    class INCt(Instruction):
        def __init__(self, table_id, index):
            if isinstance(table_id, TableId):
                self.table_id = table_id
            else:
                raise TypeError("invalid %s of table id (%s). Should be %s."
                                % (type(table_id), table_id, TableId))
            if isinstance(index, OperandCollection.Operand_):
                self.index = index
            else:
                raise TypeError("invalid %s of index (%s). Should be %s."
                                % (type(index), index, OperandCollection.Operand_))

        def __repr__(self):
            return "InstructionCollection.STt(" + repr(self.table_id) + "," + repr(self.index) + ")"

    class LKt(Instruction):
        def __init__(self, index, table_id, sources):
            if isinstance(index, OperandCollection.Operand__):
                self.index = index
            else:
                raise TypeError("invalid %s of index (%s). Should be %s."
                                % (type(index), index, OperandCollection.Operands__))
            if isinstance(table_id, TableId):
                self.table_id = table_id
            else:
                raise TypeError("invalid %s of table id (%s). Should be %s."
                                % (type(table_id), table_id, TableId))
            if isinstance(sources, OperandCollection.Operands_):
                self.sources = sources
            else:
                raise TypeError("invalid %s of sources (%s). Should be %s."
                                % (type(sources), sources, OperandCollection.Operands_))

        def __repr__(self):
            return "InstructionCollection.STt(" + repr(self.index) + "," + repr(self.table_id) + "," \
                   + repr(self.sources) + ")"

    class CRC(Instruction):
        def __init__(self, destination, sources):
            if isinstance(destination, OperandCollection.Operand__):
                self.destination = destination
            else:
                raise TypeError("invalid %s destination (%s). Should be %s."
                                % (type(destination), destination, OperandCollection.Operand__))
            if isinstance(sources, OperandCollection.Operands_):
                self.sources = sources
            else:
                raise TypeError("invalid %s sources (%s). Should be %s."
                                % (type(sources), sources, OperandCollection.Operands_))

        def __repr__(self):
            return "InstructionCollection.CRC(" + repr(self.destination) + "," + repr(self.sources) + ")"

    class HSH(Instruction):
        def __init__(self, destination, sources):
            if isinstance(destination, OperandCollection.Operand__):
                self.destination = destination
            else:
                raise TypeError("invalid %s of destination (%s). Should be %s."
                                % (type(destination), destination, OperandCollection.Operand__))
            if isinstance(sources, OperandCollection.Operands_):
                self.sources = sources
            else:
                raise TypeError("invalid %s of sources (%s). Should be %s."
                                % (type(sources), sources, OperandCollection.Operands_))

        def __repr__(self):
            return "InstructionCollection.CRC(" + repr(self.destination) + "," + repr(self.sources) + ")"

    class HLT(Instruction):
        def __repr__(self):
            return "InstructionCollection.HLT()"

    class CNC(Instruction):
        def __init__(self, codes):
            if isinstance(codes, InstructionCollection.Codes):
                self.codes = codes
            else:
                raise TypeError("invalid %s of codes (%s). Should be %s."
                                % (type(codes), codes, InstructionCollection.Codes))

        def __repr__(self):
            return "InstructionCollection.CNC(" + repr(self.codes) + ")"

    class ATM(Instruction):
        def __init__(self, code):
            if isinstance(code, InstructionCollection.Code):
                self.code = code
            else:
                raise TypeError("invalid %s of code (%s). Should be %s."
                                % (type(code), code, InstructionCollection.Code))

        def __repr__(self):
            return "InstructionCollection.ATM(" + repr(self.code) + ")"

    class SEQ(Instruction):
        def __init__(self, code):
            if isinstance(code, InstructionCollection.Code):
                self.code = code
            else:
                raise TypeError("invalid %s of code (%s). Should be %s."
                                % (type(code), code, InstructionCollection.Code))

        def __repr__(self):
            return "InstructionCollection.ATM(" + repr(self.code) + ")"


class Policy:
    def __init__(self, decls, code):
        if isinstance(decls, Decls):
            self.decls = decls
        else:
            raise TypeError("invalid %s of declarations (%s). Should be %s."
                            % (type(decls), decls, Decls))
        if isinstance(code, InstructionCollection.Code):
            self.code = code
        else:
            raise TypeError("invalid %s of code (%s). Should be %s."
                            % (type(code), code, InstructionCollection.Code))

    def __repr__(self):
        return "Policy(" + repr(self.decls) + "," + repr(self.code) + ")"
