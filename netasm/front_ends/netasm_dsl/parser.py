# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        parser.py
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

from ply import yacc
from lexer import Lexer
from netasm.netasm.core import *


class Parser:
    def __init__(self):
        self.lexer = Lexer()
        self.lexer.build()

        self.tokens = self.lexer.tokens

        self.parser = yacc.yacc(module=self, start='policy',
                                write_tables=0, debug=False)

        self.errors_cnt = 0

    def parse(self, input):
        self.lexer.reset_lineno()
        policy = self.parser.parse(input=input,
                                   lexer=self.lexer)
        return policy, self.errors_cnt

    def print_error(self, lineno, msg):
        self.errors_cnt += 1
        print "parse error at line", lineno, ":", msg

    def p_empty(self, p):
        ''' empty :
        '''
        pass

    def get_value(self, x):
        if "'d" in x.lower():
            return int(x[2:], 10)
        elif "'h" in x.lower():
            return int(x[2:], 16)

    def p_value_number(self, p):
        ''' value_number : DEC
                         | HEX
        '''
        p[0] = p[1]

    def p_value(self, p):  # TODO: remove the Size class, it's actually Value class
        ''' value : NUM value_number
        '''
        p[0] = Value(self.get_value(p[2]), Size(int(p[1])))

    def p_size(self, p):
        ''' size : value
        '''
        p[0] = Size(p[1].value)

    def p_field(self, p):
        ''' field : IDN
        '''
        p[0] = Field(p[1])

    def p_fields(self, p):
        ''' fields : empty
                   | field
                   | fields field
        '''
        if len(p) == 2:
            if not p[1]:
                p[0] = Fields()
            else:
                p[0] = Fields(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_mask(self, p):
        ''' mask : value
        '''
        p[0] = Mask(p[1].value)

    def p_label(self, p):
        ''' label : STR
        '''
        p[0] = Label(p[1])

    def p_reason(self, p):
        ''' reason : STR STR
        '''
        p[0] = Reason(p[1], p[2])

    def p_operator(self, p):
        ''' operator : Add
                     | Sub
                     | Mul
                     | Div
                     | And
                     | Or
                     | Xor
        '''
        if p[1] == 'Add':
            p[0] = OperatorCollection.Add
        elif p[1] == 'Sub':
            p[0] = OperatorCollection.Sub
        elif p[1] == 'Mul':
            p[0] = OperatorCollection.Mul
        elif p[1] == 'Div':
            p[0] = OperatorCollection.Div
        elif p[1] == 'And':
            p[0] = OperatorCollection.And
        elif p[1] == 'Or':
            p[0] = OperatorCollection.Or
        elif p[1] == 'Xor':
            p[0] = OperatorCollection.Xor

    def p_comparator(self, p):
        ''' comparator : Eq
                       | Neq
                       | Lt
                       | Gt
                       | Le
                       | Ge
        '''
        if p[1] == 'Eq':
            p[0] = OperatorCollection.Eq
        elif p[1] == 'Neq':
            p[0] = OperatorCollection.Neq
        elif p[1] == 'Lt':
            p[0] = OperatorCollection.Lt
        elif p[1] == 'Gt':
            p[0] = OperatorCollection.Gt
        elif p[1] == 'Le':
            p[0] = OperatorCollection.Le
        elif p[1] == 'Ge':
            p[0] = OperatorCollection.Ge

    def p_operand__(self, p):
        ''' operand__ : field
        '''
        p[0] = OperandCollection.Field(p[1])

    def p_operands__(self, p):
        ''' operands__ : operand__
                       | operands__ operand__
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.Operands__(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_operand_(self, p):
        ''' operand_ : operand__
                     | value
        '''
        if isinstance(p[1], Value):
            p[0] = OperandCollection.Value(p[1])
        else:
            p[0] = p[1]

    def p_operands_(self, p):
        ''' operands_ : operand_
                      | operands_ operand_
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.Operands_(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_operand_mask_(self, p):
        ''' operand_mask_ : LPAREN operand_ mask RPAREN
        '''
        p[0] = (p[2], p[3])

    def p_operands_masks_(self, p):
        ''' operands_masks_ : operand_mask_
                            | operands_masks_ operand_mask_
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.OperandsMasks_(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_operand(self, p):
        ''' operand : operand_
                    | location
        '''
        if isinstance(p[1], Location):
            p[0] = OperandCollection.Location(p[1])
        else:
            p[0] = p[1]

    def p_location(self, p):
        ''' location : operand_ LOC
        '''
        p[0] = Location(p[1])

    def p_table_id(self, p):
        ''' table_id : IDN
        '''
        p[0] = TableId(p[1])

    def p_match_type(self, p):
        ''' match_type : Binary
                       | Ternary
        '''
        if p[1] == 'Binary':
            p[0] = MatchTypeCollection.Binary
        elif p[1] == 'Ternary':
            p[0] = MatchTypeCollection.Ternary

    def p_match_field(self, p):
        ''' match_field : LPAREN field size match_type RPAREN
        '''
        p[0] = p[2], (p[3], p[4])

    def p_match_fields(self, p):
        ''' match_fields : match_field
                         | match_fields match_field
        '''
        if len(p) == 2:
            if p[1]:
                field, (size, match_type) = p[1]

                p[0] = TableFieldsCollection.MatchFields()
                p[0][field] = (size, match_type)
        else:
            field, (size, match_type) = p[2]

            p[1][field] = (size, match_type)
            p[0] = p[1]

    def p_simple_field(self, p):
        ''' simple_field : LPAREN field size RPAREN
        '''
        p[0] = p[2], p[3]

    def p_simple_fields(self, p):
        ''' simple_fields : simple_field
                          | simple_fields simple_field
        '''
        if len(p) == 2:
            if p[1]:
                field, size = p[1]

                p[0] = TableFieldsCollection.SimpleFields()
                p[0][field] = size
        else:
            field, size = p[2]

            p[1][field] = size
            p[0] = p[1]

    def p_table_fields(self, p):
        ''' table_fields : match_fields
                         | simple_fields
        '''
        p[0] = p[1]

    def p_table_type(self, p):
        ''' table_type : CAM
                       | RAM
                       | HASH
        '''
        if p[1] == 'CAM':
            p[0] = TableTypeCollection.CAM
        elif p[1] == 'RAM':
            p[0] = TableTypeCollection.RAM
        elif p[1] == 'HASH':
            p[0] = TableTypeCollection.HSH

    def p_table(self, p):
        ''' table : LPAREN LBRACKET table_fields RBRACKET size table_type RPAREN
        '''
        p[0] = Table(p[3], p[5], p[6])

    def p_table_decl(self, p):
        ''' table_decl : table_id EQUAL table
        '''
        p[0] = p[1], p[3]

    def p_table_decls(self, p):
        ''' table_decls : empty
                        | table_decl
                        | table_decls table_decl
        '''
        if len(p) == 2:
            if not p[1]:
                p[0] = TableDecls()
            else:
                table_id, table = p[1]

                p[0] = TableDecls()
                p[0][table_id] = table
        else:
            table_id, table = p[2]

            p[1][table_id] = table
            p[0] = p[1]

    def p_decls(self, p):
        ''' decls : S_DECLS LPAREN table_decls RPAREN
        '''
        p[0] = Decls(p[3])

    def p_instruction(self, p):
        ''' instruction : ID
                        | DRP
                        | DRP reason
                        | CTR
                        | CTR reason
                        | ADD operand__ size
                        | RMV operand__
                        | LD operand__ operand
                        | ST location operand_
                        | OP operand__ operand_ operator operand_
                        | PUSH location operand_
                        | POP operand__ location
                        | BR operand_ comparator operand_ label
                        | JMP label
                        | LBL label
                        | LDt LBRACKET operands__ RBRACKET table_id operand_
                        | STt table_id operand_ LBRACKET operands_ RBRACKET
                        | STt table_id operand_ LBRACKET operands_masks_ RBRACKET
                        | INCt table_id operand_
                        | LKt operand__ table_id LBRACKET operands_ RBRACKET
                        | CRC operand__ LBRACKET operands_ RBRACKET
                        | HSH operand__ LBRACKET operands_ RBRACKET
                        | HLT
                        | CNC LPAREN codes RPAREN
                        | ATM LPAREN code RPAREN
                        | SEQ LPAREN code RPAREN
        '''
        if p[1] == 'ID':
            p[0] = InstructionCollection.ID()
        elif p[1] == 'DRP':
            if len(p) == 2:
                p[0] = InstructionCollection.DRP()
            else:
                p[0] = InstructionCollection.DRP(p[2])
        elif p[1] == 'CTR':
            if len(p) == 2:
                p[0] = InstructionCollection.DRP()
            else:
                p[0] = InstructionCollection.DRP(p[2])
        elif p[1] == 'ADD':
            p[0] = InstructionCollection.ADD(p[2], p[3])
        elif p[1] == 'RMV':
            p[0] = InstructionCollection.RMV(p[2])
        elif p[1] == 'LD':
            p[0] = InstructionCollection.LD(p[2], p[3])
        elif p[1] == 'ST':
            p[0] = InstructionCollection.ST(OperandCollection.Location(p[2]), p[3])
        elif p[1] == 'OP':
            p[0] = InstructionCollection.OP(p[2], p[3], p[4], p[5])
        elif p[1] == 'PUSH':
            p[0] = InstructionCollection.PUSH(p[2], p[3])
        elif p[1] == 'POP':
            p[0] = InstructionCollection.POP(p[2], p[3])
        elif p[1] == 'BR':
            p[0] = InstructionCollection.BR(p[2], p[3], p[4], p[5])
        elif p[1] == 'JMP':
            p[0] = InstructionCollection.JMP(p[2])
        elif p[1] == 'LBL':
            p[0] = InstructionCollection.LBL(p[2])
        elif p[1] == 'LDt':
            p[0] = InstructionCollection.LDt(p[3], p[5], p[6])
        elif p[1] == 'STt':
            p[0] = InstructionCollection.STt(p[2], p[3], p[5])
        elif p[1] == 'INCt':
            p[0] = InstructionCollection.INCt(p[2], p[3])
        elif p[1] == 'LKt':
            p[0] = InstructionCollection.LKt(p[2], p[3], p[5])
        elif p[1] == 'CRC':
            p[0] = InstructionCollection.CRC(p[2], p[4])
        elif p[1] == 'HSH':
            p[0] = InstructionCollection.HSH(p[2], p[4])
        elif p[1] == 'HLT':
            p[0] = InstructionCollection.HLT()
        elif p[1] == 'CNC':
            p[0] = InstructionCollection.CNC(p[3])
        elif p[1] == 'ATM':
            p[0] = InstructionCollection.ATM(p[3])
        elif p[1] == 'SEQ':
            p[0] = InstructionCollection.SEQ(p[3])
        else:
            # raise TypeError()
            pass

    def p_instructions(self, p):
        ''' instructions : instruction
                         | instructions instruction
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = InstructionCollection.Instructions(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_code_fields(self, p):
        ''' code_fields : S_FIELDS LPAREN fields RPAREN
        '''
        p[0] = p[3]

    def p_code_instructions(self, p):
        ''' code_instructions : S_INSTRS LPAREN instructions RPAREN
        '''
        p[0] = p[3]

    def p_code(self, p):
        ''' code : S_CODE LPAREN code_fields code_instructions RPAREN
                 | S_CODE LPAREN code_instructions RPAREN
        '''
        if len(p) == 6:
            p[0] = InstructionCollection.Code(p[3], p[4])
        else:
            p[0] = InstructionCollection.Code(Fields(), p[3])

    def p_codes(self, p):
        ''' codes : code
                  | codes code
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = InstructionCollection.Codes(p[1])
        else:
            p[1].append(p[2])
            p[0] = p[1]

    def p_policy(self, p):
        ''' policy : decls code
                   | code
        '''
        if len(p) == 3:
            p[0] = Policy(p[1], p[2])
        else:
            p[0] = Policy(Decls(), p[1])

    def p_error(self, p):
        if p is None:
            self.print_error(self.lexer.get_lineno(),
                             "Unexpected end-of-file (missing brace?)")
        else:
            self.print_error(
                p.lineno,
                "Syntax error while parsing at token %s (%s)" % (p.value, p.type)
            )


if __name__ == '__main__':
    parser = Parser()
    policy, errors_cnt = parser.parse('''
.code (
    .fields ()
    .instrs (
        ADD reg0 8'H16
        LD reg0 16'd4::l
        LBL "LBL_0"
        BR reg0 Eq 16'd0 "LBL_HLT"
        OP reg0 reg0 Sub 10'd-11
        JMP "LBL_0"
        LBL "LBL_HLT"
        LD outport_bitmap reg0
        HLT
    )
)
    ''')

    print policy, errors_cnt
