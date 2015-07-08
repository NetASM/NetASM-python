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

    def get_base(self, x):
        if x.lower() == "'b":
            return 2
        elif x.lower() == "'o":
            return 8
        elif x.lower() == "'d":
            return 10
        elif x.lower() == "'h":
            return 16

    def p_value(self, p):  # TODO: remove the Size class, it's actually Value
        ''' value : NUM BASE NUM
                  | BASE NUM
                  | NUM
        '''
        if len(p) == 4:
            base = self.get_base(p[2])
            p[0] = Value(int(p[3], base), Size(int(p[1])))
        elif len(p) == 3:
            base = self.get_base(p[1])
            p[0] = Value(int(p[2], base), Size(64))
        else:
            p[0] = Value(int(p[1]), Size(64))

    def p_size(self, p):  # TODO: correct this in the semantics!
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
                   | fields COMMA field
        '''
        if len(p) == 2:
            if not p[1]:
                p[0] = Fields()
            else:
                p[0] = Fields(p[1])
        else:
            p[1].append(p[3])
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
        ''' reason : STR COLON STR
        '''
        p[0] = Reason(p[1], p[3])

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
                       | operands__ COMMA operand__
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.Operands__(p[1])
        else:
            p[1].append(p[3])
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
                      | operands_ COMMA operand_
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.Operands_(p[1])
        else:
            p[1].append(p[3])
            p[0] = p[1]

    def p_operand_mask_(self, p):
        ''' operand_mask_ : LPAREN operand_ COMMA mask RPAREN
        '''
        p[0] = (p[2], p[4])

    def p_operands_masks_(self, p):
        ''' operands_masks_ : operand_mask_
                            | operands_masks_ COMMA operand_mask_
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = OperandCollection.OperandsMasks_(p[1])
        else:
            p[1].append(p[3])
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
        ''' location : operand_
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
        ''' match_field : LPAREN field COMMA size COMMA match_type RPAREN
        '''
        p[0] = p[2], (p[4], p[6])

    def p_match_fields(self, p):
        ''' match_fields : match_field
                         | match_fields COMMA match_field
        '''
        if len(p) == 2:
            if p[1]:
                field, (size, match_type) = p[1]

                p[0] = TableFieldsCollection.MatchFields()
                p[0][field] = (size, match_type)
        else:
            field, (size, match_type) = p[3]

            p[1][field] = (size, match_type)
            p[0] = p[1]

    def p_simple_field(self, p):
        ''' simple_field : LPAREN field COMMA size RPAREN
        '''
        p[0] = p[2], p[4]

    def p_simple_fields(self, p):
        ''' simple_fields : simple_field
                          | simple_fields COMMA simple_field
        '''
        if len(p) == 2:
            if p[1]:
                field, size = p[1]

                p[0] = TableFieldsCollection.SimpleFields()
                p[0][field] = size
        else:
            field, size = p[3]

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
        ''' table : LPAREN LBRACKET table_fields RBRACKET COMMA size COMMA table_type RPAREN
        '''
        p[0] = Table(p[3], p[6], p[8])

    def p_table_decl(self, p):
        ''' table_decl : table_id EQUAL table
        '''
        p[0] = p[1], p[3]

    def p_table_decls(self, p):
        ''' table_decls : empty
                        | table_decl
                        | table_decls SEMI table_decl
        '''
        if len(p) == 2:
            if not p[1]:
                p[0] = TableDecls()
            else:
                table_id, table = p[1]

                p[0] = TableDecls()
                p[0][table_id] = table
        else:
            table_id, table = p[3]

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
                        | ADD operand__ COMMA size
                        | RMV operand__
                        | LD operand__ COMMA operand
                        | ST location COMMA operand_
                        | OP operand__ COMMA operand_ COMMA operator COMMA operand_
                        | PUSH location COMMA operand_
                        | POP operand__ COMMA location
                        | BR operand_ COMMA comparator COMMA operand_ COMMA label
                        | JMP label
                        | LBL label
                        | LDt LBRACKET operands__ RBRACKET COMMA table_id COMMA operand_
                        | STt table_id COMMA operand_ COMMA LBRACKET operands_masks_ RBRACKET
                        | INCt table_id COMMA operand_
                        | LKt operand__ COMMA table_id COMMA LBRACKET operands_ RBRACKET
                        | CRC operand__ COMMA LBRACKET operands_ RBRACKET
                        | HSH operand__ COMMA LBRACKET operands_ RBRACKET
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
            p[0] = InstructionCollection.ADD(p[2], p[4])
        elif p[1] == 'RMV':
            p[0] = InstructionCollection.RMV(p[2])
        elif p[1] == 'LD':
            p[0] = InstructionCollection.LD(p[2], p[4])
        elif p[1] == 'ST':
            p[0] = InstructionCollection.ST(p[2], p[4])
        elif p[1] == 'OP':
            p[0] = InstructionCollection.OP(p[2], p[4], p[6], p[8])
        elif p[1] == 'PUSH':
            p[0] = InstructionCollection.PUSH(p[2], p[4])
        elif p[1] == 'POP':
            p[0] = InstructionCollection.POP(p[2], p[4])
        elif p[1] == 'BR':
            p[0] = InstructionCollection.BR(p[2], p[4], p[6], p[8])
        elif p[1] == 'JMP':
            p[0] = InstructionCollection.JMP(p[2])
        elif p[1] == 'LBL':
            p[0] = InstructionCollection.LBL(p[2])
        elif p[1] == 'LDt':
            p[0] = InstructionCollection.LDt(p[3], p[6], p[8])
        elif p[1] == 'STt':
            p[0] = InstructionCollection.STt(p[2], p[4], p[7])
        elif p[1] == 'INCt':
            p[0] = InstructionCollection.INCt(p[2], p[4])
        elif p[1] == 'LKt':
            p[0] = InstructionCollection.LKt(p[2], p[4], p[7])
        elif p[1] == 'CRC':
            p[0] = InstructionCollection.CRC(p[2], p[5])
        elif p[1] == 'HSH':
            p[0] = InstructionCollection.HSH(p[2], p[5])
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
                         | instructions SEMI instruction
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = InstructionCollection.Instructions(p[1])
        else:
            p[1].append(p[3])
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
                  | codes COMMA code
        '''
        if len(p) == 2:
            if p[1]:
                p[0] = InstructionCollection.Codes(p[1])
        else:
            p[1].append(p[3])
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
.decls (
  acl_match_table =
    ([(ipv4_src, 32, Binary),
      (ipv4_dst, 32, Binary)], 2048, CAM)
)
.code (
  .fields (
    outport, inport, bit_length
  )
  .instrs (
    ADD eth_dst, 16'd48;
    ADD eth_src, 16'd48;
    ADD eth_type, 16'd16;

    LD eth_dst, 16'h0;
    LD eth_src, 16'd48;
    LD eth_type, 16'd96;

    BR eth_type, Eq, 16'h0800, "LBL_PARSE_0";

    CTR "PARSER":"UNHANDLED_IP_PAYLOAD";

    CNC (
      .code (
        .fields ()
        .instrs (
          LD eth_type, 96;
          HLT
        )
      ),
      .code (
        .fields ()
        .instrs (
          HLT
        )
      )
    );

    HLT
  )
)
    ''')

    print policy, errors_cnt
