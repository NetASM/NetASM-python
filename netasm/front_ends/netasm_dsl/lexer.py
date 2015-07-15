# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        lexer.py
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

from ply import lex
from ply.lex import TOKEN


class Lexer:
    def __init__(self):
        self.lexer = None

    keywords = (
        # Operators
        'Add', 'Sub', 'Mul', 'Div', 'And', 'Or', 'Xor',

        # Comparators
        'Eq', 'Neq', 'Lt', 'Gt', 'Le', 'Ge',

        # Instructions
        'ID', 'DRP', 'CTR', 'ADD', 'RMV',
        'LD', 'ST', 'OP', 'PUSH', 'POP',
        'BR', 'JMP', 'LBL', 'LDt', 'STt',
        'INCt', 'LKt', 'CRC', 'HSH', 'HLT',
        'CNC', 'ATM', 'SEQ',

        # Match types
        'Binary', 'Ternary',

        # Table types
        'CAM', 'RAM', 'HASH'
    )

    keywords_map = {}
    for keyword in keywords:
        keywords_map[keyword] = keyword

    tokens = (
        # Identifiers and strings
        'IDN', 'STR',

        # Numbers and (Hexa)Decimal
        'NUM', 'DEC', 'HEX',

        # Delimeters
        'LPAREN', 'RPAREN',  # ()
        'LBRACKET', 'RBRACKET',  # []

        # Assignment
        'EQUAL',

        # Location
        'LOC',

        # Special
        'S_DECLS', 'S_CODE', 'S_FIELDS', 'S_INSTRS'
    )

    tokens += keywords

    t_ignore = ' \t'

    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_LBRACKET = r'\['
    t_RBRACKET = r'\]'

    t_EQUAL = r'='

    t_LOC = r'::[lL]'

    t_S_DECLS = r'\.decls'
    t_S_CODE = r'\.code'
    t_S_FIELDS = r'\.fields'
    t_S_INSTRS = r'\.instrs'

    t_NUM = r'[0-9]+'
    t_DEC = r"'[dD][-+]?[0-9]+"
    t_HEX = r"'[hH][0-9a-fA-F]+"

    identifier = r'[a-zA-Z_][0-9a-zA-Z_]*'

    @TOKEN(identifier)
    def t_IDN(self, t):
        t.type = self.keywords_map.get(t.value, "IDN")
        return t

    t_STR = '\"[^\"]*\"'

    comment = r'[#][^\n]*'

    @TOKEN(comment)
    def t_comment(self, t):
        pass

    newline = r'\n+'

    @TOKEN(newline)
    def t_newline(self, t):
        t.lexer.lineno += len(t.value)

    def t_error(self, t):
        print "Illegal character '%s'" % t.value[0]
        t.lexer.skip(1)

    def warning(self, t):
        print "Illegal character '%s'" % t.value[0]
        t.lexer.skip(1)

    def reset_lineno(self):
        self.lexer.lineno = 1

    def get_lineno(self):
        return self.lexer.lineno

    def input(self, text):
        self.lexer.input(text)

    def token(self):
        t = self.lexer.token()
        return t

    def find_tok_column(self, token):
        last_cr = self.lexer.lexdata.rfind('\n', 0, token.lexpos)
        return token.lexpos - last_cr

    def build(self, **kwargs):
        self.lexer = lex.lex(module=self, **kwargs)


if __name__ == '__main__':
    lexer = Lexer()
    lexer.build()
    lexer.input('''
.code (
    .fields ()
    .instrs (
        ADD reg0 16
        LD reg0 16'd-4
        LBL "LBL_0"
        BR reg0 Eq 16'd0 "LBL_HLT"
        OP reg0 reg0 Sub 'h1
        JMP "LBL_0"
        LBL "LBL_HLT"
        LD outport_bitmap reg0
        HLT
    )
)
    ''')

    while True:
        t = lexer.token()
        if not t: break
        print t
