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
        'CAM', 'RAM', 'HASH',
    )

    keywords_map = {}
    for keyword in keywords:
        keywords_map[keyword] = keyword

    tokens = (
        # Identifiers and strings
        'IDN', 'STR',

        # Numbers and base
        'NUM', 'BASE',

        # Delimeters
        'LPAREN', 'RPAREN',  # ()
        'LBRACKET', 'RBRACKET',  # []

        # Assignment, (semi) colon, and coma
        'EQUAL', 'COLON', 'SEMI', 'COMMA',

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
    t_COLON = r':'
    t_SEMI = r';'
    t_COMMA = r','

    t_S_DECLS = r'\.decls'
    t_S_CODE = r'\.code'
    t_S_FIELDS = r'\.fields'
    t_S_INSTRS = r'\.instrs'

    number = r'[0-9]+'

    @TOKEN(number)
    def t_NUM(self, t):
        # t.value = int(t.value)
        return t

    t_BASE = r"'[bBoOdDhH]"

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
.code
  .instructions
    HLT
    ''')

    while True:
        t = lexer.token()
        if not t: break
        print t
