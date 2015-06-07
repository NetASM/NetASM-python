# ################################################################################-
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        hub.py
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

from netasm.netasm.core import *


def main():
    decls = Decls(TableDecls())

    PORT_COUNT_BITMAP = 0xFFFF  # mean [... bit(1): port_2, bit(0): port_1]

    code = I.Code(
        Fields(),
        I.Instructions(
            I.OP(
                O.Field(Field('outport_bitmap')),
                O.Field(Field('inport_bitmap')),
                Op.Xor,
                O.Value(Value(PORT_COUNT_BITMAP, Size(16))),
            ),
            I.HLT()
        )
    )

    return Policy(decls, code)

