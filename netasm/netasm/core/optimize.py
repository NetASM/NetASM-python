# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        optimize.py
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

from netasm.netasm.core.utilities.profile import time_usage
from netasm.netasm.core.syntax import InstructionCollection as I
from netasm.netasm.core.transformations import dead_code_elimination as dce
from netasm.netasm.core.transformations import redundant_code_elimination as rce
from netasm.netasm.core.transformations import add_code_motion as acm
from netasm.netasm.core.transformations import rmv_code_motion as rcm
# from netasm.netasm.core.transformations import rmv_code_insertion as rci


def _optimize_Code(code):
    code = acm.transform(code)
    code = rcm.transform(code)
    code = dce.transform(code)
    code = rce.transform(code)
    # code = rci.transform(code)

    return code


def optimize_Code(code):
    for instruction in code.instructions:
        if isinstance(instruction, I.CNC):
            codes = I.Codes()
            for _code in instruction.codes:
                codes.append(optimize_Code(_code))
            instruction.codes = codes
        elif isinstance(instruction, I.ATM):
            instruction.code = optimize_Code(instruction.code)
        elif isinstance(instruction, I.SEQ):
            instruction.code = optimize_Code(instruction.code)

    return _optimize_Code(code)


def optimize_Policy(policy):
    policy.code = optimize_Code(policy.code)
    return policy


@time_usage
def optimize_Policy__time_usage(policy):
    return optimize_Policy(policy)