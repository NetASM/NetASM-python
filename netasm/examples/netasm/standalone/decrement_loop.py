__author__ = 'mshahbaz'

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
            I.ADD(
                O.Field(Field('reg0')),
                Size(16)
            ),
            I.LD(
                O.Field(Field('reg0')),
                O.Value(Value(4, Size(16)))
            ),
            I.LBL(Label('LBL_0')),
            I.BR(
                O.Field(Field('reg0')),
                Op.Eq,
                O.Value(Value(0, Size(16))),
                Label('LBL_HLT')
            ),
            I.OP(
                O.Field(Field('reg0')),
                O.Field(Field('reg0')),
                Op.Sub,
                O.Value(Value(1, Size(16))),
            ),
            I.JMP(Label('LBL_0')),
            I.LBL(Label('LBL_HLT')),
            I.LD(
                O.Field(Field('outport_bitmap')),
                O.Field(Field('reg0'))
            ),
            I.HLT()
        )
    )

    return Policy(decls, code)

# Testing
if __name__ == "__main__":
    policy = main()

    # CFG
    if False:
        import netasm.netasm.core.graphs.control_flow_graph as cfg
        graph = cfg.generate(policy.code.instructions)
        print graph

    # Cost
    if False:
        from netasm.netasm import cost
        area, latency = cost.cost_Policy(policy)
        print area, latency

    # Execute
    if True:
        from netasm.netasm import execute

        policy = execute.Execute(policy)

        state = execute.State(execute.Header(), execute.Packet(1000))
        # Add special fields (see netasm/core/common.py)
        state.header[Field('inport_bitmap')] = Value(0, Size(64))
        state.header[Field('outport_bitmap')] = Value(0xFFFF, Size(64))
        state.header[Field('bit_length')] = Value(len(state.packet), Size(64))
        state.header[Field('DRP')] = Value(0, Size(1))
        state.header[Field('CTR')] = Value(0, Size(1))

        policy.start()

        from netasm.netasm.core.utilities.profile import time_usage

        @time_usage
        def run():
            iterations = 1

            for i in range(iterations):
                policy.put(state)

            for i in range(iterations):
                _state = policy.get()
                print _state.header[Field('outport_bitmap')].value

        run()

        policy.stop()