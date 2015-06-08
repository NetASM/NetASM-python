# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        learning_switch.py
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


# NOTE: We are not considering loop avoidance but we do take into account host migration in this example


def main():
    # Constants
    PORT_COUNT_BITMAP = 0xFFFF  # means [... bit(1): port_2, bit(0): port_1]

    # Declarations
    decls = Decls(TableDecls())

    # Tables
    # Ethernet address table
    MAC_TABLE_SIZE = Size(16)
    decls.table_decls[TableId('eth_match_table')] = \
        Table(TableFieldsCollection.MatchFields(),
            MAC_TABLE_SIZE,
            TableTypeCollection.CAM)
    match_table = decls.table_decls[TableId('eth_match_table')]
    match_table.table_fields[Field('eth_addr')] = Size(48), MatchTypeCollection.Binary

    decls.table_decls[TableId('eth_params_table')] = \
        Table(TableFieldsCollection.SimpleFields(),
            MAC_TABLE_SIZE,
            TableTypeCollection.RAM)
    params_table = decls.table_decls[TableId('eth_params_table')]
    params_table.table_fields[Field('outport_bitmap')] = Size(3)

    # Index address table
    INDEX_TABLE_SIZE = Size(1)
    decls.table_decls[TableId('index_table')] = \
        Table(TableFieldsCollection.SimpleFields(),
            INDEX_TABLE_SIZE,
            TableTypeCollection.RAM)
    index_table = decls.table_decls[TableId('index_table')]
    index_table.table_fields[Field('index')] = Size(16)

    # Code
    code = I.Code(
        ##################
        ### Arguments ####
        ##################
        Fields(),

        ##################
        ## Instructions ##
        ##################
        I.Instructions(
            ##################
            ## Parse packet ##
            ##################

            # Add ethernet header fields in the header set
            I.ADD(O.Field(Field('eth_dst')),
                  Size(48)),
            I.ADD(O.Field(Field('eth_src')),
                  Size(48)),
            I.ADD(O.Field(Field('eth_type')),
                  Size(16)),

            # Load fields with default values
            I.LD(O.Field(Field('eth_dst')),
                 O.Value(Value(0, Size(48)))),
            I.LD(O.Field(Field('eth_src')),
                 O.Value(Value(0, Size(48)))),
            I.LD(O.Field(Field('eth_type')),
                 O.Value(Value(0, Size(16)))),

            # Parse ethernet
            # load ethernet header fields from the packet
            I.LD(O.Field(Field('eth_dst')),
                 O.Location(
                     Location(
                         O.Value(Value(0, Size(16)))))),
            I.LD(O.Field(Field('eth_src')),
                 O.Location(
                     Location(
                         O.Value(Value(48, Size(16)))))),
            I.LD(O.Field(Field('eth_type')),
                 O.Location(
                     Location(
                         O.Value(Value(96, Size(16)))))),

            ########################
            ## Lookup MAC address ##
            ########################

            # Add the following header fields in the header set
            I.ADD(O.Field(Field('index')),
                  Size(16)),

            I.ATM(
                I.Code(
                    Fields(Field('index'), Field('eth_dst'), Field('eth_src')),
                    I.Instructions(
                        # Lookup in the match table and store the matched index
                        I.LKt(O.Field(Field('index')),
                              TableId('eth_match_table'),
                              O.Operands_(
                                  O.Field(Field('eth_dst')))),
                        I.BR(O.Field(Field('index')),
                             Op.Neq,
                             O.Value(Value(-1, Size(16))),
                             Label('LBL_LKP_0')),

                        # Case: there is no match in the match table
                        # Broadcast the packet
                        I.OP(
                            O.Field(Field('outport_bitmap')),
                            O.Field(Field('inport_bitmap')),
                            Op.Xor,
                            O.Value(Value(PORT_COUNT_BITMAP, Size(16))),
                        ),
                        I.JMP(Label('LBL_LRN')),

                        # Case: there is a match in the l2 match table
                        I.LBL(Label('LBL_LKP_0')),

                        # Load output port from the parameters table
                        I.LDt(
                            O.Operands__(
                                O.Field(Field('outport_bitmap'))),
                            TableId('eth_params_table'),
                            O.Field(Field('index'))),

                        #######################
                        ## Learn MAC address ##
                        #######################
                        I.LBL(Label('LBL_LRN')),

                        # Lookup in the match table and store the matched index
                        I.LKt(O.Field(Field('index')),
                              TableId('eth_match_table'),
                              O.Operands_(
                                  O.Field(Field('eth_src')))),
                        I.BR(O.Field(Field('index')),
                             Op.Neq,
                             O.Value(Value(-1, Size(16))),
                             Label('LBL_LRN_0')),

                        # Case: there is no match in the match table
                        # Read the running index from the index table
                        I.LDt(
                            O.Operands__(
                                O.Field(Field('index'))),
                            TableId('index_table'),
                            O.Value(Value(0, Size(1)))),

                        # Store eth_src in the eth_match_table
                        I.STt(TableId('eth_match_table'),
                              O.Field(Field('index')),
                              O.OperandsMasks_(
                                  (O.Field(Field('eth_src')), Mask(0xFFFFFFFFFFFF)))),

                        # Store inport_bitmap in the eth_params_table
                        I.STt(TableId('eth_params_table'),
                              O.Field(Field('index')),
                              O.Operands_(
                                  O.Field(Field('inport_bitmap')))),

                        # Increment the running index
                        I.OP(
                            O.Field(Field('index')),
                            O.Field(Field('index')),
                            Op.Add,
                            O.Value(Value(1, Size(16))),
                        ),

                        # Check if the index is less than the MAC_TABLE_SIZE
                        I.BR(O.Field(Field('index')),
                             Op.Lt,
                             O.Value(Value(MAC_TABLE_SIZE, Size(16))),
                             Label('LBL_LRN_1')),

                        # Reset the running index
                        I.LD(O.Field(Field('index')),
                             O.Value(Value(0, Size(16)))),

                        # Store the running index back in the table
                        I.LBL(Label('LBL_LRN_1')),

                        I.STt(TableId('index_table'),
                              O.Value(Value(0, Size(1))),
                              O.Operands_(
                                  O.Field(Field('index')))),
                        I.JMP(Label('LBL_HLT')),

                        # Store the current inport_bitmap in the eth_params_table
                        I.LBL(Label('LBL_LRN_0')),

                        I.STt(TableId('eth_params_table'),
                              O.Field(Field('index')),
                              O.Operands_(
                                  O.Field(Field('inport_bitmap')))),

                        # Halt
                        I.LBL(Label('LBL_HLT')),
                        I.HLT()
                    )
                )
            ),

            ##########
            ## Halt ##
            ##########
            I.LBL(Label('LBL_HLT')),
            I.HLT()
        )
    )

    return Policy(decls, code)

# Testing
if __name__ == "__main__":
    policy = main()

    # Cost
    if True:
        from netasm.netasm import cost
        area, latency = cost.cost_Policy(policy)
        print area, latency

    # Execute
    if False:
        from netasm.netasm import execute

        policy = execute.Execute(policy)

        state = execute.State(execute.Header(), execute.Packet(1000))
        # Add special fields (see netasm/core/common.py)
        state.header[Field('inport_bitmap')] = Value(0, Size(64))
        state.header[Field('outport_bitmap')] = Value(0, Size(64))
        state.header[Field('bit_length')] = Value(len(state.packet), Size(64))
        state.header[Field('DRP')] = Value(0, Size(1))
        state.header[Field('CTR')] = Value(0, Size(1))

        policy.start()

        from netasm.netasm.core.utilities.profile import time_usage

        @time_usage
        def run():
            iterations = 100

            for i in range(iterations):
                policy.put(state)

            for i in range(iterations):
                policy.get()

        run()

        policy.stop()
