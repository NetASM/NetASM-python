# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        table_based_simple.py
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
    ### Declarations ###
    decls = Decls(TableDecls())

    ## Tables ##
    TABLE_SIZE = Size(2)
    decls.table_decls[TableId('match_table')] = \
        Table(TableFieldsCollection.MatchFields(),
            TABLE_SIZE,
            TableTypeCollection.CAM)
    match_table = decls.table_decls[TableId('match_table')]
    match_table.table_fields[Field('eth_src')] = Size(48), MatchTypeCollection.Binary

    decls.table_decls[TableId('params_table')] = \
        Table(TableFieldsCollection.SimpleFields(),
            TABLE_SIZE,
            TableTypeCollection.RAM)
    params_table = decls.table_decls[TableId('params_table')]
    params_table.table_fields[Field('outport_bitmap')] = Size(2)
    # Note: outport_bitmap is a bitmap

    ### Code ###
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

            ##################
            ## Pass through ##
            ##################

            # Add the following header fields in the header set
            I.ADD(O.Field(Field('index')),
                  Size(16)),

            # Lookup in the match table and store the matched index
            I.LKt(O.Field(Field('index')),
                  TableId('match_table'),
                  O.Operands_(
                      O.Field(Field('eth_src')))),
            I.BR(O.Field(Field('index')),
                 Op.Neq,
                 O.Value(Value(-1, Size(16))),
                 Label('LBL_PT_0')),

            # Case: there is not match in the match table
            # send to controller
            I.CTR(Reason('MATCH_TABLE_MISS', '')),
            I.JMP(Label('LBL_HLT')),

            # Case: there is a match in the l2 match table
            I.LBL(Label('LBL_PT_0')),

            # Load output port and others from the l2 parameters table
            I.LDt(
                O.Operands__(
                    O.Field(Field('outport_bitmap'))),
                TableId('params_table'),
                O.Field(Field('index'))),

            ##########
            ## Halt ##
            ##########
            I.LBL(Label('LBL_HLT')),
            I.HLT()
        )
    )

    return Policy(decls, code)