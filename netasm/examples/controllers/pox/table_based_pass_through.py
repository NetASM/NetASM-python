# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        table_based_pass_through.py
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

from pox.core import core
from pox.lib.util import dpidToStr

from netasm.netasm.core.common import ports_to_bitmap
from netasm.back_ends.soft_switch.api import OutMessage, InMessage, QueryMessage


log = core.getLogger()


def _handle_VendorIn(event):
    in_msg = InMessage(event.ofp)

    if in_msg.is_query_table_entry:
        print "Query Table Entry: %s %s %s" % (in_msg.table_name, in_msg.table_index, in_msg.table_entry)
    elif in_msg.is_query_table_list:
        print "Query Table List: %s" % (in_msg.table_list, )


def _handle_ConnectionUp(event):
    msg = OutMessage()

    msg.set_policy("netasm.examples.netasm.controller_assisted.table_based_simple")
    event.connection.send(msg)

    msg.add_table_entry('match_table', 0,
                        {'eth_src': (0x000000000001, 0xFFFFFFFFFFFF)})
    event.connection.send(msg)
    msg.add_table_entry('params_table', 0,
                        {'outport_bitmap': ports_to_bitmap(2)})
    event.connection.send(msg)

    msg.add_table_entry('match_table', 1,
                        {'eth_src': (0x000000000002, 0xFFFFFFFFFFFF)})
    event.connection.send(msg)
    msg.add_table_entry('params_table', 1,
                        {'outport_bitmap': ports_to_bitmap(1)})
    event.connection.send(msg)

    msg = QueryMessage()

    msg.table_entry('match_table', 0)
    event.connection.send(msg)
    msg.table_entry('params_table', 0)
    event.connection.send(msg)

    msg.table_entry('match_table', 1)
    event.connection.send(msg)
    msg.table_entry('params_table', 1)
    event.connection.send(msg)

    msg.table_list()
    event.connection.send(msg)

    log.info("netasm.examples.netasm.controller_assisted.table_based_simple (pass through) for %s",
             dpidToStr(event.dpid))


def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("VendorIn", _handle_VendorIn)

    log.info("netasm.examples.netasm.controller_assisted.table_based_simple (pass through) running.")