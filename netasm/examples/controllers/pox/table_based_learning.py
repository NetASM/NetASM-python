# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        table_based_learning.py
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

from netasm.back_ends.soft_switch.api import OutMessage, InMessage


log = core.getLogger()


def _handle_VendorIn(event):
    in_msg = InMessage(event.ofp)

    if in_msg.is_packet_in:

        if in_msg.reason == 'MATCH_TABLE_MISS':

            out_msg = OutMessage()

            if in_msg.port == 1:
                out_msg.packet_out([2], in_msg.packet_data)
            elif in_msg.port == 2:
                out_msg.packet_out([1], in_msg.packet_data)

            event.connection.send(out_msg)

            # TODO: on learning, install a rule in the switch ... Missing


def _handle_ConnectionUp(event):
    msg = OutMessage()

    msg.set_policy("netasm.examples.netasm.controller_assisted.table_based_simple")
    event.connection.send(msg)

    log.info("netasm.examples.netasm.controller_assisted.table_based_simple (learning) for %s", dpidToStr(event.dpid))


def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("VendorIn", _handle_VendorIn)

    log.info("netasm.examples.netasm.controller_assisted.table_based_simple (learning) running.")