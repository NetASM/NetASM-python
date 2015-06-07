# ###############################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        api.py
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

from ast import literal_eval

from pox.openflow import libopenflow_01 as of


class InMessage:
    def __init__(self, vendor):
        self.vendor = vendor
        self.message = literal_eval(vendor.data)

        if not self.message['type'] == 'in':
            raise TypeError()

        self.is_packet_in = self.message['operation'] == 'packet-in'
        self.is_query_table_entry = self.message['operation'] == 'query-table-entry'
        self.is_query_table_list = self.message['operation'] == 'query-table-list'

        if self.is_packet_in:
            self.port = self.message['data'][0]
            self.packet_data = self.message['data'][1]
            self.reason = self.message['data'][2][0]
            self.description = self.message['data'][2][1]
        elif self.is_query_table_entry:
            self.table_name = self.message['data'][0]
            self.table_index = self.message['data'][1]
            self.table_entry = self.message['data'][2]
        elif self.is_query_table_list:
            self.table_list = self.message['data']
        else:
            raise TypeError()


class OutMessage(of.ofp_vendor_generic):
    def __init__(self):
        super(OutMessage, self).__init__()
        self.message = {'type': 'out'}

    def set_policy(self, policy):
        self.message['operation'] = 'set-policy'
        self.message['data'] = policy
        self.data = str(self.message)

    def clr_policy(self):
        self.message['operation'] = 'clr-policy'
        self.message['data'] = None
        self.data = str(self.message)

    def add_table_entry(self, name, index, entry):
        self.message['operation'] = 'add-table-entry'
        self.message['data'] = (name, index, entry)
        self.data = str(self.message)

    def del_table_entry(self, name, index):
        self.message['operation'] = 'del-table-entry'
        self.message['data'] = (name, index)
        self.data = str(self.message)

    def packet_out(self, ports, packet=None):
        self.message['operation'] = 'packet-out'
        self.message['data'] = (ports, packet)
        self.data = str(self.message)


class QueryMessage(of.ofp_vendor_generic):
    def __init__(self):
        super(QueryMessage, self).__init__()
        self.message = {'type': 'query'}

    def table_entry(self, name, index):
        self.message['operation'] = 'query-table-entry'
        self.message['data'] = (name, index)
        self.data = str(self.message)

    def table_list(self):
        self.message['operation'] = 'query-table-list'
        self.message['data'] = None
        self.data = str(self.message)