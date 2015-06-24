# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:#
# ##        datapath.py
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

'''
Software switch with PCap ports

Example:
./pox.py --no-openflow datapath --address=localhost
'''

import sys
from ast import literal_eval
from importlib import import_module
from Queue import Queue
from threading import Thread
import logging

from bitstring import BitArray

from pox.core import core
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.ioworker.workers import BackoffWorker
from pox.datapaths.switch import SoftwareSwitchBase
from pox.datapaths.switch import ExpireMixin
from pox.datapaths.switch import OFConnection
import pox.lib.pxpcap as pxpcap
import pox.openflow.libopenflow_01 as of
from netasm.netasm.core.syntax import *
from netasm.netasm.core.common import bitmap_to_ports, ports_to_bitmap
from netasm.netasm import validate, execute, optimize, cost


class OpenFlowWorker(BackoffWorker):
    def __init__(self, switch=None, **kw):
        self.switch = switch
        self.connection = None
        from pox.core import core

        self.log = core.getLogger("dp." + dpid_to_str(self.switch.dpid))
        super(OpenFlowWorker, self).__init__(switch=switch, **kw)
        self._info("Connecting to %s:%s", kw.get('addr'), kw.get('port'))

    def _handle_close(self):
        if self.switch.policy:
            self.switch.policy.stop()
        self.switch.policy = None

        super(OpenFlowWorker, self)._handle_close()

    def _handle_connect(self):
        super(OpenFlowWorker, self)._handle_connect()
        self.connection = OFConnection(self)
        self.switch.set_connection(self.connection)
        self._info("Connected to controller")

    def _error(self, *args, **kw):
        self.log.error(*args, **kw)

    def _warn(self, *args, **kw):
        self.log.warn(*args, **kw)

    def _info(self, *args, **kw):
        self.log.info(*args, **kw)

    def _debug(self, *args, **kw):
        self.log.debug(*args, **kw)


def do_launch(cls, standalone, address='127.0.0.1', port=6633, max_retry_delay=16,
              dpid=None, extra_args=None, **kw):
    """
    Used for implementing custom switch launching functions

    cls is the class of the switch you want to add.

    Returns switch instance.
    """

    if extra_args is not None:
        import ast

        extra_args = ast.literal_eval('{%s}' % (extra_args,))
        kw.update(extra_args)

    from pox.core import core

    if not core.hasComponent('datapaths'):
        core.register("datapaths", {})
    _switches = core.datapaths

    if dpid is None:
        for dpid in range(1, 256):
            if dpid not in _switches: break
        if dpid in _switches:
            raise RuntimeError("Out of DPIDs")
    else:
        dpid = str_to_dpid(dpid)

    switch = cls(dpid=dpid, name="sw" + str(dpid), **kw)
    _switches[dpid] = switch

    port = int(port)
    max_retry_delay = int(max_retry_delay)

    def up(event):
        import pox.lib.ioworker

        global loop
        loop = pox.lib.ioworker.RecocoIOLoop()
        # loop.more_debugging = True
        loop.start()
        OpenFlowWorker.begin(loop=loop, addr=address, port=port,
                             max_retry_delay=max_retry_delay, switch=switch)

    from pox.core import core

    if not standalone:
        core.addListenerByName("UpEvent", up)

    return switch


log = core.getLogger()

DEFAULT_CTL_PORT = 7791

_switches = {}

_MAX_PORTS = 64


def load_policy(switch, policy_name):
    if switch.policy:
        switch.policy.stop()
    switch.policy_name = ''
    switch.policy = None

    try:
        if policy_name in sys.modules:
            del sys.modules[policy_name]
        module = import_module(policy_name)
    except ImportError, e:
        raise RuntimeError('Must be a valid python module\n' +
                           'e.g, full module name,\n' +
                           '     no .py suffix,\n' +
                           '     located on the system PYTHONPATH\n' +
                           '\n' +
                           'Exception message for ImportError was:' + e.message)
    main = module.main

    if main:
        policy = main()
        if isinstance(policy, Policy):
            try:
                validate.type_check.type_check_Policy(policy, _MAX_PORTS)
                print "Policy [%s] (type check): passed!" % policy_name
            except Exception, e:
                print "Policy [%s] (type check): failed... " % policy_name + e.message
                switch.policy_name = ''
                switch.policy = None

            area, latency = cost.cost_Policy(policy)
            print "policy [%s] (original cost): Area=%s, Latency=%s" % (policy_name, area, latency)

            policy = optimize.optimize_Policy(policy)
            area, latency = cost.cost_Policy(policy)
            print "Policy [%s] (optimize cost): Area=%s, Latency=%s" % (policy_name, area, latency)

            switch.policy_name = policy_name
            switch.policy = execute.Execute(policy)
            switch.policy.start()
        else:
            raise RuntimeError("Invalid policy: %s" % (policy_name, ))
    else:
        raise RuntimeError("Invalid policy: %s" % (policy_name, ))


def _do_ctl(event):
    r = _do_ctl2(event)
    if r is None:
        r = "Okay."
    event.worker.send(r + "\n")


def _do_ctl2(event):
    def errf(msg, *args):
        raise RuntimeError(msg % args)

    def ra(low, high=None):
        if high is None: high = low
        if len(event.args) < low or len(event.args) > high:
            raise RuntimeError("Wrong number of arguments")
        return False

    try:
        if event.first == "add-port":
            ra(1, 2)
            if len(event.args) == 1 and len(_switches) == 1:
                switch = _switches[_switches.keys()[0]]
                p = event.args[0]
            else:
                ra(2)
                if event.args[0] not in _switches:
                    raise RuntimeError("No such switch")
                switch = _switches[event.args[0]]
                p = event.args[1]
            switch.add_interface(p, start=True, on_error=errf)
        elif event.first == "del-port":
            ra(1, 2)
            if len(event.args) == 1:
                for switch in _switches.values():
                    for p in switch.ports:
                        if p.name == event.args[0]:
                            switch.remove_interface(event.args[0])
                            return
                raise RuntimeError("No such interface")
            switch = _switches[event.args[0]]
            switch.remove_interface(event.args[1])
        elif event.first == 'set-policy':
            ra(2)
            switch = _switches[event.args[0]]
            policy_name = event.args[1]

            load_policy(switch, policy_name)
        elif event.first == 'clr-policy':
            ra(1)
            switch = _switches[event.args[0]]

            if switch.policy:
                switch.policy.stop()
            switch.policy_name = ''
            switch.policy = None
        elif event.first == "add-table-entry":
            ra(4)
            switch = _switches[event.args[0]]
            t_name = event.args[1]
            t_index = literal_eval(event.args[2])
            t_entry = literal_eval(event.args[3])

            if switch.policy:
                t_id = TableId(t_name)
                switch.policy.add_table_entry(t_id, t_index, t_entry)
        elif event.first == "del-table-entry":
            ra(3)
            switch = _switches[event.args[0]]
            t_name = event.args[1]
            t_index = literal_eval(event.args[2])

            if switch.policy:
                t_id = TableId(t_name)
                switch.policy.del_table_entry(switch.policy.tables, t_id, t_index)
        elif event.first == "query-table-entry":
            ra(3)
            switch = _switches[event.args[0]]
            t_name = event.args[1]
            t_index = literal_eval(event.args[2])

            if switch.policy:
                t_id = TableId(t_name)
                t_entry = switch.policy.query_table_entry(t_id, t_index)
                return str(t_entry)
        elif event.first == "query-table-list":
            ra(1)
            switch = _switches[event.args[0]]

            if switch.policy:
                t_list = switch.policy.query_table_list()
                return str(t_list)
        elif event.first == "show":
            ra(0)
            s = []
            for switch in _switches.values():
                s.append("Switch %s (%s)" % (switch.name, switch.policy_name))
                for no, p in switch.ports.iteritems():
                    s.append(" %3s %s" % (no, p.name))
            return "\n".join(s)

        else:
            raise RuntimeError("Unknown command")

    except Exception as e:
        log.exception("While processing command")
        return "Error: " + str(e)


def launch(standalone=False, address='127.0.0.1', port=6633, max_retry_delay=16,
           dpid=None, ports='', policy='', extra=None, ctl_port=None,
           __INSTANCE__=None):
    """
    Launches a switch
    """

    if not pxpcap.enabled:
        raise RuntimeError("You need PXPCap to use this component")

    if ctl_port:
        if core.hasComponent('ctld'):
            raise RuntimeError("Only one ctl_port is allowed")

        if ctl_port is True:
            ctl_port = DEFAULT_CTL_PORT

        from pox.datapaths import ctl

        ctl.server(ctl_port)
        core.ctld.addListenerByName("CommandEvent", _do_ctl)

    _ports = ports.strip()

    def up(event):
        ports = [p for p in _ports.split(",") if p]

        switch = do_launch(ProgSwitch, standalone, address, port, max_retry_delay, dpid,
                           ports=ports, policy=policy, extra_args=extra)
        _switches[switch.name] = switch

    core.addListenerByName("UpEvent", up)


class ProgSwitch(ExpireMixin, SoftwareSwitchBase):
    # Default level for loggers of this class
    default_log_level = logging.INFO

    def __init__(self, **kw):
        """
        Create a switch instance

        Additional options over superclass:
        log_level (default to default_log_level) is level for this instance
        ports is a list of interface names
        """
        log_level = kw.pop('log_level', self.default_log_level)
        self.policy = None
        self.rx_q = Queue()
        self.consumer_thread = Thread(target=self._consumer_threadproc)
        self.tx_q = Queue()
        self.producer_thread = Thread(target=self._producer_threadproc)
        core.addListeners(self)

        ports = kw.pop('ports', [])
        kw['ports'] = []

        self.policy_name = kw.pop("policy", '')
        if self.policy_name:
            load_policy(self, self.policy_name)

        super(ProgSwitch, self).__init__(**kw)

        self._next_port = 1

        self.px = {}

        for p in ports:
            self.add_interface(p, start=False)

        self.log.setLevel(log_level)

        for px in self.px.itervalues():
            px.start()

        self.consumer_thread.start()
        self.producer_thread.start()

    def add_interface(self, name, port_no=-1, on_error=None, start=False):
        if on_error is None:
            on_error = log.error

        devs = pxpcap.PCap.get_devices()
        if name not in devs:
            on_error("Device %s not available -- ignoring", name)
            return
        dev = devs[name]
        if dev.get('addrs', {}).get('ethernet', {}).get('addr') is None:
            on_error("Device %s has no ethernet address -- ignoring", name)
            return
        if dev.get('addrs', {}).get('AF_INET') != None:
            on_error("Device %s has an IP address -- ignoring", name)
            return
        for no, p in self.px.iteritems():
            if p.device == name:
                on_error("Device %s already added", name)

        if port_no == -1:
            while True:
                port_no = self._next_port
                self._next_port += 1
                if port_no not in self.ports: break

        if port_no in self.ports:
            on_error("Port %s already exists -- ignoring", port_no)
            return

        phy = of.ofp_phy_port()
        phy.port_no = port_no
        phy.hw_addr = dev['addrs']['ethernet']['addr']
        phy.name = name
        # Fill in features sort of arbitrarily
        phy.curr = of.OFPPF_10MB_HD
        phy.advertised = of.OFPPF_10MB_HD
        phy.supported = of.OFPPF_10MB_HD
        phy.peer = of.OFPPF_10MB_HD

        self.add_port(phy)

        px = pxpcap.PCap(name, callback=self._pcap_rx, start=False)
        px.port_no = phy.port_no
        self.px[phy.port_no] = px

        if start:
            px.start()

        return px

    def remove_interface(self, name_or_num):
        if isinstance(name_or_num, basestring):
            for no, p in self.px.iteritems():
                if p.device == name_or_num:
                    self.remove_interface(no)
                    return
            raise ValueError("No such interface")

        px = self.px[name_or_num]
        px.stop()
        px.port_no = None
        self.delete_port(name_or_num)

    def _handle_GoingDownEvent(self, event):
        if self.policy:
            self.policy.stop()
        self.policy = None
        self.rx_q.put(None)
        self.tx_q.put(None)

    def _rx_vendor(self, vendor, connection):
        if vendor.data:
            message = literal_eval(vendor.data)
            type = message['type']

            if type == 'out':
                self._handle_out_message(message, connection)
            elif type == 'query':
                self._handle_query_message(message, connection)
        else:
            raise RuntimeError("Invalid message from the controller")

    def _tx_vendor(self, vendor):
        self.send(vendor)

    def _handle_out_message(self, message, connection):
        if message['operation'] == 'set-policy':
            policy_name = message['data']

            load_policy(self, policy_name)
        elif message['operation'] == 'clr-policy':
            if self.policy:
                self.policy.stop()
            self.policy = None
        elif message['operation'] == 'add-table-entry':
            t_name = message['data'][0]
            t_index = message['data'][1]
            t_entry = message['data'][2]

            if self.policy:
                t_id = TableId(t_name)
                self.policy.add_table_entry(t_id, t_index, t_entry)
        elif message['operation'] == 'del-table-entry':
            t_name = message['data'][0]
            t_index = message['data'][1]

            if self.policy:
                t_id = TableId(t_name)
                self.policy.del_table_entry(t_id, t_index)
        elif message['operation'] == 'packet-out':
            # self.log.debug("Packet out details: %s", packet_out.show())
            ports = message['data'][0]
            packet = message['data'][1]

            if packet:
                out_ports = ports
                for out_port in out_ports:
                    self.tx_packet(packet, out_port)
            else:
                self.log.warn("No data -- don't know what to send")
        else:
            raise RuntimeError("Invalid message from the controller")

    def _handle_query_message(self, message, connection):
        if message['operation'] == 'query-table-entry':
            t_name = message['data'][0]
            t_index = message['data'][1]

            if self.policy:
                t_id = TableId(t_name)
                t_entry = self.policy.query_table_entry(t_id, t_index)

                data = {'type': 'in', 'operation': 'query-table-entry',
                        'data': (t_name, t_index, t_entry)}
                self._tx_vendor(of.ofp_vendor_generic(data=str(data)))
        elif message['operation'] == 'query-table-list':
            if self.policy:
                t_list = self.policy.query_table_list()

                data = {'type': 'in', 'operation': 'query-table-list',
                        'data': t_list}
                self._tx_vendor(of.ofp_vendor_generic(data=str(data)))
        else:
            raise RuntimeError("Invalid message from the controller")

    def _consumer_threadproc(self):
        timeout = 3
        while core.running:
            try:
                data = self.rx_q.get(timeout=timeout)
            except:
                continue
            if data is None:
                # Signal to quit
                break
            batch = []
            while True:
                self.rx_q.task_done()
                port_no, data = data
                # data = ethernet(data)
                batch.append((data, port_no))
                try:
                    data = self.rx_q.get(block=False)
                except:
                    break
            core.callLater(self.rx_batch, batch)

    def rx_batch(self, batch):
        for packet_data, port_no in batch:
            self.rx_packet(None, port_no, packet_data)

    def _pcap_rx(self, px, data, sec, usec, length):
        if px.port_no is None: return
        self.rx_q.put((px.port_no, data))

    def rx_packet(self, packet, in_port, packet_data=None):
        if self.policy:
            state = execute.State(execute.Header(), execute.Packet())

            state.packet.append(BitArray(bytes=packet_data))

            port = ports_to_bitmap(in_port)
            state.header[Field('inport_bitmap')] = Value(port, Size(_MAX_PORTS))
            state.header[Field('outport_bitmap')] = Value(0, Size(_MAX_PORTS))
            state.header[Field('bit_length')] = Value(len(state.packet), Size(32))
            state.header[Field('DRP')] = Value(0, Size(1))
            state.header[Field('CTR')] = Value(0, Size(1))

            self.policy.put(state)
        self.tx_q.put((in_port, packet_data))

    def _output_packet_physical(self, packet, port_no):
        """
        send a packet out a single physical port

        This is called by the more general _output_packet().
        """
        px = self.px.get(port_no)
        if not px:
            return
        px.inject(packet)

    tx_packet = _output_packet_physical

    def _producer_threadproc(self):
        while core.running:
            data = self.tx_q.get()
            if data is None:
                # Signal to quit
                break
            (in_port, packet_data) = data

            if self.policy:
                state = self.policy.get()

                if state.header[Field('DRP')].value == 1:
                    pass
                elif state.header[Field('CTR')].value == 1:
                    reason = (str(state.reason.reason), str(state.reason.description))
                    data = {'type': 'in', 'operation': 'packet-in',
                            'data': (in_port, packet_data, reason)}
                    self._tx_vendor(of.ofp_vendor_generic(data=str(data)))
                else:
                    out_ports = bitmap_to_ports(state.header[Field('outport_bitmap')].value)
                    packet_data = state.packet.bytes

                    for out_port in out_ports:
                        self.tx_packet(packet_data, out_port)
            else:
                continue
