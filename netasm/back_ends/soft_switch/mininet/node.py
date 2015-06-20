# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        node.py
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

from mininet.node import Switch
from mininet.log import error
from netasm.back_ends.soft_switch.mininet.bash import get_path, run_command, kill_command


path = get_path("pox")


class NetASMSwitch(Switch):
    CTL_ADDRESS = "127.0.0.1"
    CTL_PORT = 7791
    CTL_ENABLE = False

    def __init__(self, name, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.policy = ''

        # ''' Check if 'pcap_switch' is running '''
        # try:
        # subprocess.check_output('netstat -lnp | grep ' + str(NetASMSwitch.CTL_PORT), shell=True).strip()
        # except:
        # error(
        # "*** error: 'prog_switch' is not running at " + NetASMSwitch.CTL_ADDRESS + "::" + str(
        #             NetASMSwitch.CTL_PORT) + "\n")
        #     exit(1)

    def start(self, controllers):
        pass

    def stop(self):
        pass

    # def set_policy(self, policy):
    #     if NetASMSwitch.CTL_ENABLE:
    #         command = \
    #             ['python', path + '/pox.py', '--no-openflow', 'datapaths.ctl',
    #              '--cmd="set-policy ' + self.dpid + ' ' + policy + '"',
    #              '--address=' + NetASMSwitch.CTL_ADDRESS, '--port=' + str(NetASMSwitch.CTL_PORT)]
    #         print ' '.join(command)
    #         run_command(command)
    #     else:
    #         error("*** error: netasm switch(s) is not running at " + NetASMSwitch.CTL_ADDRESS + "::" + str(
    #             NetASMSwitch.CTL_PORT) + "\n")
    #         exit(1)
    #
    # def clear_policy(self):
    #     if NetASMSwitch.CTL_ENABLE:
    #         command = \
    #             ['python', path + '/pox.py', '--no-openflow', 'datapaths.ctl',
    #              '--cmd="clr-policy ' + self.dpid + '"',
    #              '--address=' + NetASMSwitch.CTL_ADDRESS, '--port=' + str(NetASMSwitch.CTL_PORT)]
    #         run_command(command)
    #     else:
    #         error("*** error: netasm switch(s) is not running at " + NetASMSwitch.CTL_ADDRESS + "::" + str(
    #             NetASMSwitch.CTL_PORT) + "\n")
    #         exit(1)

    def add_table_entry(self, name, index, entry):
        if NetASMSwitch.CTL_ENABLE:
            command = \
                ['python', path + '/pox.py', '--no-openflow', 'datapaths.ctl',
                 '--cmd="add-table-entry ' + self.dpid + ' ' + name + ' ' + str(index) + ' '
                 + str(entry).replace(' ', '') + '"',
                 '--address=' + NetASMSwitch.CTL_ADDRESS, '--port=' + str(NetASMSwitch.CTL_PORT)]
            run_command(command)
        else:
            error("*** error: netasm switch(s) is not running at " + NetASMSwitch.CTL_ADDRESS + "::" + str(
                NetASMSwitch.CTL_PORT) + "\n")
            exit(1)

    def delete_table_entry(self, name, index):
        if NetASMSwitch.CTL_ENABLE:
            command = \
                ['python', path + '/pox.py', '--no-openflow', 'datapaths.ctl',
                 '--cmd="del-table-entry ' + self.dpid + ' ' + name + ' ' + str(index) + '"',
                 '--address=' + NetASMSwitch.CTL_ADDRESS, ' --port=' + str(NetASMSwitch.CTL_PORT)]
            run_command(command)
        else:
            error("*** error: netasm switch(s) is not running at " + NetASMSwitch.CTL_ADDRESS + "::" + str(
                NetASMSwitch.CTL_PORT) + "\n")
            exit(1)

    @staticmethod
    def start_datapath(switches, address="127.0.0.1", port=6633, standalone=False):
        global _process

        args = []
        for switch in switches:
            args += ['netasm.back_ends.soft_switch.datapath'] + \
                    (['--standalone'] if standalone else []) + \
                    ['--address=' + address] + ['--port=' + str(port)] + \
                    ['--dpid=' + switch.dpid]

            args += ['--policy=' + switch.policy]

            intfs = ''
            for intf in switch.intfList():
                if switch.name in intf.name:
                    intfs += intf.name + ','

            args += ['--ports=' + intfs[:-1]]

        _process = None

        if args:
            command = ['python', path + '/pox.py', '--no-openflow'] + args + \
                      ['--ctl_port=' + str(NetASMSwitch.CTL_PORT)]
            raw_input("*** Run this command in a separate terminal then press Enter!\n" + 'sudopy ' + ' '.join(command))
            # _process = run_command(command)
            NetASMSwitch.CTL_ENABLE = True
        else:
            NetASMSwitch.CTL_ENABLE = False

    @staticmethod
    def stop_datapath():
        global _process

        if _process:
            import signal

            kill_command(_process, signal.SIGINT)
            _process = None

        NetASMSwitch.CTL_ENABLE = False
