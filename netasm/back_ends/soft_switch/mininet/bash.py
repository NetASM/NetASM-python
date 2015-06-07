# ################################################################################
# ##
# ##  https://github.com/NetASM/NetASM-python
# ##
# ##  File:
# ##        bash.py
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

import os
import sys
import subprocess
import re

import psutil


def get_path(filename):
    try:
        output = os.environ['PYTHONPATH']
    except:
        print 'Error: Unable to obtain PYTHONPATH'
        sys.exit(1)

    path = None

    for p in output.split(':'):
        if re.match('.*' + filename + '.*/?$', p):
            path = os.path.abspath(p)
            break

    if path is None:
        print 'Error: ' + filename + ' not found in PYTHONPATH'
        print output
        sys.exit(1)

    return path


def set_path(filename):
    try:
        output = os.environ['PYTHONPATH']
    except:
        print 'Error: Unable to obtain PYTHONPATH'
        sys.exit(1)

    os.environ['PYTHONPATH'] += ':' + filename


def run_silent_command(command):
    devnull = open(os.devnull, 'w')

    return subprocess.Popen(command, stdout=devnull, stderr=devnull, preexec_fn=os.setpgrp)


run_command = run_silent_command


def kill_command(process, signal):
    try:
        process = psutil.Process(process.pid)
    except:
        return

    child_processes_pid = process.get_children(recursive=True)
    for pid in child_processes_pid:
        os.kill(pid.pid, signal)

    os.kill(process.pid, signal)


