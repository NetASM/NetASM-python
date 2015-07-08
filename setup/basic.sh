#!/usr/bin/env bash

################################################################################
##
##  https://github.com/NetASM/NetASM-python
##
##  File:
##        basic.sh
##
##  Project:
##        NetASM: A Network Assembly Language for Programmable Dataplanes
##
##  Author:
##        Muhammad Shahbaz
##
##  Copyright notice:
##        Copyright (C) 2014 Princeton University
##      Network Operations and Internet Security Lab
##
##  Licence:
##        This file is a part of the NetASM development base package.
##
##        This file is free code: you can redistribute it and/or modify it under
##        the terms of the GNU Lesser General Public License version 2.1 as
##        published by the Free Software Foundation.
##
##        This package is distributed in the hope that it will be useful, but
##        WITHOUT ANY WARRANTY; without even the implied warranty of
##        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##        Lesser General Public License for more details.
##
##        You should have received a copy of the GNU Lesser General Public
##        License along with the NetASM source package.  If not, see
##        http://www.gnu.org/licenses/.

# Update virtualbox
sudo apt-get update

# Install essentials
sudo apt-get install -y ssh git
 
sudo apt-get install -y build-essential autoconf automake graphviz libtool vim
sudo apt-get install -y python-all python-qt4 python-dev python-twisted-conch python-pip python-sphinx python-ply
sudo apt-get install -y libpcap-dev

sudo pip install alabaster psutil bitstring
