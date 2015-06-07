#!/usr/bin/env bash

################################################################################
##
##  https://github.com/NetASM/NetASM-python
##
##  File:
##        pox-patch.sh
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

# Apply patch for POX
cd ~/pox
sudo git remote add netasm-patch https://github.com/PrincetonUniversity/pox
sudo git pull netasm-patch carp

# Install pxpcap
cd ~/pox/pox/lib/pxpcap/pxpcap_c/ 
sudo ./build_linux

# Add POX to PATH and PYTHONPATH environment variables
echo 'export PATH=$PATH:$HOME/pox' >> ~/.profile
echo 'export PYTHONPATH=$PYTHONPATH:$HOME/pox' >> ~/.profile