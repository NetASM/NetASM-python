################################################################################
##
##  https://github.com/NetASM/NetASM-python
##
##  File:
##        Vagrantfile
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

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "ubuntu/trusty64"

    config.vm.provider "virtualbox" do |v|
        v.customize ["modifyvm", :id, "--cpuexecutioncap", "50"]
        v.customize ["modifyvm", :id, "--memory", "1024"]
    end

    config.vm.provision "shell", privileged: false, path: "./setup/basic.sh"
    config.vm.provision "shell", privileged: false, path: "./setup/mininet.sh"
    config.vm.provision "shell", privileged: false, path: "./setup/pox-patch.sh"
    config.vm.provision "shell", privileged: false, path: "./setup/netasm.sh"
    config.vm.provision "shell", privileged: false, path: "./setup/last.sh"
end
