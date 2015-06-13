#!/bin/bash

vethpairs=48

if [ $# -eq 1 ]; then
    vethpairs=$1
fi

echo "No of veth pairs is $vethpairs"

idx=0

while [ $idx -lt $vethpairs ]
do
    intf="veth$(($idx*2))"
    if ip link show $intf &> /dev/null; then
        ip link delete $intf type veth
    fi
    idx=$((idx + 1))
done