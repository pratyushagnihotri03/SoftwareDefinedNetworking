#!/bin/bash
sudo mn --topo linear,n=2,k=2 --mac --arp --switch ovsk,protocols=OpenFlow13 --controller=remote,ip=127.0.0.1