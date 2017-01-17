#!/bin/bash
# Setting initial topology with -x flag
sudo mn --topo single,3 --mac --arp --switch ovsk -x --controller=remote,ip=127.0.0.1
