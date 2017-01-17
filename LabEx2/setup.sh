#!/bin/bash

sudo mn --topo single,3 --mac --arp --switch ovsk --controller=remote,ip=127.0.0.1
