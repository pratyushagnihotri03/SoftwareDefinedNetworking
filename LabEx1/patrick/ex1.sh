#!/bin/bash

## Software Defined Networking WS2014/15
## Exercise 1

# Group members: Patrick Welzel (1478819), Mahshid Okhovatzadeh (2796600)

# This script assumes that the network is set up as in the slides described in ex1-setup.sh

SWITCH=tcp:127.0.0.1:6634

#### Task 1: Layer 2 Bridge

#broadcast: send to all ports
dpctl add-flow $SWITCH priority=2000,dl_dst=ff:ff:ff:ff:ff:ff,idle_timeout=0,actions=output:1,output:2,output:3

#host specific rules
dpctl add-flow $SWITCH priority=1000,dl_dst=00:00:00:00:00:01,idle_timeout=0,actions=output:1
dpctl add-flow $SWITCH priority=1000,dl_dst=00:00:00:00:00:02,idle_timeout=0,actions=output:2
dpctl add-flow $SWITCH priority=1000,dl_dst=00:00:00:00:00:03,idle_timeout=0,actions=output:3


#### Task 1: Layer 2 Bridge

#blocking TCP destination port 25 (reserved for SMTP) in- and outbound on each host...
dpctl add-flow $SWITCH priority=10000,tcp,tp_dst=25,idle_timeout=0,actions=
