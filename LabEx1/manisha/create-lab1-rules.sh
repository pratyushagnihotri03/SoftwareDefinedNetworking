#!/bin/bash
#Group Members: Manisha Luthra, Pratyush Agnihotri, Raghunath Deshpande 
echo "Lab exercise 1 task 1"
echo "Defining OpenFlow Layer 2 rules, so that all three hosts are able to ping others"
echo "***********************************************"
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:01,priority=500,idle_timeout=0,actions=output:1
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:02,priority=500,idle_timeout=0,actions=output:2
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:03,priority=500,idle_timeout=0,actions=output:3
echo "Successfully created!! Now displaying the flows created"
dpctl dump-flows tcp:127.0.0.1:6634

echo "***********************************************"
echo "Lab exercise 1 task 2"
echo "Defining rules such that hosts are not able to exchange smtp traffic"
dpctl add-flow tcp:127.0.0.1:6634 tcp,tp_dst=25,priority=10000,idle_timeout=0,actions=

echo "***********************************************"
echo "Successfully created!! Now displaying the flows created"
dpctl dump-flows tcp:127.0.0.1:6634


