
"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def topo():

    "Create an empty network and add nodes to it."

    #net = Mininet( controller=RemoteController,ip="127.0.0.1")
    net = Mininet( controller=Controller )
    info( '*** Adding controller\n' )
    net.addController( 'c0' )

    info( '*** Adding servers\n' )
    srv1 = net.addHost('srv1')
    srv2 = net.addHost('srv2')

    info( '*** Adding hosts\n' )
    h1 =  net.addHost( 'h1')
    h2 =  net.addHost( 'h2')
    h3 =  net.addHost( 'h3')
    h4 =  net.addHost( 'h4')
    h5 =  net.addHost( 'h5')
    h6 =  net.addHost( 'h6')

    info( '*** Adding switch\n' )
    s1 = net.addSwitch( 's1')#, dpid="0000000000000201")]
    s2 = net.addSwitch( 's2')#, dpid="0000000000000202")]

    info( '*** Creating links\n' )
    net.addLink(s1,srv1)
    net.addLink(s1,srv2)
    net.addLink(h1,s2)
    net.addLink(h2,s2)
    net.addLink(h3,s2)
    net.addLink(h4,s2)
    net.addLink(h5,s2)
    net.addLink(h6,s2)
    net.addLink(s2,s1)

    info( '*** Starting network\n')
    net.start()

    info( '*** Running CLI\n' )
    CLI(net)

    info( '*** Stopping network' )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topo()



