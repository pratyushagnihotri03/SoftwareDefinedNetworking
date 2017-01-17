from mininet.topo import Topo

class LBTopo( Topo ):

    "Lab 5: Load Balancer Topology"

    def __init__( self ):

        Topo.__init__( self )

        srv1 =  [ self.addHost( 'srv1')]
        srv2 =  [ self.addHost( 'srv2')]
        h1 =  [ self.addHost( 'h1')]
        h2 =  [ self.addHost( 'h2')]
	h3 =  [ self.addHost( 'h3')]
	h4 =  [ self.addHost( 'h4')]
	h5 =  [ self.addHost( 'h5')]
	h6 =  [ self.addHost( 'h6')]

        s1 = [ self.addSwitch( 's1', dpid="0000000000000201")]
        s2 = [ self.addSwitch( 's2', dpid="0000000000000202")]

        self.addLink('s1','srv1')
        self.addLink('s1','srv2')

        self.addLink('h1','s2')
        self.addLink('h2','s2')
        self.addLink('h3','s2')
        self.addLink('h4','s2')
        self.addLink('h5','s2')
        self.addLink('h6','s2')

        self.addLink('s2','s1')

topos = { 'lbtopo': ( lambda: LBTopo() ) }

