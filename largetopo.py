# -*- coding: utf-8 -*-
from mininet.topo import Topo

class MyLoopFreeTopo(Topo):
    def build(self):
        # CREATE HOSTS
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3 = self.addHost('h3')
        host4 = self.addHost('h4')
        host5 = self.addHost('h5')
        host6 = self.addHost('h6')
        host7 = self.addHost('h7')
        host8 = self.addHost('h8')

        # CREATE SWITCHES
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')
        switch6 = self.addSwitch('s6')

        # CREATE LINKS BETWEEN SWITCHES AND HOSTS
        self.addLink(host1, switch1)
        self.addLink(host2, switch1)
        self.addLink(host3, switch2)
        self.addLink(host4, switch2)
        self.addLink(host5, switch4)
        self.addLink(host6, switch4)
        self.addLink(host7, switch5)
        self.addLink(host8, switch5)

        # CREATE LINKS BETWEEN SWITCHES WITHOUT CREATING LOOPS
        self.addLink(switch1, switch3)
        self.addLink(switch2, switch3)
        self.addLink(switch3, switch6)
        self.addLink(switch4, switch6)
        self.addLink(switch5, switch6)

        # Note: No additional links between switches to ensure no loops

topos = {'mylargetopo': (lambda: MyLoopFreeTopo())}

