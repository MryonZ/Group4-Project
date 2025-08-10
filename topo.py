

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
class WifiAuthTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1')        # 用户主机
        h2 = self.addHost('h2')        # 外部服务器
        h_auth = self.addHost('h_auth')  # Portal认证服务器

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h_auth, s1)

topos = {'wifi_auth': (lambda: WifiAuthTopo())}
if __name__ == '__main__':
    setLogLevel('info')
    topo = WifiAuthTopo()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()
    CLI(net)
    net.stop()