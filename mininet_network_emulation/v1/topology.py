from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
import time

class FiveZoneTopo(Topo):
    def build(self):
        # Zone switches
        s1 = self.addSwitch('s1')  # zone1 DMZ
        s2 = self.addSwitch('s2')  # zone2 Internal
        s3 = self.addSwitch('s3')  # zone3 Cloud
        s4 = self.addSwitch('s4')  # zone4 OT (air-gapped)
        s5 = self.addSwitch('s5')  # zone5 Mgmt

        # Inter-zone links
        self.addLink(s1, s2, bw=100, delay='5ms')   # DMZ <-> Internal
        self.addLink(s2, s3, bw=100, delay='20ms')  # Internal <-> Cloud
        self.addLink(s2, s5, bw=10,  delay='2ms')   # Internal <-> Mgmt
        # zone4 (s4) NOT linked — air-gapped

        # Use ONE subnet — routing handled by OVS
        # zone1 DMZ
        h_web  = self.addHost('h_web',  ip='10.0.0.1/8')
        h_dns  = self.addHost('h_dns',  ip='10.0.0.2/8')
        h_ssh1 = self.addHost('h_ssh1', ip='10.0.0.3/8')

        # zone2 Internal
        h_db   = self.addHost('h_db',   ip='10.0.1.1/8')
        h_ssh2 = self.addHost('h_ssh2', ip='10.0.1.2/8')
        h_smb  = self.addHost('h_smb',  ip='10.0.1.3/8')

        # zone3 Cloud
        h_cloud1 = self.addHost('h_cloud1', ip='10.0.2.1/8')
        h_cloud2 = self.addHost('h_cloud2', ip='10.0.2.2/8')

        # zone4 OT — air-gapped (connected only to s4)
        h_scada = self.addHost('h_scada', ip='10.0.3.1/8')
        h_plc   = self.addHost('h_plc',   ip='10.0.3.2/8')

        # zone5 Mgmt
        h_ad   = self.addHost('h_ad',   ip='10.0.4.1/8')
        h_mgmt = self.addHost('h_mgmt', ip='10.0.4.2/8')

        # Connect hosts to switches
        for h in [h_web, h_dns, h_ssh1]:
            self.addLink(h, s1)
        for h in [h_db, h_ssh2, h_smb]:
            self.addLink(h, s2)
        for h in [h_cloud1, h_cloud2]:
            self.addLink(h, s3)
        for h in [h_scada, h_plc]:
            self.addLink(h, s4)   # isolated
        for h in [h_ad, h_mgmt]:
            self.addLink(h, s5)

def run():
    topo = FiveZoneTopo()
    net  = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=RemoteController('c0', ip='127.0.0.1', port=6633),
        link=TCLink,
        autoSetMacs=True,
        waitConnected=True
    )
    net.start()

    print("\n=== 5-Zone Topology Started ===")
    print("zone1 DMZ:      h_web(10.0.0.1)  h_dns(10.0.0.2)  h_ssh1(10.0.0.3)")
    print("zone2 Internal: h_db(10.0.1.1)   h_ssh2(10.0.1.2) h_smb(10.0.1.3)")
    print("zone3 Cloud:    h_cloud1(10.0.2.1) h_cloud2(10.0.2.2)")
    print("zone4 OT:       h_scada(10.0.3.1) h_plc(10.0.3.2) [AIR-GAPPED]")
    print("zone5 Mgmt:     h_ad(10.0.4.1)   h_mgmt(10.0.4.2)")

    # Wait for controller to learn
    print("\nWaiting for controller to learn topology...")
    time.sleep(3)

    # Test 1: same zone (should work)
    print("\n--- Test 1: Same zone (zone1 h_web -> h_dns) ---")
    net.ping([net.get('h_web'), net.get('h_dns')])

    # Test 2: cross zone connected (should work)
    print("\n--- Test 2: Cross zone connected (zone1 -> zone2) ---")
    net.ping([net.get('h_web'), net.get('h_db')])

    # Test 3: zone1 -> zone3 via zone2 (should work)
    print("\n--- Test 3: zone1 -> zone3 (via zone2) ---")
    net.ping([net.get('h_web'), net.get('h_cloud1')])

    # Test 4: air gap (zone4 -> zone1 should FAIL)
    print("\n--- Test 4: AIR GAP zone4 -> zone1 (should FAIL) ---")
    result = net.ping([net.get('h_scada'), net.get('h_web')], timeout=2)

    # Test 5: zone2 -> zone5 (should work)
    print("\n--- Test 5: zone2 -> zone5 (should work) ---")
    net.ping([net.get('h_db'), net.get('h_ad')])

    print("\n=== Summary ===")
    print("✓ Same zone:       should be 0% drop")
    print("✓ Cross zone:      should be 0% drop")
    print("✓ Via zone2:       should be 0% drop")
    print("✓ Air gap zone4:   should be 100% drop")
    print("✓ zone2->zone5:    should be 0% drop")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()