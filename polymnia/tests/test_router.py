import unittest
import polymnia
import polymnia.core.router
import polymnia.protocol
import polymnia.protocol.layer2


class TestRouter(unittest.TestCase):

    def setUp(self):
        self.testStr = 'Als Gregor Samsa eines Morgens aus unruhigen Träumen erwachte, fand er sich in seinem Bett zu einem ungeheuren Ungeziefer verwandelt. '\
            'Er lag auf seinem panzerartig harten Rücken und sah, wenn er den Kopf ein wenig hob, seinen gewölbten, braunen, von bogenförmigen Versteifungen '\
            'geteilten Bauch, auf dessen Höhe sich die Bettdecke, zum gänzlichen Niedergleiten bereit, kaum noch erhalten konnte. Seine vielen, im Vergleich '\
            'zu seinem sonstigen Umfang kläglich dünnen Beine flimmerten ihm hilflos vor den Augen.'

    def testTempRouterTestMustBeChangedTODO(self):
        import pytun
        import dpkt
        tun = polymnia.core.router.createEthernetDevice('polymnia1')
        # CI does not run as root, aborting
        if (tun == None):
            return
        arp = polymnia.protocol.layer2.ARP()
        arp.addDestination('ff:ff:ff:ff:ff:ff')
        ip = polymnia.protocol.layer2.IP()
        ip.addDestination('1e:00:00:00:14:12')
        icmp = polymnia.protocol.layer2.ICMP()
        icmp.addDestination('1e:00:00:00:14:12')
        polymnia.core.router.registerService(arp)
        polymnia.core.router.registerService(ip)
        polymnia.core.router.loop(tun)
        
        # while (True):
        #     data = tun.read(tun.mtu)
        #     packet = dpkt.ethernet.Ethernet(data)
        #     print(f'Src: {":".join("%02x" % dpkt.compat.compat_ord(b) for b in packet.src)} Dest: {":".join("%02x" % dpkt.compat.compat_ord(b) for b in packet.dst)} EtherType: {hex(packet.type)}')
        #     if (isinstance(packet.data, dpkt.arp.ARP)):
        #         print(f'ARP: OP {packet.data.op}')
        #         print(f'     from: {":".join("%02x" % dpkt.compat.compat_ord(b) for b in packet.data.sha)}')
        #         print(f'         : {".".join(str(b) for b in packet.data.spa)}')
        #         print(f'       to: {":".join("%02x" % dpkt.compat.compat_ord(b) for b in packet.data.tha)}')
        #         print(f'         : {".".join(str(b) for b in packet.data.tpa)}')
        #         answer_arp = dpkt.arp.ARP()
        #         answer_arp.op = dpkt.arp.ARP_OP_REPLY
        #         answer_arp.sha = b'\x11\x22\x33\x44\x55\x66\x77\x88'
        #         answer_arp.spa = packet.data.tpa
        #         answer_arp.tha = b'\x68\x84\x7e\x01\xfe\x51'
        #         answer_arp.tpa = b'\x10\x10\x10\x10'
        #         answer_eth = dpkt.ethernet.Ethernet(type=dpkt.ethernet.ETH_TYPE_ARP)
        #         answer_eth.type = dpkt.ethernet.ETH_TYPE_ARP
        #         answer_eth.src = b'\x11\x22\x33\x44\x55\x66\x77\x88'
        #         answer_eth.dst = packet.src
        #         answer_eth.data = answer_arp.pack()
        #         tun.write(answer_eth.pack())