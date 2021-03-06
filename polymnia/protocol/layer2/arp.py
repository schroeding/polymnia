from polymnia.protocol import Layer2
import polymnia.core.router as router
import polymnia.core.utils as utils
import polymnia.protocol.ethernet as ethernet

import dpkt


class ARP(Layer2):
    
    prettyName = "Address Resolution Protocol"
    ethernetType = dpkt.ethernet.ETH_TYPE_ARP

    def arpMessage(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, isReply: bool = False) -> None:
        _arpPacket = dpkt.arp.ARP(
            op=(dpkt.arp.ARP_OP_REPLY if isReply else dpkt.arp.ARP_OP_REQUEST),
            sha=ethernet.macStringToBytes(sourceMAC),
            spa=utils.ipStringToBytes(sourceIP),
            tha=ethernet.macStringToBytes(targetMAC),
            tpa=utils.ipStringToBytes(targetIP)
        )
        _ethernetPacket = ethernet.RawPacket(
            sourceMAC,
            ('ff:ff:ff:ff:ff:ff' if targetMAC == '00:00:00:00:00:00' else targetMAC),
            self.ethernetType,
            _arpPacket.pack()
        )
        self.sendData(_ethernetPacket, targetMAC)

    
    def announceIP(self, ipAddress: str, sourceMAC: str) -> None:
        self.arpMessage(ipAddress, sourceMAC, ipAddress, '00:00:00:00:00:00')


    def dataAvailable(self):
        _frameNumber, _packet = self.readQueue.get()
        
        if (_packet.data.op == dpkt.arp.ARP_OP_REQUEST):
            _sourceMAC = ethernet.macBytesToString(_packet.data.sha)
            _sourceIP = utils.ipBytesToString(_packet.data.spa)
            _targetMAC = ethernet.macBytesToString(_packet.data.tha)
            _targetIP = utils.ipBytesToString(_packet.data.tpa)
            print(f'ARP request from {_sourceMAC} / {_sourceIP} to {_targetMAC} / {_targetIP}')
            
            if ((_targetMAC == '00:00:00:00:00:00') or (_targetMAC == router._routerMac)):
                if (_targetIP == _sourceIP):
                    print(f'{_sourceMAC} announced IP {_sourceIP}')
                    if (_targetIP == router._routerIPv4):
                        print(f'IP collision detected: sending answer')
                        self.arpMessage(router._routerIPv4, router._routerMac, _sourceIP, _sourceMAC, True)
                    return
                if (_targetIP == router._routerIPv4):
                    print(f'Requested router IP')
                    self.arpMessage(router._routerIPv4, router._routerMac, _sourceIP, _sourceMAC, True)