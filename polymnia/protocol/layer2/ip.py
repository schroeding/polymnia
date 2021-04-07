from polymnia.protocol import Layer2
import polymnia.core.utils as utils
import polymnia.core.router as router
import polymnia.protocol.ethernet as ethernet

import dpkt
import time

class IP(Layer2):
    
    prettyName = "Internet Protocol"
    ethernetType = dpkt.ethernet.ETH_TYPE_IP

    def sendEcho(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, data: bytes, seq: int, id: int, isReply: bool = True):
        _echoPacket = dpkt.icmp.ICMP.Echo(
            id = id,
            code = 0,
            seq = seq,
            data = data,
        )
        _icmpPacket = dpkt.icmp.ICMP(
            type=(dpkt.icmp.ICMP_ECHOREPLY if isReply else dpkt.icmp.ICMP_ECHO),
            data = _echoPacket.pack(),
        )
        _ipPacket = dpkt.ip.IP(
            src = utils.ipStringToBytes(sourceIP),
            dst = utils.ipStringToBytes(targetIP),
            p = dpkt.ip.IP_PROTO_ICMP,
            data = _icmpPacket.pack(),
            ttl = 128,
        )
        _ethernetPacket = ethernet.RawPacket(
            sourceMAC,
            targetMAC,
            self.ethernetType,
            _ipPacket.pack(),
        )
        self.sendData(_ethernetPacket, targetMAC)

    def sendIPPacket(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, packetData: bytes, type: int, ttl: int = 64):
        _ipPacket = dpkt.ip.IP(
            src = utils.ipStringToBytes(sourceIP),
            dst = utils.ipStringToBytes(targetIP),
            p = type,
            data = packetData,
            id = 0,
            ttl = ttl,
        )
        _ethernetPacket = ethernet.RawPacket(
            sourceMAC,
            targetMAC,
            self.ethernetType,
            _ipPacket.pack(),
        )
        self.sendData(_ethernetPacket, targetMAC)

    def sendICMPDestinationUnreachable(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, recievedPacketData: bytes):
        _unreachPacket = dpkt.icmp.ICMP.Unreach(
            data=recievedPacketData
        )
        _icmpPacket = dpkt.icmp.ICMP(
            type=(dpkt.icmp.ICMP_UNREACH),
            data=_unreachPacket.pack()
        )
        self.sendIPPacket(sourceIP, sourceMAC, targetIP, targetMAC, _icmpPacket, dpkt.ip.IP_PROTO_ICMP)

    def sendICMPTransitTimeExceeded(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, recievedPacketData: bytes):
        _ttePacket = dpkt.icmp.ICMP.TimeExceed(
            data=recievedPacketData
        )
        _icmpPacket = dpkt.icmp.ICMP(
            type=(dpkt.icmp.ICMP_TIMEXCEED),
            data=_ttePacket.pack()
        )
        self.sendIPPacket(sourceIP, sourceMAC, targetIP, targetMAC, _icmpPacket, dpkt.ip.IP_PROTO_ICMP)



    def dataAvailable(self):
        _frameNumber, _packet = self.readQueue.get()

        # everything here is only for testing purposes

        _sourceIP = utils.ipBytesToString(_packet.data.src)
        _targetIP = utils.ipBytesToString(_packet.data.dst)
        if (_packet.data.p == dpkt.ip.IP_PROTO_ICMP):

            _doNotFragment = bool(_packet.data.off & dpkt.ip.IP_DF)
            _moreFragments = bool(_packet.data.off & dpkt.ip.IP_MF)
            _offsetFragment = _packet.data.off & dpkt.ip.IP_OFFMASK

            print(f'ICMP (IP) packet from {_packet.ethernetSource} / {_sourceIP} to {_packet.ethernetDestination} / {_targetIP}')

            if (_packet.data.data.type == dpkt.icmp.ICMP_ECHO):
                print(f'ICMP Type {_packet.data.data.type} (ECHO)')
                if (_targetIP == '1.4.1.2'): #                                                                        TODO: too much data
                    self.sendEcho(_targetIP, _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _packet.data.data.data.data, _packet.data.data.data.seq, _packet.data.data.data.id)
                    return

        # hardcoded 1.4.1.2 testip is ignored
        # the following has to be refactored
        if (_targetIP != '1.4.1.3'):

            _networkHops = router.getIPv4NetworkHops(router._ipv4Table.get(_targetIP, None))
            # TODO: Hops from Internet to target server

            if (_packet.data.ttl <= len(_networkHops)):
                _currentHop = _networkHops[_packet.data.ttl - 1]
                if (_currentHop == ''):
                    return
                self.sendICMPTransitTimeExceeded(_currentHop, _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _packet.data)
                return

            self.sendICMPDestinationUnreachable(_networkHops[-1], _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _packet.data)

            