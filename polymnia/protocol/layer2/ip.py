from polymnia.protocol import Layer2
import polymnia.core.log as log
import polymnia.core.utils as utils
import polymnia.core.router as router
import polymnia.protocol.ethernet as ethernet

import dpkt
import time

class IP(Layer2):
    
    prettyName = "Internet Protocol"
    ethernetType = dpkt.ethernet.ETH_TYPE_IP

    _fragmentedPacket = list()

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
        self.sendIPPacket(sourceIP, sourceMAC, targetIP, targetMAC, _icmpPacket.pack(), dpkt.ip.IP_PROTO_ICMP)

    def sendIPPacket(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, packetData: bytes, type: int, ttl: int = 64):
        _networkHops = router.getIPv4NetworkHops(router._ipv4Table.get(targetIP, None))
        print(f'ÄÄÄÄ sizeof: {str(len(packetData))}')
        # TODO: make MTU configurable
        if (len(packetData) > 1480):
            _numberOfFragments = (len(packetData) // 1480) + 1
            print(f'out must be fragmented in {_numberOfFragments}')
            for i in range(_numberOfFragments):
                _fragmentOffset = i * 1480
                _fragmentData = packetData[_fragmentOffset : min(_fragmentOffset + (1480), len(packetData))]
                _ipPacketFragment = dpkt.ip.IP(
                    src = utils.ipStringToBytes(sourceIP),
                    dst = utils.ipStringToBytes(targetIP),
                    p = type,
                    data = _fragmentData,
                    id = 471,
                    ttl = ttl - len(_networkHops),
                    off = (_fragmentOffset // 8),
                )
                if (i < (_numberOfFragments - 1)):
                    _ipPacketFragment.mf = True
                _ethernetPacket = ethernet.RawPacket(
                    sourceMAC,
                    targetMAC,
                    self.ethernetType,
                    _ipPacketFragment.pack(),
                )
                self.sendData(_ethernetPacket, targetMAC)
        else:           
            _ipPacket = dpkt.ip.IP(
                src = utils.ipStringToBytes(sourceIP),
                dst = utils.ipStringToBytes(targetIP),
                p = type,
                data = packetData,
                id = 0,
                ttl = ttl - len(_networkHops),
            )
            _ipPacket.df = True
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
        _doNotFragment = bool(_packet.data.off & dpkt.ip.IP_DF)
        _moreFragments = bool(_packet.data.off & dpkt.ip.IP_MF)
        _offsetFragment = _packet.data.off & dpkt.ip.IP_OFFMASK

        # TODO: Race Condition:
        #       If packets to the same host from the same host, but for another connection,
        #       arrive between a fragmented packet, the fragmented packet is dropped
        #       Fragmented packages should be an edge case, so this should be fine?

        if (_moreFragments):
            print(f'FRAGMENTED PACKET!\noffset: {str(_offsetFragment)} len: {str(len(_packet.data.data))}')
            if (self._fragmentedPacket):
                if (_packet.data.id != self._fragmentedPacket[0].data.id):
                    log.warning('Packet recieved is unexpected new fragmented packet, dropping old packets...')
                    self._fragmentedPacket.clear()
            self._fragmentedPacket.append(_packet)
            print(_packet.data)
            return
        else:
            if (self._fragmentedPacket):
                if (_packet.data.id != self._fragmentedPacket[0].data.id):
                    log.warning('Packet recieved is not part of an expected fragmented packet, dropping old packets...')
                    self._fragmentedPacket.clear()
                else:
                    print(f'#######################\nlast packet of frag-packet id {_packet.data.id}')
                    self._fragmentedPacket.append(_packet)
                    _packetData = b''.join([bytes(_fragPacket.data.data) for _fragPacket in self._fragmentedPacket])
                    try:
                        _packet.data.data = _packetData
                    except:
                        log.warning('Fragmented packet was invalid or not complete, dropping packet...')


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

            if (_packet.data.p == dpkt.ip.IP_PROTO_ICMP):
                _icmpPacket = dpkt.icmp.ICMP(bytes(_packet.data.data))
                print(f'ICMP (IP) packet from {_packet.ethernetSource} / {_sourceIP} to {_packet.ethernetDestination} / {_targetIP}')
                print(f'Typ: {_icmpPacket.type}')
                if (_icmpPacket.type == dpkt.icmp.ICMP_ECHO):
                    print(f'ICMP Type {_icmpPacket.type} (ECHO)')
                    if (router._ipv4Table.get(_targetIP, None) != None):
                        print('999999999999999 echo')
                        self.sendEcho(_targetIP, _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _icmpPacket.data.data, _icmpPacket.data.seq, _icmpPacket.data.id)
                        return

            self.sendICMPDestinationUnreachable(_networkHops[-1], _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _packet.data)

            