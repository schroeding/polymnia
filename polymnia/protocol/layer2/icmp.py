from polymnia.protocol import Layer2
import polymnia.core.utils as utils
import polymnia.protocol.ethernet as ethernet

import dpkt
import time

class ICMP(Layer2):
    
    prettyName = "Internet Control Message Protocol"
    ethernetType = dpkt.ethernet.ETH_TYPE_IP

    _ttl = 64

    def sendEcho(self, sourceIP: str, sourceMAC: str, targetIP: str, targetMAC: str, data: bytes, seq: int, id: int, isReply: bool = True):
        time.sleep(0.2)
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
            ttl = self._ttl,
        )
        self._ttl -= 1
        _ethernetPacket = ethernet.RawPacket(
            sourceMAC,
            targetMAC,
            self.ethernetType,
            _ipPacket.pack(),
        )
        self.sendData(_ethernetPacket, targetMAC)


    def dataAvailable(self):
        _frameNumber, _packet = self.readQueue.get()

        if (_packet.data.p != dpkt.ip.IP_PROTO_ICMP):
            print('is not a icmp, dropping')
            return

        _sourceIP = utils.ipBytesToString(_packet.data.src)
        _targetIP = utils.ipBytesToString(_packet.data.dst)

        _doNotFragment = bool(_packet.data.off & dpkt.ip.IP_DF)
        _moreFragments = bool(_packet.data.off & dpkt.ip.IP_MF)
        _offsetFragment = _packet.data.off & dpkt.ip.IP_OFFMASK

        print(f'ICMP (IP) packet from {_packet.ethernetSource} / {_sourceIP} to {_packet.ethernetDestination} / {_targetIP}')

        if (_packet.data.data.type == dpkt.icmp.ICMP_ECHO):
            print(f'ICMP Type {_packet.data.data.type} (ECHO)')
            if (_targetIP == '1.4.1.2'):
                self.sendEcho(_targetIP, _packet.ethernetDestination, _sourceIP, _packet.ethernetSource, _packet.data.data.data.data, _packet.data.data.data.seq, _packet.data.data.data.id)