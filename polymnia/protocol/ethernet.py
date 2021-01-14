import polymnia.core.log as log

import dpkt


def macBytesToString(macaddress: bytes) -> str:
    return ':'.join("%02x" % _byte for _byte in macaddress)


def macStringToBytes(macaddress: str) -> bytes:
    return bytes.fromhex(macaddress.replace(':', ''))


class RawPacket():

    ethernetType = None
    ethernetDestination = None
    ethernetSource = None
    ethernetFrameNumber = None

    data = None

    _rawPacket = None

    def __init__(self, macSource: str, macDestination: str, type: int, packetData: bytes):
        self._rawPacket = dpkt.ethernet.Ethernet(data=packetData, type=type, src=macStringToBytes(macSource), dst=macStringToBytes(macDestination))
        self.ethernetSource = macSource
        self.ethernetDestination = macDestination
        self.ethernetType = type
        self.data = packetData
        #try:
        #except:
        #    log.warning(f'Invalid packet recieved: Not an ethernet frame')
        #    return None

    @classmethod
    def fromEthernetFrame(cls, rawPacket: bytes):
        _packet = dpkt.ethernet.Ethernet(rawPacket)
        return cls(macBytesToString(_packet.src), macBytesToString(_packet.dst), _packet.type, _packet.data)
        
