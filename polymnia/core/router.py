import polymnia.core.log as log
import polymnia.protocol.interface as interface
import polymnia.protocol.ethernet as ethernet

import pytun
import dpkt
import threading
import selectors
import os
from typing import Optional

_deviceTable = dict()
_routerMac = '1e:00:00:00:14:12'
_routerIPv4 = '10.101.10.10'

_virtualNetworkTable = dict()

_hooks = dict()
_frameNumber = 0

def createEthernetDevice(name: str) -> Optional[pytun.TunTapDevice]:
    _ethernetDevice = None
    try:
        _ethernetDevice = pytun.TunTapDevice(name, flags=(pytun.IFF_TAP | pytun.IFF_NO_PI))
        _ethernetDevice.up()
    except (Exception):
        log.critical(f'Could not create new TAP Ethernet Device \'{name}\'')
        log.critical(f'Did you start polymnia as root?')
    return _ethernetDevice


def closeEthernetDevice(device: pytun.TunTapDevice) -> None:
    device.down()
    device.close()
    return


def registerService(service: interface.Layer2) -> None:
    _pipeOutput, _pipeInput = os.pipe()
    os.set_inheritable(_pipeInput, True)
    print(f'i {str(_pipeInput)} o {str(_pipeOutput)}')
    service.availableDataInterruptPipe = _pipeInput
    _hooks[_pipeOutput] = service


def addDevice(name: str, mac: str) -> bool:
    if (mac == _routerMac):
        log.error(f'Cannot add new device \'{name}\' because of MAC collision with router!')
        return False
    _deviceTable[name] = mac
    log.info(f'Added new device \'{name}\' ({mac})')


def getDeviceMACbyName(name: str) -> Optional[str]:
    return _deviceTable.get(name, None)


def handleIncomingPacket(packet: ethernet.RawPacket) -> None:
    print(f'Recieved Packet:\nSource: {packet.ethernetSource}\n  Dest: {packet.ethernetDestination}')
    _foundService = False
    for _pipe, _service in _hooks.items():
            if (_service.ethernetType == packet.ethernetType):
                print(f'  Type: {_service.prettyName} ({hex(_service.ethernetType)})')
                if ((_service.destinations == None) or (packet.ethernetDestination in _service.destinations)):
                    print(f'!!!!!!!!!!!!!!!!!!!!!!!\n => Responsible service found, transferring packet')
                    _service.receiveData(packet)
                    _foundService = True
    if (not _foundService):
        print(f' => No service found (Type: {hex(packet.ethernetType)})')


def handleOutgoingPacket(packet: ethernet.RawPacket, device: pytun.TunTapDevice) -> None:
    print(f'Sending Packet:\nSource: {packet.ethernetSource}\n  Dest: {packet.ethernetDestination}')
    device.write(packet._rawPacket.pack())


def loop(device: pytun.TunTapDevice) -> None:
    # This is all temporary test stuff that must be replaced by a proper schedule system
    log.info(f'DEBUG: Started Router')
    selector = selectors.DefaultSelector()
    for _pipe in _hooks:
        selector.register(_pipe, selectors.EVENT_READ)
    selector.register(device, selectors.EVENT_READ)
    while (True):
        _events = selector.select()
        for _key, _mask in _events:
            if (_key.fileobj is device):
                _rawPacket = device.read(device.mtu)
                _packet = ethernet.RawPacket.fromEthernetFrame(_rawPacket)
                threading.Thread(target=handleIncomingPacket, args=(_packet, )).start()
                continue
            else:
                print(str(_key.fileobj))
                _service = _hooks.get(_key.fileobj, None)
                os.read(_key.fileobj, 1)
                if (_service != None):
                    _frameNumber, _packet = _service.writeQueue.get()
                    handleOutgoingPacket(_packet, device)
                    continue
                log.error(f'Router selected invalid service - this should never happen!') # and it ain't
        