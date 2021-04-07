from .ethernet import RawPacket

from abc import ABC, abstractmethod
import os
import queue


class Layer2(ABC):
    """
    Abstract Layer2 Class

    Provides the interface for ARP/IP/ICMP connections
    """

    prettyName = None

    ethernetType = None
    destinations = list()

    readQueue = queue.Queue()
    writeQueue = queue.Queue()
    availableDataInterruptPipe = None

    _currentFrame = 0

    _layer4Hook = dict() # Layer 2 hooks of the connection, e.g. TCP / UDP
                         # The first layer 2 hook is assumed to be the master hook, the following
                         # hooks are secondary and *should* (not enforced) only filter / log

    def addDestination(self, macAddress: str):
        self.destinations.append(macAddress)
        print(self.destinations)


    def receiveData(self, packet: RawPacket) -> None:
        self.readQueue.put((self._currentFrame, packet))
        self._currentFrame += 1
        self.dataAvailable()
    

    def sendData(self, packet: bytes, macDestination: str) -> None:
        self.writeQueue.put((self._currentFrame, packet))
        self._currentFrame += 1
        print(f'oo {self.availableDataInterruptPipe}')
        os.write(self.availableDataInterruptPipe, bytes(1))


    @abstractmethod
    def dataAvailable(self):
        pass




class Layer4(ABC):
    """
    Abstract Layer4 Class

    Provides the interface for TCP/UDP/Layer4 connections
    """

    LISTENER = 1
    CLIENT = 2
    
    _layer2 = None

    
    _layer5Hooks = dict() # Layer 5 hooks of the connection, e.g. TLS / SSL
    _layer7Hooks = dict() # Layer 7 hooks of the connection, e.g. HTTP / FTP
                          # The first layer 7 hook is assumed to be the master hook, the following
                          # hooks are secondary and *should* (not enforced) only filter / log

    @abstractmethod
    def __init__(self, address, port, role):
        raise NotImplementedError(f'The layer 4 protocol \'{type(self).__name__}\' has not implemented a constructor')

    @classmethod
    def createListener(cls, address, port):
        return cls(address, port, cls.LISTENER)

    @classmethod
    def createClient(cls, address, port):
        return cls(address, port, cls.CLIENT)

    def setHook(self, name, function):
        # TODO: Check if hook function is valid
        raise NotImplementedError()


class Layer7(ABC):
    """
    Abstract Layer7 Hook Class

    Provides the interface for application protocols
    """

    _detectionRegEx = None

    _readBuffer = bytes()

    @abstractmethod
    def __init__(self, address, port, role):
        raise NotImplementedError(f'The layer 7 protocol \'{type(self).__name__}\' has not implemented a constructor')

    def connectionStart(self, todo):
        pass

    def connectionClosed(self, todo):
        pass

    def connectionAborted(self, todo):
        pass

    def recievedDataPacket(self, todo):
        pass

    def recievedData(self, todo):
        pass