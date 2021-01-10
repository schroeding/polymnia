import binascii
import dpkt



def ipBytesToString(ipaddress: bytes) -> str:
    return '.'.join(str(_byte) for _byte in ipaddress)


def ipStringToBytes(ipaddress: str) -> bytes:
    return bytes(map(int, ipaddress.split('.')))
