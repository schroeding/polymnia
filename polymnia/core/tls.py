import polymnia.core.log as log
import polymnia.core.io as io

import cryptography.hazmat.primitives.asymmetric as asymmetric
import cryptography.hazmat.primitives.serialization as serialization

import os
import random


_keys = dict()
_caCerts = dict()
_certs = dict()


def generateRSAKey(name: str, size: int) -> bool:
    if (_keys.get(name, None) is not None):
        log.warning(f'Overwriting existing RSA key \'{name}\' in memory')
    try:
        _keys[name] = asymmetric.rsa.generate_private_key(65537, size)
    except (Exception):
        log.error('Could not create new RSA key \'{name}\' ({size} bytes)')
        return False
    return True


def getRSAKey(name: str) -> asymmetric.rsa.RSAPrivateKeyWithSerialization:
    return _keys.get(name, None)


def dumpKey(name: str) -> bool:
    _key = _keys.get(name, None)
    if (_key is None):
        log.error(f'Cannot dump non-existing key \'{name}\'')
        return False
    if (isinstance(_key, asymmetric.rsa.RSAPrivateKeyWithSerialization)):
        _keydata = _key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
        io.writeData('privatekeys', name, _keydata, 'pem')
        return True
    else:
        log.error(f'Cannot dump key in unknown format \'{name}\'')
