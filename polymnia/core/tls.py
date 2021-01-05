import polymnia.core.log as log
import polymnia.core.io as io

import cryptography.hazmat.primitives.asymmetric as asymmetric
import cryptography.hazmat.primitives.serialization as serialization
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.x509 as x509

import os
import random
import datetime


_keys = dict()
_caCerts = dict()
_certs = dict()


def generateRSAKey(name: str, size: int) -> bool:
    if (_keys.get(name, None) is not None):
        log.warning(f'Overwriting existing RSA key \'{name}\' in memory')
    try:
        _keys[name] = asymmetric.rsa.generate_private_key(65537, size)
    except (Exception):
        log.error(f'Could not create new RSA key \'{name}\' ({size} bytes)')
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


def generateCaCertificate(name: str, caName: str) -> bool:
    _caName = bytes(caName.encode('utf-8'))
    _caBuilder = x509.CertificateBuilder(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"cryptography.io")]), x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"cryptography.io")]))
    _key = getRSAKey(f'ca_{name}')
    if (_key is None):
        generateRSAKey(f'ca_{name}', 2048)
        _key = getRSAKey(f'ca_{name}')
    _caBuilder = _caBuilder.public_key(_key.public_key())
    _caBuilder = _caBuilder.not_valid_before(datetime.datetime.now())
    _caBuilder = _caBuilder.not_valid_after(datetime.datetime.now())
    _caBuilder = _caBuilder.serial_number(random.randrange(10000000, 99999998))
    _caCertificate = _caBuilder.sign(_key, hashes.SHA256())
    if (_caCerts.get(name, None) is not None):
        log.warning(f'Overwriting existing CA certificate \'{name}\' in memory')
    _caCerts[name] = _caCertificate
    return True


def getCACertificate(name: str) -> x509.Certificate:
    return _caCerts.get(name, None)


def dumpCaCertificate(name: str) -> bool:
    _caCert = _caCerts.get(name, None)
    if (_caCert is None):
        log.error(f'Cannot dump non-existing ca certificate \'{name}\'')
        return False
    dumpKey(f'ca_{name}')
    _certdata = _caCert.public_bytes(
        encoding=serialization.Encoding.PEM)
    return io.writeData('certificates', name, _certdata, 'crt')