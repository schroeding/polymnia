import polymnia.core.log as log

import os
import hashlib


def writeData(type: str, name: str, data: bytes, extension: str = '', uniqueCopy: bool = True) -> bool:
    _dataPath = os.path.abspath('./')
    if (not os.path.exists(_dataPath)):
        log.warning(f'The specified data folder \'{_dataPath}\' does not exist and will be created')
        try:
            os.makedirs(_dataPath)
        except (Exception):
            log.error(f'Could not create the specified data folder \'{_dataPath}\', aborting')
            return False

    _typePath = os.path.join(_dataPath, type)
    if (not os.path.exists(_typePath)):
        log.info(f'Creating a new folder for data of \'{type}\' type')
        try:
            os.makedirs(_typePath)
        except (Exception):
            log.error(f'Could not create the specified data type folder \'{_typePath}\', aborting')
            return False

    _fileName = f'{name}_{hashlib.sha256(data).hexdigest() if uniqueCopy else str()}'
    if (extension != str()):
        _fileName += f'.{extension}'
    _filePath = os.path.abspath(os.path.join(_typePath, _fileName))
    
    if (os.path.commonpath([_filePath, _dataPath]) != _dataPath):
        log.critical(f'Tried to write data outside of data folder! (\'{_filePath}\')')
        log.critical('Possibly malicious behavior, aborting')
        return False

    if (os.path.exists(_filePath)):
        log.info(f'Overwriting existing file \'{_fileName}\'')

    try:
        _fileHandle = open(_filePath, 'wb+')
        _fileHandle.write(data)
        _fileHandle.close()
    except (Exception):
        log.error(f'Could not save data to file \'{_filePath}\'')
        return False

    return True


def readData(path: str) -> bytes:
    _dataPath = os.path.abspath('./')
    _filePath = os.path.abspath(path)
    if (not os.path.exists(_filePath)):
        log.warning(f'Could not read data from non-existing file \'{_filePath}\'')
        return None

    if (os.path.commonpath([_filePath, _dataPath]) != _dataPath):
        log.critical(f'Tried to read data outside of data folder! (\'{_filePath}\')')
        log.critical('Possibly malicious behavior, aborting')
        return False

    _data = None
    try:
        _fileHandle = open(_filePath, 'rb')
        _data = _fileHandle.read(None)
        _fileHandle.close()
    except (Exception):
        log.error(f'Could not read data from file \'{_filePath}\'')
        return None

    return _data
