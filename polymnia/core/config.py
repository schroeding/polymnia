import polymnia.core.log as log

import json

_defaultConfig = {
    'version': '0.0',

    'dataPath': 'data'
}

_config = dict()


def get(configKey: str) -> str:
    if (configKey in _config):
        return _config[configKey]
    if (configKey in _defaultConfig):
        return _defaultConfig[configKey]
    log.error(f'Requested config value \'{configKey}\' unknown')
    return None
