"""PSA Crypto driver description parser.
"""

import enum
import json
import jsonschema



################################################################
#### Data types ####
################################################################

class BadCapability(Exception):
    pass

class Type(enum.Enum):
    TRANSPARENT = 0
    OPAQUE = 1

class Capability:
    def __init__(self, functions, algorithms, key_types):
        self.functions = frozenset(functions)
        self.algorithms = None if algorithms is None else frozenset(algorithms)
        self.key_types = None if key_types is None else frozenset(key_types)

class Driver:
    def __init__(self):
        self.prefix = None
        self.type = None
        self.capabilities = []

    def is_transparent(self):
        return self.type == Type.TRANSPARENT

    def is_opaque(self):
        return self.type == Type.OPAQUE

    def has_function(self, name):
        return any(name in cap.functions for cap in self.capabilities)


################################################################
#### JSON parsing ####
################################################################

def js_enum(*values):
    return {'type': 'string', 'enum': list(values)}

ALGORITHM_JSON_SCHEMA = {
    'type': 'string',
    'pattern': '^PSA_ALG_[0-9A-Z_]+',
}

KEY_TYPE_JSON_SCHEMA = {
    'type': 'string',
    'pattern': '^PSA_ALG_[0-9A-Z_]+$',
}

FUNCTION_JSON_SCHEMA = {
    'type': 'string',
    'pattern': '^[0-9a-z_]+$',
}

CAPABILITY_JSON_SCHEMA = {
    'type': 'object',
    'properties': {
        'algorithms': {'type': 'array', 'items': ALGORITHM_JSON_SCHEMA},
        'functions': {'type': 'array', 'items': FUNCTION_JSON_SCHEMA},
        'key_types': {'type': 'array', 'items': KEY_TYPE_JSON_SCHEMA},
    },
    'required': ['functions'],
}

EMPTY_OBJECT_JSON_SCHEMA = {'type': 'object', 'maxProperties': 0}

DRIVER_JSON_SCHEMA = {
    'type': 'object',
    'properties': {
        'capabilities': {'type': 'array',
                         'items': {'oneOf': [CAPABILITY_JSON_SCHEMA,
                                             EMPTY_OBJECT_JSON_SCHEMA]}},
        'prefix': {'type': 'string', 'pattern': '^[a-z][0-9_a-z]*$'},
        'type': js_enum('transparent', 'opaque'),
    },
    'required': ['capabilities', 'prefix', 'type'],
}

def capability_from_json_data(data):
    algorithms = data.get('algorithms', None)
    functions = data['functions']
    key_types = data.get('key_types', None)
    return Capability(functions, algorithms, key_types)

def from_json_data(data):
    jsonschema.validate(data, DRIVER_JSON_SCHEMA)
    driver = Driver()
    driver.prefix = data['prefix']
    driver.type = Type[data['type'].upper()]
    driver.capabilities = [capability_from_json_data(elt)
                           for elt in data['capabilities']
                           if elt != {}]
    return driver

def from_json(string):
    return from_json_data(json.loads(string))

def from_json_file(filename):
    with open(filename, 'r') as stream:
        return from_json_data(json.load(stream))
