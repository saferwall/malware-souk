import json

# fn_name = "wsprintfW"
# api_hash = 0x0B6D391AE

export_db = {}

def get_api_hash(fn_name):
    result = 0x2b
    for c in fn_name:
        result = ord(c) + 0x10f * result
    return result & 0x1FFFFF


def transform_hash(api_hash):
    result = api_hash ^ ((api_hash ^ 0x76C7) << 16) ^ 0xAFB9
    return result & 0x1fffff


def lookup_hash(api_hash):
    t_hash = transform_hash(api_hash)
    return export_db.get(t_hash, "")


def setup(json_file):
    global export_db
    exports_json = json.loads(open(json_file,'rb').read())
    exports_list = exports_json['exports']
    for export in exports_list:
        api_hash = get_api_hash(export)
        export_db[api_hash] = export


def get_imports(base_address):
    for ptr in range(0,0x230,4):
        hash_value = idc.Dword(base_address + ptr)
        api_name = lookup_hash(hash_value)
        if api_name == "":
            continue
        idc.MakeName(base_address + ptr, api_name.encode('utf-8'))
