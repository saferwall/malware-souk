
import os
import pefile
import json

INTERESTING_DLLS = [
    'kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
    'gdi32.dll',    'msvcrt.dll',   'netapi32.dll', 'ntdll.dll',
    'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll',    'shell32.dll',
    'shlwapi.dll',  'srsvc.dll',    'urlmon.dll',   'user32.dll',
    'winhttp.dll',  'wininet.dll',  'ws2_32.dll',   'wship6.dll',
    'advpack.dll',
]


exports_list = []

for filename in os.listdir("C:\\Windows\\System32"):
    if filename.lower() in INTERESTING_DLLS:
        pe = pefile.PE("C:\\Windows\\System32\\" + filename)
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                exports_list.append(exp.name.decode('utf-8'))
            except:
                continue

exports_json = {'exports':exports_list}
open('exports.json','wb').write(json.dumps(exports_json))
