"""Disposable target: owns all memory modified by step-2 integration tests."""
import ctypes
import json
import os
import sys

k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
k32.VirtualAlloc.restype = ctypes.c_void_p
base = k32.VirtualAlloc(None, 4096, 0x3000, 0x04)
if not base:
    raise ctypes.WinError(ctypes.get_last_error())
print(json.dumps({'pid':os.getpid(), 'base':hex(base)}), flush=True)
for line in sys.stdin:
    command = json.loads(line)
    address = base + command['offset']
    size = command.get('size', 1)
    assert 0 <= command['offset'] < 4096 and command['offset'] + size <= 4096
    if command['op'] == 'write':
        data = bytes.fromhex(command['hex'])
        assert command['offset'] + len(data) <= 4096
        ctypes.memmove(address, data, len(data))
        print('{}', flush=True)
    else:
        print(json.dumps({'hex':ctypes.string_at(address, size).hex()}), flush=True)
