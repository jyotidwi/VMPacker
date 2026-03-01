import struct, zlib, sys

def rotl32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
i = d.find(struct.pack('<I', 0x43524332))
if i < 0:
    print('No CRC2 magic'); sys.exit()

salt = struct.unpack_from('<I', d, i+8)[0]
sc = struct.unpack_from('<H', d, i+12)[0]
so, ss = struct.unpack_from('<II', d, i+16)

# Stub code starts at: IntegrityHeader offset - stub_code_size
# (runtime: stub_base = data_start - ih->stub_code_size)
stub_start = i - ss
stub = bytes(d[stub_start : stub_start + ss])
key = salt
off = i + 32
for j in range(sc):
    co = j * 4096
    c = stub[co : min(co + 4096, ss)]
    a, s, h = co, len(c), zlib.crc32(c) & 0xFFFFFFFF
    ea = (a ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ a
    es = (s ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ s
    eh = (h ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ h
    struct.pack_into('<III', d, off, ea, es, eh)
    off += 12

struct.pack_into('<I', d, i+28, zlib.crc32(bytes(d[i:i+28])) & 0xFFFFFFFF)
open(path, 'wb').write(d)
print(f'CRC fixed: {sc} chunks, salt=0x{salt:08X}')
