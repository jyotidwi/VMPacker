import struct, os
os.chdir(r'c:\Users\Rabe\Desktop\vmp')
d = open('build/fix_proc_maps_v','rb').read()
phoff = struct.unpack_from('<Q',d,32)[0]
phnum = struct.unpack_from('<H',d,56)[0]
print(f'PHDR: offset=0x{phoff:X}, count={phnum}')
for i in range(phnum):
    off = phoff + i*56
    pt = struct.unpack_from('<I',d,off)[0]
    pflags = struct.unpack_from('<I',d,off+4)[0]
    poff = struct.unpack_from('<Q',d,off+8)[0]
    pva = struct.unpack_from('<Q',d,off+16)[0]
    pfsz = struct.unpack_from('<Q',d,off+32)[0]
    pmsz = struct.unpack_from('<Q',d,off+40)[0]
    tn = {1:'LOAD',4:'NOTE',6:'PHDR'}.get(pt,hex(pt))
    rwx = ('R' if pflags&4 else '') + ('W' if pflags&2 else '') + ('X' if pflags&1 else '')
    end_va = pva + pmsz
    mark = ' <-- 0x25F8 IN' if (pva <= 0x100025F8 < end_va) else ''
    print(f'  [{i}] {tn:6s} {rwx:3s} VA=0x{pva:X}..0x{end_va:X} fsz=0x{pfsz:X}{mark}')

# File offset 0x25F8 content
if 0x25F8+16 < len(d):
    print(f'\nData at file offset 0x25F8:')
    print(f'  hex: {d[0x25F8:0x25F8+16].hex()}')
    print(f'  txt: {d[0x25F8:0x25F8+16]}')
    # Find "[deleted]" in file
    idx_del = d.find(b'[deleted]')
    if idx_del >= 0:
        print(f'  "[deleted]" at file offset 0x{idx_del:X} (VA 0x{0x10000000+idx_del:X})')
    else:
        print(f'  "[deleted]" NOT FOUND in file!')
