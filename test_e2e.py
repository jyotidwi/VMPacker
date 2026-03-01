import subprocess, struct, zlib, os
os.chdir(r'c:\Users\Rabe\Desktop\vmp')

def rotl32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def test_vmp(name, addrs):
    # 1. Pack (每次用独立文件！)
    packed = f'build/t_{name}_packed'
    vmped = f'build/t_{name}_vmp'
    subprocess.run(['build/packer_gcc.exe','-i','demo/demo_stur_call','-o',packed,'-protect','-encrypt'], capture_output=True)
    # 2. VMP
    subprocess.run(['build/vmpacker.exe','-addr',addrs,'-strip=false','-o',vmped,packed], capture_output=True)
    # 3. CRC fix
    subprocess.run(['python','fix_crc.py',vmped], capture_output=True)
    # 4. Verify CRC
    d = open(vmped,'rb').read()
    idx = d.find(struct.pack('<I',0x43524332))
    if idx < 0:
        print(f'{name}: NO CRC2 HEADER')
        return
    salt = struct.unpack_from('<I',d,idx+8)[0]
    sc = struct.unpack_from('<H',d,idx+12)[0]
    so, ss = struct.unpack_from('<II',d,idx+16)
    stub = d[idx-ss:idx]
    key = salt; off = idx + 32; ok = True
    for j in range(sc):
        ea,es,eh = struct.unpack_from('<III',d,off)
        da=(ea^key)&0xFFFFFFFF; key=rotl32(key,7)^da
        ds=(es^key)&0xFFFFFFFF; key=rotl32(key,7)^ds
        dh=(eh^key)&0xFFFFFFFF; key=rotl32(key,7)^dh
        c = stub[da:da+ds]; h = zlib.crc32(c)&0xFFFFFFFF
        if h!=dh: ok=False
        off+=12
    # 5. Push & test
    subprocess.run(['adb','push',vmped,f'/home/root/vmp/{name}'], capture_output=True)
    r = subprocess.run(['adb','shell',f'chmod +x /home/root/vmp/{name}; /home/root/vmp/{name}; echo XDONE'],
        capture_output=True, text=True, timeout=10)
    o = r.stdout
    if 'PASS' in o: s='PASS'
    elif 'SIGSEGV' in o: s='SEGFAULT'
    elif 'XDONE' in o: s='SILENT'
    else: s='OTHER'
    crc_s = 'OK' if ok else 'FAIL'
    print(f'{name}: CRC={crc_s} RESULT={s}')

# Test individual functions
test_vmp('brk_only', '0x10001D80-0x10001DE4:scan_brk')
test_vmp('tracer_only', '0x10002340-0x10002434:tracer')
test_vmp('proc_only', '0x10002434-0x100024F0:proc')
# Test all 3
test_vmp('all3', '0x10001D80-0x10001DE4:scan_brk,0x10002340-0x10002434:tracer,0x10002434-0x100024F0:proc')
# Test all 7
test_vmp('all7', '0x10001B80-0x10001BC4:calc_crc32,0x10001BC4-0x10001C10:decrypt_crc_info,0x10001C10-0x10001CBC:check_stub_crc,0x10001CC0-0x10001D7C:check_memory_crc,0x10001D80-0x10001DE4:scan_brk,0x10002340-0x10002434:tracer,0x10002434-0x100024F0:proc')
