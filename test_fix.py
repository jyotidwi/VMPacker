"""修复后精确测试 - 用最新 vmpacker"""
import subprocess, struct, zlib, os
os.chdir(r'c:\Users\Rabe\Desktop\vmp')

def rotl32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def test(name, addr):
    packed = f'build/fix_{name}_p'
    vmped  = f'build/fix_{name}_v'
    remote = f'/home/root/vmp/fix_{name}'
    
    subprocess.run(['build/packer_gcc.exe','-i','demo/demo_stur_call','-o',packed,'-protect','-encrypt'], capture_output=True)
    subprocess.run(['build/vmpacker.exe','-addr',addr,'-strip=false','-o',vmped,packed], capture_output=True)
    subprocess.run(['python','fix_crc.py',vmped], capture_output=True)
    
    # Verify CRC
    d = open(vmped,'rb').read()
    idx = d.find(struct.pack('<I',0x43524332))
    salt = struct.unpack_from('<I',d,idx+8)[0]; sc = struct.unpack_from('<H',d,idx+12)[0]
    so, ss = struct.unpack_from('<II',d,idx+16)
    stub = d[idx-ss:idx]; key = salt; off = idx + 32; ok = True
    for j in range(sc):
        ea,es,eh = struct.unpack_from('<III',d,off)
        da=(ea^key)&0xFFFFFFFF; key=rotl32(key,7)^da
        ds=(es^key)&0xFFFFFFFF; key=rotl32(key,7)^ds
        dh=(eh^key)&0xFFFFFFFF; key=rotl32(key,7)^dh
        c = stub[da:da+ds]; h = zlib.crc32(c)&0xFFFFFFFF
        if h!=dh: ok=False
        off+=12
    
    subprocess.run(['adb','push',vmped,remote], capture_output=True)
    try:
        r = subprocess.run(['adb','shell',f'chmod +x {remote}; {remote}; echo XDONE'],
            capture_output=True, text=True, timeout=10)
        o = r.stdout
        if 'PASS' in o: s='PASS'
        elif 'SIGSEGV' in o: s='SEGFAULT'
        elif 'XDONE' in o: s='SILENT'
        else: s='OTHER'
    except subprocess.TimeoutExpired:
        s = 'TIMEOUT'
    crc = 'OK' if ok else 'FAIL'
    print(f'{name:20s}: CRC={crc}  RESULT={s}')

# Test all previous failures
test('proc_maps', '0x10002434-0x100024F0:check_proc_maps')
test('stub_crc',  '0x10001C10-0x10001CBC:check_stub_crc')
test('memory_crc', '0x10001CC0-0x10001D7C:check_memory_crc')
# Also re-test passing ones
test('brk',       '0x10001D80-0x10001DE4:scan_brk')
test('tracer',    '0x10002340-0x10002434:check_tracer_pid')
# Test all together
test('all5', '0x10001D80-0x10001DE4:brk,0x10002340-0x10002434:tracer,0x10002434-0x100024F0:proc,0x10001C10-0x10001CBC:stub_crc,0x10001CC0-0x10001D7C:mem_crc')
