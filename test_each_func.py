"""逐个保护函数 VMP + protect + CRC重算 测试"""
import subprocess, struct, zlib, os
os.chdir(r'c:\Users\Rabe\Desktop\vmp')

def rotl32(v, n):
    n = n % 32
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def verify_crc(filepath):
    d = open(filepath, 'rb').read()
    idx = d.find(struct.pack('<I', 0x43524332))
    if idx < 0: return 'NO_CRC2'
    salt = struct.unpack_from('<I', d, idx+8)[0]
    sc = struct.unpack_from('<H', d, idx+12)[0]
    so, ss = struct.unpack_from('<II', d, idx+16)
    stub = d[idx-ss:idx]; key = salt; off = idx + 32
    for j in range(sc):
        ea,es,eh = struct.unpack_from('<III', d, off)
        da=(ea^key)&0xFFFFFFFF; key=rotl32(key,7)^da
        ds=(es^key)&0xFFFFFFFF; key=rotl32(key,7)^ds
        dh=(eh^key)&0xFFFFFFFF; key=rotl32(key,7)^dh
        c = stub[da:da+ds]; h = zlib.crc32(c) & 0xFFFFFFFF
        if h != dh: return 'MISMATCH'
        off += 12
    return 'OK'

def test_one(name, addr_str):
    packed = f'build/iso_{name}_p'
    vmped = f'build/iso_{name}_v'
    remote = f'/home/root/vmp/iso_{name}'
    # 1. Pack
    r1 = subprocess.run(['build/packer_gcc.exe','-i','demo/demo_stur_call','-o',packed,'-protect','-encrypt'], capture_output=True)
    # 2. VMP
    r2 = subprocess.run(['build/vmpacker.exe','-addr',addr_str,'-strip=false','-o',vmped,packed], capture_output=True, text=True)
    if not os.path.exists(vmped):
        return 'VMP_FAIL', r2.stderr[:60] if r2.stderr else r2.stdout[:60]
    # 3. CRC fix
    subprocess.run(['python','fix_crc.py',vmped], capture_output=True)
    # 4. Verify CRC
    crc = verify_crc(vmped)
    # 5. Push & test
    subprocess.run(['adb','push',vmped,remote], capture_output=True)
    try:
        r = subprocess.run(['adb','shell',f'chmod +x {remote}; {remote}; echo XDONE'],
            capture_output=True, text=True, timeout=10)
        o = r.stdout
        if 'PASS' in o: result = 'PASS'
        elif 'SIGSEGV' in o: result = 'SEGFAULT'
        elif 'SIGILL' in o: result = 'SIGILL'
        elif 'XDONE' in o: result = 'SILENT_EXIT'
        else: result = 'OTHER'
    except subprocess.TimeoutExpired:
        result = 'TIMEOUT'
    return result, crc

# 所有可 VMP 的保护函数 (排除太小的)
funcs = [
    ('calc_crc32',          '0x10001B80-0x10001BC4:calc_crc32'),
    ('decrypt_crc_info',    '0x10001BC4-0x10001C10:decrypt_crc_info'),
    ('check_stub_crc',      '0x10001C10-0x10001CBC:check_stub_crc'),
    ('check_memory_crc',    '0x10001CC0-0x10001D7C:check_memory_crc'),
    ('scan_brk',            '0x10001D80-0x10001DE4:scan_brk'),
    ('antidump_init',       '0x10002310-0x10002338:antidump_init'),
    ('check_tracer_pid',    '0x10002340-0x10002434:check_tracer_pid'),
    ('check_proc_maps',     '0x10002434-0x100024F0:check_proc_maps'),
    ('timing_check',        '0x10002500-0x10002538:timing_check'),
    ('wipe_sensitive_data',  '0x10002540-0x10002558:wipe_sensitive_data'),
]

print(f'{"FUNCTION":25s}  {"RESULT":12s}  CRC')
print('-' * 50)
results = {}
for name, addr in funcs:
    r, crc = test_one(name, addr)
    print(f'{name:25s}  {r:12s}  {crc}')
    results[name] = r

print('\n=== SUMMARY ===')
passed = [n for n,r in results.items() if r == 'PASS']
failed = [n for n,r in results.items() if r != 'PASS']
print(f'PASS ({len(passed)}): {", ".join(passed)}')
print(f'FAIL ({len(failed)}): {", ".join(f"{n}({results[n]})" for n in failed)}')
