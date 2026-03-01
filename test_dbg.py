"""只测 check_proc_maps，分开 stdout 和 stderr"""
import subprocess, os
os.chdir(r'c:\Users\Rabe\Desktop\vmp')

def run_test(name, addr):
    packed = f'build/fin_{name}_p'
    vmped  = f'build/fin_{name}_v'
    remote = f'/home/root/vmp/fin_{name}'
    
    subprocess.run(['build/packer_dbg.exe','-i','demo/demo_stur_call','-o',packed,'-protect','-encrypt'], capture_output=True)
    if addr:
        subprocess.run(['build/vmpacker.exe','-addr',addr,'-strip=false','-o',vmped,packed], capture_output=True)
        subprocess.run(['python','fix_crc.py',vmped], capture_output=True)
        target = vmped
    else:
        target = packed
    
    subprocess.run(['adb','push',target,remote], capture_output=True)
    
    # 在设备上分离 stdout 和 stderr
    cmd = f'chmod +x {remote}; {remote} > /tmp/out.txt 2>/tmp/err.txt; echo RC=$?; echo "---STDOUT---"; cat /tmp/out.txt; echo "---STDERR---"; cat /tmp/err.txt'
    try:
        r = subprocess.run(['adb','shell',cmd], capture_output=True, text=True, timeout=10)
        print(f'\n=== {name} ===')
        for line in r.stdout.strip().split('\n'):
            print(f'  {line}')
    except subprocess.TimeoutExpired:
        print(f'\n=== {name} ===')
        print('  TIMEOUT')

run_test('baseline', None)
run_test('proc_maps', '0x10002434-0x100024F0:check_proc_maps')
run_test('stub_crc', '0x10001C10-0x10001CBC:check_stub_crc')
