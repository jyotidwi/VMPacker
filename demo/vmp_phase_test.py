"""
vmp_phase_test.py — 逐 phase 函数 VMP 保护 + 设备测试
自动对每个 sub_phase_{A..I} + stub_main 分别 VMP 保护并推送设备测试
"""
import subprocess, sys, os

PHASES = [
    ("stub_phase_A", "0x100013C0", "0x100014C0"),
    ("stub_phase_B", "0x100014C0", "0x10001528"),
    ("stub_phase_C", "0x10001528", "0x100015D0"),
    ("stub_phase_D", "0x100015D0", "0x10001660"),
    ("stub_phase_E", "0x10001660", "0x10001700"),
    ("stub_phase_F", "0x10001700", "0x10001988"),
    ("stub_phase_G", "0x10001988", "0x10001AA8"),
    ("stub_phase_H", "0x10001AA8", "0x10001B58"),
    ("stub_phase_I", "0x10001B58", "0x10001CB8"),
    ("stub_main",    "0x10001CB8", "0x10001D18"),  # dispatcher
]

PACKED = "demo/demo_split_packed"
DEVICE_DIR = "/home/root/vmp"

def run(cmd, show=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
    if show:
        print(r.stdout[-400:] if len(r.stdout) > 400 else r.stdout, end='')
        if r.stderr: print(r.stderr[-200:] if len(r.stderr) > 200 else r.stderr, end='')
    return r

print("=" * 60)
print("VMP Phase-by-Phase Test")
print("=" * 60)

results = []
for name, start, end in PHASES:
    tag = name.replace("stub_", "")
    out_file = f"demo/demo_vmp_{tag}"
    remote = f"{DEVICE_DIR}/demo_vmp_{tag}"

    addr_spec = f"{start}-{end}:{name}"
    print(f"\n[{name}] VMP protecting {start}-{end} ...", end=" ", flush=True)

    # VMP protect
    r = run(f'go run ./cmd/vmpacker -addr "{addr_spec}" -strip=false -o {out_file} {PACKED}')
    if r.returncode != 0:
        print(f"VMP FAIL (rc={r.returncode})")
        print(r.stderr[-300:])
        results.append((name, "VMP_FAIL"))
        continue
    print("OK", end=" ", flush=True)

    # Push to device
    run(f'adb push {out_file} {remote}')
    run(f'adb shell "chmod +x {remote}"')

    # Run test  
    r = run(f'adb shell "{remote}; echo EXIT=$?"')
    output = r.stdout.strip()
    
    if "EXIT=0" in output or "EXIT=True" in output:
        status = "PASS"
    elif "Segmentation fault" in output or "SIGSEGV" in output or "EXIT=139" in output:
        status = "CRASH"
    else:
        status = f"FAIL({output[-60:]})"
    
    print(f"-> {status}")
    results.append((name, status))

print("\n" + "=" * 60)
print("RESULTS SUMMARY")
print("=" * 60)
for name, status in results:
    marker = "OK" if status == "PASS" else "XX"
    print(f"  {marker} {name:20s} : {status}")

crashes = [n for n, s in results if "CRASH" in s or "FAIL" in s]
if crashes:
    print(f"\n>> CRASH CANDIDATES: {', '.join(crashes)}")
else:
    print(f"\n>> ALL PHASES PASSED!")
