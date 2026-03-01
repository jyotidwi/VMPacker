#!/usr/bin/env python3
"""
一键加壳+VMP保护
用法: python vmp_protect.py <input_elf> [output]
流程: packer加壳(protect+encrypt) → vmpacker VMP保护7个壳函数 → CRC重算
"""
import os, sys, platform, struct, subprocess, zlib

# 7个可VMP函数地址 (OLLVM版stub.elf, stub_main/phase_F已OLLVM保护)
VMP_ADDRS = ",".join([
    "0x10005AE0-0x10005B24:calc_crc32",
    "0x10005B24-0x10005B70:decrypt_crc_info",
    "0x10005B70-0x10005C1C:check_stub_crc",
    "0x10005C20-0x10005CDC:check_memory_crc",
    "0x10005CE0-0x10005D44:scan_brk_instructions",
    "0x100062A0-0x10006394:check_tracer_pid",
    "0x10006394-0x10006450:check_proc_maps",
])

INTEGRITY_MAGIC = 0x43524332  # "CRC2"
CHUNK_SIZE = 4096


def rotl32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def recalc_crc(path):
    """VMP后重算stub CRC, 修复-protect模式"""
    data = bytearray(open(path, 'rb').read())
    magic = struct.pack('<I', INTEGRITY_MAGIC)
    idx = data.find(magic)
    if idx < 0:
        return  # 没启用CRC保护, 跳过

    salt = struct.unpack_from('<I', data, idx + 8)[0]
    stub_count = struct.unpack_from('<H', data, idx + 12)[0]
    stub_off = struct.unpack_from('<I', data, idx + 16)[0]
    stub_size = struct.unpack_from('<I', data, idx + 20)[0]

    # 找stub所在LOAD段的文件偏移
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    load_foff = 0
    for i in range(e_phnum):
        po = e_phoff + i * 56
        if struct.unpack_from('<I', data, po)[0] == 1:  # PT_LOAD
            pv = struct.unpack_from('<Q', data, po + 16)[0]
            if pv == 0x10000000:
                load_foff = struct.unpack_from('<Q', data, po + 8)[0]
                break

    # 读取VMP后的stub代码, 重算CRC
    stub_data = bytes(data[load_foff + stub_off: load_foff + stub_off + stub_size])
    key = salt
    off = idx + 32
    for i in range(stub_count):
        chunk_off = i * CHUNK_SIZE
        chunk = stub_data[chunk_off: min(chunk_off + CHUNK_SIZE, stub_size)]
        addr, size, new_hash = chunk_off, len(chunk), zlib.crc32(chunk) & 0xFFFFFFFF

        # 加密写回 (chained XOR + rotl32)
        enc_a = (addr ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ addr
        enc_s = (size ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ size
        enc_h = (new_hash ^ key) & 0xFFFFFFFF; key = rotl32(key, 7) ^ new_hash
        struct.pack_into('<III', data, off, enc_a, enc_s, enc_h)
        off += 12

    # 重算header CRC
    struct.pack_into('<I', data, idx + 28, zlib.crc32(bytes(data[idx:idx + 28])) & 0xFFFFFFFF)
    open(path, 'wb').write(data)
    print(f"  CRC重算: {stub_count}个块已更新")


def main():
    if len(sys.argv) < 2:
        print("用法: python vmp_protect.py <input_elf> [output]"); sys.exit(1)

    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else inp + ".protected"
    tmp = out + ".packed"

    d = os.path.dirname(os.path.abspath(__file__))
    ext = ".exe" if platform.system() == "Windows" else "_linux"
    packer = os.path.join(d, "build", "packer" + ext)
    vmpacker = os.path.join(d, "build", "vmpacker" + ext)

    # Step 1: 加壳 (protect+encrypt)
    print(f"[1/3] 加壳: {inp}")
    r = subprocess.run([packer, "-i", inp, "-o", tmp, "-protect", "-encrypt"],
                       capture_output=True, text=True, errors="replace")
    print(r.stdout)
    if r.returncode != 0:
        print(f"加壳失败: {r.stderr}"); sys.exit(1)

    # Step 2: VMP保护7个函数
    print(f"[2/3] VMP保护7个函数")
    r = subprocess.run([vmpacker, "-addr", VMP_ADDRS, "-o", out, tmp],
                       capture_output=True, text=True, errors="replace")
    print(r.stdout)
    if r.returncode != 0:
        print(f"VMP失败: {r.stderr}"); sys.exit(1)

    # Step 3: CRC重算
    print(f"[3/3] CRC重算")
    recalc_crc(out)

    os.remove(tmp)
    print(f"✅ {out} ({os.path.getsize(out):,} bytes)")

if __name__ == "__main__":
    main()
