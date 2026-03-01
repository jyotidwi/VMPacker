import re, os, sys

base = r"c:\Users\Rabe\Desktop\vmp\stub\vm_handlers"
files = ["h_alu.h", "h_branch.h", "h_cmp.h", "h_mem.h", "h_mov.h", "h_stack.h", "h_system.h"]
total = 0

for f in files:
    p = os.path.join(base, f)
    if not os.path.exists(p):
        print(f"  SKIP: {f}")
        continue
    c = open(p, encoding="utf-8").read()
    # Replace vm->R[var & 31] with VM_R(vm, var)
    n, cnt = re.subn(r'vm->R\[(\w+)\s*&\s*31\]', lambda m: f'VM_R(vm, {m.group(1)})', c)
    if cnt > 0:
        open(p, "w", encoding="utf-8").write(n)
    total += cnt
    print(f"  {f}: {cnt} replacements")

print(f"\nTotal: {total} replacements")
