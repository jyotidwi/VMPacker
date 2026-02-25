# ============================================================
# VMP 工具链 Makefile
# make all    → 编译 C stub → 嵌入 Go → 输出到 build/
# make stub   → 仅编译 VM 解释器 blob
# make packer → 仅编译 Go packer（需先 make stub）
# make demo   → 交叉编译 demo 程序
# make test   → 运行 Go 单元测试
# make clean  → 清理所有产物
# ============================================================

# 交叉编译工具链
CROSS   ?= aarch64-linux-gnu-
CC       = $(CROSS)gcc
LD       = $(CROSS)ld
OBJCOPY  = $(CROSS)objcopy
GO       = go

# 目录
STUB_DIR   = stub
CMD_DIR    = cmd/vmpacker
DEMO_DIR   = demo
BUILD_DIR  = build

# ------ VM 解释器 blob ------
STUB_SRC   = $(STUB_DIR)/vm_interp_clean.c
STUB_LDS   = $(STUB_DIR)/vm_interp.lds
STUB_O     = $(BUILD_DIR)/stub/vm_interp.o
STUB_ELF   = $(BUILD_DIR)/stub/vm_interp.elf
STUB_BIN   = $(CMD_DIR)/vm_interp.bin

# ------ Go packer ------
PACKER     = $(BUILD_DIR)/vmpacker.exe

# ------ Demo ------
DEMO_LICENSE     = $(BUILD_DIR)/demo_license
DEMO_SIMPLE      = $(BUILD_DIR)/demo_simple

# 编译选项 (必须 -mcmodel=tiny，禁止 -fPIC)
STUB_CFLAGS = -c -Os -mcmodel=tiny -fno-stack-protector \
              -fno-builtin -nostdlib -march=armv8-a

DEMO_CFLAGS = -static -O0 -march=armv8-a

# ============================================================
.PHONY: all stub packer demo test clean help

all: stub packer
	@echo ""
	@echo "[+] Build complete: $(BUILD_DIR)/"

# ------ VM 解释器 blob ------
stub: $(STUB_BIN)

$(STUB_O): $(STUB_SRC) | $(BUILD_DIR)/stub
	$(CC) $(STUB_CFLAGS) $< -o $@

$(STUB_ELF): $(STUB_O) $(STUB_LDS)
	$(LD) -T $(STUB_LDS) -o $@ $(STUB_O)

$(STUB_BIN): $(STUB_ELF) | $(BUILD_DIR)
	$(OBJCOPY) -O binary $< $(BUILD_DIR)/vm_interp_raw.bin
	@powershell -Command "\
		$$line = & '$(CROSS)nm' '$<' | Select-String 'vm_entry';\
		if (!$$line) { Write-Error 'vm_entry not found'; exit 1 };\
		$$off = [Convert]::ToUInt64($$line.ToString().Split(' ')[0], 16);\
		$$hdr = [BitConverter]::GetBytes([UInt64]$$off);\
		$$raw = [IO.File]::ReadAllBytes('$(BUILD_DIR)/vm_interp_raw.bin');\
		$$blob = $$hdr + $$raw;\
		[IO.File]::WriteAllBytes('$(STUB_BIN)', $$blob);\
		Write-Host '[+] vm_interp.bin:' $$blob.Length 'bytes (vm_entry @ 0x' + $$off.ToString('X') + ')'\
	"
	@copy /Y "$(subst /,\,$(STUB_BIN))" "$(subst /,\,$(BUILD_DIR))\vm_interp.bin" > nul

# ------ Go packer (embed vm_interp.bin) ------
packer: $(STUB_BIN) | $(BUILD_DIR)
	@powershell -Command "if (Test-Path '$(PACKER)') { Remove-Item -Force '$(PACKER)' -ErrorAction SilentlyContinue }"
	$(GO) build -o $(PACKER) ./$(CMD_DIR)/
	@echo "[+] packer: $(PACKER)"

# ------ Demo 程序 ------
demo: $(DEMO_LICENSE) $(DEMO_SIMPLE)

$(DEMO_LICENSE): $(DEMO_DIR)/demo_license.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) $< -o $@
	@echo "[+] demo: $@"

$(DEMO_SIMPLE): $(DEMO_DIR)/demo_simple.c | $(BUILD_DIR)
	$(CC) $(DEMO_CFLAGS) $< -o $@
	@echo "[+] demo: $@"

# ------ 测试 ------
test:
	$(GO) test ./...

# ------ 目录创建 ------
$(BUILD_DIR):
	@powershell -Command "New-Item -ItemType Directory -Force -Path '$(BUILD_DIR)' | Out-Null"

$(BUILD_DIR)/stub: | $(BUILD_DIR)
	@powershell -Command "New-Item -ItemType Directory -Force -Path '$(BUILD_DIR)/stub' | Out-Null"

# ------ 清理 ------
clean:
	@powershell -Command "Remove-Item -Recurse -Force -ErrorAction SilentlyContinue '$(BUILD_DIR)', '$(STUB_BIN)'"
	@echo "[+] cleaned"

# ------ 帮助 ------
help:
	@echo "make all     - 编译 stub + packer (输出到 build/)"
	@echo "make stub    - 仅编译 VM 解释器 blob"
	@echo "make packer  - 编译 Go packer (自动嵌入 blob)"
	@echo "make demo    - 交叉编译 demo 程序"
	@echo "make test    - 运行单元测试"
	@echo "make clean   - 清理所有产物"
