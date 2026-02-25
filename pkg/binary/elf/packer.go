package elf

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vmpacker/pkg/arch/arm64"
	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ELF 解析器 + 修改器 v3
//
// 注入策略: PT_NOTE → PT_LOAD 劫持
//   1. 将 VM 解释器 blob + 加密字节码追加到文件末尾
//   2. 将 PT_NOTE 段转换为 PT_LOAD (RX)，映射追加的数据
//   3. 新 LOAD 段使用独立的虚拟地址 (0x800000 起)
//   4. 原函数改写为跳板 → BL 到新段中的 VM 解释器
//
// 优点: 不移动任何现有数据，不破坏段对齐
// ============================================================

// AddrSpec 按地址指定函数
type AddrSpec struct {
	Addr uint64
	End  uint64 // 0 = 自动检测
	Name string // 可选名称
}

// ParseAddrSpec 解析地址规格: "0xADDR", "0xSTART-0xEND", "0xSTART-0xEND:name"
func ParseAddrSpec(s string) (AddrSpec, error) {
	var spec AddrSpec
	// 分离可选名称 (最后一个冒号后面)
	if idx := strings.LastIndex(s, ":"); idx > 2 {
		candidate := s[idx+1:]
		// 如果不像十六进制数则是名称
		if _, err := strconv.ParseUint(candidate, 0, 64); err != nil {
			spec.Name = candidate
			s = s[:idx]
		}
	}
	// 解析地址范围
	if parts := strings.Split(s, "-"); len(parts) == 2 {
		start, err := strconv.ParseUint(parts[0], 0, 64)
		if err != nil {
			return spec, fmt.Errorf("起始地址无效: %s", parts[0])
		}
		end, err := strconv.ParseUint(parts[1], 0, 64)
		if err != nil {
			return spec, fmt.Errorf("结束地址无效: %s", parts[1])
		}
		if end <= start {
			return spec, fmt.Errorf("结束地址必须大于起始地址")
		}
		spec.Addr = start
		spec.End = end
	} else {
		addr, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return spec, fmt.Errorf("地址无效: %s", s)
		}
		spec.Addr = addr
	}
	if spec.Name == "" {
		spec.Name = fmt.Sprintf("sub_%X", spec.Addr)
	}
	return spec, nil
}

// Packer ELF VMP 打包器
type Packer struct {
	inputPath    string
	outputPath   string
	funcNames    []string
	addrSpecs    []AddrSpec
	verbose      bool
	stripSymbols bool
	debug        bool
	data         []byte
	interpBlob   []byte
}

// FuncBytecode 保存单个函数的加密字节码和元信息
type FuncBytecode struct {
	FI        *vm.FuncInfo
	Encrypted []byte
	XorKey    byte
}

// NewPacker 创建 ELF 打包器
func NewPacker(input, output string, funcs []string, addrSpecs []AddrSpec, verbose, strip, debug bool, interpBlob []byte) *Packer {
	return &Packer{
		inputPath:    input,
		outputPath:   output,
		funcNames:    funcs,
		addrSpecs:    addrSpecs,
		verbose:      verbose,
		stripSymbols: strip,
		debug:        debug,
		interpBlob:   interpBlob,
	}
}

// FindFunction 在 ELF 中查找函数
func (p *Packer) FindFunction(f *elf.File, name string) (*vm.FuncInfo, error) {
	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("reading symbol table failed: %v", err)
	}
	for _, sym := range syms {
		if sym.Name == name && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			info := &vm.FuncInfo{
				Name: sym.Name,
				Addr: sym.Value,
				Size: sym.Size,
			}
			if int(sym.Section) < len(f.Sections) {
				sec := f.Sections[sym.Section]
				info.Section = sec.Name
				info.Offset = sec.Offset + (sym.Value - sec.Addr)
			}
			return info, nil
		}
	}
	return nil, fmt.Errorf("function '%s' not found", name)
}

// FindFunctionByAddr 通过地址查找函数
func (p *Packer) FindFunctionByAddr(f *elf.File, spec AddrSpec) (*vm.FuncInfo, error) {
	// 在 .text 段中定位
	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf(".text section not found")
	}

	// 确认地址在 .text 范围内
	if spec.Addr < textSec.Addr || spec.Addr >= textSec.Addr+textSec.Size {
		return nil, fmt.Errorf("address 0x%X not in .text (0x%X-0x%X)",
			spec.Addr, textSec.Addr, textSec.Addr+textSec.Size)
	}

	var size uint64
	if spec.End > 0 {
		// 用户指定了结束地址
		size = spec.End - spec.Addr
	} else {
		// 自动检测: 扫描到 RET (0xD65F03C0) 指令
		data, err := textSec.Data()
		if err != nil {
			return nil, fmt.Errorf("reading .text failed: %v", err)
		}
		startOff := spec.Addr - textSec.Addr
		found := false
		for i := startOff; i+4 <= uint64(len(data)); i += 4 {
			inst := binary.LittleEndian.Uint32(data[i:])
			if inst == 0xD65F03C0 { // RET
				size = i + 4 - startOff
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("cannot detect function size at 0x%X (no RET found)", spec.Addr)
		}
	}

	fi := &vm.FuncInfo{
		Name:    spec.Name,
		Addr:    spec.Addr,
		Size:    size,
		Section: ".text",
		Offset:  textSec.Offset + (spec.Addr - textSec.Addr),
	}
	return fi, nil
}

// ExtractFuncCode 提取函数机器码
func (p *Packer) ExtractFuncCode(f *elf.File, fi *vm.FuncInfo) ([]byte, error) {
	if fi.Size == 0 {
		return nil, fmt.Errorf("function %s has zero size", fi.Name)
	}
	section := f.Section(fi.Section)
	if section == nil {
		return nil, fmt.Errorf("section %s not found", fi.Section)
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("reading section data failed: %v", err)
	}
	localOff := fi.Addr - section.Addr
	if localOff+fi.Size > uint64(len(data)) {
		return nil, fmt.Errorf("function exceeds section bounds")
	}
	code := make([]byte, fi.Size)
	copy(code, data[localOff:localOff+fi.Size])
	return code, nil
}

// DecodeFunction 解码 ARM64 指令
func (p *Packer) DecodeFunction(code []byte) []vm.Instruction {
	dec := arm64.NewDecoder()
	var insts []vm.Instruction
	for off := 0; off+4 <= len(code); off += 4 {
		raw := binary.LittleEndian.Uint32(code[off:])
		inst := dec.Decode(raw, off)
		insts = append(insts, inst)
	}
	return insts
}

// Process 主入口
func (p *Packer) Process() error {
	var err error
	p.data, err = os.ReadFile(p.inputPath)
	if err != nil {
		return fmt.Errorf("reading file failed: %v", err)
	}

	f, err := elf.NewFile(bytes.NewReader(p.data))
	if err != nil {
		return fmt.Errorf("parsing ELF failed: %v", err)
	}
	defer f.Close()

	if f.Machine != elf.EM_AARCH64 {
		return fmt.Errorf("ARM64 only, got: %s", f.Machine)
	}
	if f.Class != elf.ELFCLASS64 {
		return fmt.Errorf("64-bit ELF only")
	}

	fmt.Printf("[*] ELF: %s, Type: %s\n", f.Machine, f.Type)
	fmt.Printf("[*] VM interp blob: %d bytes\n", len(p.interpBlob))

	dec := arm64.NewDecoder()

	// 第一阶段: 收集所有函数的字节码
	type funcEntry struct {
		name   string
		finder func() (*vm.FuncInfo, error)
	}
	var entries []funcEntry
	for _, funcName := range p.funcNames {
		fn := funcName
		entries = append(entries, funcEntry{fn, func() (*vm.FuncInfo, error) {
			return p.FindFunction(f, fn)
		}})
	}
	for _, spec := range p.addrSpecs {
		s := spec
		entries = append(entries, funcEntry{s.Name, func() (*vm.FuncInfo, error) {
			return p.FindFunctionByAddr(f, s)
		}})
	}

	var funcs []FuncBytecode
	for _, entry := range entries {
		fmt.Printf("\n[*] Processing: %s\n", entry.name)

		fi, err := entry.finder()
		if err != nil {
			return err
		}
		fmt.Printf("    Addr: 0x%X, Size: %d bytes, Section: %s\n",
			fi.Addr, fi.Size, fi.Section)

		code, err := p.ExtractFuncCode(f, fi)
		if err != nil {
			return err
		}

		insts := p.DecodeFunction(code)
		fmt.Printf("    Instructions: %d\n", len(insts))

		if p.verbose {
			fmt.Println("    --- Disasm ---")
			for _, inst := range insts {
				fmt.Printf("    0x%04X: %-12s raw=0x%08X\n",
					inst.Offset, dec.InstName(inst.Op), inst.Raw)
			}
			fmt.Println("    --- End ---")
		}

		trans := arm64.NewTranslator(fi.Addr, int(fi.Size))
		if p.debug {
			trans.SetDebug(true)
		}
		result, err := trans.Translate(insts)
		if err != nil {
			return fmt.Errorf("translation failed: %v", err)
		}

		fmt.Printf("    Translated: %d/%d\n", result.TransInsts, result.TotalInsts)
		fmt.Printf("    Bytecode: %d bytes\n", len(result.Bytecode))

		if len(result.Unsupported) > 0 {
			fmt.Printf("    [!] Unsupported (%d):\n", len(result.Unsupported))
			for _, u := range result.Unsupported {
				fmt.Printf("        %s\n", u)
			}
		}

		xorKey := byte(0xA5)
		encrypted := make([]byte, len(result.Bytecode))
		for i, b := range result.Bytecode {
			encrypted[i] = b ^ xorKey
		}

		funcs = append(funcs, FuncBytecode{FI: fi, Encrypted: encrypted, XorKey: xorKey})

		// debug: 生成对照文件
		if p.debug {
			debugPath := p.outputPath + ".debug.txt"
			df, derr := os.OpenFile(debugPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if derr != nil {
				fmt.Printf("    [!] debug file create failed: %v\n", derr)
			} else {
				fmt.Fprintf(df, "================================================================\n")
				fmt.Fprintf(df, "Function: %s @ 0x%X (size: %d)\n", entry.name, fi.Addr, fi.Size)
				fmt.Fprintf(df, "VM bytecode: %d bytes\n", len(result.Bytecode))
				fmt.Fprintf(df, "================================================================\n\n")

				for _, dbg := range trans.DebugLog() {
					vmLines := vm.DisasmRange(result.Bytecode, dbg.VMStart, dbg.VMEnd)
					fmt.Fprintf(df, "ARM64  %04X: %-16s  (raw=0x%08X)\n",
						dbg.ARM64Offset, dbg.ARM64Asm, dbg.ARM64Raw)
					for _, vl := range vmLines {
						fmt.Fprintf(df, "  VM   %s\n", vl)
					}
					fmt.Fprintln(df)
				}

				df.Close()
				fmt.Printf("    [+] Debug: %s\n", debugPath)
			}
		}
	}

	// 第二阶段: 批量注入 (一次 PT_NOTE 劫持)
	fmt.Printf("\n[*] Injecting %d functions...\n", len(funcs))
	err = p.injectVMPBatch(funcs)
	if err != nil {
		return fmt.Errorf("injection failed: %v", err)
	}

	for _, fb := range funcs {
		fmt.Printf("    [+] %s VMP protected\n", fb.FI.Name)
	}

	// 第三阶段: 清除符号表 (可选)
	if p.stripSymbols {
		p.stripSections()
		fmt.Println("[*] Symbols stripped")
	}

	err = os.WriteFile(p.outputPath, p.data, 0755)
	if err != nil {
		return fmt.Errorf("writing output failed: %v", err)
	}

	fmt.Printf("\n[+] Output: %s\n", p.outputPath)
	return nil
}

// stripSections 就地清除符号/调试 section
// 不改变文件布局，只将目标 section 的内容清零并置类型为 SHT_NULL
// 这样 strip 后 payload 不会被破坏
func (p *Packer) stripSections() {
	ehdr := readEhdr64(p.data)

	// 读取 section name string table
	shstrIdx := binary.LittleEndian.Uint16(p.data[0x3E:])
	shstrOff := ehdr.Shoff + uint64(shstrIdx)*uint64(ehdr.Shentsize)
	shstrSecOff := binary.LittleEndian.Uint64(p.data[shstrOff+24:])
	shstrSecSz := binary.LittleEndian.Uint64(p.data[shstrOff+32:])

	getSectionName := func(nameOff uint32) string {
		start := shstrSecOff + uint64(nameOff)
		if start >= uint64(len(p.data)) {
			return ""
		}
		end := start
		for end < shstrSecOff+shstrSecSz && end < uint64(len(p.data)) && p.data[end] != 0 {
			end++
		}
		return string(p.data[start:end])
	}

	// 要清除的 section 名称
	stripNames := map[string]bool{
		".symtab":            true,
		".strtab":            true,
		".comment":           true,
		".note.GNU-stack":    true,
		".note.gnu.build-id": true,
	}

	for i := 0; i < int(ehdr.Shnum); i++ {
		shOff := ehdr.Shoff + uint64(i)*uint64(ehdr.Shentsize)
		nameOff := binary.LittleEndian.Uint32(p.data[shOff:])
		name := getSectionName(nameOff)

		if !stripNames[name] {
			continue
		}

		// 读取 section 的文件偏移和大小
		secOff := binary.LittleEndian.Uint64(p.data[shOff+24:])
		secSz := binary.LittleEndian.Uint64(p.data[shOff+32:])

		// 用随机垃圾覆盖 section 内容
		if secOff+secSz <= uint64(len(p.data)) {
			garbage := make([]byte, secSz)
			rand.Read(garbage)
			copy(p.data[secOff:], garbage)
		}

		// 置 section type 为 SHT_NULL (0)
		binary.LittleEndian.PutUint32(p.data[shOff+4:], 0) // sh_type = SHT_NULL

		if p.verbose {
			fmt.Printf("    [strip] %s zeroed (off=0x%X, sz=%d)\n", name, secOff, secSz)
		}
	}
}

// injectVMPBatch — 批量 PT_NOTE hijack 注入
func (p *Packer) injectVMPBatch(funcs []FuncBytecode) error {
	ehdr := readEhdr64(p.data)

	// 从 blob 前 8 字节读取 vm_entry 偏移（由 Makefile 自动注入）
	if len(p.interpBlob) < 8 {
		return fmt.Errorf("interp blob too small: %d bytes", len(p.interpBlob))
	}
	entryOff := binary.LittleEndian.Uint64(p.interpBlob[:8])
	interpCode := p.interpBlob[8:] // 纯代码部分（去掉 8 字节头）

	// 1. 构造 payload: [interpCode][bc0][pad][bc1][pad][...]
	payload := make([]byte, 0, len(interpCode)+1024)
	payload = append(payload, interpCode...)
	for len(payload)%4 != 0 {
		payload = append(payload, 0x00)
	}

	type bcRecord struct {
		payloadOff int
		bcLen      int
	}
	records := make([]bcRecord, len(funcs))

	for i, fb := range funcs {
		records[i].payloadOff = len(payload)
		records[i].bcLen = len(fb.Encrypted)
		payload = append(payload, fb.Encrypted...)
		for len(payload)%4 != 0 {
			payload = append(payload, 0x00)
		}
	}

	// 2. 追加到文件末尾 (页对齐，兼容 QEMU 用户态)
	// 先将文件填充到页边界
	appendOff := uint64(len(p.data))
	padLen := (0x1000 - (appendOff % 0x1000)) % 0x1000
	for i := uint64(0); i < padLen; i++ {
		p.data = append(p.data, 0x00)
	}
	payloadFileOff := uint64(len(p.data)) // 现在是页对齐的
	payloadVA := uint64(0x800000)         // 页对齐的 VA

	p.data = append(p.data, payload...)

	interpVA := payloadVA + entryOff // vm_entry 偏移由 Makefile 自动注入到 blob 头部

	fmt.Printf("    Payload at file offset: 0x%X, VA: 0x%X, size: %d\n",
		payloadFileOff, payloadVA, len(payload))
	fmt.Printf("    VM interp VA: 0x%X\n", interpVA)

	for i, fb := range funcs {
		bcVA := payloadVA + uint64(records[i].payloadOff)
		fmt.Printf("    [%s] bytecode VA: 0x%X, len: %d\n",
			fb.FI.Name, bcVA, records[i].bcLen)
	}

	// 3. 找到 PT_NOTE 段并劫持
	noteIdx := -1
	for i := 0; i < int(ehdr.Phnum); i++ {
		phOff := ehdr.Phoff + uint64(i)*uint64(ehdr.Phentsize)
		ph := readPhdr64(p.data, phOff)
		if ph.Type == uint32(elf.PT_NOTE) {
			noteIdx = i
			break
		}
	}
	if noteIdx < 0 {
		return fmt.Errorf("PT_NOTE segment not found")
	}

	// 4. PT_NOTE → PT_LOAD (RX)
	notePhdrOff := ehdr.Phoff + uint64(noteIdx)*uint64(ehdr.Phentsize)
	newPhdr := elf64Phdr{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_R | elf.PF_X),
		Off:    payloadFileOff,
		Vaddr:  payloadVA,
		Paddr:  payloadVA,
		Filesz: uint64(len(payload)),
		Memsz:  uint64(len(payload)),
		Align:  0x1000,
	}
	writePhdr64(p.data, notePhdrOff, newPhdr)

	fmt.Printf("    PT_NOTE[%d] -> PT_LOAD RX: off=0x%X va=0x%X sz=0x%X\n",
		noteIdx, payloadFileOff, payloadVA, len(payload))

	// 5. 为每个函数写跳板 + 销毁原始代码
	for i, fb := range funcs {
		bcVA := payloadVA + uint64(records[i].payloadOff)
		bcLen := uint32(records[i].bcLen)

		trampoline := BuildTrampoline(fb.FI.Addr, interpVA, bcVA, bcLen, fb.XorKey)
		if uint64(len(trampoline)) > fb.FI.Size {
			return fmt.Errorf("trampoline for %s (%d bytes) exceeds function size (%d bytes)",
				fb.FI.Name, len(trampoline), fb.FI.Size)
		}

		// 写入跳板
		for j := 0; j < len(trampoline); j++ {
			p.data[fb.FI.Offset+uint64(j)] = trampoline[j]
		}

		// 用随机垃圾字节彻底销毁跳板后的原始代码
		// 使用 crypto/rand 生成不可预测的数据，防止逆向还原
		garbageLen := int(fb.FI.Size) - len(trampoline)
		if garbageLen > 0 {
			garbage := make([]byte, garbageLen)
			rand.Read(garbage)
			copy(p.data[fb.FI.Offset+uint64(len(trampoline)):], garbage)
		}

		if p.verbose {
			fmt.Printf("    [%s] Trampoline (%d bytes) + Garbage (%d bytes):\n",
				fb.FI.Name, len(trampoline), garbageLen)
			for j := 0; j < len(trampoline); j += 4 {
				inst := binary.LittleEndian.Uint32(trampoline[j:])
				fmt.Printf("      +%02X: 0x%08X\n", j, inst)
			}
		}
	}

	return nil
}

// PrintELFInfo 打印 ELF 信息
func PrintELFInfo(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Printf("ELF: %s\n", path)
	fmt.Printf("  Arch: %s, Type: %s, Entry: 0x%X\n", f.Machine, f.Type, f.Entry)

	fmt.Println("\n  Sections:")
	for _, s := range f.Sections {
		if s.Size > 0 {
			fmt.Printf("    %-16s  Addr=0x%08X  Size=0x%X  Off=0x%X\n",
				s.Name, s.Addr, s.Size, s.Offset)
		}
	}

	fmt.Println("\n  Program Headers:")
	raw, _ := os.ReadFile(path)
	if len(raw) >= 64 {
		ehdr := readEhdr64(raw)
		for i := 0; i < int(ehdr.Phnum); i++ {
			ph := readPhdr64(raw, ehdr.Phoff+uint64(i)*uint64(ehdr.Phentsize))
			flags := ""
			if ph.Flags&uint32(elf.PF_R) != 0 {
				flags += "R"
			}
			if ph.Flags&uint32(elf.PF_W) != 0 {
				flags += "W"
			}
			if ph.Flags&uint32(elf.PF_X) != 0 {
				flags += "X"
			}
			fmt.Printf("    [%d] Type=0x%X Flags=%s Off=0x%X VA=0x%X FileSz=0x%X MemSz=0x%X\n",
				i, ph.Type, flags, ph.Off, ph.Vaddr, ph.Filesz, ph.Memsz)
		}
	}

	fmt.Println("\n  Functions:")
	syms, err := f.Symbols()
	if err != nil {
		fmt.Println("  (no symbol table)")
		return nil
	}
	count := 0
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Size > 0 {
			fmt.Printf("    %-24s  Addr=0x%08X  Size=%d\n",
				sym.Name, sym.Value, sym.Size)
			count++
		}
	}
	fmt.Printf("  Total: %d functions\n", count)
	return nil
}
