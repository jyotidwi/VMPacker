package elf

import (
	"bytes"
	"encoding/binary"
	"io"
)

// ============================================================
// ARM64 跳板代码生成 + ELF64 二进制结构读写
// ============================================================

// BuildTrampoline 构造 ARM64 跳板代码
//
//	MOV X5, SP                  ; 传递真实 SP 给解释器
//	MOV X6, X29                 ; 传递调用者的 FP
//	MOV X7, X30                 ; 传递调用者的 LR
//	STP X29, X30, [SP, #-16]!   ; 保存 FP/LR
//	MOV X29, SP                 ; 建立栈帧
//	; X0, X1 保持不变 (原始函数参数)
//	MOV X2, bcVA                ; 加密字节码地址
//	MOV X3, bcLen               ; 字节码长度
//	MOV X4, xorKey              ; XOR 密钥
//	BL  interpVA                ; 调用 VM 解释器
//	LDP X29, X30, [SP], #16     ; 恢复 FP/LR
//	RET                         ; 返回 (结果在 X0)
func BuildTrampoline(funcAddr, interpVA, bcVA uint64, bcLen uint32, xorKey byte) []byte {
	var buf bytes.Buffer

	// MOV X5, SP
	writeU32(&buf, 0x910003E5)

	// MOV X6, X29
	writeU32(&buf, 0xAA1D03E6)

	// MOV X7, X30
	writeU32(&buf, 0xAA1E03E7)

	// STP X29, X30, [SP, #-16]!
	writeU32(&buf, 0xA9BF7BFD)

	// MOV X29, SP
	writeU32(&buf, 0x910003FD)

	// Load bcVA into X2
	writeARM64MovZ(&buf, 2, uint16(bcVA&0xFFFF), 0)
	writeARM64MovK(&buf, 2, uint16((bcVA>>16)&0xFFFF), 1)
	writeARM64MovK(&buf, 2, uint16((bcVA>>32)&0xFFFF), 2)

	// Load bcLen into X3
	writeARM64MovZ(&buf, 3, uint16(bcLen&0xFFFF), 0)
	if bcLen > 0xFFFF {
		writeARM64MovK(&buf, 3, uint16((bcLen>>16)&0xFFFF), 1)
	}

	// Load xorKey into X4
	writeARM64MovZ(&buf, 4, uint16(xorKey), 0)

	// BL interpVA
	blPC := funcAddr + uint64(buf.Len())
	blOffset := int64(interpVA) - int64(blPC)
	blImm26 := (blOffset >> 2) & 0x03FFFFFF
	blInst := uint32(0x94000000) | uint32(blImm26)
	writeU32(&buf, blInst)

	// LDP X29, X30, [SP], #16
	writeU32(&buf, 0xA8C17BFD)

	// RET
	writeU32(&buf, 0xD65F03C0)

	return buf.Bytes()
}

// ============================================================
// ELF64 二进制结构读写
// ============================================================

type elf64Ehdr struct {
	Phoff     uint64
	Shoff     uint64
	Phentsize uint16
	Phnum     uint16
	Shentsize uint16
	Shnum     uint16
}

func readEhdr64(d []byte) elf64Ehdr {
	return elf64Ehdr{
		Phoff:     binary.LittleEndian.Uint64(d[0x20:]),
		Shoff:     binary.LittleEndian.Uint64(d[0x28:]),
		Phentsize: binary.LittleEndian.Uint16(d[0x36:]),
		Phnum:     binary.LittleEndian.Uint16(d[0x38:]),
		Shentsize: binary.LittleEndian.Uint16(d[0x3A:]),
		Shnum:     binary.LittleEndian.Uint16(d[0x3C:]),
	}
}

type elf64Phdr struct {
	Type   uint32
	Flags  uint32
	Off    uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

func readPhdr64(d []byte, off uint64) elf64Phdr {
	return elf64Phdr{
		Type:   binary.LittleEndian.Uint32(d[off:]),
		Flags:  binary.LittleEndian.Uint32(d[off+4:]),
		Off:    binary.LittleEndian.Uint64(d[off+8:]),
		Vaddr:  binary.LittleEndian.Uint64(d[off+16:]),
		Paddr:  binary.LittleEndian.Uint64(d[off+24:]),
		Filesz: binary.LittleEndian.Uint64(d[off+32:]),
		Memsz:  binary.LittleEndian.Uint64(d[off+40:]),
		Align:  binary.LittleEndian.Uint64(d[off+48:]),
	}
}

func writePhdr64(d []byte, off uint64, ph elf64Phdr) {
	binary.LittleEndian.PutUint32(d[off:], ph.Type)
	binary.LittleEndian.PutUint32(d[off+4:], ph.Flags)
	binary.LittleEndian.PutUint64(d[off+8:], ph.Off)
	binary.LittleEndian.PutUint64(d[off+16:], ph.Vaddr)
	binary.LittleEndian.PutUint64(d[off+24:], ph.Paddr)
	binary.LittleEndian.PutUint64(d[off+32:], ph.Filesz)
	binary.LittleEndian.PutUint64(d[off+40:], ph.Memsz)
	binary.LittleEndian.PutUint64(d[off+48:], ph.Align)
}

// ============================================================
// ARM64 指令编码辅助
// ============================================================

func writeARM64MovZ(w io.Writer, rd int, imm16 uint16, hw int) {
	inst := uint32(0xD2800000) | (uint32(hw) << 21) | (uint32(imm16) << 5) | uint32(rd)
	writeU32(w, inst)
}

func writeARM64MovK(w io.Writer, rd int, imm16 uint16, hw int) {
	inst := uint32(0xF2800000) | (uint32(hw) << 21) | (uint32(imm16) << 5) | uint32(rd)
	writeU32(w, inst)
}

func writeU32(w io.Writer, v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	w.Write(b)
}
