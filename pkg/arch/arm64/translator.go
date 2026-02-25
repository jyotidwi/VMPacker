package arm64

import (
	"encoding/binary"
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ARM64 → VM 字节码翻译器
//
// 把解码后的 ARM64 指令翻译为自定义 VM 字节码。
// 不支持的指令返回错误（不会静默跳过）。
//
// 寄存器映射:
//   ARM64 X0-X15 → VM R0-R15 (直接映射)
//   ARM64 X16-X28 → 不支持 (trap)
//   ARM64 X29(FP) → 函数内不翻译
//   ARM64 X30(LR) → 特殊处理
//   ARM64 XZR/SP  → 看上下文
//
// 模块文件:
//   tr_alu.go       — 算术/逻辑/移动指令
//   tr_bitfield.go  — 位域操作 (UBFM/SBFM/EXTR)
//   tr_loadstore.go — 加载/存储 (LDR/STR/STP/LDP)
//   tr_branch.go    — 分支/条件选择 (B/BL/CBZ/CSEL)
//   tr_special.go   — 特殊指令 (ADRP/ADR)
// ============================================================

// TranslateResult 翻译结果
type TranslateResult struct {
	Bytecode    []byte   // 生成的 VM 字节码
	Unsupported []string // 不支持的指令列表
	TotalInsts  int      // 总指令数
	TransInsts  int      // 已翻译指令数
}

// DebugEntry 单条指令的 debug 对照信息
type DebugEntry struct {
	ARM64Offset int    // ARM64 指令在函数内的偏移
	ARM64Asm    string // ARM64 反汇编文本
	ARM64Raw    uint32 // ARM64 原始编码
	VMStart     int    // 翻译后 VM 字节码起始位置
	VMEnd       int    // 翻译后 VM 字节码结束位置
}

// Translator ARM64 → VM 翻译器
type Translator struct {
	code        []byte        // 输出缓冲
	labels      map[int]int   // ARM64偏移 → VM字节码位置 映射
	fixups      []branchFixup // 待修补的分支目标
	funcSize    int           // 原函数大小（字节）
	funcAddr    uint64        // 原函数起始地址
	unsupported []string
	decoder     *Decoder     // 解码器引用（用于名称查找）
	debug       bool         // debug 模式
	debugLog    []DebugEntry // debug 对照记录
}

type branchFixup struct {
	vmOffset    int  // VM 字节码中需要修补的位置
	arm64Target int  // 目标 ARM64 偏移
	isRelToFunc bool // 是否相对于函数起始
}

// NewTranslator 创建翻译器
func NewTranslator(funcAddr uint64, funcSize int) *Translator {
	return &Translator{
		code:     make([]byte, 0, funcSize*4),
		labels:   make(map[int]int),
		funcAddr: funcAddr,
		funcSize: funcSize,
		decoder:  NewDecoder(),
	}
}

// SetDebug 开启 debug 模式
func (t *Translator) SetDebug(on bool) {
	t.debug = on
}

// DebugLog 返回 debug 对照记录
func (t *Translator) DebugLog() []DebugEntry {
	return t.debugLog
}

// emit 追加字节
func (t *Translator) emit(b ...byte) {
	t.code = append(t.code, b...)
}

// emitU32 追加 32 位小端
func (t *Translator) emitU32(v uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	t.code = append(t.code, b...)
}

// emitU64 追加 64 位小端
func (t *Translator) emitU64(v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	t.code = append(t.code, b...)
}

// pos 当前字节码位置
func (t *Translator) pos() int {
	return len(t.code)
}

// trunc32 截断为32位 (W寄存器): Rd &= 0xFFFFFFFF
func (t *Translator) trunc32(rd byte) {
	t.emit(vm.OpAndImm, rd, rd)
	t.emitU32(0xFFFFFFFF)
}

// mapReg ARM64寄存器 → VM寄存器
func (t *Translator) mapReg(arm64Reg int) (byte, error) {
	if arm64Reg < 0 || arm64Reg > 31 {
		return 0, fmt.Errorf("寄存器 X%d 超出 VM 范围", arm64Reg)
	}
	return byte(arm64Reg), nil
}

// Translate 翻译整个函数
func (t *Translator) Translate(instructions []vm.Instruction) (*TranslateResult, error) {
	result := &TranslateResult{TotalInsts: len(instructions)}

	skip := 0
	for i := 0; i < len(instructions); i++ {
		if skip > 0 {
			t.labels[instructions[i].Offset] = t.pos()
			skip--
			result.TransInsts++
			continue
		}

		t.labels[instructions[i].Offset] = t.pos()

		vmStartPos := t.pos()
		var err error
		skip, err = t.translateOne(instructions, i)

		// debug: 记录对照
		if t.debug {
			inst := instructions[i]
			entry := DebugEntry{
				ARM64Offset: inst.Offset,
				ARM64Asm:    OpName(Op(inst.Op)),
				ARM64Raw:    inst.Raw,
				VMStart:     vmStartPos,
				VMEnd:       t.pos(),
			}
			t.debugLog = append(t.debugLog, entry)
			// 如果有 skip 的后续指令也记录
			for s := 1; s <= skip && i+s < len(instructions); s++ {
				skipped := instructions[i+s]
				t.debugLog = append(t.debugLog, DebugEntry{
					ARM64Offset: skipped.Offset,
					ARM64Asm:    OpName(Op(skipped.Op)) + " (merged)",
					ARM64Raw:    skipped.Raw,
					VMStart:     vmStartPos,
					VMEnd:       t.pos(),
				})
			}
		}

		if err != nil {
			t.unsupported = append(t.unsupported, fmt.Sprintf(
				"偏移 0x%04X: %s (raw=0x%08X) - %v",
				instructions[i].Offset, OpName(Op(instructions[i].Op)), instructions[i].Raw, err))
			t.emit(vm.OpHalt)
		} else {
			result.TransInsts++
		}
	}

	t.labels[t.funcSize] = t.pos()
	t.emit(vm.OpHalt)

	for _, fix := range t.fixups {
		target, ok := t.labels[fix.arm64Target]
		if !ok {
			return nil, fmt.Errorf("分支目标 ARM64 偏移 0x%X 未找到对应 VM 位置", fix.arm64Target)
		}
		binary.LittleEndian.PutUint32(t.code[fix.vmOffset:], uint32(target))
	}

	result.Bytecode = t.code
	result.Unsupported = t.unsupported
	return result, nil
}

// translateOne 翻译单条指令，返回需要跳过的后续指令数
func (t *Translator) translateOne(instructions []vm.Instruction, idx int) (int, error) {
	inst := instructions[idx]
	op := Op(inst.Op)

	switch op {
	case NOP:
		t.emit(vm.OpNop)
		return 0, nil

	// ========== 数据处理（立即数）==========

	case ADD_IMM:
		return 0, t.trAluImm(inst, vm.OpAddImm)
	case SUB_IMM:
		return 0, t.trAluImm(inst, vm.OpSubImm)
	case ADDS_IMM, SUBS_IMM:
		if inst.Rd == 31 {
			rn, err := t.mapReg(inst.Rn)
			if err != nil {
				return 0, err
			}
			t.emit(vm.OpCmpImm, rn)
			t.emitU32(uint32(inst.Imm))
			return 0, nil
		}
		if op == ADDS_IMM {
			return 0, t.trAluImm(inst, vm.OpAddImm)
		}
		return 0, t.trAluImm(inst, vm.OpSubImm)

	case AND_IMM:
		return 0, t.trAluImm(inst, vm.OpAndImm)
	case ORR_IMM:
		return 0, t.trAluImm(inst, vm.OpOrImm)
	case EOR_IMM:
		return 0, t.trAluImm(inst, vm.OpXorImm)

	case MOVZ:
		return 0, t.trMov(inst)
	case MOVK:
		return 0, t.trMovK(inst)
	case MOVN:
		return 0, t.trMovN(inst)

	// ========== 数据处理（寄存器）==========

	case ADD_REG:
		return 0, t.trAluReg(inst, vm.OpAdd)
	case SUB_REG:
		return 0, t.trAluReg(inst, vm.OpSub)
	case AND_REG:
		return 0, t.trAluReg(inst, vm.OpAnd)
	case ORR_REG:
		if inst.Rn == 31 {
			rd, err := t.mapReg(inst.Rd)
			if err != nil {
				return 0, err
			}
			rm, err := t.mapReg(inst.Rm)
			if err != nil {
				return 0, err
			}
			t.emit(vm.OpMovReg, rd, rm)
			return 0, nil
		}
		return 0, t.trAluReg(inst, vm.OpOr)
	case EOR_REG:
		return 0, t.trAluReg(inst, vm.OpXor)
	case MUL:
		return 0, t.trAluReg(inst, vm.OpMul)
	case LSL_REG:
		return 0, t.trAluReg(inst, vm.OpShl)
	case LSR_REG:
		return 0, t.trAluReg(inst, vm.OpShr)
	case ASR_REG:
		return 0, t.trAluReg(inst, vm.OpAsr)
	case ROR_REG:
		return 0, t.trAluReg(inst, vm.OpRor)

	case ADDS_REG, SUBS_REG:
		if inst.Rd == 31 {
			rn, err := t.mapReg(inst.Rn)
			if err != nil {
				return 0, err
			}
			rm, err := t.mapReg(inst.Rm)
			if err != nil {
				return 0, err
			}
			t.emit(vm.OpCmp, rn, rm)
			return 0, nil
		}
		if op == ADDS_REG {
			return 0, t.trAluReg(inst, vm.OpAdd)
		}
		return 0, t.trAluReg(inst, vm.OpSub)

	case ANDS_REG:
		if inst.Rd == 31 {
			rn, err := t.mapReg(inst.Rn)
			if err != nil {
				return 0, err
			}
			rm, err := t.mapReg(inst.Rm)
			if err != nil {
				return 0, err
			}
			t.emit(vm.OpAnd, 15, rn, rm)
			t.emit(vm.OpCmpImm, 15)
			t.emitU32(0)
			return 0, nil
		}
		return 0, t.trAluReg(inst, vm.OpAnd)

	// ========== 位域操作 ==========

	case UBFM:
		return 0, t.trUBFM(inst)
	case SBFM:
		return 0, t.trSBFM(inst)

	// ========== 加载/存储 ==========

	case LDR_IMM, LDRB_IMM, LDRH_IMM, LDRSB_IMM, LDRSH_IMM, LDRSW_IMM:
		return 0, t.trLoad(inst)
	case STR_IMM, STRB_IMM, STRH_IMM:
		return 0, t.trStore(inst)

	case STP:
		return 0, t.trSTP(inst)
	case LDP:
		return 0, t.trLDP(inst)

	// ========== 分支 ==========

	case B:
		return 0, t.trBranch(inst)
	case B_COND:
		return 0, t.trBranchCond(inst)
	case CBZ:
		return 0, t.trCBZ(inst, true)
	case CBNZ:
		return 0, t.trCBZ(inst, false)
	case BL:
		return 0, t.trBL(inst)
	case RET:
		t.emit(vm.OpRet, 0)
		return 0, nil

	// ========== 条件选择 ==========
	case CSEL:
		return 0, t.trCSEL(inst)
	case CSINC:
		return 0, t.trCSEL(inst)
	case CSINV:
		return 0, t.trCSEL(inst)
	case CSNEG:
		return 0, t.trCSEL(inst)
	case MADD, MSUB:
		return 0, t.trAluReg(inst, vm.OpMul)

	// ========== 寄存器偏移加载 ==========
	case LDR_REG, LDRB_REG:
		return 0, t.trLoadReg(inst)

	// ========== ADRP ==========
	case ADRP:
		return t.trADRP(instructions, idx)
	case ADR:
		return t.trADR(inst)

	// ========== SIMD LD1/ST1 ==========
	case LD1_16B:
		rn, err := t.mapReg(inst.Rn)
		if err != nil {
			return 0, err
		}
		t.emit(vm.OpVld16, rn)
		t.code = append(t.code, byte(inst.Imm))
		return 0, nil
	case ST1_16B:
		rn, err := t.mapReg(inst.Rn)
		if err != nil {
			return 0, err
		}
		t.emit(vm.OpVst16, rn)
		t.code = append(t.code, byte(inst.Imm))
		return 0, nil

	// ========== 位域提取 ==========
	case EXTR:
		return 0, t.trEXTR(inst)

	default:
		return 0, fmt.Errorf("不支持的指令类型")
	}
}
