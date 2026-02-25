package arm64

import (
	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// ALU 翻译 — 算术/逻辑/移动指令
// ============================================================

func (t *Translator) trAluImm(inst vm.Instruction, vmOp byte) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	t.emit(vmOp, rd, rn)
	t.emitU32(uint32(inst.Imm))
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

func (t *Translator) trAluReg(inst vm.Instruction, vmOp byte) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	rm, err := t.mapReg(inst.Rm)
	if err != nil {
		return err
	}

	if inst.Shift != 0 {
		t.emit(vm.OpShlImm, 15, rm)
		t.emitU32(uint32(inst.Shift))
		t.emit(vmOp, rd, rn, 15)
	} else {
		t.emit(vmOp, rd, rn, rm)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

func (t *Translator) trMov(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	val := uint64(inst.Imm) << uint(inst.Shift)
	if val <= 0xFFFFFFFF {
		t.emit(vm.OpMovImm32, rd)
		t.emitU32(uint32(val))
	} else {
		t.emit(vm.OpMovImm, rd)
		t.emitU64(val)
	}
	return nil
}

func (t *Translator) trMovK(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	shift := uint(inst.Shift)
	val := uint64(inst.Imm) << shift
	mask := uint64(0xFFFF) << shift

	t.emit(vm.OpAndImm, rd, rd)
	t.emitU32(uint32(^mask & 0xFFFFFFFF))
	t.emit(vm.OpOrImm, rd, rd)
	t.emitU32(uint32(val & 0xFFFFFFFF))
	return nil
}

func (t *Translator) trMovN(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	val := ^(uint64(inst.Imm) << uint(inst.Shift))
	if val <= 0xFFFFFFFF || !inst.SF {
		t.emit(vm.OpMovImm32, rd)
		t.emitU32(uint32(val))
	} else {
		t.emit(vm.OpMovImm, rd)
		t.emitU64(val)
	}
	return nil
}
