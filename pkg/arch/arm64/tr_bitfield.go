package arm64

import (
	"fmt"

	"github.com/vmpacker/pkg/vm"
)

// ============================================================
// 位域翻译 — UBFM / SBFM / EXTR
// ============================================================

func (t *Translator) trUBFM(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	immr := uint32(inst.Imm)
	imms := uint32(inst.Shift)

	regSize := uint32(32)
	if inst.SF {
		regSize = 64
	}

	switch {
	case imms == regSize-1:
		t.emit(vm.OpShrImm, rd, rn)
		t.emitU32(immr)
	case imms+1 == immr:
		t.emit(vm.OpShlImm, rd, rn)
		t.emitU32(regSize - immr)
	case imms == 7 && immr == 0:
		t.emit(vm.OpAndImm, rd, rn)
		t.emitU32(0xFF)
	case imms == 15 && immr == 0:
		t.emit(vm.OpAndImm, rd, rn)
		t.emitU32(0xFFFF)
	default:
		width := imms + 1
		if imms >= immr {
			t.emit(vm.OpShrImm, rd, rn)
			t.emitU32(immr)
			mask := uint32((1 << width) - 1)
			t.emit(vm.OpAndImm, rd, rd)
			t.emitU32(mask)
		} else {
			// UBFIZ: (Rn & mask) << shift
			shift := regSize - immr
			mask := uint32((1 << width) - 1)
			t.emit(vm.OpAndImm, rd, rn)
			t.emitU32(mask)
			t.emit(vm.OpShlImm, rd, rd)
			t.emitU32(shift)
		}
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}

func (t *Translator) trSBFM(inst vm.Instruction) error {
	rd, err := t.mapReg(inst.Rd)
	if err != nil {
		return err
	}
	rn, err := t.mapReg(inst.Rn)
	if err != nil {
		return err
	}
	immr := uint32(inst.Imm)
	imms := uint32(inst.Shift)

	regSize := uint32(32)
	if inst.SF {
		regSize = 64
	}

	if imms == regSize-1 {
		t.emit(vm.OpAsrImm, rd, rn)
		t.emitU32(immr)
		return nil
	}
	if immr == 0 {
		shiftAmt := regSize - (imms + 1)
		t.emit(vm.OpShlImm, rd, rn)
		t.emitU32(shiftAmt)
		t.emit(vm.OpAsrImm, rd, rd)
		t.emitU32(shiftAmt)
		return nil
	}
	return fmt.Errorf("复杂 SBFM (immr=%d, imms=%d) 暂不支持", immr, imms)
}

func (t *Translator) trEXTR(inst vm.Instruction) error {
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
	lsb := uint32(inst.Imm)
	regSize := uint32(32)
	if inst.SF {
		regSize = 64
	}

	if inst.Rn == inst.Rm {
		t.emit(vm.OpShrImm, rd, rn)
		t.emitU32(lsb)
		t.emit(vm.OpShlImm, 15, rn)
		t.emitU32(regSize - lsb)
		t.emit(vm.OpOr, rd, rd, 15)
	} else {
		t.emit(vm.OpShrImm, rd, rm)
		t.emitU32(lsb)
		t.emit(vm.OpShlImm, 15, rn)
		t.emitU32(regSize - lsb)
		t.emit(vm.OpOr, rd, rd, 15)
	}
	if !inst.SF {
		t.trunc32(rd)
	}
	return nil
}
