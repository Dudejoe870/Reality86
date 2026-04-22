package reality86

import "core:math/bits"

X86_MAX_INST_LENGTH :: 15 // 15 bytes is the max instruction length on x86-64

x86_Reg :: enum u8 {
	None = 0,
	AX = 0b001_00000, CX, DX, BX, SP, BP, SI, DI,
	R8, R9, R10, R11, R12, R13, R14, R15,
	IP,
	AH = 0b010_00100, CH, DH, BH, // GPH registers start at a offset of 4
	ES = 0b011_00000, CS, SS, DS, FS, GS,
	XMM0 = 0b100_00000, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7,
	XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15, 
	// AVX-512 registers are here but... I don't even have it so...
	XMM16, XMM17, XMM18, XMM19, XMM20, XMM21, XMM22, XMM23, 
	XMM24, XMM25, XMM26, XMM27, XMM28, XMM29, XMM30, XMM31,
}

_x86_is_gpl :: #force_inline proc "contextless" (reg: x86_Reg) -> bool {
	return u8(reg) & 0b111_00000 == 0b001_00000
}

_x86_is_gph :: #force_inline proc "contextless" (reg: x86_Reg) -> bool {
	return u8(reg) & 0b111_00000 == 0b010_00000
}

_x86_is_seg :: #force_inline proc "contextless" (reg: x86_Reg) -> bool {
	return u8(reg) & 0b111_00000 == 0b011_00000
}

_x86_is_xmm :: #force_inline proc "contextless" (reg: x86_Reg) -> bool {
	return u8(reg) & 0b111_00000 == 0b100_00000
}

x86_Mem :: bit_field u64 {
	offset: i32 | 32,
	base: x86_Reg | 8,
	index: x86_Reg | 8,
	scale: u8 | 4, // only 0, 1, 2, 4, and 8 are valid values. A 0 value is treated as 1
}

x86_REX :: bit_field u8 {
	b: bool | 1,
	x: bool | 1,
	r: bool | 1,
	w: bool | 1,
	_0100: u8 | 4,
}

x86_Mod_RM :: bit_field u8 {
	rm:        u8 | 3,
	reg_or_op: u8 | 3,
	mod:       u8 | 2,
}

x86_SIB :: bit_field u8 {
	base:  u8 | 3,
	index: u8 | 3,
	scale: u8 | 2,
}

_x86_enc_scale :: #force_inline proc "contextless" (scale: u8) -> u8 {
	return min(bits.log2(max(scale, 1)), 3)
}

_x86_set_base :: #force_inline proc "contextless" (sib: ^x86_SIB, value: u8, rex: ^x86_REX) {
	sib.base = value & 0b111
	if rex != nil {
		rex.b = value & 0b1000 > 0
	}
}

_x86_set_index :: #force_inline proc "contextless" (sib: ^x86_SIB, value: u8, rex: ^x86_REX) {
	sib.index = value & 0b111
	if rex != nil {
		rex.x = value & 0b1000 > 0
	}
}

_x86_enc_rm_reg :: #force_inline proc(
	buffer: []u8,
	offset: ^int,
	reg: x86_Reg,
	rm: x86_Reg,
	rex: ^x86_REX = nil,
	op: u8 = 0,
	is_8bit := false,
) {
	assert(!(is_8bit && rex == nil && _x86_is_gpl(reg) && u8(reg) & 0b111 >= 4))
	assert(!(is_8bit && rex == nil && _x86_is_gpl(rm) && u8(rm) & 0b111 >= 4))
	assert(!(is_8bit && rex != nil && _x86_is_gph(reg)))
	assert(!(is_8bit && rex != nil && _x86_is_gph(rm)))
	assert(!(rex == nil && (u8(reg) & 0b1111 > 0b111 || u8(rm) & 0b1111 > 0b111)))
	mod_rm := x86_Mod_RM {
		reg_or_op = op if reg == .None else u8(reg) & 0b111,
		mod = 0b11,
		rm = u8(rm) & 0b111,
	}
	if rex != nil {
		rex.r = u8(op) & 0b1000 > 0 if reg == .None else u8(reg) & 0b1000 > 0
		rex.b = u8(rm) & 0b1000 > 0
	}
	buffer[offset^] = u8(mod_rm)
	offset^ += 1
}

_x86_enc_rm_mem :: proc(
	buffer: []u8,
	offset: ^int,
	reg: x86_Reg,
	ptr: x86_Mem,
	rex: ^x86_REX = nil,
	op: u8 = 0,
	is_8bit := false,
) {
	assert(_x86_is_gpl(ptr.base) || (is_8bit && _x86_is_gph(ptr.base)))
	assert(_x86_is_gpl(ptr.index) || (is_8bit && _x86_is_gph(ptr.index)))
	assert(!(rex == nil && (u8(reg) & 0b1111 > 0b111 || u8(ptr.base) & 0b1111 > 0b111 || u8(ptr.index) & 0b1111 > 0b111)))
	assert(ptr.index != .SP)
	assert(!(ptr.base == .IP && ptr.index != .None))
	assert(ptr.scale == 0 || ptr.scale == 1 || ptr.scale == 2 || ptr.scale == 4 || ptr.scale == 8)
	assert(!(is_8bit && rex == nil && _x86_is_gpl(reg) && u8(reg) & 0b1111 >= 4))
	assert(!(is_8bit && rex != nil && _x86_is_gph(reg)))
	mod_rm := x86_Mod_RM {
		reg_or_op = op if reg == .None else u8(reg) & 0b111,
		mod = 0b00,
		rm = u8(ptr.base) & 0b111,
	}
	if rex != nil {
		rex.r = u8(op) & 0b1000 > 0 if reg == .None else u8(reg) & 0b1000 > 0
		rex.b = u8(ptr.base) & 0b1000 > 0
	}
	sib: x86_SIB
	disp_size: int
	if ptr.offset == 0 {
		disp_size = 0
	} else if i32(i8(ptr.offset)) == ptr.offset { // 8-bit displacement
		mod_rm.mod = 0b01
		disp_size = 1
	} else { // 32-bit displacement
		mod_rm.mod = 0b10
		disp_size = 4
	}
	if ptr.base == .IP {
		mod_rm.mod = 0b00
		mod_rm.rm = 0b101
		disp_size = 4
	} else if u8(ptr.base) & 0b111 == 0b101 && disp_size == 0 {
		mod_rm.mod = 0b01 // Write a zero byte as the displacement
		disp_size = 1 // to allow us to address the BP and R13 registers
	}
	// (Addressing the SP and R12 registers always requires an SIB byte)
	if (ptr.base == .None && ptr.index == .None) || 
			ptr.index != .None || u8(ptr.base) & 0b111 == 0b100 {
		mod_rm.rm = 0b100
		sib.scale = _x86_enc_scale(ptr.scale)
		base := u8(ptr.base)
		index := u8(ptr.index)
		if ptr.base == .None {
			mod_rm.mod = 0b00
			disp_size = 4
			base = 0b101
		}
		if ptr.index == .None {
			index = 0b100
		}
		_x86_set_base(&sib, base & 0b1111, rex)
		_x86_set_index(&sib, index & 0b1111, rex)
	}
	buffer[offset^] = u8(mod_rm)
	offset^ += 1

	if mod_rm.rm == 0b100 {
		buffer[offset^] = u8(sib)
		offset^ += 1
	}

	switch disp_size {
	case 1:
		buffer[offset^] = transmute(u8)i8(ptr.offset)
		offset^ += 1
	case 4:
		// Endian doesn't matter, we're on x86, everything is LE :)
		(transmute(^type_of(ptr.offset))raw_data(buffer[offset^:][:4]))^ = ptr.offset
		offset^ += size_of(ptr.offset)
	case:
	}
}

_x86_enc_rex :: #force_inline proc(buffer: []u8, offset: ^int) -> (rex: ^x86_REX) {
	buffer[offset^] = 0x00
	rex = transmute(^x86_REX)&buffer[offset^]
	rex._0100 = 0b0100
	offset^ += 1
	return
}

// Only applies to 8-bit registers
_x86_is_rex_needed_for_8breg :: #force_inline proc(reg: x86_Reg) -> bool {
	return _x86_is_gpl(reg) && u8(reg) & 0b1111 >= 4
}

_x86_is_rex_needed_for_8bregs :: #force_inline proc(rega: x86_Reg, regb: x86_Reg) -> bool {
	return _x86_is_rex_needed_for_8breg(rega) || _x86_is_rex_needed_for_8breg(regb)
}

_x86_is_rex_needed :: #force_inline proc(registers: [3]x86_Reg) -> bool {
	return max(u8(registers[0]) & 0b1111, u8(registers[1]) & 0b1111, u8(registers[2]) & 0b1111) > 0b111
}

x86_mov64 :: proc {
	x86_mov64_to_rm_mem,
	x86_mov64_from_rm_mem,
	x86_mov64_reg,
	x86_mov64_reg_imm,
	x86_mov64_rm_mem_imm,
}

x86_mov64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i64,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true
	rex.b = u8(dst) & 0b1000 > 0

	buffer[offset] = 0xB8 | (u8(dst) & 0b111)
	(transmute(^type_of(imm))&buffer[offset+1])^ = imm
	offset += 1 + size_of(imm)

	return offset
}

x86_mov64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0xC7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)

	(transmute(^type_of(imm))&buffer[offset])^ = imm
	offset += size_of(imm)
	return offset
}

x86_mov64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = src, rm = dst, rex = rex)
	return offset
}

x86_mov64_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_mov64_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x8B
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_mov32 :: proc {
	x86_mov32_to_rm_mem,
	x86_mov32_from_rm_mem,
	x86_mov32_reg,
	x86_mov32_reg_imm,
	x86_mov32_rm_mem_imm,
}

x86_mov32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(dst) & 0b1000 > 0
	}

	buffer[offset] = 0xB8 | (u8(dst) & 0b111)
	(transmute(^type_of(imm))&buffer[offset+1])^ = imm
	offset += 1 + size_of(imm)

	return offset
}

x86_mov32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xC7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)

	(transmute(^type_of(imm))&buffer[offset])^ = imm
	offset += size_of(imm)
	return offset
}

x86_mov32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = src, rm = dst, rex = rex)
	return offset
}

x86_mov32_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, src }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_mov32_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ src.base, src.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x8B
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_mov16 :: proc {
	x86_mov16_to_rm_mem,
	x86_mov16_from_rm_mem,
	x86_mov16_reg,
	x86_mov16_reg_imm,
	x86_mov16_rm_mem_imm,
}

x86_mov16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(dst) & 0b1000 > 0
	}

	buffer[offset] = 0xB8 | (u8(dst) & 0b111)
	(transmute(^type_of(imm))&buffer[offset+1])^ = imm
	offset += 1 + size_of(imm)

	return offset
}

x86_mov16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xC7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)

	(transmute(^type_of(imm))&buffer[offset])^ = imm
	offset += size_of(imm)
	return offset
}

x86_mov16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = src, rm = dst, rex = rex)
	return offset
}

x86_mov16_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, src }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x89
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_mov16_from_rm_mem :: proc(
	buffer: []u8, 
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ src.base, src.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x8B
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_mov8 :: proc {
	x86_mov8_to_rm_mem,
	x86_mov8_from_rm_mem,
	x86_mov8_reg,
	x86_mov8_reg_imm,
	x86_mov8_rm_mem_imm,
}

x86_mov8_reg_imm :: proc(
	buffer: []u8, 
	dst: x86_Reg, imm: i8,
) -> int {
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) || _x86_is_rex_needed_for_8breg(dst) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(dst) & 0b1000 > 0
	}

	buffer[offset  ] = 0xB0 | u8(dst) & 0b111
	buffer[offset+1] = transmute(u8)imm
	offset += 1 + size_of(imm)
	return offset
}

x86_mov8_rm_mem_imm :: proc(
	buffer: []u8, 
	dst: x86_Mem, imm: i8,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xC6
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex, is_8bit = true)

	buffer[offset] = transmute(u8)imm
	offset += 1
	return offset
}

x86_mov8_reg :: proc(
	buffer: []u8, 
	dst: x86_Reg, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src) || _x86_is_gph(src))
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	assert(!(_x86_is_gph(src) && _x86_is_rex_needed_for_8breg(dst)))
	assert(!(_x86_is_gph(dst) && _x86_is_rex_needed_for_8breg(src)))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src, .None }) || _x86_is_rex_needed_for_8bregs(dst, src) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x88
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = src, rm = dst, rex = rex, is_8bit = true)
	return offset
}

x86_mov8_to_rm_mem :: proc(
	buffer: []u8, 
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src) || _x86_is_gph(src))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, src }) || _x86_is_rex_needed_for_8breg(src) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x88
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex, is_8bit = true)
	return offset
}

x86_mov8_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ src.base, src.index, dst }) || _x86_is_rex_needed_for_8breg(dst) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x8A
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex, is_8bit = true)
	return offset
}

x86_movbe16 :: proc {
	x86_movbe16_from_rm_mem,
	x86_movbe16_to_rm_mem,
}

x86_movbe16_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ src.base, src.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF0
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_movbe16_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, src }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF1
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_movbe32 :: proc {
	x86_movbe32_from_rm_mem,
	x86_movbe32_to_rm_mem,
}

x86_movbe32_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ src.base, src.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF0
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_movbe32_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, src }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF1
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_movbe64 :: proc {
	x86_movbe64_from_rm_mem,
	x86_movbe64_to_rm_mem,
}

x86_movbe64_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF0
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_movbe64_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, src: x86_Reg,
) -> int {
	assert(_x86_is_gpl(src))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x38
	buffer[offset+2] = 0xF1
	offset += 3

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
	return offset
}

x86_push64 :: proc {
	x86_push64_imm,
	x86_push64_reg,
	x86_push64_rm_mem,
}

// It's a 32-bit immediate, but it's sign-extended to 64-bits
x86_push64_imm :: proc(
	buffer: []u8, 
	imm: i32,
) -> int {
	offset: int = 0

	buffer[offset] = 0x68
	(transmute(^type_of(imm))&buffer[offset+1])^ = imm
	offset += 1 + size_of(imm)

	return offset
}

x86_push64_reg :: proc(
	buffer: []u8, 
	reg: x86_Reg,
) -> int {
	assert(_x86_is_gpl(reg))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ reg, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(reg) & 0b1000 > 0
	}

	buffer[offset] = 0x50 | (u8(reg) & 0b111)
	offset += 1

	return offset
}

x86_push64_rm_mem :: proc(
	buffer: []u8, 
	mem: x86_Mem,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ mem.base, mem.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xFF
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, rex = rex)
	return offset
}

x86_push16 :: proc {
	x86_push16_imm,
	x86_push16_reg,
	x86_push16_rm_mem,
}

x86_push16_imm :: proc(
	buffer: []u8, 
	imm: i16,
) -> int {
	offset: int = 0

	buffer[offset  ] = 0x66
	buffer[offset+1] = 0x68
	(transmute(^type_of(imm))&buffer[offset+2])^ = imm
	offset += 2 + size_of(imm)

	return offset
}

x86_push16_reg :: proc(
	buffer: []u8, 
	reg: x86_Reg,
) -> int {
	assert(_x86_is_gpl(reg))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ reg, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(reg) & 0b1000 > 0
	}

	buffer[offset] = 0x50 | (u8(reg) & 0b111)
	offset += 1

	return offset
}

x86_push16_rm_mem :: proc(
	buffer: []u8, 
	mem: x86_Mem,
) -> int {
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ mem.base, mem.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xFF
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, rex = rex)
	return offset
}

x86_pushseg :: proc(
	buffer: []u8,
	reg: x86_Reg,
) -> int {
	offset: int = 0
	assert(_x86_is_seg(reg))
	assert(reg == .FS || reg == .GS)

	buffer[offset] = 0x0F
	#partial switch reg {
	case .FS:
		buffer[offset+1] = 0xA0
	case .GS:
		buffer[offset+1] = 0xA8
	}
	offset += 2
	return offset
}

x86_pushf :: proc(
	buffer: []u8,
) -> int {
	buffer[0] = 0x66
	buffer[1] = 0x9C
	return 2
}

x86_pushfq :: proc(
	buffer: []u8,
) -> int {
	buffer[0] = 0x9C
	return 1
}

x86_pop64 :: proc {
	x86_pop64_reg,
	x86_pop64_rm_mem,
}

x86_pop64_reg :: proc(
	buffer: []u8, 
	reg: x86_Reg,
) -> int {
	assert(_x86_is_gpl(reg))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ reg, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(reg) & 0b1000 > 0
	}

	buffer[offset] = 0x58 | (u8(reg) & 0b111)
	offset += 1

	return offset
}

x86_pop64_rm_mem :: proc(
	buffer: []u8, 
	mem: x86_Mem,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ mem.base, mem.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x8F
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, rex = rex)
	return offset
}

x86_pop16 :: proc {
	x86_pop16_reg,
	x86_pop16_rm_mem,
}

x86_pop16_reg :: proc(
	buffer: []u8, 
	reg: x86_Reg,
) -> int {
	assert(_x86_is_gpl(reg))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ reg, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(reg) & 0b1000 > 0
	}

	buffer[offset] = 0x58 | (u8(reg) & 0b111)
	offset += 1

	return offset
}

x86_pop16_rm_mem :: proc(
	buffer: []u8, 
	mem: x86_Mem,
) -> int {
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ mem.base, mem.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x8F
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, rex = rex)
	return offset
}

x86_ret :: proc(
	buffer: []u8,
) -> int {
	buffer[0] = 0xC3
	return 1
}

x86_retn :: proc(
	buffer: []u8,
	imm: i16,
) -> int {
	buffer[0] = 0xC2
	(transmute(^type_of(imm))&buffer[1])^ = imm
	return 1 + size_of(imm)
}

x86_add64 :: proc {
	x86_add64_reg,
	x86_add64_rm_mem_to_reg,
	x86_add64_reg_to_rm_mem,
	x86_add64_reg_imm,
	x86_add64_rm_mem_imm,
}

x86_add64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	if i32(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		if dst == .AX {
			buffer[offset] = 0x05
			offset += 1
		} else {
			buffer[offset] = 0x81
			offset += 1

			_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		}
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	if i32(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		buffer[offset] = 0x81
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst) && _x86_is_gpl(op))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = op, rm = dst, rex = rex)
	return offset
}

x86_add64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x03
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = op, rex = rex)
	return offset
}

x86_add64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(op))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = op, ptr = dst, rex = rex)
	return offset
}

x86_add32 :: proc {
	x86_add32_reg,
	x86_add32_rm_mem_to_reg,
	x86_add32_reg_to_rm_mem,
	x86_add32_reg_imm,
	x86_add32_rm_mem_imm,
}

x86_add32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	if i32(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		if dst == .AX {
			buffer[offset] = 0x05
			offset += 1
		} else {
			buffer[offset] = 0x81
			offset += 1

			_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		}
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	if i32(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		buffer[offset] = 0x81
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst) && _x86_is_gpl(op))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, op, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = op, rm = dst, rex = rex)
	return offset
}

x86_add32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ op.base, op.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x03
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = op, rex = rex)
	return offset
}

x86_add32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(op))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, op }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = op, ptr = dst, rex = rex)
	return offset
}

x86_add16 :: proc {
	x86_add16_reg,
	x86_add16_rm_mem_to_reg,
	x86_add16_reg_to_rm_mem,
	x86_add16_reg_imm,
	x86_add16_rm_mem_imm,
}

x86_add16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	if i16(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		if dst == .AX {
			buffer[offset] = 0x05
			offset += 1
		} else {
			buffer[offset] = 0x81
			offset += 1

			_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = .None, rex = rex)
		}
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	if i16(i8(imm)) == imm {
		buffer[offset] = 0x83
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		buffer[offset] = 0x81
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex)
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

x86_add16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst) && _x86_is_gpl(op))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, op, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = op, rm = dst, rex = rex)
	return offset
}

x86_add16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ op.base, op.index, dst }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x03
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = op, rex = rex)
	return offset
}

x86_add16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	assert(_x86_is_gpl(op))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, op }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0x01
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = op, ptr = dst, rex = rex)
	return offset
}
