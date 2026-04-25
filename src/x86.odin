package reality86

/*
Copyright 2026 John Clemis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
and associated documentation files (the “Software”), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice 
shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// Feel free to copy this out, modify it, whatever (under the terms of the MIT license)
// if you need a base x86 encoder to work from :)

// A quick rundown of how the encoding of your run-of-the-mill x86 instruction works
// (And also how it relates to the code below):
//  opt = Optional
//  doi = Depends on instruction / Opcode
//  doo = Depends on operands
//
//  Operation bytes                    Addressing bytes
//  _______________________________    ____________________________________________
//  |                             |    |                                          |
//  [Prefixes] -> [REX] -> [Opcode] -> [Mod R/M] -> [SIB] -> [Pointer Displacement] -> [Immediate]
//   ^ opt/doo    ^ opt/doo            ^ doi        ^ doo    ^ doo                     ^ doi
//
//     First you have the prefixes, these come in various forms; 
//   for example 0x66 is an operand size prefix, 
//   all it does in 64-bit mode is change the operand size to 16-bits
//   so you can treat registers and immediates etc. all as 16-bits instead of 32 or 64
//   This is encoded per instruction procedure.
//   
//     Second comes the REX byte, this allows you to address additional registers of any size
//   by adding an extra bit to the relevant fields,
//   or set an originally 32-bit instruction to a 64-bit operand size.
//     This is encoded using the procedure _x86_enc_rex, though the bits of REX are manipulated
//   per instruction procedure. 
//     In some cases it also checks whether or not the REX byte is 
//   needed for certain non-64-bit instructions due to register addressing 
//   using the _x86_is_rex_needed procedure and for 8bit operations _x86_is_rex_needed_for_8breg 
//   and _x86_is_rex_needed_for_8bregs procedures.
//   This allows for omitting the REX byte when it is not needed.
//
//     Third is the actual opcode, this is a byte or sometimes a few that encodes
//   the actual instruction we want to execute. Sometimes other things may be encoded
//   into this byte like the least significant 3 bits might encode a register for some operations 
//   if it doesn't use the Mod R/M byte, or the least siginifcant 4 bits being used 
//   as a Condition Code for conditional operations like Jcc or CMOVcc
//   This is encoded per instruction procedure.
//   
//     Next is the Mod R/M byte, SIB, and Displacement bytes.
//   These all kind of go together since they all kind of inter-depend
//   on eachothers fields. The Mod R/M byte itself selects an addressing mode,
//   it can be as simple as telling the instruction to operate on two registers,
//   or use one of the registers as a pointer (the R/M meaning Register/Memory),
//   also with options to allow that pointer to be offset by a Displacement.
//     It also has the option to use an additional byte called the SIB (Scale, Index, Base) byte
//   which allows you to choose a Base register, an Index register, and a Scale value (1, 2, 4, or 8)
//   to calculate a final effective address in memory to access. The very basic formula is 
//   simply Base + Index * Scale.
//     The encoding of these bytes is handled by two procedures in my implementation,
//   _x86_enc_rm_reg for the simple register case, and _x86_enc_rm_mem for 
//   the more complicated memory operand case.
//
//     Last is the Immediate, this is just like the Displacement in that it's just a raw value 
//   ordered in Little Endian that comes after the Instruction. 
//   If there's also a Displacement, that comes before.
//   This is encoded per instruction procedure.
//
//     This should hopefully be enough knowledge to be able to extend it and understand
//   why the code is structured as it is.

import "core:math/bits"

X86_MAX_INST_LENGTH :: 15 // 15 bytes is the max instruction length on x86-64

x86_Reg :: enum u8 {
	None = 0,
	AX = 0b001_00000, CX, DX, BX, SP, BP, SI, DI,
	R8, R9, R10, R11, R12, R13, R14, R15,
	IP = 0b111_00000, // RIP is special
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
) {
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
) {
	assert(!(rex == nil && (u8(reg) & 0b1111 > 0b111 || u8(ptr.base) & 0b1111 > 0b111 || u8(ptr.index) & 0b1111 > 0b111)))
	assert(ptr.index != .SP)
	assert(!(ptr.base == .IP && ptr.index != .None))
	assert(ptr.scale == 0 || ptr.scale == 1 || ptr.scale == 2 || ptr.scale == 4 || ptr.scale == 8)
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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = 0, rex = rex)

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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = 0, rex = rex)

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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = 0, rex = rex)

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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = 0, rex = rex)

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

	_x86_enc_rm_reg(buffer, &offset, reg = src, rm = dst, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = src, ptr = dst, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
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

// I only implement the 64-bit operand version because... 
// in 64-bit mode is there any reason for any other 
// operand size???
x86_lea :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0x8D
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, op = 0, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, op = 0, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, op = 0, rex = rex)
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

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = mem, op = 0, rex = rex)
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

_x86_basic_alu_reg_imm :: proc(
	buffer: []u8, 
	dst: x86_Reg, imm: $T,
	$opsize: int,
	opimm8: u8,
	opimm32: u8,
	regop: u8,
	axop: u8,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	when opsize == 2 {
		buffer[offset] = 0x66
		offset += 1
	}

	when opsize == 8 {
		rex := _x86_enc_rex(buffer, &offset)
		rex.w = true
		rex.b = u8(dst) & 0b1000 > 0
	} else when opsize == 4 || opsize == 2 {
		rex: ^x86_REX
		if _x86_is_rex_needed({ dst, .None, .None }) {
			rex = _x86_enc_rex(buffer, &offset)
			rex.b = u8(dst) & 0b1000 > 0
		}
	}
	
	if cast(type_of(imm))i8(imm) == imm {
		buffer[offset] = opimm8
		offset += 1

		_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, op = regop, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		if dst == .AX {
			buffer[offset] = axop
			offset += 1
		} else {
			buffer[offset] = opimm32
			offset += 1

			_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, op = regop, rex = rex)
		}
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

_x86_basic_alu_rm_mem_imm :: proc(
	buffer: []u8, 
	dst: x86_Mem, imm: $T,
	$opsize: int,
	opimm8: u8,
	opimm32: u8,
	regop: u8,
) -> int {
	offset: int = 0

	when opsize == 2 {
		buffer[offset] = 0x66
		offset += 1
	}

	when opsize == 8 {
		rex := _x86_enc_rex(buffer, &offset)
		rex.w = true
	} else when opsize == 4 || opsize == 2 {
		rex: ^x86_REX
		if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
			rex = _x86_enc_rex(buffer, &offset)
		}
	}
	
	if cast(type_of(imm))i8(imm) == imm {
		buffer[offset] = opimm8
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = regop, rex = rex)
		
		buffer[offset] = transmute(u8)i8(imm)
		offset += 1
	} else {
		buffer[offset] = opimm32
		offset += 1

		_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = regop, rex = rex)
		(transmute(^type_of(imm))&buffer[offset])^ = imm
		offset += size_of(imm)
	}
	return offset
}

_x86_basic_alu_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg, 
	$opsize: int,
	opcode: u8,
) -> int {
	assert(_x86_is_gpl(dst) && _x86_is_gpl(op))
	offset: int = 0

	when opsize == 2 {
		buffer[offset] = 0x66
		offset += 1
	}

	when opsize == 8 {
		rex := _x86_enc_rex(buffer, &offset)
		rex.w = true
	} else when opsize == 4 || opsize == 2 {
		rex: ^x86_REX
		if _x86_is_rex_needed({ dst, op, .None }) {
			rex = _x86_enc_rex(buffer, &offset)
		}
	}

	buffer[offset] = opcode
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = op, rm = dst, rex = rex)
	return offset
}

_x86_basic_alu_mem :: proc(
	buffer: []u8,
	reg: x86_Reg, ptr: x86_Mem, 
	$opsize: int,
	opcode: u8,
) -> int {
	assert(_x86_is_gpl(reg))
	offset: int = 0

	when opsize == 2 {
		buffer[offset] = 0x66
		offset += 1
	}

	when opsize == 8 {
		rex := _x86_enc_rex(buffer, &offset)
		rex.w = true
	} else when opsize == 4 || opsize == 2 {
		rex: ^x86_REX
		if _x86_is_rex_needed({ reg, ptr.base, ptr.index }) {
			rex = _x86_enc_rex(buffer, &offset)
		}
	}

	buffer[offset] = opcode
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = reg, ptr = ptr, rex = rex)
	return offset
}

_x86_basic_alu8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
	baseop: u8,
	regop: u8,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = baseop
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, op = regop, rex = rex)
	
	buffer[offset] = transmute(u8)i8(imm)
	offset += 1
	return offset
}

_x86_basic_alu8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
	opcode: u8,
) -> int {
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	assert(_x86_is_gpl(op)  || _x86_is_gph(op))
	assert(!(_x86_is_gph(dst) && _x86_is_rex_needed_for_8breg(op)))
	assert(!(_x86_is_gph(op)  && _x86_is_rex_needed_for_8breg(dst)))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, op, .None }) || _x86_is_rex_needed_for_8bregs(dst, op) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = opcode
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = op, rm = dst, rex = rex)
	return offset
}

_x86_basic_alu8_mem :: proc(
	buffer: []u8,
	reg: x86_Reg, ptr: x86_Mem,
	opcode: u8,
) -> int {
	assert(_x86_is_gpl(reg) || _x86_is_gph(reg))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ ptr.base, ptr.index, reg }) || _x86_is_rex_needed_for_8breg(reg) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = opcode
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = reg, ptr = ptr, rex = rex)
	return offset
}

_x86_basic_alu8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
	baseop: u8,
	regop: u8,
	axop: u8,
) -> int {
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) || _x86_is_rex_needed_for_8breg(dst) {
		rex = _x86_enc_rex(buffer, &offset)
		rex.b = u8(dst) & 0b1000 > 0
	}

	if dst == .AX {
		buffer[offset] = axop
		offset += 1
	} else {
		buffer[offset] = baseop
		offset += 1

		_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, op = regop, rex = rex)
	}
	buffer[offset] = transmute(u8)imm
	offset += 1
	return offset
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
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 0, 0x05)
}

x86_add64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 0)
}

x86_add64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x01)
}

x86_add64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x03)
}

x86_add64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x01)
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
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 0, 0x05)
}

x86_add32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 0)
}

x86_add32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x01)
}

x86_add32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x03)
}

x86_add32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x01)
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
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 0, 0x05)
}

x86_add16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 0)
}

x86_add16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x01)
}

x86_add16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x03)
}

x86_add16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x01)
}

x86_add8 :: proc {
	x86_add8_reg,
	x86_add8_rm_mem_to_reg,
	x86_add8_reg_to_rm_mem,
	x86_add8_reg_imm,
	x86_add8_rm_mem_imm,
}

x86_add8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 0, 0x04)
}

x86_add8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 0)
}

x86_add8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x00)
}

x86_add8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x02)
}

x86_add8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x00)
}

x86_adc64 :: proc {
	x86_adc64_reg,
	x86_adc64_rm_mem_to_reg,
	x86_adc64_reg_to_rm_mem,
	x86_adc64_reg_imm,
	x86_adc64_rm_mem_imm,
}

x86_adc64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 2, 0x15)
}

x86_adc64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 2)
}

x86_adc64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x11)
}

x86_adc64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x13)
}

x86_adc64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x11)
}

x86_adc32 :: proc {
	x86_adc32_reg,
	x86_adc32_rm_mem_to_reg,
	x86_adc32_reg_to_rm_mem,
	x86_adc32_reg_imm,
	x86_adc32_rm_mem_imm,
}

x86_adc32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 2, 0x15)
}

x86_adc32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 2)
}

x86_adc32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x11)
}

x86_adc32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x13)
}

x86_adc32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x11)
}

x86_adc16 :: proc {
	x86_adc16_reg,
	x86_adc16_rm_mem_to_reg,
	x86_adc16_reg_to_rm_mem,
	x86_adc16_reg_imm,
	x86_adc16_rm_mem_imm,
}

x86_adc16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 2, 0x15)
}

x86_adc16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 2)
}

x86_adc16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x11)
}

x86_adc16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x13)
}

x86_adc16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x11)
}

x86_adc8 :: proc {
	x86_adc8_reg,
	x86_adc8_rm_mem_to_reg,
	x86_adc8_reg_to_rm_mem,
	x86_adc8_reg_imm,
	x86_adc8_rm_mem_imm,
}

x86_adc8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 2, 0x04)
}

x86_adc8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 2)
}

x86_adc8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x10)
}

x86_adc8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x12)
}

x86_adc8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x10)
}

x86_sub64 :: proc {
	x86_sub64_reg,
	x86_sub64_rm_mem_from_reg,
	x86_sub64_reg_from_rm_mem,
	x86_sub64_reg_imm,
	x86_sub64_rm_mem_imm,
}

x86_sub64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 5, 0x2D)
}

x86_sub64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 5)
}

x86_sub64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x29)
}

x86_sub64_rm_mem_from_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x2B)
}

x86_sub64_reg_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x29)
}

x86_sub32 :: proc {
	x86_sub32_reg,
	x86_sub32_rm_mem_from_reg,
	x86_sub32_reg_from_rm_mem,
	x86_sub32_reg_imm,
	x86_sub32_rm_mem_imm,
}

x86_sub32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 5, 0x2D)
}

x86_sub32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 5)
}

x86_sub32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x29)
}

x86_sub32_rm_mem_from_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x2B)
}

x86_sub32_reg_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x29)
}

x86_sub16 :: proc {
	x86_sub16_reg,
	x86_sub16_rm_mem_from_reg,
	x86_sub16_reg_from_rm_mem,
	x86_sub16_reg_imm,
	x86_sub16_rm_mem_imm,
}

x86_sub16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 5, 0x2D)
}

x86_sub16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 5)
}

x86_sub16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x29)
}

x86_sub16_rm_mem_from_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x2B)
}

x86_sub16_reg_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x29)
}

x86_sub8 :: proc {
	x86_sub8_reg,
	x86_sub8_rm_mem_from_reg,
	x86_sub8_reg_from_rm_mem,
	x86_sub8_reg_imm,
	x86_sub8_rm_mem_imm,
}

x86_sub8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 5, 0x2C)
}

x86_sub8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 5)
}

x86_sub8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x28)
}

x86_sub8_rm_mem_from_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x2A)
}

x86_sub8_reg_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x28)
}

x86_and64 :: proc {
	x86_and64_reg,
	x86_and64_rm_mem_to_reg,
	x86_and64_reg_to_rm_mem,
	x86_and64_reg_imm,
	x86_and64_rm_mem_imm,
}

x86_and64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 4, 0x25)
}

x86_and64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 4)
}

x86_and64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x21)
}

x86_and64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x23)
}

x86_and64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x21)
}

x86_and32 :: proc {
	x86_and32_reg,
	x86_and32_rm_mem_to_reg,
	x86_and32_reg_to_rm_mem,
	x86_and32_reg_imm,
	x86_and32_rm_mem_imm,
}

x86_and32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 4, 0x25)
}

x86_and32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 4)
}

x86_and32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x21)
}

x86_and32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x23)
}

x86_and32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x21)
}

x86_and16 :: proc {
	x86_and16_reg,
	x86_and16_rm_mem_to_reg,
	x86_and16_reg_to_rm_mem,
	x86_and16_reg_imm,
	x86_and16_rm_mem_imm,
}

x86_and16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 4, 0x25)
}

x86_and16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 4)
}

x86_and16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x21)
}

x86_and16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x23)
}

x86_and16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x21)
}

x86_and8 :: proc {
	x86_and8_reg,
	x86_and8_rm_mem_to_reg,
	x86_and8_reg_to_rm_mem,
	x86_and8_reg_imm,
	x86_and8_rm_mem_imm,
}

x86_and8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 4, 0x24)
}

x86_and8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 4)
}

x86_and8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x20)
}

x86_and8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x22)
}

x86_and8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x20)
}

x86_or64 :: proc {
	x86_or64_reg,
	x86_or64_rm_mem_to_reg,
	x86_or64_reg_to_rm_mem,
	x86_or64_reg_imm,
	x86_or64_rm_mem_imm,
}

x86_or64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 1, 0x0D)
}

x86_or64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 1)
}

x86_or64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x09)
}

x86_or64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x0B)
}

x86_or64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x09)
}

x86_or32 :: proc {
	x86_or32_reg,
	x86_or32_rm_mem_to_reg,
	x86_or32_reg_to_rm_mem,
	x86_or32_reg_imm,
	x86_or32_rm_mem_imm,
}

x86_or32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 1, 0x0D)
}

x86_or32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 1)
}

x86_or32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x09)
}

x86_or32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x0B)
}

x86_or32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x09)
}

x86_or16 :: proc {
	x86_or16_reg,
	x86_or16_rm_mem_to_reg,
	x86_or16_reg_to_rm_mem,
	x86_or16_reg_imm,
	x86_or16_rm_mem_imm,
}

x86_or16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 1, 0x0D)
}

x86_or16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 1)
}

x86_or16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x09)
}

x86_or16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x0B)
}

x86_or16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x09)
}

x86_or8 :: proc {
	x86_or8_reg,
	x86_or8_rm_mem_to_reg,
	x86_or8_reg_to_rm_mem,
	x86_or8_reg_imm,
	x86_or8_rm_mem_imm,
}

x86_or8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 1, 0x0C)
}

x86_or8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 1)
}

x86_or8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x09)
}

x86_or8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x0B)
}

x86_or8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x09)
}

x86_xor64 :: proc {
	x86_xor64_reg,
	x86_xor64_rm_mem_to_reg,
	x86_xor64_reg_to_rm_mem,
	x86_xor64_reg_imm,
	x86_xor64_rm_mem_imm,
}

x86_xor64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 6, 0x35)
}

x86_xor64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 6)
}

x86_xor64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x31)
}

x86_xor64_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x33)
}

x86_xor64_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x31)
}

x86_xor32 :: proc {
	x86_xor32_reg,
	x86_xor32_rm_mem_to_reg,
	x86_xor32_reg_to_rm_mem,
	x86_xor32_reg_imm,
	x86_xor32_rm_mem_imm,
}

x86_xor32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 6, 0x35)
}

x86_xor32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 6)
}

x86_xor32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x31)
}

x86_xor32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x33)
}

x86_xor32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x31)
}

x86_xor16 :: proc {
	x86_xor16_reg,
	x86_xor16_rm_mem_to_reg,
	x86_xor16_reg_to_rm_mem,
	x86_xor16_reg_imm,
	x86_xor16_rm_mem_imm,
}

x86_xor16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 6, 0x35)
}

x86_xor16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 6)
}

x86_xor16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x31)
}

x86_xor16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x33)
}

x86_xor16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x31)
}

x86_xor8 :: proc {
	x86_xor8_reg,
	x86_xor8_rm_mem_to_reg,
	x86_xor8_reg_to_rm_mem,
	x86_xor8_reg_imm,
	x86_xor8_rm_mem_imm,
}

x86_xor8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 6, 0x34)
}

x86_xor8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 6)
}

x86_xor8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x30)
}

x86_xor8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x32)
}

x86_xor8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x30)
}

x86_neg64 :: proc {
	x86_neg64_reg,
	x86_neg64_mem,
}

x86_neg64_reg :: proc(
	buffer: []u8, 
	dst: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, rex = rex, op = 3)
	return offset
}

x86_neg64_mem :: proc(
	buffer: []u8, 
	dst: x86_Mem,
) -> int {
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex, op = 3)
	return offset
}

x86_neg32 :: proc {
	x86_neg32_reg,
	x86_neg32_mem,
}

x86_neg32_reg :: proc(
	buffer: []u8, 
	dst: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, rex = rex, op = 3)
	return offset
}

x86_neg32_mem :: proc(
	buffer: []u8, 
	dst: x86_Mem,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex, op = 3)
	return offset
}

x86_neg16 :: proc {
	x86_neg16_reg,
	x86_neg16_mem,
}

x86_neg16_reg :: proc(
	buffer: []u8, 
	dst: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, rex = rex, op = 3)
	return offset
}

x86_neg16_mem :: proc(
	buffer: []u8, 
	dst: x86_Mem,
) -> int {
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF7
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex, op = 3)
	return offset
}

x86_neg8 :: proc {
	x86_neg8_reg,
	x86_neg8_mem,
}

x86_neg8_reg :: proc(
	buffer: []u8, 
	dst: x86_Reg,
) -> int {
	assert(_x86_is_gpl(dst) || _x86_is_gph(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, .None, .None }) || _x86_is_rex_needed_for_8breg(dst) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF6
	offset += 1

	_x86_enc_rm_reg(buffer, &offset, reg = .None, rm = dst, rex = rex, op = 3)
	return offset
}

x86_neg8_mem :: proc(
	buffer: []u8, 
	dst: x86_Mem,
) -> int {
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst.base, dst.index, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset] = 0xF6
	offset += 1

	_x86_enc_rm_mem(buffer, &offset, reg = .None, ptr = dst, rex = rex, op = 3)
	return offset
}

x86_cmp64 :: proc {
	x86_cmp64_reg,
	x86_cmp64_rm_mem_from_reg,
	x86_cmp64_reg_from_rm_mem,
	x86_cmp64_reg_imm,
	x86_cmp64_rm_mem_imm,
}

x86_cmp64_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 8, 0x83, 0x81, 7, 0x3D)
}

x86_cmp64_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 8, 0x83, 0x81, 7)
}

x86_cmp64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 8, 0x39)
}

x86_cmp64_rm_mem_from_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 8, opcode = 0x3B)
}

x86_cmp64_reg_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 8, opcode = 0x39)
}

x86_cmp32 :: proc {
	x86_cmp32_reg,
	x86_cmp32_rm_mem_to_reg,
	x86_cmp32_reg_to_rm_mem,
	x86_cmp32_reg_imm,
	x86_cmp32_rm_mem_imm,
}

x86_cmp32_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i32,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 4, 0x83, 0x81, 7, 0x3D)
}

x86_cmp32_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i32,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 4, 0x83, 0x81, 7)
}

x86_cmp32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 4, 0x39)
}

x86_cmp32_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 4, opcode = 0x3B)
}

x86_cmp32_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 4, opcode = 0x39)
}

x86_cmp16 :: proc {
	x86_cmp16_reg,
	x86_cmp16_rm_mem_to_reg,
	x86_cmp16_reg_to_rm_mem,
	x86_cmp16_reg_imm,
	x86_cmp16_rm_mem_imm,
}

x86_cmp16_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i16,
) -> int {
	return _x86_basic_alu_reg_imm(buffer, dst, imm, 2, 0x83, 0x81, 7, 0x3D)
}

x86_cmp16_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i16,
) -> int {
	return _x86_basic_alu_rm_mem_imm(buffer, dst, imm, 2, 0x83, 0x81, 7)
}

x86_cmp16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu_reg(buffer, dst, op, 2, 0x39)
}

x86_cmp16_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = dst, ptr = op, opsize = 2, opcode = 0x3B)
}

x86_cmp16_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu_mem(buffer, reg = op, ptr = dst, opsize = 2, opcode = 0x39)
}

x86_cmp8 :: proc {
	x86_cmp8_reg,
	x86_cmp8_rm_mem_to_reg,
	x86_cmp8_reg_to_rm_mem,
	x86_cmp8_reg_imm,
	x86_cmp8_rm_mem_imm,
}

x86_cmp8_reg_imm :: proc(
	buffer: []u8,
	dst: x86_Reg, imm: i8,
) -> int {
	return _x86_basic_alu8_reg_imm(buffer, dst, imm, 0x80, 7, 0x3C)
}

x86_cmp8_rm_mem_imm :: proc(
	buffer: []u8,
	dst: x86_Mem, imm: i8,
) -> int {
	return _x86_basic_alu8_rm_mem_imm(buffer, dst, imm, 0x80, 5)
}

x86_cmp8_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_reg(buffer, dst, op, 0x38)
}

x86_cmp8_rm_mem_to_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, op: x86_Mem,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = dst, ptr = op, opcode = 0x3A)
}

x86_cmp8_reg_to_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Mem, op: x86_Reg,
) -> int {
	return _x86_basic_alu8_mem(buffer, reg = op, ptr = dst, opcode = 0x38)
}

x86_Condition_Code :: enum u8 {
	Overflow              = 0b0000,
	NoOverflow            = 0b0001,
	Below                 = 0b0010,
	Carry                 = Below,
	NeitherAboveOrEqual   = Below,
	NotBelow              = 0b0011,
	NotCarry              = NotBelow,
	AboveOrEqual          = NotBelow,
	Equal                 = 0b0100,
	Zero                  = Equal,
	NotEqual              = 0b0101,
	NotZero               = NotEqual,
	BelowOrEqual          = 0b0110,
	NotAbove              = BelowOrEqual,
	NeitherBelowOrEqual   = 0b0111,
	Above                 = NeitherBelowOrEqual,
	Sign                  = 0b1000,
	NotSign               = 0b1001,
	Parity                = 0b1010,
	ParityEven            = Parity,
	NoParity              = 0b1011,
	ParityOdd             = NoParity,
	Less                  = 0b1100,
	NeitherGreaterOrEqual = Less,
	NotLess               = 0b1101,
	GreaterOrEqual        = NotLess,
	LessOrEqual           = 0b1110,
	NotGreater            = LessOrEqual,
	NeitherLessOrEqual    = 0b1111,
	Greater               = NeitherLessOrEqual,
}

x86_jcc :: proc(
	buffer: []u8, 
	rel: i32,
	cond: x86_Condition_Code,
) -> int {
	offset: int = 0
	if i32(i8(rel)) == rel {
		buffer[offset  ] = 0x70 | u8(cond)
		buffer[offset+1] = transmute(u8)i8(rel)
		offset += 2
	} else if i32(i16(rel)) == rel {
		buffer[offset  ] = 0x66
		buffer[offset+1] = 0x0F
		buffer[offset+2] = 0x80 | u8(cond)
		(transmute(^i16)&buffer[offset+3])^ = i16(rel)
		offset += 3 + size_of(i16)
	} else {
		buffer[offset  ] = 0x0F
		buffer[offset+1] = 0x80 | u8(cond)
		(transmute(^type_of(rel))&buffer[offset+2])^ = rel
		offset += 2 + size_of(rel)
	}
	return offset
}

x86_cmov64 :: proc {
	x86_cmov64_reg,
	x86_cmov64_from_rm_mem,
}

x86_cmov64_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = src, rex = rex)
	return offset
}

x86_cmov64_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex := _x86_enc_rex(buffer, &offset)
	rex.w = true

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_cmov32 :: proc {
	x86_cmov32_reg,
	x86_cmov32_from_rm_mem,
}

x86_cmov32_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = src, rex = rex)
	return offset
}

x86_cmov32_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src.base, src.index }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}

x86_cmov16 :: proc {
	x86_cmov16_reg,
	x86_cmov16_from_rm_mem,
}

x86_cmov16_reg :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Reg,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(src) && _x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src, .None }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_reg(buffer, &offset, reg = dst, rm = src, rex = rex)
	return offset
}

x86_cmov16_from_rm_mem :: proc(
	buffer: []u8,
	dst: x86_Reg, src: x86_Mem,
	cond: x86_Condition_Code,
) -> int {
	assert(_x86_is_gpl(dst))
	offset: int = 0

	buffer[offset] = 0x66
	offset += 1

	rex: ^x86_REX
	if _x86_is_rex_needed({ dst, src.base, src.index }) {
		rex = _x86_enc_rex(buffer, &offset)
	}

	buffer[offset  ] = 0x0F
	buffer[offset+1] = 0x40 | u8(cond)
	offset += 2

	_x86_enc_rm_mem(buffer, &offset, reg = dst, ptr = src, rex = rex)
	return offset
}
