package reality86

RF_Stage :: struct {
	next_pc: u64,
	inst: u32,
}

D_Cache_Line :: struct #align(64) {
	tag: bit_field [3]u8 {
		p_tag: u32 | 20,
		dirty: bool | 1,
		valid: bool | 1,
	},
	data: [16]u8,
}

I_Cache_Line :: struct #align(64) {
	tag: bit_field [3]u8 {
		p_tag: u32 | 20,
		valid: bool | 1,
		_: int | 3,
	},
	data: [32]u8,
}

R4300 :: struct {
	gpr: [32]u64,
	cp0: [32]u32,
	fpr: [32]u64,
	pipe: struct {
		rf: RF_Stage,
	},
	d_cache: [512]D_Cache_Line,
	i_cache: [512]I_Cache_Line,
}
