package reality86

SysAD_Request_Index :: distinct int

SysAD_Size :: enum {
	Single_1Byte = 0b000,
	Single_2Byte = 0b001,
	Single_3Byte = 0b010,
	Single_4Byte = 0b011,
	Block_2Word = 0b100,
	Block_4Word = 0b101,
	Block_8Word = 0b110,
}

SysAD_Command :: bit_field u8 {
	size: SysAD_Size | 3,
	is_write: bool | 1,
}

SysAD_Bus :: struct {
	command: SysAD_Command,
	data: struct #raw_union {
		_u8: u8,
		_u16: u16,
		_u24: u32,
		_u32: u32,
		_u64: u64,
		_128_bit: [16]u8,
		_256_bit: [32]u8,
	},
	cycle_timer: int, // Countdown timer until the data is "ready" to be used.
	                  // This being equal to zero means you can use the data 
	                  // and stop stalling.
}
