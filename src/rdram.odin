package reality86

// Is it necessary for the request encoding to be based off of the og hardware at all?
// no. But it's fun right? :)

RamBus_Operation :: enum u8 {
	Read                     = 0b0000,
	Write_Sequential         = 0b0100,
	Read_Register            = 0b0110,
	Write_Register           = 0b0111,
	Write_Random             = 0b1000,
	Write_Random_Byte_Mask   = 0b1100,
	Write_Register_Broadcast = 0b1111,
}

RamBus_Request :: bit_field u64 {
	op: RamBus_Operation | 4,
	opx: u8 | 2,
	byte_mask_right_shift: int | 3,
	address: u64 | 33,
	byte_mask_left_shift: int | 3,
	count: u8 | 5,
}

RamBus_Transaction :: struct {
	request: RamBus_Request,

}

RDRAM_Row :: struct {
	data: [256][9]u8, // Last byte represents the ninth bit of the other 8 bytes
}

// 1MiB Bank
RDRAM_Bank :: struct {
	activated_row: int, // -1 means none
	rows: [512]RDRAM_Row,
}

// 2MiB RDRAM Device
RDRAM_Device :: struct {
	banks: [2]RDRAM_Bank,
	swap_field: u16,
	mask_data_reg: u16, // 9 bits
}

RDRAM_Bus :: struct {
	devices: [4]RDRAM_Device,
}

rdram_poweron :: proc(device: ^RDRAM_Device) {
	for &bank in device.banks {
		bank.activated_row = -1
	}
}

rdram_process_transaction :: proc(transaction: ^RamBus_Transaction) -> (cycle_count: int) {
	/*switch transaction.request.op {

	}*/
	return 0
}
