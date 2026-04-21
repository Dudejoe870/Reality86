package reality86

AI_Flags :: enum {
	Full,
	Busy,
	Dma_Enable,
	Word_Clock,
	Bit_Clock,
}

AI :: struct {
	dram_addr: u32,
	length: u32,
	flags: bit_set[AI_Flags; u8],
	count: u16,
}
