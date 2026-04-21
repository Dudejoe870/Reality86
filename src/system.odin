package reality86

// A little context: The structs contained within the RCP struct are not supposed to 
// *directly* reflect the memory mapped representation of these registers,
// that's handled by the MMIO code. They simply represent the state of
// any particular RCP subsystem using the most efficient representation for
// the emulator to manipulate.
//
// Similar to how on the actual hardware the MMIO register bits
// are simply connected to actual pins on / in the physical chips :)

RCP :: struct {
	ai: AI,
}

N64_System :: struct {
	r4300: R4300,
					  // ^
	sysad: SysAD_Bus, // |  This bus connects the R4300 and the RCP together.
					  // v
	rcp: RCP,
	rdram: RDRAM_Bus,

	jit: JIT,
}

n64: ^N64_System

system_poweron :: proc() {
	n64 = new(N64_System)
	for &device in n64.rdram.devices {
		rdram_poweron(&device)
	}

	jit_init(&n64.jit)
}
