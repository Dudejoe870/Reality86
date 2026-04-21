package reality86

import "core:mem"
import vmem "core:mem/virtual"

JIT_MAX_EXEC_BUFFER :: mem.DEFAULT_PAGE_SIZE * 256

Execute_Buffer :: struct {
	data: []u8,
	offs: int,
	committed_space: int, // Number of committed pages * the page size
}

JIT :: struct {
	using ex_buffer: Execute_Buffer,
}

jit_init :: proc(jit: ^JIT) {
	jit.data, _ = vmem.reserve(JIT_MAX_EXEC_BUFFER)
	vmem.commit(raw_data(jit.data), mem.DEFAULT_PAGE_SIZE)
	jit.committed_space = mem.DEFAULT_PAGE_SIZE
}

jit_run :: proc(jit: ^JIT) {
	ensure(_jit_allow_write(jit))
	
	jit.offs += x86_push64(_jit_next_buf(jit), x86_Reg.BP)
	jit.offs += x86_mov64(_jit_next_buf(jit), x86_Reg.BP, x86_Reg.SP)
	jit.offs += x86_mov64(_jit_next_buf(jit), x86_Reg.AX, i64(34))
	jit.offs += x86_pop64(_jit_next_buf(jit), x86_Reg.BP)
	jit.offs += x86_ret(_jit_next_buf(jit))
	
	ensure(_jit_allow_execute(jit))

	_jit_execute_block(jit, 0)
	jit.offs = 0
}

_jit_next_buf :: #force_inline proc(jit: ^JIT, location := #caller_location) -> []u8 {
	ensure(_jit_ensure_space(jit, X86_MAX_INST_LENGTH), loc = location)
	return jit.data[jit.offs:][:X86_MAX_INST_LENGTH]
}

_jit_execute_block :: proc (jit: ^JIT, block_offset: int) {
	fptr := transmute(proc "c" ())raw_data(jit.data[block_offset:])
	fptr()
}

_jit_allow_execute :: proc (jit: ^JIT) -> bool {
	return vmem.protect(raw_data(jit.data), uint(jit.committed_space), { .Read, .Execute })
}

_jit_allow_write :: proc (jit: ^JIT) -> bool {
	return vmem.protect(raw_data(jit.data), uint(jit.committed_space), { .Read, .Write })
}

@(require_results)
_jit_ensure_space :: proc (jit: ^JIT, size: int) -> bool {
	assert(size >= 0)
	// We're using this for instructions, it shouldn't be bigger than the page size
	assert(size < mem.DEFAULT_PAGE_SIZE)
	if jit.offs + size >= jit.committed_space {
		if jit.offs + size >= JIT_MAX_EXEC_BUFFER {
			return false
		}
		vmem.commit(
			raw_data(jit.data[jit.offs:]), 
			mem.DEFAULT_PAGE_SIZE,
		)
		jit.committed_space += mem.DEFAULT_PAGE_SIZE
	}
	return true
}
