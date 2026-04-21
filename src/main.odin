package reality86

main :: proc() {
	system_poweron()
	jit_run(&n64.jit)
}
