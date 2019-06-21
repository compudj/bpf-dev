#include "./bpf.h"
#include "./bpf_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int do_test(void)
{
	union bpf_dword bytecode[] = {
		[0].insn = {
			.code = BPF_LD | BPF_W | BPF_IMM_X,
			.dst_reg = BPF_REG_0,
			.imm = 0x123,
		},
		[1].insn = {
			.code = BPF_LD | BPF_DW | BPF_IMM_X,
			.dst_reg = BPF_REG_1,
		},
		[2].imm = 4566666666999,
	};
	if (validate_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error validating bytecode\n");
		return -1;
	}
	if (print_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error printing bytecode\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	return do_test();
}
