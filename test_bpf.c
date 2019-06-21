#include "./bpf.h"
#include "./bpf_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define BPF_LD_IMM64(reg, v)					\
		{						\
			.code = BPF_LD | BPF_DW | BPF_IMM,	\
			.dst_reg = (reg),			\
			.src_reg = 0,				\
			.off = 0,				\
			.imm = (__u32) (v),			\
		},						\
		{						\
			.code = BPF_LD | BPF_W | BPF_IMM,	\
			.dst_reg = 0,				\
			.src_reg = 0,				\
			.off = 0,				\
			.imm = (__u32)(((__u64) v) >> 32),	\
		},


int do_test(void)
{
	struct bpf_insn bytecode[] = {
		{
			.code = BPF_LD | BPF_W | BPF_IMM,
			.dst_reg = BPF_REG_0,
			.imm = 0x123,
		},
		BPF_LD_IMM64(BPF_REG_1, 4566666666999)
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
