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
			.off = 0,				\
			.imm = (__u32) (v),			\
		},						\
		{						\
			.code = BPF_LD | BPF_W | BPF_IMM,	\
			.dst_reg = 0,				\
			.src_reg = 0,				\
			.off = 0,				\
			.imm = (__u32)(((__u64) (v)) >> 32),	\
		},

static
int test_st = 0;
static
int test_stx = 0;

int do_test(void)
{
	struct bpf_insn bytecode[] = {
		{
			.code = BPF_LD | BPF_W | BPF_IMM,
			.dst_reg = BPF_REG_0,
			.imm = 123,
		},
		BPF_LD_IMM64(BPF_REG_1, 4566666666999)
		{
			.code = BPF_ALU64 | BPF_X | BPF_ADD,
			.dst_reg = BPF_REG_0,
			.src_reg = BPF_REG_1,
		},
		{
			.code = BPF_JMP | BPF_JLT | BPF_X,
			.dst_reg = BPF_REG_1,
			.src_reg = BPF_REG_0,
			.off = 1,
		},
		{
			.code = BPF_LD | BPF_W | BPF_IMM,
			.dst_reg = BPF_REG_9,
			.imm = 666,
		},
		{
			.code = BPF_LD | BPF_W | BPF_IMM,
			.dst_reg = BPF_REG_10,
			.imm = 777,
		},
		BPF_LD_IMM64(BPF_REG_2, (unsigned long) &test_st)
		{
			.code = BPF_ST | BPF_W | BPF_MEM,
			.dst_reg = BPF_REG_2,
			.off = 0,
			.imm = 444,
		},
		BPF_LD_IMM64(BPF_REG_3, (unsigned long) &test_stx)
		{
			.code = BPF_STX | BPF_W | BPF_MEM,
			.dst_reg = BPF_REG_3,
			.src_reg = BPF_REG_10,
			.off = 0,
		},
	};

	if (validate_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error validating bytecode\n");
		return -1;
	}
	if (print_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error printing bytecode\n");
		return -1;
	}
	if (interpret_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error interpreting bytecode\n");
		return -1;
	}
	printf("test_st: %d\n", test_st);
	printf("test_stx: %d\n", test_stx);
	return 0;
}

int do_loop(void)
{
	struct bpf_insn bytecode[] = {
		{
			.code = BPF_ALU | BPF_ADD | BPF_K,
			.dst_reg = BPF_REG_0,
			.imm = 1,
		},
		{
			.code = BPF_JMP | BPF_JA,
			.off = -2,
		},
	};
	if (validate_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error validating bytecode\n");
		return -1;
	}
	if (print_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error printing bytecode\n");
		return -1;
	}
	/* Expect error. */
	if (interpret_bytecode(bytecode, ARRAY_SIZE(bytecode))) {
		fprintf(stderr, "Error interpreting bytecode\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (do_test()) {
		return -1;
	}
	if (do_loop() == 0) {
		return -1;
	}
	return 0;
}
