#include "./bpf.h"
#include "./bpf_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

static
int print_class(const struct bpf_insn *insn)
{
	unsigned int bpf_class = BPF_CLASS(insn->code);

	switch (bpf_class) {
	case BPF_LD:
		printf("class=LD");
		break;
	case BPF_LDX:
		printf("class=LDX");
		break;
	case BPF_ST:
		printf("class=ST");
		break;
	case BPF_STX:
		printf("class=STX");
		break;
	case BPF_ALU:
		printf("class=ALU");
		break;
	case BPF_ALU64:
		printf("class=ALU64");
		break;
	case BPF_JMP:
		printf("class=JMP");
		break;
	case BPF_JMP32:
		printf("class=JMP32");
		break;

		/* Classes not implemented. */
	default:
		fprintf(stderr, "Error: class %d not implemented\n", bpf_class);
		return -1;
	}
	return 0;
}

static
int print_size(const struct bpf_insn *insn)
{
	unsigned int bpf_size = BPF_SIZE(insn->code);

	switch (bpf_size) {
	case BPF_W:
		printf("size=32-bit");
		break;
	case BPF_H:
		printf("size=16-bit");
		break;
	case BPF_B:
		printf("size=8-bit");
		break;
	case BPF_DW:
		printf("size=64-bit");
		break;
	default:
		fprintf(stderr, "Error: size %d not implemented\n", bpf_size);
		return -1;
	}
	return 0;
}

static
int print_imm(const struct bpf_insn *insn)
{
	unsigned int bpf_size = BPF_SIZE(insn->code);

	switch (bpf_size) {
	case BPF_W:
		printf("imm=%d", insn->imm);
		break;
	case BPF_DW:
	{
		/*
		 * We can access next insn because it has been validated
		 * in validation pass.
		 */
		printf("imm=%lld", ((__u64) insn[1].imm << 32) | (__u64) insn->imm);
		break;
	}

	case BPF_H:
	case BPF_B:
	default:
		fprintf(stderr, "Error: size %d not implemented\n", bpf_size);
		return -1;
	}
	return 0;
}

static
int print_mode(const struct bpf_insn *insn)
{
	unsigned int bpf_mode = BPF_MODE(insn->code);

	switch (bpf_mode) {
	case BPF_IMM:
		printf("mode=imm");
		printf(",");
		print_imm(insn);
		break;
	case BPF_MEM:
		printf("mode=mem");
		break;

		/* Modes not implemented. */
	case BPF_ABS:
	case BPF_IND:
	case BPF_LEN:
	case BPF_MSH:
	default:
		fprintf(stderr, "Error: mode %d not implemented\n", bpf_mode);
		return -1;
	}
	return 0;
}

static
int print_reg(__u8 reg)
{
	if (reg >= __MAX_BPF_REG) {
		fprintf(stderr, "Error: printing register %u\n", (unsigned int) reg);
		return -1;
	}
	printf("%d", reg);
	return 0;
}

static
int print_alu_op(const struct bpf_insn *insn)
{
	unsigned int bpf_op = BPF_OP(insn->code);

	switch (bpf_op) {
	case BPF_ADD:
		printf("op=add");
		break;
	case BPF_SUB:
		printf("op=sub");
		break;
	case BPF_MUL:
		printf("op=mul");
		break;
	case BPF_DIV:
		printf("op=div");
		break;
	case BPF_OR:
		printf("op=or");
		break;
	case BPF_AND:
		printf("op=and");
		break;
	case BPF_LSH:
		printf("op=lsh");
		break;
	case BPF_RSH:
		printf("op=rsh");
		break;
	case BPF_NEG:
		printf("op=neg");
		break;
	case BPF_MOD:
		printf("op=mod");
		break;
	case BPF_XOR:
		printf("op=xor");
		break;
	case BPF_MOV:
		printf("op=mov");
		break;
	case BPF_ARSH:
		printf("op=arsh");
		break;

		/* Unsupported alu ops. */
	default:
		fprintf(stderr, "Error: unsupported alu op %u\n", bpf_op);
		return -1;
	}

	printf(",");

	switch (bpf_op) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_MUL:
	case BPF_DIV:
	case BPF_OR:
	case BPF_AND:
	case BPF_LSH:
	case BPF_RSH:
	case BPF_MOD:
	case BPF_XOR:
	case BPF_MOV:
	case BPF_ARSH:
		printf("dst_reg=");
		if (print_reg(insn->dst_reg))
			return -1;
		printf(",");
		switch (BPF_SRC(insn->code)) {
		case BPF_K:
			printf("imm=%d", insn->imm);
			break;
		case BPF_X:
			printf("src_reg=");
			if (print_reg(insn->src_reg))
				return -1;
			break;
		default:
			fprintf(stderr, "Error: unsupported src %u\n",
				BPF_SRC(insn->code));
		}
		break;

	case BPF_NEG:
		printf("dst_reg=");
		if (print_reg(insn->dst_reg))
			return -1;
		break;

		/* Unsupported alu ops. */
	default:
		fprintf(stderr, "Error: unsupported alu op %u\n", bpf_op);
		return -1;
	}
	return 0;
}

static
int print_jmp_op(const struct bpf_insn *insn)
{
	unsigned int bpf_op = BPF_OP(insn->code);

	switch (bpf_op) {
	case BPF_JA:
		printf("op=ja");
		break;
	case BPF_JEQ:
		printf("op=jeq");
		break;
	case BPF_JGT:
		printf("op=jgt");
		break;
	case BPF_JGE:
		printf("op=jge");
		break;
	case BPF_JSET:
		printf("op=jset");
		break;
	case BPF_JNE:
		printf("op=jne");
		break;
	case BPF_JLT:
		printf("op=jlt");
		break;
	case BPF_JLE:
		printf("op=jle");
		break;
	case BPF_JSGT:
		printf("op=jsgt");
		break;
	case BPF_JSGE:
		printf("op=jsge");
		break;
	case BPF_JSLT:
		printf("op=jslt");
		break;
	case BPF_JSLE:
		printf("op=jsle");
		break;

		/* Unsupported jmp ops. */
	default:
		fprintf(stderr, "Error: unsupported jmp op %u\n", bpf_op);
		return -1;
	}

	printf(",");

	switch (bpf_op) {
	case BPF_JA:
		printf("off=%d", insn->off);
		break;
	case BPF_JEQ:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JSET:
	case BPF_JNE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JSLT:
	case BPF_JSLE:
		printf("off=%d,dst_reg=", insn->off);
		if (print_reg(insn->dst_reg))
			return -1;
		printf(",");
		switch (BPF_SRC(insn->code)) {
		case BPF_K:
			printf("imm=%d", insn->imm);
			break;
		case BPF_X:
			printf("src_reg=");
			if (print_reg(insn->src_reg))
				return -1;
			break;
		default:
			fprintf(stderr, "Error: unsupported src %u\n",
				BPF_SRC(insn->code));
		}
		break;

		/* Unsupported jmp ops. */
	default:
		fprintf(stderr, "Error: unsupported jmp op %u\n", bpf_op);
		return -1;
	}
	return 0;
}

static
int print_insn(const struct bpf_insn *insn)
{
	unsigned int bpf_class = BPF_CLASS(insn->code);

	if (print_class(insn))
		return -1;

	switch (bpf_class) {
	case BPF_LD:
	case BPF_LDX:
	case BPF_ST:
	case BPF_STX:
		printf(",");
		if (print_size(insn))
			return -1;
		printf(",");
		if (print_mode(insn))
			return -1;
		printf(",");
		printf("dst_reg=");
		if (print_reg(insn->dst_reg))
			return -1;
		printf(",");
		printf("src_reg=");
		if (print_reg(insn->src_reg))
			return -1;
		printf(",off=%d", (int) insn->off);
		break;
	case BPF_ALU:
	case BPF_ALU64:
		printf(",");
		if (print_alu_op(insn))
			return -1;
		break;
	case BPF_JMP:
	case BPF_JMP32:
		printf(",");
		if (print_jmp_op(insn))
			return -1;
		break;

		/* Classes not implemented. */
	default:
		fprintf(stderr, "Error: class %d not implemented\n", bpf_class);
		return -1;
	}
	printf("\n");
	return 0;
}

int print_bytecode(const struct bpf_insn *bytecode, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		const struct bpf_insn *insn = &bytecode[i];

		if (print_insn(insn))
			return -1;
	}
	return 0;
}
