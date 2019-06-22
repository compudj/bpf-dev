#include "./bpf.h"
#include "./bpf_private.h"

bool is_imm64(const struct bpf_insn *insn)
{
	unsigned int bpf_class = BPF_CLASS(insn->code);

	switch (bpf_class) {
	case BPF_LD:
	case BPF_LDX:
	case BPF_ST:
	case BPF_STX:
		if (BPF_MODE(insn->code) == BPF_IMM && BPF_SIZE(insn->code) == BPF_DW)
			return true;
		break;
	case BPF_ALU:
	case BPF_ALU64:
	case BPF_JMP:
	case BPF_JMP32:
		break;

		/* Classes not implemented. */
	default:
		fprintf(stderr, "Error: class %d not implemented\n", bpf_class);
		return -1;
	}
	return false;
}

/*
 * When loading a 64-bit immediate, the following instruction appears
 * as a 32-bit immediate load.
 */
static
int validate_insn(struct bpf_insn *insn, size_t i, size_t len)
{
	if (is_imm64(insn) && (i + 1 == len ||
	    (insn + 1)->code != (BPF_LD | BPF_W | BPF_IMM) ||
	    (insn + 1)->dst_reg != BPF_REG_0 ||
	    (insn + 1)->src_reg != BPF_REG_0 ||
	    (insn + 1)->off != 0)) {
			return -1;
	}


	switch (insn->code) {
		/* Load from immediate. */
	case BPF_LD | BPF_W | BPF_IMM:
	case BPF_LD | BPF_DW | BPF_IMM:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Load from address. */
	case BPF_LDX | BPF_W | BPF_MEM:
	case BPF_LDX | BPF_H | BPF_MEM:
	case BPF_LDX | BPF_B | BPF_MEM:
	case BPF_LDX | BPF_DW | BPF_MEM:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Load from address with acquire semantic. */
	case BPF_LDX | BPF_W | BPF_MEM_ACQ_REL:
	case BPF_LDX | BPF_H | BPF_MEM_ACQ_REL:
	case BPF_LDX | BPF_B | BPF_MEM_ACQ_REL:
	case BPF_LDX | BPF_DW | BPF_MEM_ACQ_REL:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Store from immediate to address. */
	case BPF_ST | BPF_W | BPF_MEM:
	case BPF_ST | BPF_H | BPF_MEM:
	case BPF_ST | BPF_B | BPF_MEM:
	case BPF_ST | BPF_DW | BPF_MEM:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Store from immediate to address with release semantic. */
	case BPF_ST | BPF_W | BPF_MEM_ACQ_REL:
	case BPF_ST | BPF_H | BPF_MEM_ACQ_REL:
	case BPF_ST | BPF_B | BPF_MEM_ACQ_REL:
	case BPF_ST | BPF_DW | BPF_MEM_ACQ_REL:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Store from register to address. */
	case BPF_STX | BPF_W | BPF_MEM:
	case BPF_STX | BPF_H | BPF_MEM:
	case BPF_STX | BPF_B | BPF_MEM:
	case BPF_STX | BPF_DW | BPF_MEM:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

		/* Store from register to address with release semantic. */
	case BPF_STX | BPF_W | BPF_MEM_ACQ_REL:
	case BPF_STX | BPF_H | BPF_MEM_ACQ_REL:
	case BPF_STX | BPF_B | BPF_MEM_ACQ_REL:
	case BPF_STX | BPF_DW | BPF_MEM_ACQ_REL:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		break;

	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

	case BPF_JMP | BPF_JA:
	case BPF_JMP32 | BPF_JA:
		if (insn->off == -1)
			insn->off = -2;
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if (insn->off == -1)
			insn->off = -2;
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		if (insn->off == -1)
			insn->off = -2;
		if (insn->dst_reg >= MAX_BPF_REG)
			return -1;
		if (insn->src_reg >= MAX_BPF_REG)
			return -1;
		break;

	default:
		fprintf(stderr, "Error: Unsupported insn code %d\n",
			insn->code);
		return -1;
	}
	return 0;
}

int validate_bytecode(struct bpf_insn *bytecode, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		struct bpf_insn *insn = &bytecode[i];

		if (validate_insn(insn, i, len))
			return -1;
	}
	return 0;
}
