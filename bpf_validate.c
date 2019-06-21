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
int validate_insn(const struct bpf_insn *insn, size_t i, size_t len)
{
	if (is_imm64(insn) && (i + 1 == len ||
	    (insn + 1)->code != (BPF_LD | BPF_W | BPF_IMM) ||
	    (insn + 1)->dst_reg != BPF_REG_0 ||
	    (insn + 1)->src_reg != BPF_REG_0 ||
	    (insn + 1)->off != 0)) {
			return -1;
	}
	return 0;
}

int validate_bytecode(const struct bpf_insn *bytecode, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		const struct bpf_insn *insn = &bytecode[i];

		if (validate_insn(insn, i, len))
			return -1;
	}
	return 0;
}
