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
		if (BPF_MODE(insn->code) == BPF_IMM_X && BPF_SIZE(insn->code) == BPF_DW)
			return true;
		break;
	case BPF_ALU:
	case BPF_JMP:
		break;

		/* Classes not implemented. */
	case BPF_RET:
	case BPF_MISC:
	default:
		fprintf(stderr, "Error: class %d not implemented\n", bpf_class);
		return -1;
	}
	return false;
}

static
int validate_insn(const struct bpf_insn *insn, size_t i, size_t len)
{
	if (is_imm64(insn) && i + 1 == len)
		return -1;
	return 0;
}

int validate_bytecode(const union bpf_dword *bytecode, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		const struct bpf_insn *insn = &bytecode[i].insn;

		if (validate_insn(insn, i, len))
			return -1;
		/* Skip following 64-bit immediate. */
		if (is_imm64(insn)) {
			i++;
		}
	}
	return 0;
}
