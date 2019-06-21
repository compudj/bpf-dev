#include "./bpf.h"
#include <stdio.h>
#include <stdbool.h>

int validate_bytecode(const union bpf_dword *bytecode, size_t len);
int print_bytecode(const union bpf_dword *bytecode, size_t len);
bool is_imm64(const struct bpf_insn *insn);
