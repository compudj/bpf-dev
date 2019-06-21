#include "./bpf.h"
#include "./bpf_private.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_NR_INTERPRETED_INSN		128

static
void clear_regs(__s64 *reg, int nr_regs)
{
	int i;

	/* Registers are initialized to 0. */
	for (i = 0; i < nr_regs; i++)
		reg[i] = 0;
}

static
void show_regs(__s64 *reg, int nr_regs)
{
	int i;

	for (i = 0; i < nr_regs; i++) {
		printf("r%d: %lld\n", i, reg[i]);
	}
}

int interpret_bytecode(const struct bpf_insn *bytecode, size_t len)
{
	__s64 reg[MAX_BPF_REG];
	size_t pc = 0, nr_interpreted_insn = 0;

	clear_regs(reg, MAX_BPF_REG);

	for (;;) {
		const struct bpf_insn *insn = bytecode + pc;

		if (pc == len) {
			/* Bytecode terminates. */
			break;
		}
		if (pc > len) {
			fprintf(stderr, "Error: pc (%zu) overflows bytecode length (%zu)\n",
				pc, len);
			return -1;

		}
		if (nr_interpreted_insn++ >= MAX_NR_INTERPRETED_INSN) {
			fprintf(stderr, "Error: Reached maximum number of interpreted insn (%d)\n",
				MAX_NR_INTERPRETED_INSN);
			return -1;
		}

		switch (insn->code) {
			/* Load from immediate. */
		case BPF_LD | BPF_W | BPF_IMM:
			reg[insn->dst_reg] = insn->imm;
			pc++;
			break;
		case BPF_LD | BPF_DW | BPF_IMM:
			reg[insn->dst_reg] = ((__u64) (insn + 1)->imm << 32) | (__u32) insn->imm;
			pc += 2;	/* Skip next insn. */
			break;

			/* Load from address. */
		case BPF_LDX | BPF_W | BPF_MEM:
			/* TODO: validate pointer. */
			reg[insn->dst_reg] = *(__u32 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_H | BPF_MEM:
			/* TODO: validate pointer. */
			reg[insn->dst_reg] = *(__u16 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_B | BPF_MEM:
			/* TODO: validate pointer. */
			reg[insn->dst_reg] = *(__u8 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_DW | BPF_MEM:
			/* TODO: validate pointer. */
			reg[insn->dst_reg] = *(__u64 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;

			/* Load from address with acquire semantic. */
		case BPF_LDX | BPF_W | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: load acquire */
			reg[insn->dst_reg] = *(__u32 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_H | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: load acquire */
			reg[insn->dst_reg] = *(__u16 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_B | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: load acquire */
			reg[insn->dst_reg] = *(__u8 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;
		case BPF_LDX | BPF_DW | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: load acquire */
			reg[insn->dst_reg] = *(__u64 *) (reg[insn->src_reg] + insn->off);
			pc++;
			break;

			/* Store from immediate to address. */
		case BPF_ST | BPF_W | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u32 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_H | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u16 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_B | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u8 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_DW | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u64 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;

			/* Store from immediate to address with release semantic. */
		case BPF_ST | BPF_W | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u32 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_H | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u16 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_B | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u8 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;
		case BPF_ST | BPF_DW | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u64 *) (reg[insn->dst_reg] + insn->off) = insn->imm;
			pc++;
			break;

			/* Store from register to address. */
		case BPF_STX | BPF_W | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u32 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_H | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u16 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_B | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u8 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_DW | BPF_MEM:
			/* TODO: validate pointer. */
			*(__u64 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;

			/* Store from register to address with release semantic. */
		case BPF_STX | BPF_W | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u32 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_H | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u16 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_B | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u8 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;
		case BPF_STX | BPF_DW | BPF_MEM_ACQ_REL:
			/* TODO: validate pointer. */
			/* TODO: store release. */
			*(__u64 *) (reg[insn->dst_reg] + insn->off) = reg[insn->src_reg];
			pc++;
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
			reg[insn->dst_reg] += insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_ADD | BPF_X:
			reg[insn->dst_reg] += reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_SUB | BPF_K:
			reg[insn->dst_reg] -= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_SUB | BPF_X:
			reg[insn->dst_reg] -= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_MUL | BPF_K:
			reg[insn->dst_reg] *= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_MUL | BPF_X:
			reg[insn->dst_reg] *= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_DIV | BPF_K:
			if (!insn->imm) {
				fprintf(stderr, "error: Divide by 0\n");
				return -1;
			}
			reg[insn->dst_reg] /= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_DIV | BPF_X:
			if (!reg[insn->src_reg]) {
				fprintf(stderr, "Error: Divide by 0\n");
				return -1;
			}
			reg[insn->dst_reg] /= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_OR | BPF_K:
			reg[insn->dst_reg] |= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_OR | BPF_X:
			reg[insn->dst_reg] |= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_AND | BPF_K:
			reg[insn->dst_reg] &= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_AND | BPF_X:
			reg[insn->dst_reg] &= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_LSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Left shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] << insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_LSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Left shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] << reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_RSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Right shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] >> insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_RSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Right shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] >> reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_NEG:
			reg[insn->dst_reg] = -reg[insn->dst_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_MOD | BPF_K:
			if (insn->imm <= 0) {
				fprintf(stderr, "Error: Modulo by %d\n", insn->imm);
				return -1;
			}
			reg[insn->dst_reg] %= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_MOD | BPF_X:
			if (reg[insn->src_reg] <= 0) {
				fprintf(stderr, "Error: Modulo by %lld\n", reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] %= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_XOR | BPF_K:
			reg[insn->dst_reg] ^= insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_XOR | BPF_X:
			reg[insn->dst_reg] ^= reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_MOV | BPF_K:
			reg[insn->dst_reg] = insn->imm;
			pc++;
			break;
		case BPF_ALU | BPF_MOV | BPF_X:
			reg[insn->dst_reg] = reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_ARSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Right shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = reg[insn->dst_reg] >> insn->imm;
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU | BPF_ARSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Right shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = reg[insn->dst_reg] >> reg[insn->src_reg];
			reg[insn->dst_reg] = (__u32) reg[insn->dst_reg];
			pc++;
			break;

		case BPF_ALU64 | BPF_ADD | BPF_K:
			reg[insn->dst_reg] += insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_ADD | BPF_X:
			reg[insn->dst_reg] += reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_SUB | BPF_K:
			reg[insn->dst_reg] -= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_SUB | BPF_X:
			reg[insn->dst_reg] -= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_MUL | BPF_K:
			reg[insn->dst_reg] *= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MUL | BPF_X:
			reg[insn->dst_reg] *= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_DIV | BPF_K:
			if (!insn->imm) {
				fprintf(stderr, "Error: divide by 0\n");
				return -1;
			}
			reg[insn->dst_reg] /= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_DIV | BPF_X:
			if (!reg[insn->src_reg]) {
				fprintf(stderr, "Error: Divide by 0\n");
				return -1;
			}
			reg[insn->dst_reg] /= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_OR | BPF_K:
			reg[insn->dst_reg] |= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_OR | BPF_X:
			reg[insn->dst_reg] |= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_AND | BPF_K:
			reg[insn->dst_reg] &= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_AND | BPF_X:
			reg[insn->dst_reg] &= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_LSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Left shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] << insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_LSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Left shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] << reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_RSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Right shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] >> insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_RSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Right shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = (__u64) reg[insn->dst_reg] >> reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_NEG:
			reg[insn->dst_reg] = -reg[insn->dst_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_MOD | BPF_K:
			if (insn->imm <= 0) {
				fprintf(stderr, "Error: modulo by %d\n", insn->imm);
				return -1;
			}
			reg[insn->dst_reg] %= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOD | BPF_X:
			if (reg[insn->src_reg] <= 0) {
				fprintf(stderr, "Error: modulo by %lld\n", reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] %= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_XOR | BPF_K:
			reg[insn->dst_reg] ^= insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_XOR | BPF_X:
			reg[insn->dst_reg] ^= reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_MOV | BPF_K:
			reg[insn->dst_reg] = insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_MOV | BPF_X:
			reg[insn->dst_reg] = reg[insn->src_reg];
			pc++;
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			if (insn->imm >= 32 || insn->imm < 0) {
				fprintf(stderr, "Error: Right shift by %d undefined.\n",
					insn->imm);
				return -1;
			}
			reg[insn->dst_reg] = reg[insn->dst_reg] >> insn->imm;
			pc++;
			break;
		case BPF_ALU64 | BPF_ARSH | BPF_X:
			if (reg[insn->src_reg] >= 32 || reg[insn->src_reg] < 0) {
				fprintf(stderr, "Error: Right shift by %lld undefined.\n",
					reg[insn->src_reg]);
				return -1;
			}
			reg[insn->dst_reg] = reg[insn->dst_reg] >> reg[insn->src_reg];
			pc++;
			break;

		case BPF_JMP | BPF_JA:
			pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			if (reg[insn->dst_reg] == insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JEQ | BPF_X:
			if (reg[insn->dst_reg] == reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGT | BPF_K:
			if ((__u64) reg[insn->dst_reg] > (__u64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGT | BPF_X:
			if ((__u64) reg[insn->dst_reg] > (__u64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGE | BPF_K:
			if ((__u64) reg[insn->dst_reg] >= (__u64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JGE | BPF_X:
			if ((__u64) reg[insn->dst_reg] >= (__u64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSET | BPF_K:
			/* TODO */
			pc++;
			break;
		case BPF_JMP | BPF_JSET | BPF_X:
			/* TODO */
			pc++;
			break;
		case BPF_JMP | BPF_JNE | BPF_K:
			if (reg[insn->dst_reg] != insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JNE | BPF_X:
			if (reg[insn->dst_reg] != reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLT | BPF_K:
			if ((__u64) reg[insn->dst_reg] < (__u64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLT | BPF_X:
			if ((__u64) reg[insn->dst_reg] < (__u64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLE | BPF_K:
			if ((__u64) reg[insn->dst_reg] <= (__u64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JLE | BPF_X:
			if ((__u64) reg[insn->dst_reg] <= (__u64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGT | BPF_K:
			if ((__s64) reg[insn->dst_reg] > (__s64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGT | BPF_X:
			if ((__s64) reg[insn->dst_reg] > (__s64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGE | BPF_K:
			if ((__s64) reg[insn->dst_reg] >= (__s64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSGE | BPF_X:
			if ((__s64) reg[insn->dst_reg] >= (__s64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLT | BPF_K:
			if ((__s64) reg[insn->dst_reg] < (__s64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLT | BPF_X:
			if ((__s64) reg[insn->dst_reg] < (__s64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLE | BPF_K:
			if ((__s64) reg[insn->dst_reg] <= (__s64) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP | BPF_JSLE | BPF_X:
			if ((__s64) reg[insn->dst_reg] <= (__s64) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;

		case BPF_JMP32 | BPF_JA:
			pc += insn->off;
			pc++;
		case BPF_JMP32 | BPF_JEQ | BPF_K:
			if ((__u32) reg[insn->dst_reg] == (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JEQ | BPF_X:
			if ((__u32) reg[insn->dst_reg] == (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGT | BPF_K:
			if ((__u32) reg[insn->dst_reg] > (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGT | BPF_X:
			if ((__u32) reg[insn->dst_reg] > (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGE | BPF_K:
			if ((__u32) reg[insn->dst_reg] >= (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JGE | BPF_X:
			if ((__u32) reg[insn->dst_reg] >= (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSET | BPF_K:
			/* TODO */
			pc++;
			break;
		case BPF_JMP32 | BPF_JSET | BPF_X:
			/* TODO */
			pc++;
			break;
		case BPF_JMP32 | BPF_JNE | BPF_K:
			if ((__u32) reg[insn->dst_reg] != (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JNE | BPF_X:
			if ((__u32) reg[insn->dst_reg] != (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLT | BPF_K:
			if ((__u32) reg[insn->dst_reg] < (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLT | BPF_X:
			if ((__u32) reg[insn->dst_reg] < (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLE | BPF_K:
			if ((__u32) reg[insn->dst_reg] <= (__u32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JLE | BPF_X:
			if ((__u32) reg[insn->dst_reg] <= (__u32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_K:
			if ((__s32) reg[insn->dst_reg] > (__s32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGT | BPF_X:
			if ((__s32) reg[insn->dst_reg] > (__s32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_K:
			if ((__s32) reg[insn->dst_reg] >= (__s32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSGE | BPF_X:
			if ((__s32) reg[insn->dst_reg] >= (__s32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_K:
			if ((__s32) reg[insn->dst_reg] < (__s32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLT | BPF_X:
			if ((__s32) reg[insn->dst_reg] < (__s32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_K:
			if ((__s32) reg[insn->dst_reg] <= (__s32) insn->imm)
				pc += insn->off;
			pc++;
			break;
		case BPF_JMP32 | BPF_JSLE | BPF_X:
			if ((__s32) reg[insn->dst_reg] <= (__s32) reg[insn->src_reg])
				pc += insn->off;
			pc++;
			break;

		default:
			fprintf(stderr, "Error: Unsupported insn code %d\n",
				insn->code);
			return -1;
		}
	}
	show_regs(reg, MAX_BPF_REG);
	return 0;
}
