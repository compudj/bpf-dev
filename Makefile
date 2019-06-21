all:
	gcc -Wall -g -o test_bpf test_bpf.c bpf_validate.c bpf_print.c bpf_interpreter.c

.PHONY: clean

clean:
	rm -f test_bpf
