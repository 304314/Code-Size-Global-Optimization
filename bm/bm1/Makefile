FILE2 = bm1.s

CC = /codesize/install/bin/clang
CFLAGS = --target=riscv32 -march=rv32imafdc -mabi=ilp32d -Os -static -w
LDFLAGS = /codesize/install/lib/clang-runtimes/riscv32/lib/crt0.o -Wl,--relax,--relax-gp

all: clean bm1

bm1: ${FILE2}
	$(CC) $(CFLAGS) ${FILE2} $(LDFLAGS) -o bm1.out

clean:
	rm -f bm1.out

