FILE2 = bm2_1.s bm2_2.s bm2_3.s bm2_4.s

CC = /codesize/install/bin/clang
CFLAGS = --target=riscv32 -march=rv32imafdc -mabi=ilp32d -Os -static
LDFLAGS = /codesize/install/lib/clang-runtimes/riscv32/lib/crt0.o -Wl,--relax,--relax-gp

all: clean bm2

bm2: ${FILE2}
	$(CC) $(CFLAGS) ${FILE2} $(LDFLAGS) -o bm2.out

clean:
	rm -f bm2.out

