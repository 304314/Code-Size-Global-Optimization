FILE2 = rnd_output0.s rnd_output1.s rnd_output2.o rnd_output3.o

CC = /codesize/install/bin/clang
CFLAGS = --target=riscv32 -march=rv32imafdc -mabi=ilp32d -Os -static
LDFLAGS = /codesize/install/lib/clang-runtimes/riscv32/lib/crt0.o -Wl,--relax,--relax-gp

all: clean rnd

rnd: ${FILE2}
	$(CC) $(CFLAGS) ${FILE2} $(LDFLAGS) -o rnd.out

clean:
	rm -f rnd.out

