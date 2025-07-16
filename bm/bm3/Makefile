FILE2 = qrencode.s qrframe.s qrtest.s support/beebsc.s support/main.s support/chipsupport.s support/boardsupport.s

CC = /codesize/install/bin/clang
CFLAGS = --target=riscv32 -march=rv32imafdc -mabi=ilp32d -Os -static -I support
LDFLAGS = /codesize/install/lib/clang-runtimes/riscv32/lib/crt0.o -Wl,--relax,--relax-gp

all: clean qrduino

qrduino: ${FILE2}
	$(CC) $(CFLAGS) ${FILE2} $(LDFLAGS) -o qrduino.out

clean:
	rm -f qrduino.out

