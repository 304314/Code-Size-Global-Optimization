#!/bin/bash

qemu-riscv32 -B 0x10000000 ./bm1.out > output.txt

if ! diff expect.txt output.txt;then
    echo "fail"
    exit 1
else
    echo "pass"
    exit 0
fi
