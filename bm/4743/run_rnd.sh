#!/bin/bash

qemu-riscv32 -B 0x10000000 ./rnd.out > rnd.txt

if ! diff expect.txt rnd.txt;then
    echo "fail"
    exit 1
else
    echo "pass"
    exit 0
fi
