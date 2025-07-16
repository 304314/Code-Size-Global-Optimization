#!/bin/bash

if ! qemu-riscv32 -B 0x10000000 ./qrduino;then
    echo "fail"
    exit 1
else
    echo "pass"
    exit 0
fi
