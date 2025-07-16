#!/bin/sh
my_dir=$(cd $(dirname $0); pwd)
cd ${my_dir}
qemu-riscv32 -B 0x10000000 ./rnd.out > rnd.txt
if ! diff rnd.txt expect.txt;then
    echo "fail"
    exit 1
else
    echo "pass"
    exit 0
fi
