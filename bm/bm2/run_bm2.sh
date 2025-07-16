#!/bin/sh
my_dir=$(cd $(dirname $0); pwd)

cd ${my_dir}
qemu-riscv32 -B 0x10000000 ./bm2.out > output_2.txt

if ! diff output_2.txt expect.txt;then
    echo "fail"
    exit 1
else
    echo "pass"
    exit 0
fi
