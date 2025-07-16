	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"qrtest.c"
	.globl	warm_caches
	.p2align	1
	.type	warm_caches,@function
warm_caches:
	tail	benchmark_body
.Lfunc_end0:
	.size	warm_caches, .Lfunc_end0-warm_caches

	.p2align	1
	.type	benchmark_body,@function
benchmark_body:
	addi	sp, sp, -32
	sw	ra, 28(sp)
	sw	s0, 24(sp)
	sw	s1, 20(sp)
	sw	s2, 16(sp)
	sw	s3, 12(sp)
	blez	a0, .LBB1_3
	mv	s0, a0
	lui	a0, %hi(heap)
	addi	s2, a0, %lo(heap)
	lui	s3, %hi(strinbuf)
	lui	a0, %hi(.L.str)
	addi	s1, a0, %lo(.L.str)
.LBB1_2:
	lui	a1, 2
	mv	a0, s2
	call	init_heap_beebs
	li	a0, 1
	li	a1, 22
	call	initeccsize
	lw	a0, %lo(strinbuf)(s3)
	li	a2, 22
	mv	a1, s1
	call	memcpy@plt
	call	initframe
	call	qrencode
	call	freeframe
	call	freeecc
	addi	s0, s0, -1
	bnez	s0, .LBB1_2
.LBB1_3:
	lw	ra, 28(sp)
	lw	s0, 24(sp)
	lw	s1, 20(sp)
	lw	s2, 16(sp)
	lw	s3, 12(sp)
	addi	sp, sp, 32
	ret
.Lfunc_end1:
	.size	benchmark_body, .Lfunc_end1-benchmark_body

	.globl	benchmark
	.p2align	1
	.type	benchmark,@function
benchmark:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	li	a0, 5
	call	benchmark_body
	li	a0, 0
	lw	ra, 12(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end2:
	.size	benchmark, .Lfunc_end2-benchmark

	.globl	initialise_benchmark
	.p2align	1
	.type	initialise_benchmark,@function
initialise_benchmark:
	ret
.Lfunc_end3:
	.size	initialise_benchmark, .Lfunc_end3-initialise_benchmark

	.globl	verify_benchmark
	.p2align	1
	.type	verify_benchmark,@function
verify_benchmark:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	lui	a0, %hi(strinbuf)
	lw	a0, %lo(strinbuf)(a0)
	lui	a1, %hi(.L__const.verify_benchmark.expected)
	addi	a1, a1, %lo(.L__const.verify_benchmark.expected)
	li	a2, 22
	call	memcmp
	mv	a1, a0
	li	a0, 0
	bnez	a1, .LBB4_2
	lui	a0, %hi(heap)
	addi	a0, a0, %lo(heap)
	call	check_heap_beebs
	snez	a0, a0
.LBB4_2:
	lw	ra, 12(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end4:
	.size	verify_benchmark, .Lfunc_end4-verify_benchmark

	.type	.L__const.verify_benchmark.expected,@object
	.section	.rodata,"a",@progbits
.L__const.verify_benchmark.expected:
	.ascii	"\376e?\200\202n\240\200\272A.\200\272&.\200\272\t\256\200\202\024"
	.size	.L__const.verify_benchmark.expected, 22

	.type	heap,@object
	.local	heap
	.comm	heap,8192,1
	.type	.L.str,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"http://www.mageec.com"
	.size	.L.str, 22

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym heap
