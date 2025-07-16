	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"main.c"
	.globl	main
	.p2align	1
	.type	main,@function
main:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	call	initialise_board
	call	initialise_benchmark
	li	a0, 1
	call	warm_caches
	call	start_trigger
	call	benchmark
	sw	a0, 8(sp)
	call	stop_trigger
	lw	a0, 8(sp)
	call	verify_benchmark
	seqz	a0, a0
	lw	ra, 12(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end0:
	.size	main, .Lfunc_end0-main

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym main
