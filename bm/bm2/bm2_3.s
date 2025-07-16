	.text
	.attribute	4, 16
	.attribute  5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	//.attribute	5, "rv32i2p0_m2p0_c2p0"
	.file	"bmhsrch.c"
	.globl	bmh_init
	.p2align	1
	.type	bmh_init,@function
bmh_init:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	sw	s0, 8(sp)
	mv	s0, a0
	lui	a0, %hi(pat)
	sw	s0, %lo(pat)(a0)
	mv	a0, s0
	call	strlen
	li	a1, 0
	lui	a2, %hi(patlen)
	sw	a0, %lo(patlen)(a2)
	lui	a2, %hi(skip)
	addi	a2, a2, %lo(skip)
	li	a3, 1024
.LBB0_1:
	add	a4, a2, a1
	addi	a1, a1, 4
	sw	a0, 0(a4)
	bne	a1, a3, .LBB0_1
	blez	a0, .LBB0_5
	addi	a1, a0, -1
	lui	a2, %hi(skip)
	addi	a2, a2, %lo(skip)
	li	a3, -1
	mv	a4, s0
.LBB0_4:
	lbu	a5, 0(a4)
	slli	a5, a5, 2
	add	a5, a5, a2
	sw	a1, 0(a5)
	addi	a1, a1, -1
	addi	a4, a4, 1
	bne	a1, a3, .LBB0_4
.LBB0_5:
	addi	a1, a0, -1
	add	a2, s0, a1
	lbu	a2, 0(a2)
	slli	a3, a2, 2
	lui	a4, %hi(skip)
	addi	a4, a4, %lo(skip)
	add	a3, a3, a4
	lui	a4, 8
	addi	a4, a4, -1
	sw	a4, 0(a3)
	lui	a3, %hi(skip2)
	li	a4, 2
	sw	a0, %lo(skip2)(a3)
	blt	a0, a4, .LBB0_9
.LBB0_6:
	lbu	a0, 0(s0)
	bne	a0, a2, .LBB0_8
	sw	a1, %lo(skip2)(a3)
.LBB0_8:
	addi	a1, a1, -1
	addi	s0, s0, 1
	bnez	a1, .LBB0_6
.LBB0_9:
	lw	ra, 12(sp)
	lw	s0, 8(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end0:
	.size	bmh_init, .Lfunc_end0-bmh_init

	.globl	bmh_search
	.p2align	1
	.type	bmh_search,@function
bmh_search:
	addi	sp, sp, -16
	sw	s0, 12(sp)
	lui	a2, %hi(patlen)
	lw	t4, %lo(patlen)(a2)
	not	a2, a1
	add	a5, t4, a2
	mv	a2, a0
	li	a0, 0
	bltz	a5, .LBB1_2
.LBB1_1:
	lw	s0, 12(sp)
	addi	sp, sp, 16
	ret
.LBB1_2:
	add	t5, a2, a1
	lui	a0, 8
	addi	a0, a0, -1
	sub	t0, a0, a1
	addi	a7, t4, -1
	lui	a0, %hi(pat)
	lw	a0, %lo(pat)(a0)
	lui	a1, %hi(skip2)
	lw	a6, %lo(skip2)(a1)
	lui	a1, 1048568
	add	t1, t5, a1
	addi	a4, a0, -2
	lui	a0, %hi(skip)
	addi	t3, a0, %lo(skip)
	addi	t2, a1, 1
.LBB1_3:
	add	a0, t5, a5
	lbu	a0, 0(a0)
	slli	a0, a0, 2
	add	a0, a0, t3
	lw	a0, 0(a0)
	add	a5, a5, a0
	bltz	a5, .LBB1_3
	blt	a5, t0, .LBB1_9
	add	t6, a5, t2
	sub	a0, t6, a7
	add	a0, a0, t5
	add	a5, a5, t1
	mv	a2, t4
.LBB1_6:
	addi	a3, a2, -1
	blez	a3, .LBB1_1
	lbu	a1, 0(a5)
	add	a2, a2, a4
	lbu	s0, 0(a2)
	addi	a5, a5, -1
	mv	a2, a3
	beq	a1, s0, .LBB1_6
	add	a5, a6, t6
	bltz	a5, .LBB1_3
.LBB1_9:
	li	a0, 0
	j	.LBB1_1
.Lfunc_end1:
	.size	bmh_search, .Lfunc_end1-bmh_search

	.type	pat,@object
	.section	.sbss,"aw",@nobits
	.p2align	2
pat:
	.word	0
	.size	pat, 4

	.type	patlen,@object
	.p2align	2
patlen:
	.word	0
	.size	patlen, 4

	.type	skip,@object
	.local	skip
	.comm	skip,1024,4
	.type	skip2,@object
	.p2align	2
skip2:
	.word	0
	.size	skip2, 4

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
