	.text
	.attribute	4, 16
	.attribute  5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	//.attribute	5, "rv32i2p0_m2p0_c2p0"
	.file	"bmhisrch.c"
	.globl	bmhi_init
	.p2align	1
	.type	bmhi_init,@function
bmhi_init:
	addi	sp, sp, -32
	sw	ra, 28(sp)
	sw	s0, 24(sp)
	sw	s1, 20(sp)
	sw	s2, 16(sp)
	sw	s3, 12(sp)
	sw	s4, 8(sp)
	sw	s5, 4(sp)
	sw	s6, 0(sp)
	mv	s2, a0
	call	strlen
	lui	s1, %hi(pat)
	lw	a1, %lo(pat)(s1)
	mv	a2, a0
	lui	s0, %hi(patlen)
	sw	a0, %lo(patlen)(s0)
	mv	a0, a1
	mv	a1, a2
	call	realloc
	sw	a0, %lo(pat)(s1)
	beqz	a0, .LBB0_14
	lui	a0, %hi(bhmi_cleanup)
	addi	a0, a0, %lo(bhmi_cleanup)
	call	atexit
	lw	s3, %lo(patlen)(s0)
	blez	s3, .LBB0_4
	lui	a0, %hi(pat)
	lw	s1, %lo(pat)(a0)
	mv	s0, s3
.LBB0_3:
	lbu	a0, 0(s2)
	call	toupper
	sb	a0, 0(s1)
	addi	s0, s0, -1
	addi	s1, s1, 1
	addi	s2, s2, 1
	bnez	s0, .LBB0_3
.LBB0_4:
	li	a0, 0
	lui	a1, %hi(skip)
	addi	a1, a1, %lo(skip)
	li	a2, 1024
.LBB0_5:
	add	a3, a1, a0
	addi	a0, a0, 4
	sw	s3, 0(a3)
	bne	a0, a2, .LBB0_5
	lui	a0, %hi(pat)
	lw	s5, %lo(pat)(a0)
	li	s4, 2
	addi	s6, s3, -1
	blt	s3, s4, .LBB0_9
	lui	a0, %hi(skip)
	addi	s2, a0, %lo(skip)
	mv	s0, s5
	mv	s1, s6
.LBB0_8:
	lbu	a0, 0(s0)
	slli	a1, a0, 2
	add	a1, a1, s2
	sw	s1, 0(a1)
	call	tolower
	slli	a0, a0, 2
	add	a0, a0, s2
	sw	s1, 0(a0)
	addi	s1, s1, -1
	addi	s0, s0, 1
	bnez	s1, .LBB0_8
.LBB0_9:
	add	a0, s5, s6
	lbu	s2, 0(a0)
	slli	a0, s2, 2
	lui	a1, %hi(skip)
	addi	s0, a1, %lo(skip)
	add	a0, a0, s0
	lui	a1, 8
	addi	s1, a1, -1
	sw	s1, 0(a0)
	mv	a0, s2
	call	tolower
	slli	a0, a0, 2
	add	a0, a0, s0
	sw	s1, 0(a0)
	lui	a0, %hi(skip2)
	sw	s3, %lo(skip2)(a0)
	blt	s3, s4, .LBB0_13
.LBB0_10:
	lbu	a1, 0(s5)
	bne	a1, s2, .LBB0_12
	sw	s6, %lo(skip2)(a0)
.LBB0_12:
	addi	s6, s6, -1
	addi	s5, s5, 1
	bnez	s6, .LBB0_10
.LBB0_13:
	lw	ra, 28(sp)
	lw	s0, 24(sp)
	lw	s1, 20(sp)
	lw	s2, 16(sp)
	lw	s3, 12(sp)
	lw	s4, 8(sp)
	lw	s5, 4(sp)
	lw	s6, 0(sp)
	addi	sp, sp, 32
	ret
.LBB0_14:
	li	a0, 1
	call	exit
.Lfunc_end0:
	.size	bmhi_init, .Lfunc_end0-bmhi_init

	.globl	bhmi_cleanup
	.p2align	1
	.type	bhmi_cleanup,@function
bhmi_cleanup:
	lui	a0, %hi(pat)
	lw	a0, %lo(pat)(a0)
	tail	free
.Lfunc_end1:
	.size	bhmi_cleanup, .Lfunc_end1-bhmi_cleanup

	.globl	bmhi_search
	.p2align	1
	.type	bmhi_search,@function
bmhi_search:
	addi	sp, sp, -64
	sw	ra, 60(sp)
	sw	s0, 56(sp)
	sw	s1, 52(sp)
	sw	s2, 48(sp)
	sw	s3, 44(sp)
	sw	s4, 40(sp)
	sw	s5, 36(sp)
	sw	s6, 32(sp)
	sw	s7, 28(sp)
	sw	s8, 24(sp)
	sw	s9, 20(sp)
	sw	s10, 16(sp)
	sw	s11, 12(sp)
	lui	a2, %hi(patlen)
	lw	s4, %lo(patlen)(a2)
	not	a2, a1
	add	a2, a2, s4
	li	s11, 0
	bltz	a2, .LBB2_2
.LBB2_1:
	mv	a0, s11
	lw	ra, 60(sp)
	lw	s0, 56(sp)
	lw	s1, 52(sp)
	lw	s2, 48(sp)
	lw	s3, 44(sp)
	lw	s4, 40(sp)
	lw	s5, 36(sp)
	lw	s6, 32(sp)
	lw	s7, 28(sp)
	lw	s8, 24(sp)
	lw	s9, 20(sp)
	lw	s10, 16(sp)
	lw	s11, 12(sp)
	addi	sp, sp, 64
	ret
.LBB2_2:
	add	s2, a0, a1
	lui	a0, 8
	addi	a0, a0, -1
	sub	s6, a0, a1
	addi	a3, s4, -1
	lui	a0, %hi(pat)
	lw	a0, %lo(pat)(a0)
	lui	a1, %hi(skip2)
	lw	a1, %lo(skip2)(a1)
	sw	a1, 8(sp)
	lui	a1, 1048568
	add	a4, s2, a1
	addi	s1, a0, -2
	lui	a0, %hi(skip)
	addi	s8, a0, %lo(skip)
	addi	a1, a1, 1
	sw	a1, 4(sp)
.LBB2_3:
	add	a0, s2, a2
	lbu	a0, 0(a0)
	slli	a0, a0, 2
	add	a0, a0, s8
	lw	a0, 0(a0)
	add	a2, a2, a0
	bltz	a2, .LBB2_3
	blt	a2, s6, .LBB2_9
	add	s10, a2, a1
	mv	s3, a3
	sub	a0, s10, a3
	add	s11, s2, a0
	mv	s9, a4
	add	s0, a4, a2
	mv	s5, s4
.LBB2_6:
	addi	s7, s5, -1
	blez	s7, .LBB2_1
	lbu	a0, 0(s0)
	call	toupper
	add	a1, s1, s5
	lbu	a1, 0(a1)
	addi	s0, s0, -1
	mv	s5, s7
	beq	a0, a1, .LBB2_6
	lw	a0, 8(sp)
	add	a2, a0, s10
	mv	a3, s3
	mv	a4, s9
	lw	a1, 4(sp)
	bltz	a2, .LBB2_3
.LBB2_9:
	li	s11, 0
	j	.LBB2_1
.Lfunc_end2:
	.size	bmhi_search, .Lfunc_end2-bmhi_search

	.type	patlen,@object
	.section	.sbss,"aw",@nobits
	.p2align	2
patlen:
	.word	0
	.size	patlen, 4

	.type	pat,@object
	.p2align	2
pat:
	.word	0
	.size	pat, 4

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
	.addrsig_sym bhmi_cleanup
