	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"qrframe.c"
	.globl	initframe
	.p2align	1
	.type	initframe,@function
initframe:
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
	lui	s7, %hi(WDB)
	lbu	a0, %lo(WDB)(s7)
	lui	s3, %hi(WD)
	lbu	a1, %lo(WD)(s3)
	mul	a0, a1, a0
	li	a1, 1
	li	s2, 1
	call	calloc_beebs
	lbu	a1, %lo(WD)(s3)
	lui	s10, %hi(framebase)
	sw	a0, %lo(framebase)(s10)
	addi	a0, a1, 1
	mul	a0, a0, a1
	srli	a0, a0, 1
	addi	a0, a0, 7
	srli	a0, a0, 3
	li	a1, 1
	call	calloc_beebs
	lbu	a1, %lo(WD)(s3)
	lui	s4, %hi(framask)
	sw	a0, %lo(framask)(s4)
	addi	a0, a1, 1
	call	malloc_beebs
	li	t0, 0
	lui	a1, %hi(rlens)
	sw	a0, %lo(rlens)(a1)
	li	a6, 2
	li	s11, 128
	li	t1, 6
	li	t2, 4
.LBB0_1:
	lbu	a0, %lo(WD)(s3)
	andi	a7, t0, 255
	addi	t4, a0, -7
	mv	t3, t4
	beq	a7, s2, .LBB0_3
	li	t3, 0
.LBB0_3:
	beq	a7, a6, .LBB0_5
	li	t4, 0
.LBB0_5:
	andi	s6, t4, 255
	addi	a1, s6, 3
	lw	a0, %lo(framebase)(s10)
	lbu	a3, %lo(WDB)(s7)
	srli	a4, a1, 3
	andi	s8, t3, 255
	addi	a5, s8, 3
	mul	a3, a5, a3
	add	a3, a3, a4
	add	a3, a3, a0
	lb	a4, 0(a3)
	li	a0, 0
	andi	a1, a1, 7
	srl	a1, s11, a1
	or	a1, a1, a4
	sb	a1, 0(a3)
	andi	a1, t4, 7
	srl	t5, s11, a1
	srli	t6, s6, 3
	addi	a5, s6, 6
	andi	a4, a5, 7
	srl	s5, s11, a4
	srli	a5, a5, 3
	addi	s0, s8, 6
.LBB0_6:
	lbu	s1, %lo(WDB)(s7)
	add	a2, s6, a0
	lw	a1, %lo(framebase)(s10)
	srli	a3, a2, 3
	mul	s1, s8, s1
	add	a3, a3, s1
	add	a1, a1, a3
	lb	a3, 0(a1)
	andi	s1, a2, 7
	srl	s1, s11, s1
	or	a3, a3, s1
	sb	a3, 0(a1)
	lbu	a1, %lo(WDB)(s7)
	lw	a3, %lo(framebase)(s10)
	add	s1, s8, a0
	addi	a4, s1, 1
	mul	a1, a4, a1
	add	a1, a1, t6
	add	a1, a1, a3
	lb	a3, 0(a1)
	or	a3, a3, t5
	sb	a3, 0(a1)
	lbu	a1, %lo(WDB)(s7)
	lw	a3, %lo(framebase)(s10)
	mul	a1, s1, a1
	add	a1, a1, a5
	add	a1, a1, a3
	lb	a3, 0(a1)
	or	a3, a3, s5
	sb	a3, 0(a1)
	lbu	a1, %lo(WDB)(s7)
	addi	a2, a2, 1
	lw	a3, %lo(framebase)(s10)
	srli	a4, a2, 3
	mul	a1, s0, a1
	add	a1, a1, a4
	add	a1, a1, a3
	lb	a3, 0(a1)
	andi	a2, a2, 7
	srl	a2, s11, a2
	or	a2, a2, a3
	addi	a0, a0, 1
	sb	a2, 0(a1)
	bne	a0, t1, .LBB0_6
	addi	t5, t3, 1
	addi	t6, t4, 1
	addi	s5, t4, 5
	addi	s9, t3, 5
	li	a3, 1
.LBB0_8:
	add	a1, a3, t4
	andi	a5, a1, 255
	andi	a4, t5, 255
	mv	a0, a5
	bltu	a5, a4, .LBB0_10
	mv	a0, a4
.LBB0_10:
	bltu	a4, a5, .LBB0_12
	mv	a5, a4
.LBB0_12:
	mul	a2, a5, a5
	add	a2, a2, a5
	lw	a4, %lo(framask)(s4)
	srli	a2, a2, 1
	add	a0, a0, a2
	srli	a2, a0, 3
	add	a2, a2, a4
	lb	a4, 0(a2)
	andi	a0, a0, 7
	srl	a0, s11, a0
	or	a4, a4, a0
	add	a0, a3, t3
	addi	a5, a0, 1
	andi	a5, a5, 255
	andi	s0, t6, 255
	sb	a4, 0(a2)
	mv	a4, s0
	bltu	s0, a5, .LBB0_14
	mv	a4, a5
.LBB0_14:
	bltu	a5, s0, .LBB0_16
	mv	s0, a5
.LBB0_16:
	mul	a2, s0, s0
	add	a2, a2, s0
	lw	a5, %lo(framask)(s4)
	srli	a2, a2, 1
	add	a2, a2, a4
	srli	a4, a2, 3
	add	a4, a4, a5
	lb	a5, 0(a4)
	andi	s0, a0, 255
	andi	a0, a2, 7
	srl	a0, s11, a0
	or	a0, a0, a5
	andi	a5, s5, 255
	sb	a0, 0(a4)
	mv	a0, a5
	bltu	a5, s0, .LBB0_18
	mv	a0, s0
.LBB0_18:
	bltu	s0, a5, .LBB0_20
	mv	a5, s0
.LBB0_20:
	mul	a2, a5, a5
	add	a2, a2, a5
	lw	a4, %lo(framask)(s4)
	srli	a2, a2, 1
	add	a0, a0, a2
	srli	a2, a0, 3
	add	a2, a2, a4
	lb	a4, 0(a2)
	andi	a0, a0, 7
	srl	a0, s11, a0
	or	a0, a0, a4
	addi	a1, a1, 1
	andi	a1, a1, 255
	andi	a4, s9, 255
	sb	a0, 0(a2)
	mv	a0, a1
	bltu	a1, a4, .LBB0_22
	mv	a0, a4
.LBB0_22:
	bltu	a4, a1, .LBB0_24
	mv	a1, a4
.LBB0_24:
	mul	a2, a1, a1
	add	a1, a1, a2
	lw	a2, %lo(framask)(s4)
	srli	a1, a1, 1
	add	a0, a0, a1
	srli	a1, a0, 3
	add	a1, a1, a2
	lb	a2, 0(a1)
	andi	a4, a3, 255
	andi	a0, a0, 7
	srl	a0, s11, a0
	or	a0, a0, a2
	sb	a0, 0(a1)
	addi	a3, a3, 1
	bltu	a4, t2, .LBB0_8
	addi	t3, s8, 2
	addi	a0, s6, 2
	andi	a1, a0, 7
	srl	t4, s11, a1
	srli	t5, a0, 3
	addi	a1, s6, 4
	andi	a0, a1, 7
	srl	t6, s11, a0
	srli	s0, a1, 3
	addi	a5, s8, 4
	li	a1, -2
.LBB0_26:
	add	a2, s6, a1
	lbu	s1, %lo(WDB)(s7)
	addi	a3, a2, 4
	lw	a4, %lo(framebase)(s10)
	srli	a0, a3, 3
	mul	s1, t3, s1
	add	a0, a0, s1
	add	a0, a0, a4
	lb	a4, 0(a0)
	andi	a3, a3, 7
	srl	a3, s11, a3
	or	a3, a3, a4
	sb	a3, 0(a0)
	lbu	a0, %lo(WDB)(s7)
	lw	a3, %lo(framebase)(s10)
	add	a4, s8, a1
	addi	s1, a4, 5
	mul	a0, s1, a0
	add	a0, a0, t5
	add	a0, a0, a3
	lb	a3, 0(a0)
	or	a3, a3, t4
	sb	a3, 0(a0)
	lbu	a0, %lo(WDB)(s7)
	lw	a3, %lo(framebase)(s10)
	addi	a4, a4, 4
	mul	a0, a4, a0
	add	a0, a0, s0
	add	a0, a0, a3
	lb	a3, 0(a0)
	or	a3, a3, t6
	sb	a3, 0(a0)
	lbu	a0, %lo(WDB)(s7)
	addi	a2, a2, 5
	lw	a3, %lo(framebase)(s10)
	srli	a4, a2, 3
	mul	a0, a5, a0
	add	a0, a0, a4
	add	a0, a0, a3
	lb	a3, 0(a0)
	andi	a2, a2, 7
	srl	a2, s11, a2
	or	a2, a2, a3
	addi	a1, a1, 1
	sb	a2, 0(a0)
	bnez	a1, .LBB0_26
	addi	t0, t0, 1
	bltu	a7, a6, .LBB0_1
	lui	a0, %hi(VERSION)
	lbu	a0, %lo(VERSION)(a0)
	li	a1, 2
	bgeu	a0, a1, .LBB0_109
.LBB0_29:
	lui	a1, %hi(framebase)
	lui	a0, %hi(WD)
	lbu	a2, %lo(WD)(a0)
	lui	a3, %hi(WDB)
	lbu	a3, %lo(WDB)(a3)
	lw	a1, %lo(framebase)(a1)
	addi	a2, a2, -8
	mul	a2, a2, a3
	add	a2, a2, a1
	lb	a3, 1(a2)
	li	a1, 0
	ori	a3, a3, 128
	sb	a3, 1(a2)
	li	a2, 128
	lui	a3, %hi(framask)
.LBB0_30:
	lw	a4, %lo(framask)(a3)
	addi	a5, a1, 28
	srli	s1, a5, 3
	add	a4, a4, s1
	lb	s1, 0(a4)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s1
	sb	a5, 0(a4)
	lb	a5, %lo(WD)(a0)
	andi	a4, a1, 255
	addi	a5, a5, -8
	andi	a5, a5, 255
	mv	s1, a5
	bltu	a5, a4, .LBB0_32
	mv	s1, a4
.LBB0_32:
	bltu	a4, a5, .LBB0_34
	mv	a5, a4
.LBB0_34:
	mul	a4, a5, a5
	add	a4, a4, a5
	lw	a5, %lo(framask)(a3)
	srli	a4, a4, 1
	add	a4, a4, s1
	srli	s1, a4, 3
	add	a5, a5, s1
	lb	s1, 0(a5)
	andi	a4, a4, 7
	srl	a4, a2, a4
	or	a4, a4, s1
	sb	a4, 0(a5)
	lb	a4, %lo(WD)(a0)
	add	a4, a4, a1
	addi	a4, a4, -7
	andi	a5, a4, 255
	li	a4, 7
	mv	s1, a5
	bltu	a5, a4, .LBB0_36
	li	s1, 7
.LBB0_36:
	bltu	a4, a5, .LBB0_38
	li	a5, 7
.LBB0_38:
	mul	s0, a5, a5
	add	a5, a5, s0
	lw	s0, %lo(framask)(a3)
	srli	a5, a5, 1
	add	a5, a5, s1
	srli	s1, a5, 3
	add	s1, s1, s0
	lb	s0, 0(s1)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s0
	addi	a1, a1, 1
	sb	a5, 0(s1)
	bne	a1, a4, .LBB0_30
	li	a0, 0
	li	a1, 0
	li	a2, 128
	lui	a3, %hi(framask)
	lui	a7, %hi(WD)
	li	a6, 8
.LBB0_40:
	andi	a5, a0, 255
	li	s1, 7
	bltu	s1, a5, .LBB0_42
	li	a5, 7
.LBB0_42:
	addi	s0, a5, 1
	mul	a5, s0, a5
	lw	s0, %lo(framask)(a3)
	srli	a5, a5, 1
	add	a5, a5, a1
	srli	a4, a5, 3
	add	a4, a4, s0
	lb	s0, 0(a4)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s0
	sb	a5, 0(a4)
	lb	a4, %lo(WD)(a7)
	add	a4, a4, a1
	addi	a4, a4, -8
	andi	s0, a4, 255
	mv	a5, s0
	bltu	s0, s1, .LBB0_44
	li	a5, 7
.LBB0_44:
	bltu	s1, s0, .LBB0_46
	li	s0, 7
.LBB0_46:
	mul	a4, s0, s0
	add	a4, a4, s0
	lw	s1, %lo(framask)(a3)
	srli	a4, a4, 1
	add	a4, a4, a5
	srli	a5, a4, 3
	add	a5, a5, s1
	lb	s1, 0(a5)
	andi	a4, a4, 7
	srl	a4, a2, a4
	or	a4, a4, s1
	sb	a4, 0(a5)
	lb	a4, %lo(WD)(a7)
	andi	s1, a1, 255
	addi	a4, a4, -8
	andi	a5, a4, 255
	mv	s0, s1
	bltu	s1, a5, .LBB0_48
	mv	s0, a5
.LBB0_48:
	bltu	a5, s1, .LBB0_50
	mv	s1, a5
.LBB0_50:
	mul	a4, s1, s1
	add	a4, a4, s1
	lw	a5, %lo(framask)(a3)
	srli	a4, a4, 1
	add	a4, a4, s0
	srli	s1, a4, 3
	add	a5, a5, s1
	lb	s1, 0(a5)
	andi	a4, a4, 7
	srl	a4, a2, a4
	or	a4, a4, s1
	sb	a4, 0(a5)
	addi	a1, a1, 1
	addi	a0, a0, 1
	bne	a1, a6, .LBB0_40
	li	a0, 0
	li	a1, 0
	li	a2, 128
	lui	a3, %hi(framask)
	li	a4, 9
.LBB0_52:
	andi	a5, a0, 255
	li	s1, 8
	bltu	s1, a5, .LBB0_54
	li	a5, 8
.LBB0_54:
	addi	s1, a5, 1
	mul	a5, s1, a5
	lw	s1, %lo(framask)(a3)
	srli	a5, a5, 1
	add	a5, a5, a1
	srli	s0, a5, 3
	add	s1, s1, s0
	lb	s0, 0(s1)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s0
	sb	a5, 0(s1)
	addi	a1, a1, 1
	addi	a0, a0, 1
	bne	a1, a4, .LBB0_52
	li	a0, 0
	lui	a1, %hi(WD)
	li	a2, 128
	lui	a3, %hi(framask)
.LBB0_56:
	lb	a4, %lo(WD)(a1)
	add	a4, a4, a0
	addi	a4, a4, -8
	andi	a5, a4, 255
	li	a4, 8
	mv	s1, a5
	bltu	a5, a4, .LBB0_58
	li	s1, 8
.LBB0_58:
	bltu	a4, a5, .LBB0_60
	li	a5, 8
.LBB0_60:
	mul	s0, a5, a5
	add	a5, a5, s0
	lw	s0, %lo(framask)(a3)
	srli	a5, a5, 1
	add	a5, a5, s1
	srli	s1, a5, 3
	add	s1, s1, s0
	lb	s0, 0(s1)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s0
	sb	a5, 0(s1)
	lw	a5, %lo(framask)(a3)
	addi	s1, a0, 36
	srli	s0, s1, 3
	add	a5, a5, s0
	lb	s0, 0(a5)
	andi	s1, s1, 7
	srl	s1, a2, s1
	or	s1, s1, s0
	addi	a0, a0, 1
	sb	s1, 0(a5)
	bne	a0, a4, .LBB0_56
	li	a0, 0
	lui	a1, %hi(WD)
	li	a2, 128
	lui	a3, %hi(framask)
	li	a4, 7
.LBB0_62:
	lb	a5, %lo(WD)(a1)
	add	a5, a5, a0
	addi	a5, a5, -7
	andi	a5, a5, 255
	li	s0, 8
	mv	s1, a5
	bltu	a5, s0, .LBB0_64
	li	s1, 8
.LBB0_64:
	bltu	s0, a5, .LBB0_66
	li	a5, 8
.LBB0_66:
	mul	s0, a5, a5
	add	a5, a5, s0
	lw	s0, %lo(framask)(a3)
	srli	a5, a5, 1
	add	a5, a5, s1
	srli	s1, a5, 3
	add	s1, s1, s0
	lb	s0, 0(s1)
	andi	a5, a5, 7
	srl	a5, a2, a5
	or	a5, a5, s0
	addi	a0, a0, 1
	sb	a5, 0(s1)
	bne	a0, a4, .LBB0_62
	lui	t1, %hi(WD)
	lbu	a1, %lo(WD)(t1)
	li	s0, 14
	beq	a1, s0, .LBB0_77
	li	a1, 8
	li	a7, 128
	lui	t0, %hi(framebase)
	lui	a4, %hi(WDB)
	li	a6, 6
	lui	s1, %hi(framask)
.LBB0_69:
	addi	s0, a1, -8
	andi	a2, s0, 1
	bnez	a2, .LBB0_71
	lbu	a0, %lo(WDB)(a4)
	lw	a2, %lo(framebase)(t0)
	srli	a3, a1, 3
	mul	a0, a0, a6
	add	a0, a0, a3
	add	a0, a0, a2
	lb	a2, 0(a0)
	andi	a3, s0, 7
	srl	a3, a7, a3
	or	a2, a2, a3
	sb	a2, 0(a0)
	lbu	a0, %lo(WDB)(a4)
	lw	a2, %lo(framebase)(t0)
	mul	a0, a1, a0
	add	a5, a2, a0
	li	s0, 2
	j	.LBB0_76
.LBB0_71:
	addi	a2, s0, 8
	andi	s0, a2, 255
	li	a2, 6
	mv	a5, s0
	bltu	s0, a2, .LBB0_73
	li	a5, 6
.LBB0_73:
	bltu	a2, s0, .LBB0_75
	li	s0, 6
.LBB0_75:
	mul	a2, s0, s0
	add	a2, a2, s0
	lw	s0, %lo(framask)(s1)
	srli	a2, a2, 1
	add	a2, a2, a5
	srli	a5, a2, 3
	add	a3, s0, a5
	lb	a0, 0(a3)
	andi	a2, a2, 7
	srl	s0, a7, a2
	or	a0, a0, s0
	sb	a0, 0(a3)
	lw	a0, %lo(framask)(s1)
	add	a5, a5, a0
.LBB0_76:
	lb	a0, 0(a5)
	or	a0, a0, s0
	sb	a0, 0(a5)
	lbu	s0, %lo(WD)(t1)
	addi	a0, s0, -14
	addi	a2, a1, -7
	addi	a1, a1, 1
	bltu	a2, a0, .LBB0_69
.LBB0_77:
	lui	a0, %hi(VERSION)
	lbu	t2, %lo(VERSION)(a0)
	li	a0, 7
	bltu	t2, a0, .LBB0_97
	li	a7, 0
	slli	a0, t2, 2
	lui	a1, %hi(vpat)
	addi	a1, a1, %lo(vpat)
	add	a0, a0, a1
	lw	t3, -28(a0)
	li	s7, 17
	li	a6, 5
	li	s5, 128
	li	t4, 11
	lui	s6, %hi(WD)
	li	t0, -9
	lui	t5, %hi(framask)
	li	t6, 3
	li	t1, 6
	lui	s2, %hi(framebase)
	lui	s3, %hi(WDB)
.LBB0_79:
	li	s1, 0
	sub	a1, a6, a7
	srl	s4, s5, a1
	li	a0, -9
.LBB0_80:
	add	a2, s7, a0
	addi	a3, a2, 9
	bltu	t4, a3, .LBB0_82
	srl	a2, t3, a3
	j	.LBB0_83
.LBB0_82:
	addi	a2, a2, -3
	srl	a2, t2, a2
.LBB0_83:
	andi	a2, a2, 1
	bnez	a2, .LBB0_93
	lb	a3, %lo(WD)(s6)
	andi	a2, a1, 255
	sub	a4, t0, s1
	add	a3, a3, a4
	andi	a5, a3, 255
	mv	s0, a2
	bltu	a2, a5, .LBB0_86
	mv	s0, a5
.LBB0_86:
	mv	a3, a2
	bltu	a5, a2, .LBB0_88
	mv	a3, a5
.LBB0_88:
	mul	a5, a3, a3
	add	a3, a3, a5
	lw	a5, %lo(framask)(t5)
	srli	a3, a3, 1
	add	a3, a3, s0
	srli	s0, a3, 3
	add	a5, a5, s0
	lb	s0, 0(a5)
	andi	a3, a3, 7
	srl	a3, s5, a3
	or	a3, a3, s0
	sb	a3, 0(a5)
	lb	a3, %lo(WD)(s6)
	add	a3, a3, a4
	andi	a5, a3, 255
	mv	a4, a5
	bltu	a5, a2, .LBB0_90
	mv	a4, a2
.LBB0_90:
	bltu	a2, a5, .LBB0_92
	mv	a5, a2
.LBB0_92:
	mul	a2, a5, a5
	add	a2, a2, a5
	lw	a3, %lo(framask)(t5)
	srli	a2, a2, 1
	add	a2, a2, a4
	srli	a4, a2, 3
	add	a4, a4, a3
	j	.LBB0_94
.LBB0_93:
	lbu	a2, %lo(WD)(s6)
	lbu	a3, %lo(WDB)(s3)
	lw	a4, %lo(framebase)(s2)
	add	a2, a2, a0
	mul	a2, a2, a3
	add	a2, a2, a4
	lb	a3, 0(a2)
	or	a3, a3, s4
	sb	a3, 0(a2)
	lbu	a2, %lo(WD)(s6)
	lbu	a3, %lo(WDB)(s3)
	add	a2, a2, a0
	lw	a4, %lo(framebase)(s2)
	srai	a5, a2, 3
	mul	a3, a1, a3
	add	a3, a3, a5
	add	a4, a4, a3
.LBB0_94:
	lb	a3, 0(a4)
	andi	a2, a2, 7
	srl	a2, s5, a2
	or	a2, a2, a3
	sb	a2, 0(a4)
	addi	s1, s1, 1
	addi	a0, a0, -1
	bne	s1, t6, .LBB0_80
	addi	a7, a7, 1
	addi	s7, s7, -3
	bne	a7, t1, .LBB0_79
	lui	a0, %hi(WD)
	lbu	s0, %lo(WD)(a0)
.LBB0_97:
	beqz	s0, .LBB0_108
	li	a0, 0
	lui	a7, %hi(framebase)
	lw	a4, %lo(framebase)(a7)
	lui	t0, %hi(WDB)
	lbu	a1, %lo(WDB)(t0)
	li	a3, 1
	lui	a6, %hi(WD)
	li	t1, 128
	lui	s1, %hi(framask)
.LBB0_99:
	li	s0, 0
.LBB0_100:
	srli	a2, s0, 3
	andi	a5, a1, 255
	mul	a5, a0, a5
	add	a2, a2, a5
	add	a2, a2, a4
	lbu	a2, 0(a2)
	not	a5, s0
	andi	a5, a5, 7
	srl	a2, a2, a5
	andi	a2, a2, 1
	beqz	a2, .LBB0_106
	andi	a1, a0, 255
	andi	a4, s0, 255
	mv	a2, a4
	bltu	a4, a1, .LBB0_103
	mv	a2, a1
.LBB0_103:
	bltu	a1, a4, .LBB0_105
	mv	a4, a1
.LBB0_105:
	mul	a1, a4, a4
	add	a1, a1, a4
	lw	a4, %lo(framask)(s1)
	srli	a1, a1, 1
	add	a1, a1, a2
	srli	a2, a1, 3
	add	a2, a2, a4
	lb	a4, 0(a2)
	andi	a1, a1, 7
	srl	a1, t1, a1
	or	a1, a1, a4
	sb	a1, 0(a2)
	lw	a4, %lo(framebase)(a7)
	lbu	a1, %lo(WDB)(t0)
.LBB0_106:
	addi	s0, s0, 1
	bne	a3, s0, .LBB0_100
	lbu	a2, %lo(WD)(a6)
	addi	a0, a0, 1
	addi	a3, a3, 1
	bltu	a0, a2, .LBB0_99
.LBB0_108:
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
.LBB0_109:
	lui	a1, %hi(adelta)
	addi	a1, a1, %lo(adelta)
	add	a1, a1, a0
	lui	s2, %hi(WD)
	lbu	a0, %lo(WD)(s2)
	lbu	s1, 0(a1)
	addi	s3, a0, -7
	addi	s4, s1, -3
	addi	s5, s1, 9
.LBB0_110:
	addi	s0, a0, -7
	andi	a0, s0, 255
	andi	s6, s3, 255
	bgeu	s4, a0, .LBB0_112
.LBB0_111:
	mv	a1, s6
	call	putalign
	andi	a0, s0, 255
	sltu	a0, a0, s1
	xori	a1, a0, 1
	sub	s0, s0, s1
	andi	a0, s0, 255
	sltu	a2, s4, a0
	and	a1, a1, a2
	bnez	a1, .LBB0_111
.LBB0_112:
	bgeu	s5, s6, .LBB0_29
	sub	s3, s3, s1
	andi	s0, s3, 255
	li	a0, 6
	mv	a1, s0
	call	putalign
	li	a1, 6
	mv	a0, s0
	call	putalign
	lbu	a0, %lo(WD)(s2)
	j	.LBB0_110
.Lfunc_end0:
	.size	initframe, .Lfunc_end0-initframe

	.globl	freeframe
	.p2align	1
	.type	freeframe,@function
freeframe:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	lui	a0, %hi(framebase)
	lw	a0, %lo(framebase)(a0)
	call	free_beebs
	lui	a0, %hi(framask)
	lw	a0, %lo(framask)(a0)
	call	free_beebs
	lui	a0, %hi(rlens)
	lw	a0, %lo(rlens)(a0)
	lw	ra, 12(sp)
	addi	sp, sp, 16
	tail	free_beebs
.Lfunc_end1:
	.size	freeframe, .Lfunc_end1-freeframe

	.globl	initecc
	.p2align	1
	.type	initecc,@function
initecc:
	addi	sp, sp, -32
	sw	ra, 28(sp)
	sw	s0, 24(sp)
	sw	s1, 20(sp)
	sw	s2, 16(sp)
	sw	s3, 12(sp)
	mv	s1, a1
	mv	s2, a0
	slli	a0, a1, 2
	addi	a0, a0, 17
	lui	a1, %hi(WD)
	sb	a0, %lo(WD)(a1)
	andi	a0, a0, 253
	addi	a1, a0, 7
	srli	a1, a1, 3
	lui	a2, %hi(WDB)
	sb	a1, %lo(WDB)(a2)
	lui	a2, %hi(VERSION)
	mul	s0, a1, a0
	li	a0, 768
	sb	s1, %lo(VERSION)(a2)
	bltu	a0, s0, .LBB2_2
	li	s0, 768
.LBB2_2:
	mv	a0, s0
	call	malloc_beebs
	lui	a1, %hi(qrframe)
	sw	a0, %lo(qrframe)(a1)
	slli	a0, s2, 2
	slli	a1, s1, 4
	add	a0, a0, a1
	lui	a1, %hi(eccblocks)
	addi	a1, a1, %lo(eccblocks)
	add	a0, a0, a1
	lbu	a1, -20(a0)
	lui	a2, %hi(ECCLEVEL)
	sb	s2, %lo(ECCLEVEL)(a2)
	lui	s2, %hi(neccblk1)
	sb	a1, %lo(neccblk1)(s2)
	lbu	a2, -19(a0)
	lui	s3, %hi(neccblk2)
	lbu	a3, -18(a0)
	lbu	a4, -17(a0)
	sb	a2, %lo(neccblk2)(s3)
	lui	s1, %hi(datablkw)
	sb	a3, %lo(datablkw)(s1)
	add	a0, a4, a3
	add	a1, a1, a2
	mul	a0, a0, a1
	lui	a1, %hi(eccblkwid)
	add	a2, a2, a3
	add	a0, a0, a2
	sb	a4, %lo(eccblkwid)(a1)
	bltu	a0, s0, .LBB2_4
	mv	s0, a0
.LBB2_4:
	mv	a0, s0
	call	malloc_beebs
	lbu	a1, %lo(neccblk1)(s2)
	lbu	a2, %lo(neccblk2)(s3)
	lbu	a3, %lo(datablkw)(s1)
	lui	a4, %hi(strinbuf)
	add	a1, a1, a2
	mul	a1, a1, a3
	add	a1, a1, a2
	addi	a1, a1, -3
	sw	a0, %lo(strinbuf)(a4)
	mv	a0, a1
	lw	ra, 28(sp)
	lw	s0, 24(sp)
	lw	s1, 20(sp)
	lw	s2, 16(sp)
	lw	s3, 12(sp)
	addi	sp, sp, 32
	ret
.Lfunc_end2:
	.size	initecc, .Lfunc_end2-initecc

	.globl	initeccsize
	.p2align	1
	.type	initeccsize,@function
initeccsize:
	slli	a2, a0, 2
	lui	a3, %hi(eccblocks)
	addi	a3, a3, %lo(eccblocks)
	add	a2, a2, a3
	addi	a5, a2, -2
	li	a3, 1
.LBB3_1:
	lbu	a7, -2(a5)
	lbu	a4, -1(a5)
	lbu	a6, 0(a5)
	add	a2, a4, a7
	mul	a2, a2, a6
	add	a2, a2, a4
	addi	a2, a2, -3
	bltu	a1, a2, .LBB3_3
	addi	a3, a3, 1
	li	a2, 40
	addi	a5, a5, 16
	bne	a3, a2, .LBB3_1
	j	.LBB3_4
.LBB3_3:
	mv	a2, a3
.LBB3_4:
	lui	a1, %hi(neccblk1)
	sb	a7, %lo(neccblk1)(a1)
	lui	a1, %hi(neccblk2)
	sb	a4, %lo(neccblk2)(a1)
	lui	a3, %hi(datablkw)
	andi	a1, a2, 255
	sb	a6, %lo(datablkw)(a3)
	tail	initecc
.Lfunc_end3:
	.size	initeccsize, .Lfunc_end3-initeccsize

	.globl	freeecc
	.p2align	1
	.type	freeecc,@function
freeecc:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	lui	a0, %hi(qrframe)
	lw	a0, %lo(qrframe)(a0)
	call	free_beebs
	lui	a0, %hi(strinbuf)
	lw	a0, %lo(strinbuf)(a0)
	lw	ra, 12(sp)
	addi	sp, sp, 16
	tail	free_beebs
.Lfunc_end4:
	.size	freeecc, .Lfunc_end4-freeecc

	.p2align	1
	.type	putalign,@function
putalign:
	addi	sp, sp, -16
	sw	s0, 12(sp)
	sw	s1, 8(sp)
	sw	s2, 4(sp)
	sw	s3, 0(sp)
	lui	t5, %hi(WDB)
	lbu	a2, %lo(WDB)(t5)
	lui	t6, %hi(framebase)
	lw	a4, %lo(framebase)(t6)
	srai	a5, a0, 3
	mul	a2, a2, a1
	add	a2, a2, a5
	add	a2, a2, a4
	lb	a4, 0(a2)
	andi	a5, a0, 7
	li	a6, 128
	srl	a5, a6, a5
	or	a4, a4, a5
	sb	a4, 0(a2)
	addi	t0, a1, -2
	addi	a2, a0, -2
	andi	a4, a2, 7
	srl	a7, a6, a4
	srai	t1, a2, 3
	addi	a2, a0, 2
	andi	a4, a2, 7
	srl	t2, a6, a4
	srai	t3, a2, 3
	addi	t4, a1, 2
	addi	a4, a0, -1
	li	a5, 4
	mv	a2, t0
.LBB5_1:
	lbu	s2, %lo(WDB)(t5)
	addi	s0, a4, -1
	lw	s3, %lo(framebase)(t6)
	srai	a3, s0, 3
	mul	s1, t0, s2
	add	a3, a3, s1
	add	a3, a3, s3
	lb	s1, 0(a3)
	andi	s0, s0, 7
	srl	s0, a6, s0
	or	s0, s0, s1
	sb	s0, 0(a3)
	lbu	a3, %lo(WDB)(t5)
	lw	s0, %lo(framebase)(t6)
	addi	s1, a2, 1
	mul	a3, s1, a3
	add	a3, a3, t1
	add	a3, a3, s0
	lb	s0, 0(a3)
	or	s0, s0, a7
	sb	s0, 0(a3)
	lbu	a3, %lo(WDB)(t5)
	lw	s0, %lo(framebase)(t6)
	mul	a2, a2, a3
	add	a2, a2, t3
	add	a2, a2, s0
	lb	a3, 0(a2)
	or	a3, a3, t2
	sb	a3, 0(a2)
	lbu	a2, %lo(WDB)(t5)
	lw	a3, %lo(framebase)(t6)
	srai	s0, a4, 3
	mul	a2, t4, a2
	add	a2, a2, s0
	add	a2, a2, a3
	lb	a3, 0(a2)
	andi	s0, a4, 7
	srl	s0, a6, s0
	or	a3, a3, s0
	sb	a3, 0(a2)
	addi	a5, a5, -1
	addi	a4, a4, 1
	mv	a2, s1
	bnez	a5, .LBB5_1
	addi	a2, a0, -1
	addi	a3, a0, 1
	addi	a4, a1, -1
	addi	t1, a1, 1
	li	t2, 1
	andi	t3, a2, 255
	li	a6, 128
	lui	a7, %hi(framask)
	andi	t4, a3, 255
	andi	t0, a4, 255
	andi	t1, t1, 255
.LBB5_3:
	add	a2, a5, a1
	andi	a4, a2, 255
	mv	a2, t3
	bltu	t3, a4, .LBB5_5
	mv	a2, a4
.LBB5_5:
	mv	a3, t3
	bltu	a4, t3, .LBB5_7
	mv	a3, a4
.LBB5_7:
	mul	a4, a3, a3
	add	a3, a3, a4
	lw	a4, %lo(framask)(a7)
	srli	a3, a3, 1
	add	a2, a2, a3
	srli	a3, a2, 3
	add	a3, a3, a4
	lb	a4, 0(a3)
	andi	a2, a2, 7
	srl	a2, a6, a2
	or	a2, a2, a4
	sub	a4, a1, a5
	andi	a4, a4, 255
	sb	a2, 0(a3)
	mv	a2, t4
	bltu	t4, a4, .LBB5_9
	mv	a2, a4
.LBB5_9:
	mv	a3, t4
	bltu	a4, t4, .LBB5_11
	mv	a3, a4
.LBB5_11:
	mul	a4, a3, a3
	add	a3, a3, a4
	lw	a4, %lo(framask)(a7)
	srli	a3, a3, 1
	add	a2, a2, a3
	srli	a3, a2, 3
	add	a3, a3, a4
	lb	a4, 0(a3)
	andi	a2, a2, 7
	srl	a2, a6, a2
	or	a4, a4, a2
	sub	a2, a0, a5
	andi	a2, a2, 255
	sb	a4, 0(a3)
	mv	a4, a2
	bltu	a2, t0, .LBB5_13
	mv	a4, t0
.LBB5_13:
	bltu	t0, a2, .LBB5_15
	mv	a2, t0
.LBB5_15:
	mul	a3, a2, a2
	add	a2, a2, a3
	lw	a3, %lo(framask)(a7)
	srli	a2, a2, 1
	add	a2, a2, a4
	srli	a4, a2, 3
	add	a3, a3, a4
	lb	a4, 0(a3)
	andi	a2, a2, 7
	srl	a2, a6, a2
	or	a2, a2, a4
	add	a4, a5, a0
	andi	a4, a4, 255
	sb	a2, 0(a3)
	mv	a2, a4
	bltu	a4, t1, .LBB5_17
	mv	a2, t1
.LBB5_17:
	bltu	t1, a4, .LBB5_19
	mv	a4, t1
.LBB5_19:
	mul	a3, a4, a4
	add	a3, a3, a4
	lw	a4, %lo(framask)(a7)
	srli	a3, a3, 1
	add	a2, a2, a3
	srli	a3, a2, 3
	add	a3, a3, a4
	lb	a4, 0(a3)
	andi	a2, a2, 7
	srl	a2, a6, a2
	or	a2, a2, a4
	sb	a2, 0(a3)
	andi	a2, t2, 1
	li	a5, 1
	li	t2, 0
	bnez	a2, .LBB5_3
	lw	s0, 12(sp)
	lw	s1, 8(sp)
	lw	s2, 4(sp)
	lw	s3, 0(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end5:
	.size	putalign, .Lfunc_end5-putalign

	.type	WDB,@object
	.section	.sbss,"aw",@nobits
	.globl	WDB
WDB:
	.byte	0
	.size	WDB, 1

	.type	WD,@object
	.globl	WD
WD:
	.byte	0
	.size	WD, 1

	.type	framebase,@object
	.globl	framebase
	.p2align	2
framebase:
	.word	0
	.size	framebase, 4

	.type	framask,@object
	.globl	framask
	.p2align	2
framask:
	.word	0
	.size	framask, 4

	.type	rlens,@object
	.globl	rlens
	.p2align	2
rlens:
	.word	0
	.size	rlens, 4

	.type	VERSION,@object
	.globl	VERSION
VERSION:
	.byte	0
	.size	VERSION, 1

	.type	qrframe,@object
	.globl	qrframe
	.p2align	2
qrframe:
	.word	0
	.size	qrframe, 4

	.type	ECCLEVEL,@object
	.globl	ECCLEVEL
ECCLEVEL:
	.byte	0
	.size	ECCLEVEL, 1

	.type	eccblocks,@object
	.section	.rodata,"a",@progbits
eccblocks:
	.ascii	"\001\000\023\007\001\000\020\n\001\000\r\r\001\000\t\021\001\000\"\n\001\000\034\020\001\000\026\026\001\000\020\034\001\0007\017\001\000,\032\002\000\021\022\002\000\r\026\001\000P\024\002\000 \022\002\000\030\032\004\000\t\020\001\000l\032\002\000+\030\002\002\017\022\002\002\013\026\002\000D\022\004\000\033\020\004\000\023\030\004\000\017\034\002\000N\024\004\000\037\022\002\004\016\022\004\001\r\032\002\000a\030\002\002&\026\004\002\022\026\004\002\016\032\002\000t\036\003\002$\026\004\004\020\024\004\004\f\030\002\002D\022\004\001+\032\006\002\023\030\006\002\017\034\004\000Q\024\001\0042\036\004\004\026\034\003\b\f\030\002\002\\\030\006\002$\026\004\006\024\032\007\004\016\034\004\000k\032\b\001%\026\b\004\024\030\f\004\013\026\003\001s\036\004\005(\030\013\005\020\024\013\005\f\030\005\001W\026\005\005)\030\005\007\030\036\013\007\f\030\005\001b\030\007\003-\034\017\002\023\030\003\r\017\036\001\005k\034\n\001.\034\001\017\026\034\002\021\016\034\005\001x\036\t\004+\032\021\001\026\034\002\023\016\034\003\004q\034\003\013,\032\021\004\025\032\t\020\r\032\003\005k\034\003\r)\032\017\005\030\036\017\n\017\034\004\004t\034\021\000*\032\021\006\026\034\023\006\020\036\002\007o\034\021\000.\034\007\020\030\036\"\000\r\030\004\005y\036\004\016/\034\013\016\030\036\020\016\017\036\006\004u\036\006\016-\034\013\020\030\036\036\002\020\036\b\004j\032\b\r/\034\007\026\030\036\026\r\017\036\n\002r\034\023\004.\034\034\006\026\034!\004\020\036\b\004z\036\026\003-\034\b\032\027\036\f\034\017\036\003\nu\036\003\027-\034\004\037\030\036\013\037\017\036\007\007t\036\025\007-\034\001%\027\036\023\032\017\036\005\ns\036\023\n/\034\017\031\030\036\027\031\017\036\r\003s\036\002\035.\034*\001\030\036\027\034\017\036\021\000s\036\n\027.\034\n#\030\036\023#\017\036\021\001s\036\016\025.\034\035\023\030\036\013.\017\036\r\006s\036\016\027.\034,\007\030\036;\001\020\036\f\007y\036\f\032/\034'\016\030\036\026)\017\036\006\016y\036\006\"/\034.\n\030\036\002@\017\036\021\004z\036\035\016.\0341\n\030\036\030.\017\036\004\022z\036\r .\0340\016\030\036* \017\036\024\004u\036(\007/\034+\026\030\036\nC\017\036\023\006v\036\022\037/\034\"\"\030\036\024=\017\036"
	.size	eccblocks, 640

	.type	neccblk1,@object
	.section	.sbss,"aw",@nobits
	.globl	neccblk1
neccblk1:
	.byte	0
	.size	neccblk1, 1

	.type	neccblk2,@object
	.globl	neccblk2
neccblk2:
	.byte	0
	.size	neccblk2, 1

	.type	datablkw,@object
	.globl	datablkw
datablkw:
	.byte	0
	.size	datablkw, 1

	.type	eccblkwid,@object
	.globl	eccblkwid
eccblkwid:
	.byte	0
	.size	eccblkwid, 1

	.type	strinbuf,@object
	.globl	strinbuf
	.p2align	2
strinbuf:
	.word	0
	.size	strinbuf, 4

	.type	adelta,@object
	.section	.rodata,"a",@progbits
adelta:
	.ascii	"\000\013\017\023\027\033\037\020\022\024\026\030\032\034\024\026\030\030\032\034\034\026\030\030\032\032\034\034\030\030\032\032\032\034\034\030\032\032\032\034\034"
	.size	adelta, 41

	.type	vpat,@object
	.p2align	2
vpat:
	.word	3220
	.word	1468
	.word	2713
	.word	1235
	.word	3062
	.word	1890
	.word	2119
	.word	1549
	.word	2344
	.word	2936
	.word	1117
	.word	2583
	.word	1330
	.word	2470
	.word	1667
	.word	2249
	.word	2028
	.word	3780
	.word	481
	.word	4011
	.word	142
	.word	3098
	.word	831
	.word	3445
	.word	592
	.word	2517
	.word	1776
	.word	2234
	.word	1951
	.word	2827
	.word	1070
	.word	2660
	.word	1345
	.word	3177
	.size	vpat, 136

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
