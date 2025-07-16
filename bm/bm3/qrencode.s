	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"qrencode.c"
	.globl	qrencode
	.p2align	1
	.type	qrencode,@function
qrencode:
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
	lui	a0, %hi(strinbuf)
	lw	s0, %lo(strinbuf)(a0)
	mv	a0, s0
	call	strlen
	lui	a1, %hi(neccblk1)
	lbu	a1, %lo(neccblk1)(a1)
	lui	a2, %hi(neccblk2)
	lbu	a2, %lo(neccblk2)(a2)
	lui	a3, %hi(datablkw)
	lbu	a3, %lo(datablkw)(a3)
	add	a4, a2, a1
	lui	a1, %hi(VERSION)
	lbu	a1, %lo(VERSION)(a1)
	mul	a3, a4, a3
	add	s3, a3, a2
	li	a3, 9
	addi	a2, s3, -2
	bltu	a3, a1, .LBB0_2
	mv	a3, a2
	bgeu	a0, a2, .LBB0_3
	j	.LBB0_4
.LBB0_2:
	addi	a3, s3, -3
	bltu	a0, a2, .LBB0_4
.LBB0_3:
	mv	a0, a3
.LBB0_4:
	li	a2, 10
	bltu	a1, a2, .LBB0_9
	add	a1, a0, s0
	sb	zero, 2(a1)
	beqz	a0, .LBB0_8
	lui	a1, %hi(strinbuf)
	mv	a2, a0
.LBB0_7:
	lw	a3, %lo(strinbuf)(a1)
	add	a3, a3, a2
	lb	a4, -1(a3)
	lb	a5, 2(a3)
	slli	a4, a4, 4
	or	a4, a4, a5
	sb	a4, 2(a3)
	lw	a3, %lo(strinbuf)(a1)
	add	a3, a3, a2
	lbu	a4, -1(a3)
	addi	a5, a2, -1
	srli	a2, a4, 4
	sb	a2, 1(a3)
	mv	a2, a5
	bnez	a5, .LBB0_7
.LBB0_8:
	lui	a1, %hi(strinbuf)
	lw	a2, %lo(strinbuf)(a1)
	lb	a3, 2(a2)
	slli	a4, a0, 4
	or	a3, a3, a4
	sb	a3, 2(a2)
	lw	a1, %lo(strinbuf)(a1)
	srli	a2, a0, 4
	sb	a2, 1(a1)
	li	a2, 12
	j	.LBB0_13
.LBB0_9:
	add	a1, a0, s0
	sb	zero, 1(a1)
	beqz	a0, .LBB0_12
	lui	a1, %hi(strinbuf)
	mv	a2, a0
.LBB0_11:
	lw	a3, %lo(strinbuf)(a1)
	add	a3, a3, a2
	lb	a4, -1(a3)
	lb	a5, 1(a3)
	slli	a4, a4, 4
	or	a4, a4, a5
	sb	a4, 1(a3)
	lw	a3, %lo(strinbuf)(a1)
	add	a3, a3, a2
	lbu	a4, -1(a3)
	addi	a5, a2, -1
	srli	a2, a4, 4
	sb	a2, 0(a3)
	mv	a2, a5
	bnez	a5, .LBB0_11
.LBB0_12:
	lui	a1, %hi(strinbuf)
	lw	a1, %lo(strinbuf)(a1)
	lb	a2, 1(a1)
	slli	a3, a0, 4
	or	a2, a2, a3
	sb	a2, 1(a1)
	li	a2, 4
.LBB0_13:
	lui	a1, %hi(strinbuf)
	lw	a3, %lo(strinbuf)(a1)
	srl	a2, a0, a2
	ori	a2, a2, 64
	sb	a2, 0(a3)
	lui	a2, %hi(VERSION)
	lbu	a2, %lo(VERSION)(a2)
	sltiu	a2, a2, 10
	sub	a0, a0, a2
	addi	a0, a0, 3
	bgeu	a0, s3, .LBB0_16
	li	a2, 236
	li	a3, 17
.LBB0_15:
	lw	a4, %lo(strinbuf)(a1)
	add	a4, a4, a0
	sb	a2, 0(a4)
	lw	a4, %lo(strinbuf)(a1)
	addi	a5, a0, 2
	add	a0, a0, a4
	sb	a3, 1(a0)
	mv	a0, a5
	bltu	a5, s3, .LBB0_15
.LBB0_16:
	lui	a0, %hi(eccblkwid)
	lbu	a7, %lo(eccblkwid)(a0)
	lui	a0, %hi(qrframe)
	lw	a0, %lo(qrframe)(a0)
	lw	s5, %lo(strinbuf)(a1)
	li	a6, 1
	sb	a6, 0(a0)
	beqz	a7, .LBB0_32
	li	a1, 0
	lui	a2, %hi(g0log)
	addi	t1, a2, %lo(g0log)
	li	a4, 255
	lui	a2, %hi(g0exp)
	addi	t2, a2, %lo(g0exp)
	li	a2, 1
.LBB0_18:
	addi	t0, a1, 1
	add	a3, a0, t0
	sb	a6, 0(a3)
	beqz	a1, .LBB0_28
	mv	s1, a1
	mv	a2, a1
.LBB0_20:
	add	s0, a0, s1
	lbu	a3, 0(s0)
	beqz	a3, .LBB0_25
	add	a3, a3, t1
	lbu	a3, 0(a3)
	add	a5, a1, a3
	bltu	a5, a4, .LBB0_24
	addi	a3, a5, 1
	andi	a3, a3, 255
.LBB0_23:
	mv	a5, a3
	li	a3, 0
	beq	a5, a4, .LBB0_23
.LBB0_24:
	addi	s1, s1, -1
	add	a3, a0, s1
	lbu	a3, 0(a3)
	add	a5, a5, t2
	lb	a5, 0(a5)
	xor	a3, a3, a5
	j	.LBB0_26
.LBB0_25:
	addi	s1, s1, -1
	add	a3, a0, s1
	lbu	a3, 0(a3)
.LBB0_26:
	addi	a2, a2, -1
	andi	a5, a2, 255
	sb	a3, 0(s0)
	bnez	a5, .LBB0_20
	lbu	a2, 0(a0)
.LBB0_28:
	andi	a2, a2, 255
	add	a2, a2, t1
	lbu	a2, 0(a2)
	add	a1, a1, a2
	bltu	a1, a4, .LBB0_31
	addi	a1, a1, 1
	andi	a2, a1, 255
.LBB0_30:
	mv	a1, a2
	li	a2, 0
	beq	a1, a4, .LBB0_30
.LBB0_31:
	add	a1, a1, t2
	lbu	a2, 0(a1)
	sb	a2, 0(a0)
	mv	a1, t0
	bne	t0, a7, .LBB0_18
.LBB0_32:
	add	s1, s5, s3
	addi	a1, a7, 1
	andi	a1, a1, 255
	lui	a2, %hi(g0log)
	addi	a2, a2, %lo(g0log)
.LBB0_33:
	lbu	a3, 0(a0)
	add	a3, a3, a2
	lb	a3, 0(a3)
	sb	a3, 0(a0)
	addi	a1, a1, -1
	addi	a0, a0, 1
	bnez	a1, .LBB0_33
	lui	s2, %hi(neccblk1)
	lbu	a0, %lo(neccblk1)(s2)
	lui	s4, %hi(datablkw)
	lbu	a1, %lo(datablkw)(s4)
	beqz	a0, .LBB0_37
	lui	s6, %hi(eccblkwid)
	lbu	a0, %lo(eccblkwid)(s6)
	li	s0, 0
	lui	s7, %hi(qrframe)
.LBB0_36:
	lw	a4, %lo(qrframe)(s7)
	andi	a1, a1, 255
	andi	a3, a0, 255
	mv	a0, s5
	mv	a2, s1
	call	appendrs
	lbu	a1, %lo(datablkw)(s4)
	lbu	a0, %lo(eccblkwid)(s6)
	lbu	a2, %lo(neccblk1)(s2)
	add	s5, s5, a1
	addi	s0, s0, 1
	add	s1, s1, a0
	bltu	s0, a2, .LBB0_36
.LBB0_37:
	lui	s2, %hi(neccblk2)
	lbu	a0, %lo(neccblk2)(s2)
	beqz	a0, .LBB0_40
	lui	s4, %hi(eccblkwid)
	lbu	a0, %lo(eccblkwid)(s4)
	li	s0, 0
	lui	s6, %hi(qrframe)
	lui	s7, %hi(datablkw)
.LBB0_39:
	lw	a4, %lo(qrframe)(s6)
	addi	a1, a1, 1
	andi	a3, a0, 255
	andi	a1, a1, 255
	mv	a0, s5
	mv	a2, s1
	call	appendrs
	lbu	a1, %lo(datablkw)(s7)
	lbu	a0, %lo(eccblkwid)(s4)
	lbu	a3, %lo(neccblk2)(s2)
	add	a2, a1, s5
	addi	s5, a2, 1
	addi	s0, s0, 1
	add	s1, s1, a0
	bltu	s0, a3, .LBB0_39
	j	.LBB0_41
.LBB0_40:
	li	a3, 0
.LBB0_41:
	lui	a0, %hi(qrframe)
	lw	a0, %lo(qrframe)(a0)
	beqz	a1, .LBB0_53
	li	a1, 0
	lui	a2, %hi(neccblk1)
	lui	a4, %hi(datablkw)
	lui	t0, %hi(strinbuf)
	lui	a7, %hi(neccblk2)
	mv	a6, a3
.LBB0_43:
	lbu	s0, %lo(neccblk1)(a2)
	beqz	s0, .LBB0_47
	li	s0, 0
.LBB0_45:
	lbu	a3, %lo(datablkw)(a4)
	lw	s1, %lo(strinbuf)(t0)
	mul	a3, s0, a3
	add	a3, a3, a1
	add	a3, a3, s1
	lb	a3, 0(a3)
	add	s1, a0, s0
	sb	a3, 0(s1)
	lbu	a3, %lo(neccblk1)(a2)
	addi	s0, s0, 1
	bltu	s0, a3, .LBB0_45
	lbu	a3, %lo(neccblk2)(a7)
	add	a0, a0, s0
	mv	a6, a3
.LBB0_47:
	andi	s0, a6, 255
	beqz	s0, .LBB0_51
	li	s0, 0
.LBB0_49:
	lbu	a3, %lo(neccblk1)(a2)
	lbu	s1, %lo(datablkw)(a4)
	lw	a5, %lo(strinbuf)(t0)
	mul	a3, s1, a3
	add	a3, a3, a1
	addi	s1, s1, 1
	mul	s1, s1, s0
	add	a3, a3, s1
	add	a3, a3, a5
	lb	a3, 0(a3)
	add	a5, a0, s0
	sb	a3, 0(a5)
	lbu	a3, %lo(neccblk2)(a7)
	addi	s0, s0, 1
	bltu	s0, a3, .LBB0_49
	add	a0, a0, s0
	mv	a6, a3
	j	.LBB0_52
.LBB0_51:
	li	a6, 0
.LBB0_52:
	lbu	a5, %lo(datablkw)(a4)
	addi	a1, a1, 1
	bltu	a1, a5, .LBB0_43
.LBB0_53:
	andi	a2, a3, 255
	beqz	a2, .LBB0_57
	li	a3, 0
	lui	a6, %hi(strinbuf)
	lui	a7, %hi(neccblk1)
	lui	s1, %hi(datablkw)
	lui	s0, %hi(neccblk2)
.LBB0_55:
	lbu	a2, %lo(neccblk1)(a7)
	lbu	a4, %lo(datablkw)(s1)
	lw	a5, %lo(strinbuf)(a6)
	mul	a2, a4, a2
	add	a2, a2, a1
	addi	a4, a4, 1
	mul	a4, a4, a3
	add	a2, a2, a4
	add	a2, a2, a5
	lb	a2, 0(a2)
	add	a4, a0, a3
	sb	a2, 0(a4)
	lbu	a2, %lo(neccblk2)(s0)
	addi	a3, a3, 1
	bltu	a3, a2, .LBB0_55
	add	a0, a0, a3
.LBB0_57:
	lui	s4, %hi(eccblkwid)
	lbu	a6, %lo(eccblkwid)(s4)
	lui	s2, %hi(neccblk1)
	lbu	a3, %lo(neccblk1)(s2)
	beqz	a6, .LBB0_64
	li	a7, 0
	lui	a4, %hi(strinbuf)
	lui	a5, %hi(neccblk2)
.LBB0_59:
	andi	s1, a3, 255
	andi	s0, a2, 255
	neg	s1, s1
	beq	s0, s1, .LBB0_63
	li	s1, 0
	add	s0, a7, s3
.LBB0_61:
	lbu	a2, %lo(eccblkwid)(s4)
	lw	a3, %lo(strinbuf)(a4)
	mul	a2, s1, a2
	add	a2, a2, s0
	add	a2, a2, a3
	lb	a2, 0(a2)
	add	a3, a0, s1
	sb	a2, 0(a3)
	lbu	a3, %lo(neccblk1)(s2)
	lbu	a2, %lo(neccblk2)(a5)
	addi	s1, s1, 1
	add	a1, a2, a3
	bltu	s1, a1, .LBB0_61
	lbu	a6, %lo(eccblkwid)(s4)
	add	a0, a0, s1
.LBB0_63:
	addi	a7, a7, 1
	andi	a1, a6, 255
	bltu	a7, a1, .LBB0_59
.LBB0_64:
	andi	a4, a6, 255
	lui	s9, %hi(strinbuf)
	lw	a0, %lo(strinbuf)(s9)
	lui	s5, %hi(qrframe)
	lw	a1, %lo(qrframe)(s5)
	andi	a3, a3, 255
	andi	a2, a2, 255
	add	a2, a2, a3
	mul	a2, a2, a4
	add	a2, a2, s3
	call	memcpy@plt
	lw	a0, %lo(qrframe)(s5)
	lui	a1, %hi(framebase)
	lui	s8, %hi(WDB)
	lbu	a2, %lo(WDB)(s8)
	lui	s11, %hi(WD)
	lbu	a3, %lo(WD)(s11)
	lw	a1, %lo(framebase)(a1)
	mul	a2, a3, a2
	call	memcpy@plt
	lui	a6, %hi(datablkw)
	lbu	a0, %lo(datablkw)(a6)
	lbu	a1, %lo(eccblkwid)(s4)
	lbu	a2, %lo(neccblk1)(s2)
	lui	a7, %hi(neccblk2)
	lbu	a3, %lo(neccblk2)(a7)
	add	a0, a0, a1
	add	a1, a3, a2
	lbu	s2, %lo(WD)(s11)
	mul	a0, a1, a0
	neg	a1, a3
	beq	a0, a1, .LBB0_92
	li	t3, 0
	addi	a2, s2, -1
	li	a4, 1
	lui	t4, %hi(framask)
	li	s3, 6
	li	t5, 7
	lui	t0, %hi(eccblkwid)
	lui	t1, %hi(neccblk1)
	li	t2, 128
	mv	t6, s2
	li	a5, 1
	mv	a1, a2
.LBB0_66:
	lw	a0, %lo(strinbuf)(s9)
	add	a0, a0, t3
	lbu	s6, 0(a0)
	li	s4, 0
.LBB0_67:
	slli	a0, s6, 24
	srai	a0, a0, 24
	bgez	a0, .LBB0_69
	lw	a0, %lo(qrframe)(s5)
	lbu	a3, %lo(WDB)(s8)
	slli	s1, a1, 24
	srli	s1, s1, 27
	andi	s0, a2, 255
	mul	a3, a3, s0
	add	a3, a3, s1
	add	a0, a0, a3
	lb	a3, 0(a0)
	andi	s1, a1, 7
	srl	s1, t2, s1
	or	a3, a3, s1
	sb	a3, 0(a0)
	lbu	t6, %lo(WD)(s11)
.LBB0_69:
	lw	s0, %lo(framask)(t4)
	andi	s2, t6, 255
	addi	s7, s2, -1
.LBB0_70:
	andi	a4, a4, 255
	beqz	a4, .LBB0_72
	addi	a1, a1, -1
	j	.LBB0_85
.LBB0_72:
	andi	a0, a5, 255
	addi	a3, a1, 1
	beqz	a0, .LBB0_75
	andi	a0, a2, 255
	beqz	a0, .LBB0_79
	addi	a2, a2, -1
	li	a5, 1
	j	.LBB0_84
.LBB0_75:
	andi	a0, a2, 255
	bne	s7, a0, .LBB0_81
	addi	a1, a1, -1
	andi	a0, a1, 255
	bne	a0, s3, .LBB0_78
	addi	a2, a2, -8
	li	a1, 5
.LBB0_78:
	li	a5, 1
	j	.LBB0_85
.LBB0_79:
	addi	a3, a1, -1
	andi	a0, a3, 255
	beq	a0, s3, .LBB0_82
	li	a2, 0
	j	.LBB0_83
.LBB0_81:
	li	a5, 0
	addi	a2, a2, 1
	j	.LBB0_84
.LBB0_82:
	addi	a3, a1, -2
	li	a2, 9
.LBB0_83:
	li	a5, 0
.LBB0_84:
	mv	a1, a3
.LBB0_85:
	andi	a0, a2, 255
	andi	a3, a1, 255
	mv	s1, a3
	bltu	a3, a0, .LBB0_87
	mv	s1, a0
.LBB0_87:
	bltu	a0, a3, .LBB0_89
	mv	a3, a0
.LBB0_89:
	mul	a0, a3, a3
	add	a0, a0, a3
	srli	a0, a0, 1
	add	a0, a0, s1
	srli	a3, a0, 3
	add	a3, a3, s0
	lbu	a3, 0(a3)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a3, a0
	andi	a0, a0, 1
	seqz	a4, a4
	bnez	a0, .LBB0_70
	andi	a0, s4, 255
	addi	s4, s4, 1
	slli	s6, s6, 1
	bltu	a0, t5, .LBB0_67
	lbu	a0, %lo(datablkw)(a6)
	lbu	a3, %lo(eccblkwid)(t0)
	lbu	s0, %lo(neccblk1)(t1)
	lbu	s1, %lo(neccblk2)(a7)
	addi	t3, t3, 1
	add	a0, a0, a3
	add	a3, s1, s0
	mul	a0, a3, a0
	add	a0, a0, s1
	bltu	t3, a0, .LBB0_66
.LBB0_92:
	lw	a0, %lo(strinbuf)(s9)
	lbu	a2, %lo(WDB)(s8)
	lw	a1, %lo(qrframe)(s5)
	mul	a2, s2, a2
	call	memcpy@plt
	li	s6, 0
	li	s3, 0
	lui	a0, 7
	addi	s7, a0, 1328
	li	s9, 1
	lui	s2, %hi(rlens)
.LBB0_93:
	andi	a0, s6, 255
	sw	a0, 8(sp)
	call	applymask
	lbu	t1, %lo(WD)(s11)
	li	a0, 2
	bltu	t1, a0, .LBB0_106
	lw	t4, %lo(qrframe)(s5)
	lbu	a7, %lo(WDB)(s8)
	li	t0, 0
	li	s4, 0
	addi	a6, t1, -1
.LBB0_95:
	mul	t3, t0, a7
	addi	t0, t0, 1
	mul	t2, t0, a7
	li	a4, 1
.LBB0_96:
	neg	a2, a4
	not	s0, a4
	addi	a0, a4, -1
	srli	a0, a0, 3
	add	a3, a0, t3
	add	a3, a3, t4
	lbu	a5, 0(a3)
	andi	a2, a2, 7
	sll	s1, s9, a2
	srli	a3, a4, 3
	add	a2, a3, t3
	add	a2, a2, t4
	lbu	a1, 0(a2)
	and	a5, a5, s1
	andi	a2, s0, 7
	sll	a2, s9, a2
	and	s0, a2, a1
	beqz	a5, .LBB0_101
	beqz	s0, .LBB0_104
	add	a0, a0, t2
	add	a0, a0, t4
	lbu	a0, 0(a0)
	and	a0, a0, s1
	beqz	a0, .LBB0_104
	add	a0, a3, t2
	add	a0, a0, t4
	lbu	a0, 0(a0)
	and	a0, a0, a2
	beqz	a0, .LBB0_104
.LBB0_100:
	addi	s4, s4, 3
	j	.LBB0_104
.LBB0_101:
	bnez	s0, .LBB0_104
	add	a0, a0, t2
	add	a0, a0, t4
	lbu	a0, 0(a0)
	and	a0, a0, s1
	bnez	a0, .LBB0_104
	add	a0, a3, t2
	add	a0, a0, t4
	lbu	a0, 0(a0)
	and	a0, a0, a2
	beqz	a0, .LBB0_100
.LBB0_104:
	addi	a4, a4, 1
	bne	t1, a4, .LBB0_96
	bne	t0, a6, .LBB0_95
	j	.LBB0_107
.LBB0_106:
	li	s4, 0
.LBB0_107:
	sw	s3, 4(sp)
	beqz	t1, .LBB0_119
	li	s10, 0
	li	s0, 0
.LBB0_109:
	lw	a0, %lo(rlens)(s2)
	sb	zero, 0(a0)
	lbu	a0, %lo(WD)(s11)
	beqz	a0, .LBB0_117
	li	a2, 0
	li	a0, 0
	li	a1, 0
.LBB0_111:
	lbu	a3, %lo(WDB)(s8)
	lw	a4, %lo(qrframe)(s5)
	slli	a5, a1, 24
	srli	a5, a5, 27
	mul	a3, s10, a3
	add	a3, a3, a5
	add	a3, a3, a4
	lbu	a3, 0(a3)
	not	a4, a1
	andi	a4, a4, 7
	srl	a4, a3, a4
	lw	a3, %lo(rlens)(s2)
	andi	a5, a2, 255
	andi	a2, a4, 1
	bne	a2, a5, .LBB0_113
	andi	a4, a0, 255
	add	a3, a3, a4
	lb	a4, 0(a3)
	addi	a4, a4, 1
	sb	a4, 0(a3)
	j	.LBB0_114
.LBB0_113:
	addi	a0, a0, 1
	andi	a4, a0, 255
	add	a3, a3, a4
	sb	s9, 0(a3)
.LBB0_114:
	li	a3, -1
	beqz	a2, .LBB0_116
	li	a3, 1
.LBB0_116:
	lbu	s3, %lo(WD)(s11)
	addi	a1, a1, 1
	andi	a4, a1, 255
	add	s0, s0, a3
	bltu	a4, s3, .LBB0_111
	j	.LBB0_118
.LBB0_117:
	li	s3, 0
.LBB0_118:
	andi	a0, a0, 255
	call	badruns
	addi	s10, s10, 1
	add	s4, s4, a0
	bltu	s10, s3, .LBB0_109
	j	.LBB0_120
.LBB0_119:
	li	s3, 0
	li	s0, 0
.LBB0_120:
	srai	a0, s0, 31
	xor	a1, s0, a0
	sub	a0, a1, a0
	li	a1, 10
	mul	a0, a0, a1
	li	a2, 0
	mul	a1, s3, s3
	bgeu	a1, a0, .LBB0_122
.LBB0_121:
	sub	a0, a0, a1
	addi	a2, a2, 10
	bltu	a1, a0, .LBB0_121
.LBB0_122:
	add	s10, a2, s4
	beqz	s3, .LBB0_132
	li	s3, 0
.LBB0_124:
	lw	a0, %lo(rlens)(s2)
	sb	zero, 0(a0)
	lbu	a0, %lo(WD)(s11)
	beqz	a0, .LBB0_130
	li	a1, 0
	li	a4, 0
	li	a0, 0
	slli	a2, s3, 24
	srli	a2, a2, 27
	not	a3, s3
	andi	a3, a3, 7
.LBB0_126:
	lbu	a5, %lo(WDB)(s8)
	lw	s1, %lo(qrframe)(s5)
	mul	a5, a1, a5
	add	a5, a5, a2
	add	a5, a5, s1
	lbu	a5, 0(a5)
	srl	s1, a5, a3
	lw	a5, %lo(rlens)(s2)
	andi	s0, a4, 255
	andi	a4, s1, 1
	bne	a4, s0, .LBB0_128
	andi	s1, a0, 255
	add	a5, a5, s1
	lb	s1, 0(a5)
	addi	s1, s1, 1
	sb	s1, 0(a5)
	j	.LBB0_129
.LBB0_128:
	addi	a0, a0, 1
	andi	s1, a0, 255
	add	a5, a5, s1
	sb	s9, 0(a5)
.LBB0_129:
	lbu	s0, %lo(WD)(s11)
	addi	a1, a1, 1
	bltu	a1, s0, .LBB0_126
	j	.LBB0_131
.LBB0_130:
	li	s0, 0
.LBB0_131:
	andi	a0, a0, 255
	call	badruns
	addi	s3, s3, 1
	andi	a1, s3, 255
	add	s10, s10, a0
	bltu	a1, s0, .LBB0_124
	j	.LBB0_133
.LBB0_132:
	li	s0, 0
.LBB0_133:
	mv	s3, s6
	bltu	s10, s7, .LBB0_135
	lw	s3, 4(sp)
.LBB0_135:
	andi	s4, s3, 255
	li	a0, 7
	beq	s4, a0, .LBB0_140
	bltu	s10, s7, .LBB0_138
	mv	s10, s7
.LBB0_138:
	lw	a0, %lo(qrframe)(s5)
	lbu	a2, %lo(WDB)(s8)
	lui	a1, %hi(strinbuf)
	lw	a1, %lo(strinbuf)(a1)
	mul	a2, a2, s0
	call	memcpy@plt
	addi	s6, s6, 1
	mv	s7, s10
	li	a0, 7
	lw	a1, 8(sp)
	bltu	a1, a0, .LBB0_93
	li	s6, 8
.LBB0_140:
	andi	a0, s6, 255
	beq	s4, a0, .LBB0_142
	mv	a0, s4
	call	applymask
.LBB0_142:
	lui	a0, %hi(ECCLEVEL)
	lb	a0, %lo(ECCLEVEL)(a0)
	li	a1, 0
	addi	a0, a0, -1
	andi	a0, a0, 255
	slli	a0, a0, 3
	add	a0, a0, s4
	slli	a0, a0, 2
	lui	a2, %hi(fmtword)
	addi	a2, a2, %lo(fmtword)
	add	a0, a0, a2
	lw	a0, 0(a0)
	li	a2, -1
	li	t0, 8
	lui	a6, %hi(WD)
	li	a7, 128
	lui	t1, %hi(qrframe)
	lui	s0, %hi(WDB)
.LBB0_143:
	andi	a4, a0, 1
	beqz	a4, .LBB0_145
	lbu	a4, %lo(WD)(a6)
	lbu	a5, %lo(WDB)(s0)
	add	a4, a4, a2
	lw	a3, %lo(qrframe)(t1)
	srai	s1, a4, 3
	slli	a5, a5, 3
	add	a5, a5, s1
	add	a3, a3, a5
	lb	a5, 0(a3)
	andi	a4, a4, 7
	srl	a4, a7, a4
	or	a4, a4, a5
	sb	a4, 0(a3)
	sltiu	a3, a1, 6
	lbu	a4, %lo(WDB)(s0)
	lw	a5, %lo(qrframe)(t1)
	xori	a3, a3, 1
	add	a3, a3, a1
	mul	a3, a3, a4
	add	a3, a3, a5
	lb	a4, 1(a3)
	ori	a4, a4, 128
	sb	a4, 1(a3)
.LBB0_145:
	addi	a1, a1, 1
	srli	a0, a0, 1
	addi	a2, a2, -1
	bne	a1, t0, .LBB0_143
	li	t0, -7
	lui	a2, %hi(qrframe)
	lui	a3, %hi(WD)
	lui	a4, %hi(WDB)
	li	a6, 6
	li	a7, 128
	li	s0, -7
.LBB0_147:
	andi	a5, a0, 1
	beqz	a5, .LBB0_151
	lbu	a5, %lo(WD)(a3)
	lbu	s1, %lo(WDB)(a4)
	lw	a1, %lo(qrframe)(a2)
	add	a5, a5, s0
	mul	a5, a5, s1
	add	a1, a1, a5
	lb	a5, 1(a1)
	ori	a5, a5, 128
	sb	a5, 1(a1)
	li	a5, 1
	beq	s0, t0, .LBB0_150
	addi	a1, s0, 7
	sub	a1, a6, a1
	srl	a5, a7, a1
.LBB0_150:
	lbu	a1, %lo(WDB)(a4)
	lw	s1, %lo(qrframe)(a2)
	slli	a1, a1, 3
	add	a1, a1, s1
	lb	s1, 0(a1)
	or	a5, a5, s1
	sb	a5, 0(a1)
.LBB0_151:
	addi	s0, s0, 1
	srli	a0, a0, 1
	bnez	s0, .LBB0_147
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
.Lfunc_end0:
	.size	qrencode, .Lfunc_end0-qrencode

	.p2align	1
	.type	applymask,@function
applymask:
	li	a1, 7
	bltu	a1, a0, .LBB1_140
	slli	a0, a0, 2
	lui	a1, %hi(.LJTI1_0)
	addi	a1, a1, %lo(.LJTI1_0)
	add	a0, a0, a1
	lw	a0, 0(a0)
	jr	a0
.LBB1_2:
	lui	a6, %hi(WD)
	lbu	a0, %lo(WD)(a6)
	beqz	a0, .LBB1_140
	li	a1, 0
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_4:
	andi	a2, a0, 255
	beqz	a2, .LBB1_14
	li	a3, 0
.LBB1_6:
	add	a2, a1, a3
	andi	a2, a2, 1
	bnez	a2, .LBB1_13
	andi	a5, a1, 255
	andi	a4, a3, 255
	mv	a2, a4
	bltu	a4, a5, .LBB1_9
	mv	a2, a5
.LBB1_9:
	bltu	a5, a4, .LBB1_11
	mv	a4, a5
.LBB1_11:
	mul	a5, a4, a4
	add	a4, a4, a5
	lw	a5, %lo(framask)(t2)
	srli	a4, a4, 1
	add	a2, a2, a4
	srli	a4, a2, 3
	add	a4, a4, a5
	lbu	a4, 0(a4)
	not	a2, a2
	andi	a2, a2, 7
	srl	a2, a4, a2
	andi	a2, a2, 1
	bnez	a2, .LBB1_13
	lbu	a0, %lo(WDB)(t1)
	lw	a2, %lo(qrframe)(t0)
	srli	a4, a3, 3
	mul	a0, a1, a0
	add	a0, a0, a4
	add	a0, a0, a2
	lb	a2, 0(a0)
	andi	a4, a3, 7
	srl	a4, a7, a4
	xor	a2, a2, a4
	sb	a2, 0(a0)
	lbu	a0, %lo(WD)(a6)
.LBB1_13:
	addi	a3, a3, 1
	andi	a2, a0, 255
	bltu	a3, a2, .LBB1_6
	j	.LBB1_15
.LBB1_14:
	li	a0, 0
.LBB1_15:
	addi	a1, a1, 1
	andi	a2, a0, 255
	bltu	a1, a2, .LBB1_4
	j	.LBB1_140
.LBB1_16:
	lui	a6, %hi(WD)
	lbu	a0, %lo(WD)(a6)
	beqz	a0, .LBB1_140
	li	t3, 0
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_18:
	andi	a1, a0, 255
	beqz	a1, .LBB1_28
	li	a3, 0
	andi	a4, t3, 1
.LBB1_20:
	bnez	a4, .LBB1_27
	andi	a2, t3, 255
	andi	a5, a3, 255
	mv	a1, a5
	bltu	a5, a2, .LBB1_23
	mv	a1, a2
.LBB1_23:
	bltu	a2, a5, .LBB1_25
	mv	a5, a2
.LBB1_25:
	mul	a2, a5, a5
	add	a2, a2, a5
	lw	a5, %lo(framask)(t2)
	srli	a2, a2, 1
	add	a1, a1, a2
	srli	a2, a1, 3
	add	a2, a2, a5
	lbu	a2, 0(a2)
	not	a1, a1
	andi	a1, a1, 7
	srl	a1, a2, a1
	andi	a1, a1, 1
	bnez	a1, .LBB1_27
	lbu	a0, %lo(WDB)(t1)
	lw	a1, %lo(qrframe)(t0)
	slli	a2, a3, 24
	srli	a2, a2, 27
	mul	a0, t3, a0
	add	a0, a0, a2
	add	a0, a0, a1
	lb	a1, 0(a0)
	andi	a2, a3, 7
	srl	a2, a7, a2
	xor	a1, a1, a2
	sb	a1, 0(a0)
	lbu	a0, %lo(WD)(a6)
.LBB1_27:
	addi	a3, a3, 1
	andi	a1, a3, 255
	andi	a2, a0, 255
	bltu	a1, a2, .LBB1_20
	j	.LBB1_29
.LBB1_28:
	li	a0, 0
.LBB1_29:
	addi	t3, t3, 1
	andi	a1, a0, 255
	bltu	t3, a1, .LBB1_18
	j	.LBB1_140
.LBB1_30:
	lui	a6, %hi(WD)
	lbu	a4, %lo(WD)(a6)
	beqz	a4, .LBB1_140
	li	t4, 0
	li	t3, 3
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_32:
	andi	a0, a4, 255
	beqz	a0, .LBB1_44
	li	a0, 0
	li	a5, 0
.LBB1_34:
	andi	a1, a0, 255
	li	a3, 0
	beq	a1, t3, .LBB1_36
	mv	a3, a0
.LBB1_36:
	andi	a0, a3, 255
	bnez	a0, .LBB1_43
	andi	a2, t4, 255
	andi	a0, a5, 255
	mv	a1, a0
	bltu	a0, a2, .LBB1_39
	mv	a1, a2
.LBB1_39:
	bltu	a2, a0, .LBB1_41
	mv	a0, a2
.LBB1_41:
	mul	a2, a0, a0
	add	a0, a0, a2
	lw	a2, %lo(framask)(t2)
	srli	a0, a0, 1
	add	a0, a0, a1
	srli	a1, a0, 3
	add	a1, a1, a2
	lbu	a1, 0(a1)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a1, a0
	andi	a0, a0, 1
	bnez	a0, .LBB1_43
	lbu	a0, %lo(WDB)(t1)
	lw	a1, %lo(qrframe)(t0)
	slli	a2, a5, 24
	srli	a2, a2, 27
	mul	a0, t4, a0
	add	a0, a0, a2
	add	a0, a0, a1
	lb	a1, 0(a0)
	andi	a2, a5, 7
	srl	a2, a7, a2
	xor	a1, a1, a2
	sb	a1, 0(a0)
	lbu	a4, %lo(WD)(a6)
.LBB1_43:
	addi	a5, a5, 1
	andi	a1, a5, 255
	andi	a2, a4, 255
	addi	a0, a3, 1
	bltu	a1, a2, .LBB1_34
	j	.LBB1_45
.LBB1_44:
	li	a4, 0
.LBB1_45:
	addi	t4, t4, 1
	andi	a0, a4, 255
	bltu	t4, a0, .LBB1_32
	j	.LBB1_140
.LBB1_46:
	lui	a6, %hi(WD)
	lbu	a5, %lo(WD)(a6)
	beqz	a5, .LBB1_140
	li	t5, 0
	li	a0, 0
	li	t4, 3
	lui	t3, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_48:
	andi	a1, a0, 255
	li	t2, 0
	beq	a1, t4, .LBB1_50
	mv	t2, a0
.LBB1_50:
	andi	a0, a5, 255
	beqz	a0, .LBB1_62
	li	a4, 0
	mv	a0, t2
.LBB1_52:
	andi	a1, a0, 255
	li	a3, 0
	beq	a1, t4, .LBB1_54
	mv	a3, a0
.LBB1_54:
	andi	a0, a3, 255
	bnez	a0, .LBB1_61
	andi	a2, t5, 255
	andi	a0, a4, 255
	mv	a1, a0
	bltu	a0, a2, .LBB1_57
	mv	a1, a2
.LBB1_57:
	bltu	a2, a0, .LBB1_59
	mv	a0, a2
.LBB1_59:
	mul	a2, a0, a0
	add	a0, a0, a2
	lw	a2, %lo(framask)(t3)
	srli	a0, a0, 1
	add	a0, a0, a1
	srli	a1, a0, 3
	add	a1, a1, a2
	lbu	a1, 0(a1)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a1, a0
	andi	a0, a0, 1
	bnez	a0, .LBB1_61
	lbu	a0, %lo(WDB)(t1)
	lw	a1, %lo(qrframe)(t0)
	slli	a2, a4, 24
	srli	a2, a2, 27
	mul	a0, t5, a0
	add	a0, a0, a2
	add	a0, a0, a1
	lb	a1, 0(a0)
	andi	a2, a4, 7
	srl	a2, a7, a2
	xor	a1, a1, a2
	sb	a1, 0(a0)
	lbu	a5, %lo(WD)(a6)
.LBB1_61:
	addi	a4, a4, 1
	andi	a1, a4, 255
	andi	a2, a5, 255
	addi	a0, a3, 1
	bltu	a1, a2, .LBB1_52
	j	.LBB1_63
.LBB1_62:
	li	a5, 0
.LBB1_63:
	addi	t5, t5, 1
	andi	a1, a5, 255
	addi	a0, t2, 1
	bltu	t5, a1, .LBB1_48
	j	.LBB1_140
.LBB1_64:
	lui	a6, %hi(WD)
	lbu	t5, %lo(WD)(a6)
	beqz	t5, .LBB1_140
	li	t3, 0
	li	t4, 3
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_66:
	andi	a0, t5, 255
	beqz	a0, .LBB1_80
	li	a3, 0
	li	a5, 0
	slli	a0, t3, 30
	srli	t6, a0, 31
.LBB1_68:
	andi	a1, a3, 255
	bne	a1, t4, .LBB1_70
	andi	a0, t6, 255
	seqz	t6, a0
.LBB1_70:
	andi	a0, t6, 255
	bnez	a0, .LBB1_77
	andi	a4, t3, 255
	andi	a2, a5, 255
	mv	a0, a2
	bltu	a2, a4, .LBB1_73
	mv	a0, a4
.LBB1_73:
	bltu	a4, a2, .LBB1_75
	mv	a2, a4
.LBB1_75:
	mul	a4, a2, a2
	add	a2, a2, a4
	lw	a4, %lo(framask)(t2)
	srli	a2, a2, 1
	add	a0, a0, a2
	srli	a2, a0, 3
	add	a2, a2, a4
	lbu	a2, 0(a2)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a2, a0
	andi	a0, a0, 1
	bnez	a0, .LBB1_77
	lbu	a0, %lo(WDB)(t1)
	lw	a2, %lo(qrframe)(t0)
	slli	a4, a5, 24
	srli	a4, a4, 27
	mul	a0, t3, a0
	add	a0, a0, a4
	add	a0, a0, a2
	lb	a2, 0(a0)
	andi	a4, a5, 7
	srl	a4, a7, a4
	xor	a2, a2, a4
	sb	a2, 0(a0)
	lbu	t5, %lo(WD)(a6)
.LBB1_77:
	li	a2, 1
	beq	a1, t4, .LBB1_79
	addi	a2, a3, 1
.LBB1_79:
	addi	a5, a5, 1
	andi	a0, a5, 255
	andi	a1, t5, 255
	mv	a3, a2
	bltu	a0, a1, .LBB1_68
	j	.LBB1_81
.LBB1_80:
	li	t5, 0
.LBB1_81:
	addi	t3, t3, 1
	andi	a0, t5, 255
	bltu	t3, a0, .LBB1_66
	j	.LBB1_140
.LBB1_82:
	lui	a6, %hi(WD)
	lbu	t6, %lo(WD)(a6)
	beqz	t6, .LBB1_140
	li	t4, 0
	li	a1, 0
	li	t3, 3
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_84:
	andi	a0, a1, 255
	li	t5, 0
	beq	a0, t3, .LBB1_86
	mv	t5, a1
.LBB1_86:
	andi	a0, t6, 255
	beqz	a0, .LBB1_98
	li	a5, 0
	li	a2, 0
	andi	a4, t4, 1
.LBB1_88:
	andi	a0, a2, 255
	li	a1, 0
	beq	a0, t3, .LBB1_90
	mv	a1, a2
.LBB1_90:
	andi	a0, t5, 255
	snez	a0, a0
	andi	a2, a1, 255
	and	a3, a4, a5
	snez	a2, a2
	and	a0, a0, a2
	neg	a0, a0
	bne	a3, a0, .LBB1_97
	andi	a0, t4, 255
	andi	a2, a5, 255
	mv	a3, a2
	bltu	a2, a0, .LBB1_93
	mv	a3, a0
.LBB1_93:
	bltu	a0, a2, .LBB1_95
	mv	a2, a0
.LBB1_95:
	mul	a0, a2, a2
	add	a0, a0, a2
	lw	a2, %lo(framask)(t2)
	srli	a0, a0, 1
	add	a0, a0, a3
	srli	a3, a0, 3
	add	a2, a2, a3
	lbu	a2, 0(a2)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a2, a0
	andi	a0, a0, 1
	bnez	a0, .LBB1_97
	lbu	a0, %lo(WDB)(t1)
	lw	a2, %lo(qrframe)(t0)
	srli	a3, a5, 3
	mul	a0, t4, a0
	add	a0, a0, a3
	add	a0, a0, a2
	lb	a2, 0(a0)
	andi	a3, a5, 7
	srl	a3, a7, a3
	xor	a2, a2, a3
	sb	a2, 0(a0)
	lbu	t6, %lo(WD)(a6)
.LBB1_97:
	addi	a5, a5, 1
	andi	a0, t6, 255
	addi	a2, a1, 1
	bltu	a5, a0, .LBB1_88
	j	.LBB1_99
.LBB1_98:
	li	t6, 0
.LBB1_99:
	addi	t4, t4, 1
	andi	a0, t6, 255
	addi	a1, t5, 1
	bltu	t4, a0, .LBB1_84
	j	.LBB1_140
.LBB1_100:
	lui	a6, %hi(WD)
	lbu	t6, %lo(WD)(a6)
	beqz	t6, .LBB1_140
	li	t5, 0
	li	a0, 0
	li	t3, 3
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_102:
	andi	a1, a0, 255
	li	t4, 0
	beq	a1, t3, .LBB1_104
	mv	t4, a0
.LBB1_104:
	andi	a0, t6, 255
	beqz	a0, .LBB1_118
	li	a5, 0
	li	a2, 0
	andi	a4, t5, 1
.LBB1_106:
	andi	a1, a2, 255
	li	a0, 0
	beq	a1, t3, .LBB1_108
	mv	a0, a2
.LBB1_108:
	andi	a1, a0, 255
	and	a2, a4, a5
	beqz	a1, .LBB1_110
	andi	a3, t4, 255
	xor	a1, a1, a3
	seqz	a1, a1
	xor	a2, a2, a1
.LBB1_110:
	bnez	a2, .LBB1_117
	andi	a1, t5, 255
	andi	a2, a5, 255
	mv	a3, a2
	bltu	a2, a1, .LBB1_113
	mv	a3, a1
.LBB1_113:
	bltu	a1, a2, .LBB1_115
	mv	a2, a1
.LBB1_115:
	mul	a1, a2, a2
	add	a1, a1, a2
	lw	a2, %lo(framask)(t2)
	srli	a1, a1, 1
	add	a1, a1, a3
	srli	a3, a1, 3
	add	a2, a2, a3
	lbu	a2, 0(a2)
	not	a1, a1
	andi	a1, a1, 7
	srl	a1, a2, a1
	andi	a1, a1, 1
	bnez	a1, .LBB1_117
	lbu	a1, %lo(WDB)(t1)
	lw	a2, %lo(qrframe)(t0)
	srli	a3, a5, 3
	mul	a1, t5, a1
	add	a1, a1, a3
	add	a1, a1, a2
	lb	a2, 0(a1)
	andi	a3, a5, 7
	srl	a3, a7, a3
	xor	a2, a2, a3
	sb	a2, 0(a1)
	lbu	t6, %lo(WD)(a6)
.LBB1_117:
	addi	a5, a5, 1
	andi	a1, t6, 255
	addi	a2, a0, 1
	bltu	a5, a1, .LBB1_106
	j	.LBB1_119
.LBB1_118:
	li	t6, 0
.LBB1_119:
	addi	t5, t5, 1
	andi	a1, t6, 255
	addi	a0, t4, 1
	bltu	t5, a1, .LBB1_102
	j	.LBB1_140
.LBB1_120:
	lui	a6, %hi(WD)
	lbu	t5, %lo(WD)(a6)
	beqz	t5, .LBB1_140
	li	a1, 0
	li	a3, 0
	li	t3, 3
	lui	t2, %hi(framask)
	li	a7, 128
	lui	t0, %hi(qrframe)
	lui	t1, %hi(WDB)
.LBB1_122:
	andi	a0, a3, 255
	li	t4, 0
	beq	a0, t3, .LBB1_124
	mv	t4, a3
.LBB1_124:
	andi	a0, t5, 255
	beqz	a0, .LBB1_138
	li	a5, 0
	li	a4, 0
.LBB1_126:
	andi	a0, a4, 255
	li	a3, 0
	beq	a0, t3, .LBB1_128
	mv	a3, a4
.LBB1_128:
	andi	a0, a3, 255
	add	a4, a1, a5
	beqz	a0, .LBB1_130
	andi	a2, t4, 255
	xor	a0, a0, a2
	seqz	a0, a0
	xor	a4, a4, a0
.LBB1_130:
	andi	a0, a4, 1
	bnez	a0, .LBB1_137
	andi	a0, a1, 255
	andi	a4, a5, 255
	mv	a2, a4
	bltu	a4, a0, .LBB1_133
	mv	a2, a0
.LBB1_133:
	bltu	a0, a4, .LBB1_135
	mv	a4, a0
.LBB1_135:
	mul	a0, a4, a4
	add	a0, a0, a4
	lw	a4, %lo(framask)(t2)
	srli	a0, a0, 1
	add	a0, a0, a2
	srli	a2, a0, 3
	add	a2, a2, a4
	lbu	a2, 0(a2)
	not	a0, a0
	andi	a0, a0, 7
	srl	a0, a2, a0
	andi	a0, a0, 1
	bnez	a0, .LBB1_137
	lbu	a0, %lo(WDB)(t1)
	lw	a2, %lo(qrframe)(t0)
	srli	a4, a5, 3
	mul	a0, a1, a0
	add	a0, a0, a4
	add	a0, a0, a2
	lb	a2, 0(a0)
	andi	a4, a5, 7
	srl	a4, a7, a4
	xor	a2, a2, a4
	sb	a2, 0(a0)
	lbu	t5, %lo(WD)(a6)
.LBB1_137:
	addi	a5, a5, 1
	andi	a0, t5, 255
	addi	a4, a3, 1
	bltu	a5, a0, .LBB1_126
	j	.LBB1_139
.LBB1_138:
	li	t5, 0
.LBB1_139:
	addi	a1, a1, 1
	andi	a0, t5, 255
	addi	a3, t4, 1
	bltu	a1, a0, .LBB1_122
.LBB1_140:
	ret
.Lfunc_end1:
	.size	applymask, .Lfunc_end1-applymask
	.section	.rodata,"a",@progbits
	.p2align	2
.LJTI1_0:
	.word	.LBB1_2
	.word	.LBB1_16
	.word	.LBB1_30
	.word	.LBB1_46
	.word	.LBB1_64
	.word	.LBB1_82
	.word	.LBB1_100
	.word	.LBB1_120

	.text
	.p2align	1
	.type	appendrs,@function
appendrs:
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
	mv	s2, a4
	mv	s1, a3
	mv	s11, a2
	mv	s3, a1
	mv	s4, a0
	mv	a0, a2
	li	a1, 0
	mv	a2, a3
	call	memset@plt
	beqz	s3, .LBB2_15
	li	s7, 0
	addi	s5, s11, 1
	addi	s6, s1, -1
	add	s8, s11, s6
	lui	a0, %hi(g0log)
	addi	s9, a0, %lo(g0log)
	li	s0, 255
	lui	a0, %hi(g0exp)
	addi	s10, a0, %lo(g0exp)
.LBB2_2:
	add	a0, s4, s7
	lbu	a0, 0(a0)
	lbu	a1, 0(s11)
	beq	a1, a0, .LBB2_13
	xor	a0, a0, a1
	add	a0, a0, s9
	lbu	a0, 0(a0)
	li	a1, 2
	bltu	s1, a1, .LBB2_9
	li	a1, 1
.LBB2_5:
	sub	a2, s1, a1
	add	a2, a2, s2
	lbu	a2, 0(a2)
	add	a2, a2, a0
	bltu	a2, s0, .LBB2_8
	addi	a2, a2, 1
	andi	a3, a2, 255
.LBB2_7:
	mv	a2, a3
	li	a3, 0
	beq	a2, s0, .LBB2_7
.LBB2_8:
	add	a3, s11, a1
	lbu	a4, 0(a3)
	add	a2, a2, s10
	lb	a2, 0(a2)
	xor	a2, a2, a4
	addi	a1, a1, 1
	sb	a2, -1(a3)
	bne	a1, s1, .LBB2_5
.LBB2_9:
	lbu	a1, 0(s2)
	add	a0, a0, a1
	bltu	a0, s0, .LBB2_12
	addi	a0, a0, 1
	andi	a1, a0, 255
.LBB2_11:
	mv	a0, a1
	li	a1, 0
	beq	a0, s0, .LBB2_11
.LBB2_12:
	add	a0, a0, s10
	lbu	a0, 0(a0)
	j	.LBB2_14
.LBB2_13:
	mv	a0, s11
	mv	a1, s5
	mv	a2, s6
	call	memmove@plt
	li	a0, 0
.LBB2_14:
	addi	s7, s7, 1
	sb	a0, 0(s8)
	bne	s7, s3, .LBB2_2
.LBB2_15:
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
.Lfunc_end2:
	.size	appendrs, .Lfunc_end2-appendrs

	.p2align	1
	.type	badruns,@function
badruns:
	lui	a1, %hi(rlens)
	lw	t0, %lo(rlens)(a1)
	li	t1, 0
	addi	a1, a0, 1
	andi	a3, a1, 255
	li	a4, 4
	mv	a5, t0
.LBB3_1:
	lbu	a1, 0(a5)
	bgeu	a4, a1, .LBB3_3
	add	a1, a1, t1
	addi	t1, a1, -2
.LBB3_3:
	addi	a3, a3, -1
	addi	a5, a5, 1
	bnez	a3, .LBB3_1
	li	a1, 5
	bltu	a0, a1, .LBB3_16
	addi	a7, a0, -1
	li	a4, 3
	li	a6, 12
.LBB3_6:
	add	a2, a4, t0
	lbu	a1, -2(a2)
	addi	a5, a4, 2
	add	a3, t0, a5
	lbu	a3, 0(a3)
	bne	a1, a3, .LBB3_15
	lbu	t2, -1(a2)
	bne	a1, t2, .LBB3_15
	lbu	a3, 1(a2)
	bne	a1, a3, .LBB3_15
	lbu	a1, 0(a2)
	slli	a3, t2, 1
	add	a3, a3, t2
	bne	a3, a1, .LBB3_15
	lbu	a1, -3(a2)
	beqz	a1, .LBB3_14
	addi	a2, a4, 3
	bltu	a0, a2, .LBB3_14
	slli	a3, a1, 1
	add	a3, a3, a1
	mul	a1, t2, a6
	bgeu	a3, a1, .LBB3_14
	add	a2, a2, t0
	lbu	a2, 0(a2)
	slli	a3, a2, 1
	add	a2, a2, a3
	bltu	a2, a1, .LBB3_15
.LBB3_14:
	addi	t1, t1, 40
.LBB3_15:
	andi	a4, a5, 255
	blt	a4, a7, .LBB3_6
.LBB3_16:
	mv	a0, t1
	ret
.Lfunc_end3:
	.size	badruns, .Lfunc_end3-badruns

	.type	g0exp,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
g0exp:
	.asciz	"\001\002\004\b\020 @\200\035:t\350\315\207\023&L\230-Z\264u\352\311\217\003\006\f\0300`\300\235'N\234%J\2245j\324\265w\356\301\237#F\214\005\n\024(P\240]\272i\322\271o\336\241_\276a\302\231/^\274e\312\211\017\036<x\360\375\347\323\273k\326\261\177\376\341\337\243[\266q\342\331\257C\206\021\"D\210\r\0324h\320\275g\316\201\037>|\370\355\307\223;v\354\305\2273f\314\205\027.\\\270m\332\251O\236!B\204\025*T\250M\232)R\244U\252I\2229r\344\325\267s\346\321\277c\306\221?~\374\345\327\263{\366\361\377\343\333\253K\2261b\304\2257n\334\245W\256A\202\0312d\310\215\007\016\0348p\340\335\247S\246Q\242Y\262y\362\371\357\303\233+V\254E\212\t\022$H\220=z\364\365\367\363\373\353\313\213\013\026,X\260}\372\351\317\203\0336l\330\255G\216"
	.size	g0exp, 256

	.type	g0log,@object
	.section	.rodata,"a",@progbits
g0log:
	.ascii	"\377\000\001\031\0022\032\306\003\3373\356\033h\307K\004d\340\0164\215\357\201\034\301i\370\310\bLq\005\212e/\341$\017!5\223\216\332\360\022\202E\035\265\302}j'\371\271\311\232\txM\344r\246\006\277\213bf\3350\375\342\230%\263\020\221\"\2106\320\224\316\217\226\333\275\361\322\023\\\2038F@\036B\266\243\303H~nk:(T\372\205\272=\312^\233\237\n\025y+N\324\345\254s\363\247W\007p\300\367\214\200c\rgJ\336\3551\305\376\030\343\245\231w&\270\264|\021D\222\331# \211.7?\321[\225\274\317\315\220\207\227\262\334\374\276a\362V\323\253\024*]\236\204<9SGmA\242\037-C\330\267{\244v\304\027I\354\177\fo\366l\241;R)\235U\252\373`\206\261\273\314>Z\313Y_\260\234\251\240Q\013\365\026\353zu,\327O\256\325\351\346\347\255\350t\326\364\352\250PX\257"
	.size	g0log, 256

	.type	fmtword,@object
	.p2align	2
fmtword:
	.word	30660
	.word	29427
	.word	32170
	.word	30877
	.word	26159
	.word	25368
	.word	27713
	.word	26998
	.word	21522
	.word	20773
	.word	24188
	.word	23371
	.word	17913
	.word	16590
	.word	20375
	.word	19104
	.word	13663
	.word	12392
	.word	16177
	.word	14854
	.word	9396
	.word	8579
	.word	11994
	.word	11245
	.word	5769
	.word	5054
	.word	7399
	.word	6608
	.word	1890
	.word	597
	.word	3340
	.word	2107
	.size	fmtword, 128

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
