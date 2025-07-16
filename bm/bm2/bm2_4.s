	.text
	.attribute	4, 16
	.attribute  5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	//.attribute	5, "rv32i2p0_m2p0_c2p0"
	.file	"pbmsrch_large.c"
	.globl	init_search
	.p2align	1
	.type	init_search,@function
init_search:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	sw	s0, 8(sp)
	mv	s0, a0
	call	strlen
	li	a1, 0
	lui	a2, %hi(len)
	sw	a0, %lo(len)(a2)
	lui	a2, %hi(table)
	addi	a2, a2, %lo(table)
	li	a3, 1024
.LBB0_1:
	add	a4, a2, a1
	addi	a1, a1, 4
	sw	a0, 0(a4)
	bne	a1, a3, .LBB0_1
	beqz	a0, .LBB0_5
	addi	a0, a0, -1
	lui	a1, %hi(table)
	addi	a1, a1, %lo(table)
	li	a2, -1
	mv	a3, s0
.LBB0_4:
	lbu	a4, 0(a3)
	slli	a4, a4, 2
	add	a4, a4, a1
	sw	a0, 0(a4)
	addi	a0, a0, -1
	addi	a3, a3, 1
	bne	a0, a2, .LBB0_4
.LBB0_5:
	lui	a0, %hi(findme)
	sw	s0, %lo(findme)(a0)
	lw	ra, 12(sp)
	lw	s0, 8(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end0:
	.size	init_search, .Lfunc_end0-init_search

	.globl	strsearch
	.p2align	1
	.type	strsearch,@function
strsearch:
	addi	sp, sp, -48
	sw	ra, 44(sp)
	sw	s0, 40(sp)
	sw	s1, 36(sp)
	sw	s2, 32(sp)
	sw	s3, 28(sp)
	sw	s4, 24(sp)
	sw	s5, 20(sp)
	sw	s6, 16(sp)
	sw	s7, 12(sp)
	lui	a1, %hi(len)
	lw	s2, %lo(len)(a1)
	mv	s5, a0
	addi	s1, s2, -1
	call	strlen
	bgeu	s1, a0, .LBB1_9
	mv	s0, a0
	lui	a0, %hi(findme)
	lw	s3, %lo(findme)(a0)
	li	a0, 1
	sub	s6, a0, s2
	lui	a0, %hi(table)
	addi	s7, a0, %lo(table)
.LBB1_2:
	bgeu	s1, s0, .LBB1_5
.LBB1_3:
	add	a0, s5, s1
	lbu	a0, 0(a0)
	slli	a0, a0, 2
	add	a0, a0, s7
	lw	a0, 0(a0)
	beqz	a0, .LBB1_7
	add	s1, s1, a0
	bltu	s1, s0, .LBB1_3
	j	.LBB1_6
.LBB1_5:
	beqz	a0, .LBB1_7
.LBB1_6:
	bltu	s1, s0, .LBB1_2
	j	.LBB1_9
.LBB1_7:
	add	a0, s6, s1
	add	s4, s5, a0
	mv	a0, s3
	mv	a1, s4
	mv	a2, s2
	call	strncmp
	beqz	a0, .LBB1_10
	li	a0, 0
	addi	s1, s1, 1
	bltu	s1, s0, .LBB1_2
.LBB1_9:
	li	s4, 0
.LBB1_10:
	mv	a0, s4
	lw	ra, 44(sp)
	lw	s0, 40(sp)
	lw	s1, 36(sp)
	lw	s2, 32(sp)
	lw	s3, 28(sp)
	lw	s4, 24(sp)
	lw	s5, 20(sp)
	lw	s6, 16(sp)
	lw	s7, 12(sp)
	addi	sp, sp, 48
	ret
.Lfunc_end1:
	.size	strsearch, .Lfunc_end1-strsearch

	.globl	main
	.p2align	1
	.type	main,@function
main:
	addi	sp, sp, -48
	sw	ra, 44(sp)
	sw	s0, 40(sp)
	sw	s1, 36(sp)
	sw	s2, 32(sp)
	sw	s3, 28(sp)
	sw	s4, 24(sp)
	sw	s5, 20(sp)
	sw	s6, 16(sp)
	sw	s7, 12(sp)
	sw	s8, 8(sp)
	lui	a0, %hi(.L.str)
	addi	s1, a0, %lo(.L.str)
	lui	a0, %hi(.L__const.main.search_strings)
	addi	s5, a0, %lo(.L__const.main.search_strings)
	lui	a0, %hi(.L__const.main.find_strings+4)
	addi	s6, a0, %lo(.L__const.main.find_strings+4)
	lui	a0, %hi(.L.str.212)
	addi	s7, a0, %lo(.L.str.212)
	lui	a0, %hi(.L.str.213)
	addi	s8, a0, %lo(.L.str.213)
	lui	a0, %hi(.L.str.211)
	addi	s3, a0, %lo(.L.str.211)
	lui	a0, %hi(.L.str.214)
	addi	s2, a0, %lo(.L.str.214)
.LBB2_1:
	mv	a0, s1
	call	init_search
	lw	s4, 0(s5)
	mv	a0, s4
	call	strsearch
	mv	s0, a0
	mv	a2, s8
	beqz	a0, .LBB2_3
	mv	a2, s7
.LBB2_3:
	mv	a0, s3
	mv	a1, s1
	mv	a3, s4
	call	printf
	beqz	s0, .LBB2_5
	mv	a0, s2
	mv	a1, s0
	call	printf
.LBB2_5:
	li	a0, 10
	call	putchar
	lw	s1, 0(s6)
	addi	s5, s5, 4
	addi	s6, s6, 4
	bnez	s1, .LBB2_1
	li	a0, 0
	lw	ra, 44(sp)
	lw	s0, 40(sp)
	lw	s1, 36(sp)
	lw	s2, 32(sp)
	lw	s3, 28(sp)
	lw	s4, 24(sp)
	lw	s5, 20(sp)
	lw	s6, 16(sp)
	lw	s7, 12(sp)
	lw	s8, 8(sp)
	addi	sp, sp, 48
	ret
.Lfunc_end2:
	.size	main, .Lfunc_end2-main

	.type	len,@object
	.section	.sbss,"aw",@nobits
	.p2align	2
len:
	.word	0
	.size	len, 4

	.type	table,@object
	.local	table
	.comm	table,1024,4
	.type	findme,@object
	.p2align	2
findme:
	.word	0
	.size	findme, 4

	.type	.L.str,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"Kur"
	.size	.L.str, 4

	.type	.L.str.1,@object
.L.str.1:
	.asciz	"gent"
	.size	.L.str.1, 5

	.type	.L.str.2,@object
.L.str.2:
	.asciz	"lass"
	.size	.L.str.2, 5

	.type	.L.str.3,@object
.L.str.3:
	.asciz	"suns"
	.size	.L.str.3, 5

	.type	.L.str.4,@object
.L.str.4:
	.asciz	"for"
	.size	.L.str.4, 4

	.type	.L.str.5,@object
.L.str.5:
	.asciz	"xxx"
	.size	.L.str.5, 4

	.type	.L.str.6,@object
.L.str.6:
	.asciz	"long"
	.size	.L.str.6, 5

	.type	.L.str.7,@object
.L.str.7:
	.asciz	"have"
	.size	.L.str.7, 5

	.type	.L.str.8,@object
.L.str.8:
	.asciz	"where"
	.size	.L.str.8, 6

	.type	.L.str.9,@object
.L.str.9:
	.asciz	"xxxxxx"
	.size	.L.str.9, 7

	.type	.L.str.10,@object
.L.str.10:
	.asciz	"pense"
	.size	.L.str.10, 6

	.type	.L.str.11,@object
.L.str.11:
	.asciz	"pow"
	.size	.L.str.11, 4

	.type	.L.str.12,@object
.L.str.12:
	.asciz	"xxxxx"
	.size	.L.str.12, 6

	.type	.L.str.13,@object
.L.str.13:
	.asciz	"Yo"
	.size	.L.str.13, 3

	.type	.L.str.14,@object
.L.str.14:
	.asciz	"and"
	.size	.L.str.14, 4

	.type	.L.str.15,@object
.L.str.15:
	.asciz	"faded"
	.size	.L.str.15, 6

	.type	.L.str.16,@object
.L.str.16:
	.asciz	"20"
	.size	.L.str.16, 3

	.type	.L.str.17,@object
.L.str.17:
	.asciz	"you"
	.size	.L.str.17, 4

	.type	.L.str.18,@object
.L.str.18:
	.asciz	"bac"
	.size	.L.str.18, 4

	.type	.L.str.19,@object
.L.str.19:
	.asciz	"an"
	.size	.L.str.19, 3

	.type	.L.str.20,@object
.L.str.20:
	.asciz	"way"
	.size	.L.str.20, 4

	.type	.L.str.21,@object
.L.str.21:
	.asciz	"possibili"
	.size	.L.str.21, 10

	.type	.L.str.22,@object
.L.str.22:
	.asciz	"fat"
	.size	.L.str.22, 4

	.type	.L.str.23,@object
.L.str.23:
	.asciz	"imag"
	.size	.L.str.23, 5

	.type	.L.str.24,@object
.L.str.24:
	.asciz	"th"
	.size	.L.str.24, 3

	.type	.L.str.25,@object
.L.str.25:
	.asciz	"wor"
	.size	.L.str.25, 4

	.type	.L.str.26,@object
.L.str.26:
	.asciz	"yo"
	.size	.L.str.26, 3

	.type	.L.str.27,@object
.L.str.27:
	.asciz	"bxx"
	.size	.L.str.27, 4

	.type	.L.str.28,@object
.L.str.28:
	.asciz	"wo"
	.size	.L.str.28, 3

	.type	.L.str.29,@object
.L.str.29:
	.asciz	"kind"
	.size	.L.str.29, 5

	.type	.L.str.30,@object
.L.str.30:
	.asciz	"4"
	.size	.L.str.30, 2

	.type	.L.str.31,@object
.L.str.31:
	.asciz	"idle"
	.size	.L.str.31, 5

	.type	.L.str.32,@object
.L.str.32:
	.asciz	"Do"
	.size	.L.str.32, 3

	.type	.L.str.33,@object
.L.str.33:
	.asciz	"scare"
	.size	.L.str.33, 6

	.type	.L.str.34,@object
.L.str.34:
	.asciz	"people"
	.size	.L.str.34, 7

	.type	.L.str.35,@object
.L.str.35:
	.asciz	"wit"
	.size	.L.str.35, 4

	.type	.L.str.36,@object
.L.str.36:
	.asciz	"Th"
	.size	.L.str.36, 3

	.type	.L.str.37,@object
.L.str.37:
	.asciz	"yourself"
	.size	.L.str.37, 9

	.type	.L.str.38,@object
.L.str.38:
	.asciz	"Forget"
	.size	.L.str.38, 7

	.type	.L.str.39,@object
.L.str.39:
	.asciz	"succeed"
	.size	.L.str.39, 8

	.type	.L.str.40,@object
.L.str.40:
	.asciz	"Kee"
	.size	.L.str.40, 4

	.type	.L.str.41,@object
.L.str.41:
	.asciz	"lov"
	.size	.L.str.41, 4

	.type	.L.str.42,@object
.L.str.42:
	.asciz	"Stretc"
	.size	.L.str.42, 7

	.type	.L.str.43,@object
.L.str.43:
	.asciz	"what"
	.size	.L.str.43, 5

	.type	.L.str.44,@object
.L.str.44:
	.asciz	"life"
	.size	.L.str.44, 5

	.type	.L.str.45,@object
.L.str.45:
	.asciz	"kno"
	.size	.L.str.45, 4

	.type	.L.str.46,@object
.L.str.46:
	.asciz	"wha"
	.size	.L.str.46, 4

	.type	.L.str.47,@object
.L.str.47:
	.asciz	"40"
	.size	.L.str.47, 3

	.type	.L.str.48,@object
.L.str.48:
	.asciz	"Get"
	.size	.L.str.48, 4

	.type	.L.str.49,@object
.L.str.49:
	.asciz	"them"
	.size	.L.str.49, 5

	.type	.L.str.50,@object
.L.str.50:
	.asciz	"Maybe"
	.size	.L.str.50, 6

	.type	.L.str.51,@object
.L.str.51:
	.asciz	"may"
	.size	.L.str.51, 4

	.type	.L.str.52,@object
.L.str.52:
	.asciz	"the"
	.size	.L.str.52, 4

	.type	.L.str.53,@object
.L.str.53:
	.asciz	"your"
	.size	.L.str.53, 5

	.type	.L.str.54,@object
.L.str.54:
	.asciz	"congratulate"
	.size	.L.str.54, 13

	.type	.L.str.55,@object
.L.str.55:
	.asciz	"much"
	.size	.L.str.55, 5

	.type	.L.str.56,@object
.L.str.56:
	.asciz	"either"
	.size	.L.str.56, 7

	.type	.L.str.57,@object
.L.str.57:
	.asciz	"are"
	.size	.L.str.57, 4

	.type	.L.str.58,@object
.L.str.58:
	.asciz	"Enjoy"
	.size	.L.str.58, 6

	.type	.L.str.59,@object
.L.str.59:
	.asciz	"it"
	.size	.L.str.59, 3

	.type	.L.str.60,@object
.L.str.60:
	.asciz	"be"
	.size	.L.str.60, 3

	.type	.L.str.61,@object
.L.str.61:
	.asciz	"other"
	.size	.L.str.61, 6

	.type	.L.str.62,@object
.L.str.62:
	.asciz	"greatest"
	.size	.L.str.62, 9

	.type	.L.str.63,@object
.L.str.63:
	.asciz	"own"
	.size	.L.str.63, 4

	.type	.L.str.64,@object
.L.str.64:
	.asciz	"nowhere"
	.size	.L.str.64, 8

	.type	.L.str.65,@object
.L.str.65:
	.asciz	"room"
	.size	.L.str.65, 5

	.type	.L.str.66,@object
.L.str.66:
	.asciz	"beauty"
	.size	.L.str.66, 7

	.type	.L.str.67,@object
.L.str.67:
	.asciz	"feel"
	.size	.L.str.67, 5

	.type	.L.str.68,@object
.L.str.68:
	.asciz	"Northern"
	.size	.L.str.68, 9

	.type	.L.str.69,@object
.L.str.69:
	.asciz	"before"
	.size	.L.str.69, 7

	.type	.L.str.70,@object
.L.str.70:
	.asciz	"Accept"
	.size	.L.str.70, 7

	.type	.L.str.71,@object
.L.str.71:
	.asciz	"Politicians"
	.size	.L.str.71, 12

	.type	.L.str.72,@object
.L.str.72:
	.asciz	"get"
	.size	.L.str.72, 4

	.type	.L.str.73,@object
.L.str.73:
	.asciz	"size"
	.size	.L.str.73, 5

	.type	.L.str.74,@object
.L.str.74:
	.asciz	"reasonable"
	.size	.L.str.74, 11

	.type	.L.str.75,@object
.L.str.75:
	.asciz	"their"
	.size	.L.str.75, 6

	.type	.L.str.76,@object
.L.str.76:
	.asciz	"Dont"
	.size	.L.str.76, 5

	.type	.L.str.77,@object
.L.str.77:
	.asciz	"support"
	.size	.L.str.77, 8

	.type	.L.str.78,@object
.L.str.78:
	.asciz	"trust"
	.size	.L.str.78, 6

	.type	.L.str.79,@object
.L.str.79:
	.asciz	"spouse"
	.size	.L.str.79, 7

	.type	.L.str.80,@object
.L.str.80:
	.asciz	"one"
	.size	.L.str.80, 4

	.type	.L.str.81,@object
.L.str.81:
	.asciz	"too"
	.size	.L.str.81, 4

	.type	.L.str.82,@object
.L.str.82:
	.asciz	"time"
	.size	.L.str.82, 5

	.type	.L.str.83,@object
.L.str.83:
	.asciz	"careful"
	.size	.L.str.83, 8

	.type	.L.str.84,@object
.L.str.84:
	.asciz	"with"
	.size	.L.str.84, 5

	.type	.L.str.85,@object
.L.str.85:
	.asciz	"Dispensing"
	.size	.L.str.85, 11

	.type	.L.str.86,@object
.L.str.86:
	.asciz	"past"
	.size	.L.str.86, 5

	.type	.L.str.87,@object
.L.str.87:
	.asciz	"parts"
	.size	.L.str.87, 6

	.type	.L.str.88,@object
.L.str.88:
	.asciz	"more"
	.size	.L.str.88, 5

	.type	.L.str.89,@object
.L.str.89:
	.asciz	"me"
	.size	.L.str.89, 3

	.type	.L__const.main.find_strings,@object
	.section	.rodata,"a",@progbits
	.p2align	2
.L__const.main.find_strings:
	.word	.L.str
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	.L.str.1
	.word	.L.str.2
	.word	.L.str.3
	.word	.L.str.4
	.word	.L.str.5
	.word	.L.str.6
	.word	.L.str.7
	.word	.L.str.8
	.word	.L.str.9
	.word	.L.str.9
	.word	.L.str.10
	.word	.L.str.11
	.word	.L.str.12
	.word	.L.str.13
	.word	.L.str.14
	.word	.L.str.15
	.word	.L.str.16
	.word	.L.str.17
	.word	.L.str.18
	.word	.L.str.19
	.word	.L.str.20
	.word	.L.str.21
	.word	.L.str.19
	.word	.L.str.22
	.word	.L.str.23
	.word	.L.str.24
	.word	.L.str.25
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.26
	.word	.L.str.27
	.word	.L.str.28
	.word	.L.str.29
	.word	.L.str.30
	.word	.L.str.31
	.word	.L.str.32
	.word	.L.str.33
	.word	.L.str.34
	.word	.L.str.35
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.36
	.word	.L.str.5
	.word	.L.str.37
	.word	.L.str.38
	.word	.L.str.39
	.word	.L.str.40
	.word	.L.str.41
	.word	.L.str.26
	.word	.L.str.42
	.word	.L.str.43
	.word	.L.str.44
	.word	.L.str.45
	.word	.L.str.46
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.47
	.word	.L.str.48
	.word	.L.str.5
	.word	.L.str.49
	.word	.L.str.50
	.word	.L.str.51
	.word	.L.str.17
	.word	.L.str.52
	.word	.L.str.53
	.word	.L.str.54
	.word	.L.str.55
	.word	.L.str.56
	.word	.L.str.57
	.word	.L.str.58
	.word	.L.str.59
	.word	.L.str.60
	.word	.L.str.61
	.word	.L.str.59
	.word	.L.str.5
	.word	.L.str.62
	.word	.L.str.63
	.word	.L.str.64
	.word	.L.str.65
	.word	.L.str.17
	.word	.L.str.66
	.word	.L.str.67
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.5
	.word	.L.str.59
	.word	.L.str.68
	.word	.L.str.69
	.word	.L.str.70
	.word	.L.str.71
	.word	.L.str.72
	.word	.L.str.73
	.word	.L.str.74
	.word	.L.str.75
	.word	.L.str.76
	.word	.L.str.77
	.word	.L.str.78
	.word	.L.str.79
	.word	.L.str.80
	.word	.L.str.81
	.word	.L.str.82
	.word	.L.str.83
	.word	.L.str.84
	.word	.L.str.85
	.word	.L.str.86
	.word	.L.str.52
	.word	.L.str.87
	.word	.L.str.88
	.word	.L.str.89
	.word	0
	.size	.L__const.main.find_strings, 5332

	.type	.L.str.90,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str.90:
	.asciz	"Kurt Vonneguts Commencement Address at"
	.size	.L.str.90, 39

	.type	.L.str.91,@object
.L.str.91:
	.asciz	"MIT Ladies and gentlemen of"
	.size	.L.str.91, 28

	.type	.L.str.92,@object
.L.str.92:
	.asciz	"the class of 97 Wear"
	.size	.L.str.92, 21

	.type	.L.str.93,@object
.L.str.93:
	.asciz	"sunscreen If I could offer"
	.size	.L.str.93, 27

	.type	.L.str.94,@object
.L.str.94:
	.asciz	"you only one tip for"
	.size	.L.str.94, 21

	.type	.L.str.95,@object
.L.str.95:
	.asciz	"the future sunscreen would be"
	.size	.L.str.95, 30

	.type	.L.str.96,@object
.L.str.96:
	.asciz	"it The longterm benefits of"
	.size	.L.str.96, 28

	.type	.L.str.97,@object
.L.str.97:
	.asciz	"sunscreen have been proved by"
	.size	.L.str.97, 30

	.type	.L.str.98,@object
.L.str.98:
	.asciz	"scientists whereas the rest of"
	.size	.L.str.98, 31

	.type	.L.str.99,@object
.L.str.99:
	.asciz	"my advice has no basis"
	.size	.L.str.99, 23

	.type	.L.str.100,@object
.L.str.100:
	.asciz	"more reliable than my own meandering experience"
	.size	.L.str.100, 48

	.type	.L.str.101,@object
.L.str.101:
	.asciz	"I will dispense this advice"
	.size	.L.str.101, 28

	.type	.L.str.102,@object
.L.str.102:
	.asciz	"now Enjoy the power and beauty"
	.size	.L.str.102, 31

	.type	.L.str.103,@object
.L.str.103:
	.asciz	"of your youth Oh never mind"
	.size	.L.str.103, 28

	.type	.L.str.104,@object
.L.str.104:
	.asciz	"You will not understand the power"
	.size	.L.str.104, 34

	.type	.L.str.105,@object
.L.str.105:
	.asciz	"and beauty of your youth until theyve"
	.size	.L.str.105, 38

	.type	.L.str.106,@object
.L.str.106:
	.asciz	"faded But trust me in"
	.size	.L.str.106, 22

	.type	.L.str.107,@object
.L.str.107:
	.asciz	"20 years"
	.size	.L.str.107, 9

	.type	.L.str.108,@object
.L.str.108:
	.asciz	"youll look"
	.size	.L.str.108, 11

	.type	.L.str.109,@object
.L.str.109:
	.asciz	"back at photos of yourself"
	.size	.L.str.109, 27

	.type	.L.str.110,@object
.L.str.110:
	.asciz	"and recall in a"
	.size	.L.str.110, 16

	.type	.L.str.111,@object
.L.str.111:
	.asciz	"way you cant grasp now how much"
	.size	.L.str.111, 32

	.type	.L.str.112,@object
.L.str.112:
	.asciz	"possibility lay before you"
	.size	.L.str.112, 27

	.type	.L.str.113,@object
.L.str.113:
	.asciz	"and how fabulous you really looked You"
	.size	.L.str.113, 39

	.type	.L.str.114,@object
.L.str.114:
	.asciz	"are not as fat"
	.size	.L.str.114, 15

	.type	.L.str.115,@object
.L.str.115:
	.asciz	"as you imagine Dont worry about"
	.size	.L.str.115, 32

	.type	.L.str.116,@object
.L.str.116:
	.asciz	"the future Or"
	.size	.L.str.116, 14

	.type	.L.str.117,@object
.L.str.117:
	.asciz	"worry but know that worrying is as effective"
	.size	.L.str.117, 45

	.type	.L.str.118,@object
.L.str.118:
	.asciz	"as trying to solve an algebra equation"
	.size	.L.str.118, 39

	.type	.L.str.119,@object
.L.str.119:
	.asciz	"by chewing bubble gum The real troubles in"
	.size	.L.str.119, 43

	.type	.L.str.120,@object
.L.str.120:
	.asciz	"your life are apt to"
	.size	.L.str.120, 21

	.type	.L.str.121,@object
.L.str.121:
	.asciz	"be things that never crossed your"
	.size	.L.str.121, 34

	.type	.L.str.122,@object
.L.str.122:
	.asciz	"worried mind the"
	.size	.L.str.122, 17

	.type	.L.str.123,@object
.L.str.123:
	.asciz	"kind that blindside you at"
	.size	.L.str.123, 27

	.type	.L.str.124,@object
.L.str.124:
	.asciz	"4 pm on some"
	.size	.L.str.124, 13

	.type	.L.str.125,@object
.L.str.125:
	.asciz	"idle Tuesday"
	.size	.L.str.125, 13

	.type	.L.str.126,@object
.L.str.126:
	.asciz	"Do one thing every day that"
	.size	.L.str.126, 28

	.type	.L.str.127,@object
.L.str.127:
	.asciz	"scares you Sing Dont be reckless with other"
	.size	.L.str.127, 44

	.type	.L.str.128,@object
.L.str.128:
	.asciz	"peoples hearts Dont put up"
	.size	.L.str.128, 27

	.type	.L.str.129,@object
.L.str.129:
	.asciz	"with people who are reckless"
	.size	.L.str.129, 29

	.type	.L.str.130,@object
.L.str.130:
	.asciz	"with yours Floss Dont waste your time"
	.size	.L.str.130, 38

	.type	.L.str.131,@object
.L.str.131:
	.asciz	"on jealousy Sometimes youre ahead sometimes youre behind"
	.size	.L.str.131, 57

	.type	.L.str.132,@object
.L.str.132:
	.asciz	"The race is long and in"
	.size	.L.str.132, 24

	.type	.L.str.133,@object
.L.str.133:
	.asciz	"the end its only with"
	.size	.L.str.133, 22

	.type	.L.str.134,@object
.L.str.134:
	.asciz	"yourself Remember compliments you receive"
	.size	.L.str.134, 42

	.type	.L.str.135,@object
.L.str.135:
	.asciz	"Forget the insults If you"
	.size	.L.str.135, 26

	.type	.L.str.136,@object
.L.str.136:
	.asciz	"succeed in doing this tell me how"
	.size	.L.str.136, 34

	.type	.L.str.137,@object
.L.str.137:
	.asciz	"Keep your old"
	.size	.L.str.137, 14

	.type	.L.str.138,@object
.L.str.138:
	.asciz	"love letters Throw away"
	.size	.L.str.138, 24

	.type	.L.str.139,@object
.L.str.139:
	.asciz	"your old bank statements"
	.size	.L.str.139, 25

	.type	.L.str.140,@object
.L.str.140:
	.asciz	"Stretch Dont feel guilty if you dont know"
	.size	.L.str.140, 42

	.type	.L.str.141,@object
.L.str.141:
	.asciz	"what you want to do with your"
	.size	.L.str.141, 30

	.type	.L.str.142,@object
.L.str.142:
	.asciz	"life The most interesting people I"
	.size	.L.str.142, 35

	.type	.L.str.143,@object
.L.str.143:
	.asciz	"know didnt know at 22"
	.size	.L.str.143, 22

	.type	.L.str.144,@object
.L.str.144:
	.asciz	"what they wanted"
	.size	.L.str.144, 17

	.type	.L.str.145,@object
.L.str.145:
	.asciz	"to do with their lives Some of"
	.size	.L.str.145, 31

	.type	.L.str.146,@object
.L.str.146:
	.asciz	"the most interesting"
	.size	.L.str.146, 21

	.type	.L.str.147,@object
.L.str.147:
	.asciz	"40yearolds I know still dont"
	.size	.L.str.147, 29

	.type	.L.str.148,@object
.L.str.148:
	.asciz	"Get plenty of calcium"
	.size	.L.str.148, 22

	.type	.L.str.149,@object
.L.str.149:
	.asciz	"Be kind to your knees Youll miss"
	.size	.L.str.149, 33

	.type	.L.str.150,@object
.L.str.150:
	.asciz	"them when theyre gone"
	.size	.L.str.150, 22

	.type	.L.str.151,@object
.L.str.151:
	.asciz	"Maybe youll marry"
	.size	.L.str.151, 18

	.type	.L.str.152,@object
.L.str.152:
	.asciz	"maybe you wont Maybe youll have children maybe"
	.size	.L.str.152, 47

	.type	.L.str.153,@object
.L.str.153:
	.asciz	"you wont Maybe youll divorce at 40 maybe youll dance"
	.size	.L.str.153, 53

	.type	.L.str.154,@object
.L.str.154:
	.asciz	"the funky chicken on"
	.size	.L.str.154, 21

	.type	.L.str.155,@object
.L.str.155:
	.asciz	"your 75th wedding anniversary Whatever"
	.size	.L.str.155, 39

	.type	.L.str.156,@object
.L.str.156:
	.asciz	"you do dont congratulate yourself too"
	.size	.L.str.156, 38

	.type	.L.str.157,@object
.L.str.157:
	.asciz	"much or berate yourself"
	.size	.L.str.157, 24

	.type	.L.str.158,@object
.L.str.158:
	.asciz	"either Your choices are half chance So"
	.size	.L.str.158, 39

	.type	.L.str.159,@object
.L.str.159:
	.asciz	"are everybody elses"
	.size	.L.str.159, 20

	.type	.L.str.160,@object
.L.str.160:
	.asciz	"Enjoy your body Use"
	.size	.L.str.160, 20

	.type	.L.str.161,@object
.L.str.161:
	.asciz	"it every way you can Dont"
	.size	.L.str.161, 26

	.type	.L.str.162,@object
.L.str.162:
	.asciz	"be afraid of it or of what"
	.size	.L.str.162, 27

	.type	.L.str.163,@object
.L.str.163:
	.asciz	"other people think of"
	.size	.L.str.163, 22

	.type	.L.str.164,@object
.L.str.164:
	.asciz	"it Its"
	.size	.L.str.164, 7

	.type	.L.str.165,@object
.L.str.165:
	.asciz	"greatest instrument youll ever"
	.size	.L.str.165, 31

	.type	.L.str.166,@object
.L.str.166:
	.asciz	"own Dance even if you have"
	.size	.L.str.166, 27

	.type	.L.str.167,@object
.L.str.167:
	.asciz	"nowhere to do it but your living"
	.size	.L.str.167, 33

	.type	.L.str.168,@object
.L.str.168:
	.asciz	"room Read the directions even if"
	.size	.L.str.168, 33

	.type	.L.str.169,@object
.L.str.169:
	.asciz	"you dont follow them Do not read"
	.size	.L.str.169, 33

	.type	.L.str.170,@object
.L.str.170:
	.asciz	"beauty magazines They will only make you"
	.size	.L.str.170, 41

	.type	.L.str.171,@object
.L.str.171:
	.asciz	"feel ugly Get to know your parents You never"
	.size	.L.str.171, 45

	.type	.L.str.172,@object
.L.str.172:
	.asciz	"know when theyll be gone for good Be"
	.size	.L.str.172, 37

	.type	.L.str.173,@object
.L.str.173:
	.asciz	"nice to your siblings Theyre your"
	.size	.L.str.173, 34

	.type	.L.str.174,@object
.L.str.174:
	.asciz	"best link to your"
	.size	.L.str.174, 18

	.type	.L.str.175,@object
.L.str.175:
	.asciz	"past and the people most likely"
	.size	.L.str.175, 32

	.type	.L.str.176,@object
.L.str.176:
	.asciz	"to stick with you"
	.size	.L.str.176, 18

	.type	.L.str.177,@object
.L.str.177:
	.asciz	"in the future Understand that"
	.size	.L.str.177, 30

	.type	.L.str.178,@object
.L.str.178:
	.asciz	"friends come and go but"
	.size	.L.str.178, 24

	.type	.L.str.179,@object
.L.str.179:
	.asciz	"with a precious few you should hold"
	.size	.L.str.179, 36

	.type	.L.str.180,@object
.L.str.180:
	.asciz	"on Work hard to bridge"
	.size	.L.str.180, 23

	.type	.L.str.181,@object
.L.str.181:
	.asciz	"the gaps in geography and lifestyle"
	.size	.L.str.181, 36

	.type	.L.str.182,@object
.L.str.182:
	.asciz	"because the older"
	.size	.L.str.182, 18

	.type	.L.str.183,@object
.L.str.183:
	.asciz	"you get the more you need the"
	.size	.L.str.183, 30

	.type	.L.str.184,@object
.L.str.184:
	.asciz	"people who knew you when you"
	.size	.L.str.184, 29

	.type	.L.str.185,@object
.L.str.185:
	.asciz	"were young Live"
	.size	.L.str.185, 16

	.type	.L.str.186,@object
.L.str.186:
	.asciz	"in New York City once but leave before"
	.size	.L.str.186, 39

	.type	.L.str.187,@object
.L.str.187:
	.asciz	"it makes you hard Live in"
	.size	.L.str.187, 26

	.type	.L.str.188,@object
.L.str.188:
	.asciz	"Northern California once but leave"
	.size	.L.str.188, 35

	.type	.L.str.189,@object
.L.str.189:
	.asciz	"before it makes you soft Travel"
	.size	.L.str.189, 32

	.type	.L.str.190,@object
.L.str.190:
	.asciz	"Accept certain inalienable truths Prices will rise"
	.size	.L.str.190, 51

	.type	.L.str.191,@object
.L.str.191:
	.asciz	"Politicians will philander You too will"
	.size	.L.str.191, 40

	.type	.L.str.192,@object
.L.str.192:
	.asciz	"get old And when you do youll"
	.size	.L.str.192, 30

	.type	.L.str.193,@object
.L.str.193:
	.asciz	"fantasize that when you were young prices were"
	.size	.L.str.193, 47

	.type	.L.str.194,@object
.L.str.194:
	.asciz	"reasonable politicians were noble and children respected"
	.size	.L.str.194, 57

	.type	.L.str.195,@object
.L.str.195:
	.asciz	"their elders Respect your elders"
	.size	.L.str.195, 33

	.type	.L.str.196,@object
.L.str.196:
	.asciz	"Dont expect anyone else to"
	.size	.L.str.196, 27

	.type	.L.str.197,@object
.L.str.197:
	.asciz	"support you Maybe you have a"
	.size	.L.str.197, 29

	.type	.L.str.198,@object
.L.str.198:
	.asciz	"trust fund Maybe youll have a wealthy"
	.size	.L.str.198, 38

	.type	.L.str.199,@object
.L.str.199:
	.asciz	"spouse But you never know when either"
	.size	.L.str.199, 38

	.type	.L.str.200,@object
.L.str.200:
	.asciz	"one might run out Dont mess"
	.size	.L.str.200, 28

	.type	.L.str.201,@object
.L.str.201:
	.asciz	"too much with your hair or by the"
	.size	.L.str.201, 34

	.type	.L.str.202,@object
.L.str.202:
	.asciz	"time youre 40 it will look 85 Be"
	.size	.L.str.202, 33

	.type	.L.str.203,@object
.L.str.203:
	.asciz	"careful whose advice you buy but be patient"
	.size	.L.str.203, 44

	.type	.L.str.204,@object
.L.str.204:
	.asciz	"with those who supply it Advice is a"
	.size	.L.str.204, 37

	.type	.L.str.205,@object
.L.str.205:
	.asciz	"form of nostalgia Dispensing it is"
	.size	.L.str.205, 35

	.type	.L.str.206,@object
.L.str.206:
	.asciz	"a way of fishing the past from"
	.size	.L.str.206, 31

	.type	.L.str.207,@object
.L.str.207:
	.asciz	"the disposal wiping it off painting"
	.size	.L.str.207, 36

	.type	.L.str.208,@object
.L.str.208:
	.asciz	"over the ugly parts"
	.size	.L.str.208, 20

	.type	.L.str.209,@object
.L.str.209:
	.asciz	"and recycling it for more than its"
	.size	.L.str.209, 35

	.type	.L.str.210,@object
.L.str.210:
	.asciz	"worth But trust me on the sunscreen"
	.size	.L.str.210, 36

	.type	.L__const.main.search_strings,@object
	.section	.rodata,"a",@progbits
	.p2align	2
.L__const.main.search_strings:
	.word	.L.str.90
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.word	.L.str.91
	.word	.L.str.92
	.word	.L.str.93
	.word	.L.str.94
	.word	.L.str.95
	.word	.L.str.96
	.word	.L.str.97
	.word	.L.str.98
	.word	.L.str.99
	.word	.L.str.100
	.word	.L.str.101
	.word	.L.str.102
	.word	.L.str.103
	.word	.L.str.104
	.word	.L.str.105
	.word	.L.str.106
	.word	.L.str.107
	.word	.L.str.108
	.word	.L.str.109
	.word	.L.str.110
	.word	.L.str.111
	.word	.L.str.112
	.word	.L.str.113
	.word	.L.str.114
	.word	.L.str.115
	.word	.L.str.116
	.word	.L.str.117
	.word	.L.str.118
	.word	.L.str.119
	.word	.L.str.120
	.word	.L.str.121
	.word	.L.str.122
	.word	.L.str.123
	.word	.L.str.124
	.word	.L.str.125
	.word	.L.str.126
	.word	.L.str.127
	.word	.L.str.128
	.word	.L.str.129
	.word	.L.str.130
	.word	.L.str.131
	.word	.L.str.132
	.word	.L.str.133
	.word	.L.str.134
	.word	.L.str.135
	.word	.L.str.136
	.word	.L.str.137
	.word	.L.str.138
	.word	.L.str.139
	.word	.L.str.140
	.word	.L.str.141
	.word	.L.str.142
	.word	.L.str.143
	.word	.L.str.144
	.word	.L.str.145
	.word	.L.str.146
	.word	.L.str.147
	.word	.L.str.148
	.word	.L.str.149
	.word	.L.str.150
	.word	.L.str.151
	.word	.L.str.152
	.word	.L.str.153
	.word	.L.str.154
	.word	.L.str.155
	.word	.L.str.156
	.word	.L.str.157
	.word	.L.str.158
	.word	.L.str.159
	.word	.L.str.160
	.word	.L.str.161
	.word	.L.str.162
	.word	.L.str.163
	.word	.L.str.164
	.word	.L.str.52
	.word	.L.str.165
	.word	.L.str.166
	.word	.L.str.167
	.word	.L.str.168
	.word	.L.str.169
	.word	.L.str.170
	.word	.L.str.171
	.word	.L.str.172
	.word	.L.str.173
	.word	.L.str.174
	.word	.L.str.175
	.word	.L.str.176
	.word	.L.str.177
	.word	.L.str.178
	.word	.L.str.179
	.word	.L.str.180
	.word	.L.str.181
	.word	.L.str.182
	.word	.L.str.183
	.word	.L.str.184
	.word	.L.str.185
	.word	.L.str.186
	.word	.L.str.187
	.word	.L.str.188
	.word	.L.str.189
	.word	.L.str.190
	.word	.L.str.191
	.word	.L.str.192
	.word	.L.str.193
	.word	.L.str.194
	.word	.L.str.195
	.word	.L.str.196
	.word	.L.str.197
	.word	.L.str.198
	.word	.L.str.199
	.word	.L.str.200
	.word	.L.str.201
	.word	.L.str.202
	.word	.L.str.203
	.word	.L.str.204
	.word	.L.str.205
	.word	.L.str.206
	.word	.L.str.207
	.word	.L.str.208
	.word	.L.str.209
	.word	.L.str.210
	.size	.L__const.main.search_strings, 5328

	.type	.L.str.211,@object
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str.211:
	.asciz	"\"%s\" is%s in \"%s\""
	.size	.L.str.211, 18

	.type	.L.str.212,@object
.L.str.212:
	.zero	1
	.size	.L.str.212, 1

	.type	.L.str.213,@object
.L.str.213:
	.asciz	" not"
	.size	.L.str.213, 5

	.type	.L.str.214,@object
.L.str.214:
	.asciz	" [\"%s\"]"
	.size	.L.str.214, 8

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
