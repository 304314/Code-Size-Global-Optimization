	.text
	.attribute	4, 16
	.attribute  5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	//.attribute	5, "rv32i2p0_m2p0_c2p0"
	.file	"bmhasrch.c"
	.globl	bmha_init
	.p2align	1
	.type	bmha_init,@function
bmha_init:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	sw	s0, 8(sp)
	sw	s1, 4(sp)
	sw	s2, 0(sp)
	mv	s2, a0
	lui	a0, %hi(pat)
	sw	s2, %lo(pat)(a0)
	mv	a0, s2
	call	strlen
	lui	a1, %hi(patlen)
	sw	a0, %lo(patlen)(a1)
	mv	a6, a0
	bltz	a0, .LBB0_2
	li	a6, 0
.LBB0_2:
	li	a2, 0
	add	a1, a0, s2
	addi	a3, a1, -1
	lui	a1, %hi(skip)
	addi	t1, a1, %lo(skip)
	lui	a1, %hi(lowervec)
	addi	a5, a1, %lo(lowervec)
	lui	a1, 8
	addi	t0, a1, -1
	li	a7, 256
.LBB0_3:
	li	a4, 0
	slli	a1, a2, 2
	add	t2, t1, a1
	sw	a0, 0(t2)
	add	s0, a5, a2
.LBB0_4:
	add	s1, a0, a4
	blez	s1, .LBB0_7
	add	s1, a3, a4
	lbu	s1, 0(s1)
	lbu	a1, 0(s0)
	add	s1, s1, a5
	lbu	s1, 0(s1)
	addi	a4, a4, -1
	bne	a1, s1, .LBB0_4
	not	a1, a4
	sw	a1, 0(t2)
	add	a1, a0, a4
	addi	a4, a1, 1
	beq	a0, a4, .LBB0_8
	j	.LBB0_9
.LBB0_7:
	mv	a4, a6
	bne	a0, a4, .LBB0_9
.LBB0_8:
	sw	t0, 0(t2)
.LBB0_9:
	addi	a2, a2, 1
	bne	a2, a7, .LBB0_3
	lui	a1, %hi(skip2)
	li	a2, 2
	sw	a0, %lo(skip2)(a1)
	blt	a0, a2, .LBB0_15
	addi	a0, a0, -1
	add	a2, s2, a0
	lbu	a3, 0(a2)
	lui	a2, %hi(lowervec)
	addi	a2, a2, %lo(lowervec)
	add	a3, a3, a2
	lbu	a3, 0(a3)
.LBB0_12:
	lbu	a4, 0(s2)
	add	a4, a4, a2
	lbu	a4, 0(a4)
	bne	a4, a3, .LBB0_14
	sw	a0, %lo(skip2)(a1)
.LBB0_14:
	addi	a0, a0, -1
	addi	s2, s2, 1
	bnez	a0, .LBB0_12
.LBB0_15:
	lw	ra, 12(sp)
	lw	s0, 8(sp)
	lw	s1, 4(sp)
	lw	s2, 0(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end0:
	.size	bmha_init, .Lfunc_end0-bmha_init

	.globl	bmha_search
	.p2align	1
	.type	bmha_search,@function
bmha_search:
	addi	sp, sp, -16
	sw	s0, 12(sp)
	sw	s1, 8(sp)
	lui	a2, %hi(patlen)
	lw	t3, %lo(patlen)(a2)
	not	a2, a1
	add	a3, t3, a2
	mv	a2, a0
	li	a0, 0
	bltz	a3, .LBB1_2
.LBB1_1:
	lw	s0, 12(sp)
	lw	s1, 8(sp)
	addi	sp, sp, 16
	ret
.LBB1_2:
	add	t5, a2, a1
	lui	a0, 8
	addi	a0, a0, -1
	sub	t0, a0, a1
	addi	a7, t3, -1
	lui	a0, %hi(pat)
	lw	a0, %lo(pat)(a0)
	lui	a1, %hi(skip2)
	lw	a6, %lo(skip2)(a1)
	lui	a1, 1048568
	add	t1, t5, a1
	addi	a4, a0, -2
	lui	a0, %hi(skip)
	addi	t4, a0, %lo(skip)
	addi	t2, a1, 1
	lui	a0, %hi(lowervec)
	addi	a5, a0, %lo(lowervec)
.LBB1_3:
	add	a0, t5, a3
	lbu	a0, 0(a0)
	slli	a0, a0, 2
	add	a0, a0, t4
	lw	a0, 0(a0)
	add	a3, a3, a0
	bltz	a3, .LBB1_3
	blt	a3, t0, .LBB1_9
	add	t6, a3, t2
	sub	a0, t6, a7
	add	a0, a0, t5
	add	a3, a3, t1
	mv	a1, t3
.LBB1_6:
	addi	a2, a1, -1
	blez	a2, .LBB1_1
	lbu	s0, 0(a3)
	add	a1, a1, a4
	lbu	a1, 0(a1)
	add	s0, s0, a5
	lbu	s0, 0(s0)
	add	a1, a1, a5
	lbu	s1, 0(a1)
	addi	a3, a3, -1
	mv	a1, a2
	beq	s0, s1, .LBB1_6
	add	a3, a6, t6
	bltz	a3, .LBB1_3
.LBB1_9:
	li	a0, 0
	j	.LBB1_1
.Lfunc_end1:
	.size	bmha_search, .Lfunc_end1-bmha_search

	.type	lowervec,@object
	.data
	.globl	lowervec
lowervec:
	.ascii	"\000\001\002\003\004\005\006\007\b\t\n\013\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\177cueaaaaceeeiiiaae\221\222ooouuyou\233\234\235\236\237aiounn\246\247\250\251\252\253\254\255\256\257\260\261\262\263\264\265\266\267\270\271\272\273\274\275\276\277\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357\360\361\362\363\364\365\366\367\370\371\372\373\374\375\376\377"
	.size	lowervec, 256

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
