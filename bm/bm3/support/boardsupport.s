	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"boardsupport.c"
	.globl	initialise_board
	.p2align	1
	.type	initialise_board,@function
initialise_board:
	#APP
	li	a0, 0
	#NO_APP
	ret
.Lfunc_end0:
	.size	initialise_board, .Lfunc_end0-initialise_board

	.globl	start_trigger
	.p2align	1
	.type	start_trigger,@function
start_trigger:
	#APP
	li	a0, 0
	#NO_APP
	ret
.Lfunc_end1:
	.size	start_trigger, .Lfunc_end1-start_trigger

	.globl	stop_trigger
	.p2align	1
	.type	stop_trigger,@function
stop_trigger:
	#APP
	li	a0, 0
	#NO_APP
	ret
.Lfunc_end2:
	.size	stop_trigger, .Lfunc_end2-stop_trigger

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
