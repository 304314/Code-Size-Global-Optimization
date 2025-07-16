	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"beebsc.c"
	.globl	rand_beebs
	.p2align	1
	.type	rand_beebs,@function
rand_beebs:
	lui	a1, %hi(seed)
	lw	a0, %lo(seed)(a1)
	lui	a2, 269413
	addi	a2, a2, -403
	mul	a0, a0, a2
	lui	a2, 3
	addi	a2, a2, 57
	add	a0, a0, a2
	slli	a0, a0, 1
	srli	a2, a0, 1
	srli	a0, a2, 16
	sw	a2, %lo(seed)(a1)
	ret
.Lfunc_end0:
	.size	rand_beebs, .Lfunc_end0-rand_beebs

	.globl	srand_beebs
	.p2align	1
	.type	srand_beebs,@function
srand_beebs:
	lui	a1, %hi(seed)
	sw	a0, %lo(seed)(a1)
	ret
.Lfunc_end1:
	.size	srand_beebs, .Lfunc_end1-srand_beebs

	.globl	init_heap_beebs
	.p2align	1
	.type	init_heap_beebs,@function
init_heap_beebs:
	lui	a2, %hi(heap_ptr)
	sw	a0, %lo(heap_ptr)(a2)
	add	a0, a0, a1
	lui	a1, %hi(heap_end)
	sw	a0, %lo(heap_end)(a1)
	lui	a0, %hi(heap_requested)
	sw	zero, %lo(heap_requested)(a0)
	ret
.Lfunc_end2:
	.size	init_heap_beebs, .Lfunc_end2-init_heap_beebs

	.globl	check_heap_beebs
	.p2align	1
	.type	check_heap_beebs,@function
check_heap_beebs:
	lui	a1, %hi(heap_requested)
	lw	a1, %lo(heap_requested)(a1)
	lui	a2, %hi(heap_end)
	lw	a2, %lo(heap_end)(a2)
	add	a0, a0, a1
	sltu	a0, a2, a0
	xori	a0, a0, 1
	ret
.Lfunc_end3:
	.size	check_heap_beebs, .Lfunc_end3-check_heap_beebs

	.globl	malloc_beebs
	.p2align	1
	.type	malloc_beebs,@function
malloc_beebs:
	lui	a6, %hi(heap_ptr)
	lw	a3, %lo(heap_ptr)(a6)
	lui	a7, %hi(heap_requested)
	lw	a4, %lo(heap_requested)(a7)
	lui	a1, %hi(heap_end)
	lw	a2, %lo(heap_end)(a1)
	mv	a1, a0
	li	a0, 0
	add	a5, a4, a1
	add	a4, a3, a1
	sltu	a2, a2, a4
	seqz	a1, a1
	or	a1, a1, a2
	sw	a5, %lo(heap_requested)(a7)
	bnez	a1, .LBB4_2
	sw	a4, %lo(heap_ptr)(a6)
	mv	a0, a3
.LBB4_2:
	ret
.Lfunc_end4:
	.size	malloc_beebs, .Lfunc_end4-malloc_beebs

	.globl	calloc_beebs
	.p2align	1
	.type	calloc_beebs,@function
calloc_beebs:
	addi	sp, sp, -16
	sw	ra, 12(sp)
	sw	s0, 8(sp)
	mv	a2, a0
	li	a0, 0
	mul	a2, a1, a2
	lui	a6, %hi(heap_ptr)
	lw	s0, %lo(heap_ptr)(a6)
	lui	a3, %hi(heap_end)
	lw	a4, %lo(heap_end)(a3)
	lui	a7, %hi(heap_requested)
	lw	a1, %lo(heap_requested)(a7)
	add	a3, s0, a2
	sltu	a4, a4, a3
	seqz	a5, a2
	or	a4, a4, a5
	add	a1, a1, a2
	sw	a1, %lo(heap_requested)(a7)
	bnez	a4, .LBB5_4
	sw	a3, %lo(heap_ptr)(a6)
	beqz	s0, .LBB5_3
	mv	a0, s0
	li	a1, 0
	call	memset@plt
	mv	a0, s0
	j	.LBB5_4
.LBB5_3:
	li	a0, 0
.LBB5_4:
	lw	ra, 12(sp)
	lw	s0, 8(sp)
	addi	sp, sp, 16
	ret
.Lfunc_end5:
	.size	calloc_beebs, .Lfunc_end5-calloc_beebs

	.globl	realloc_beebs
	.p2align	1
	.type	realloc_beebs,@function
realloc_beebs:
	li	t0, 0
	lui	a6, %hi(heap_ptr)
	lw	a3, %lo(heap_ptr)(a6)
	lui	a5, %hi(heap_end)
	lw	a4, %lo(heap_end)(a5)
	lui	a7, %hi(heap_requested)
	lw	t1, %lo(heap_requested)(a7)
	add	a5, a3, a1
	sltu	a4, a4, a5
	seqz	a2, a1
	or	a2, a2, a4
	add	a4, t1, a1
	sw	a4, %lo(heap_requested)(a7)
	bnez	a2, .LBB6_5
	sw	a5, %lo(heap_ptr)(a6)
	beqz	a0, .LBB6_4
	li	a2, 0
.LBB6_3:
	add	a4, a0, a2
	lb	a4, 0(a4)
	add	a5, a3, a2
	addi	a2, a2, 1
	sb	a4, 0(a5)
	bne	a1, a2, .LBB6_3
.LBB6_4:
	mv	t0, a3
.LBB6_5:
	mv	a0, t0
	ret
.Lfunc_end6:
	.size	realloc_beebs, .Lfunc_end6-realloc_beebs

	.globl	free_beebs
	.p2align	1
	.type	free_beebs,@function
free_beebs:
	ret
.Lfunc_end7:
	.size	free_beebs, .Lfunc_end7-free_beebs

	.type	seed,@object
	.section	.sbss,"aw",@nobits
	.p2align	2
seed:
	.word	0
	.size	seed, 4

	.type	heap_ptr,@object
	.p2align	2
heap_ptr:
	.word	0
	.size	heap_ptr, 4

	.type	heap_end,@object
	.p2align	2
heap_end:
	.word	0
	.size	heap_end, 4

	.type	heap_requested,@object
	.p2align	2
heap_requested:
	.word	0
	.size	heap_requested, 4

	.ident	"clang version 15.0.7 (https://gitee.com/openeuler/llvm-project.git e748863234fee09e2977c907a89c05edd109e6b8)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
