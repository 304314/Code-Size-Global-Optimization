	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"rnd_output0.c"
	.file	1 "/home/shiyanchu/outline_test" "llvm-install/bin/../lib/clang-runtimes/riscv32/include/bits/alltypes.h"
	.file	2 "/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" "rnd_output0.c"
	.file	3 "/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" "./rnd_globals.h"
	.file	4 "/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" "./csmith.h"
	.file	5 "/home/shiyanchu/outline_test" "linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h"
	.globl	func_40                         # -- Begin function func_40
	.p2align	1
	.type	func_40,@function
func_40:                                # @func_40
.Lfunc_begin0:
	.loc	2 66 0                          # rnd_output0.c:66:0
	.cfi_sections .debug_frame
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -2032
	.cfi_def_cfa_offset 2032
	sw	ra, 2028(sp)                    # 4-byte Folded Spill
	sw	s0, 2024(sp)                    # 4-byte Folded Spill
	sw	s1, 2020(sp)                    # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	.cfi_offset s1, -12
	addi	s0, sp, 2032
	.cfi_def_cfa s0, 0
	lui	a7, 3
	addi	a7, a7, 1840
	sub	sp, sp, a7
	addi	a7, s0, -2048
	addi	a7, a7, -1476
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 756(t0)                     # 4-byte Folded Spill
	lui	a7, 1
	addi	a7, a7, 1832
	sub	a7, s0, a7
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 732(t0)                     # 4-byte Folded Spill
	lui	a7, 2
	addi	a7, a7, -216
	sub	a7, s0, a7
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 736(t0)                     # 4-byte Folded Spill
	lui	a7, 2
	addi	a7, a7, 1832
	sub	a7, s0, a7
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 740(t0)                     # 4-byte Folded Spill
	lui	a7, 3
	addi	a7, a7, 972
	sub	a7, s0, a7
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 744(t0)                     # 4-byte Folded Spill
	lui	a7, 4
	addi	a7, a7, -1056
	sub	a7, s0, a7
	lui	t0, 4
	sub	t0, s0, t0
	sw	a7, 748(t0)                     # 4-byte Folded Spill
                                        # kill: def $x17 killed $x14
                                        # kill: def $x17 killed $x13
                                        # kill: def $x17 killed $x12
                                        # kill: def $x17 killed $x11
	sw	a0, -24(s0)
	sw	a2, -28(s0)
	sw	a1, -32(s0)
	sw	a4, -36(s0)
	sw	a3, -40(s0)
	sw	a5, -44(s0)
	sw	a6, -48(s0)
.Ltmp0:
	.loc	2 67 15 prologue_end            # rnd_output0.c:67:15
	lui	a0, %hi(g_136)
	addi	a0, a0, %lo(g_136)
	addi	a0, a0, 28
	sw	a0, -52(s0)
	.loc	2 68 15                         # rnd_output0.c:68:15
	lui	a0, %hi(g_69)
	addi	a0, a0, %lo(g_69)
	addi	a0, a0, 36
	sw	a0, -56(s0)
	.loc	2 69 16                         # rnd_output0.c:69:16
	lui	a0, %hi(g_71)
	addi	a0, a0, %lo(g_71)
	sw	a0, -60(s0)
	.loc	2 70 15                         # rnd_output0.c:70:15
	lui	a0, %hi(g_200)
	addi	a0, a0, %lo(g_200)
	sw	a0, -64(s0)
	addi	a1, s0, -64
	.loc	2 71 35                         # rnd_output0.c:71:35
	lui	a0, 4
	sub	a0, s0, a0
	sw	a1, 752(a0)                     # 4-byte Folded Spill
	sw	a1, -400(s0)
	sw	a1, -396(s0)
	li	a0, 0
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 760(a2)                     # 4-byte Folded Spill
	sw	a0, -392(s0)
	sw	a1, -388(s0)
	sw	a1, -384(s0)
	sw	a1, -380(s0)
	sw	a0, -376(s0)
	.loc	2 71 90 is_stmt 0               # rnd_output0.c:71:90
	sw	a1, -372(s0)
	sw	a1, -368(s0)
	sw	a0, -364(s0)
	sw	a1, -360(s0)
	sw	a1, -356(s0)
	sw	a1, -352(s0)
	sw	a0, -348(s0)
	.loc	2 71 145                        # rnd_output0.c:71:145
	sw	a1, -344(s0)
	sw	a1, -340(s0)
	sw	a0, -336(s0)
	sw	a1, -332(s0)
	sw	a1, -328(s0)
	sw	a1, -324(s0)
	sw	a1, -320(s0)
	.loc	2 71 198                        # rnd_output0.c:71:198
	sw	a1, -316(s0)
	sw	a0, -312(s0)
	sw	a1, -308(s0)
	sw	a1, -304(s0)
	sw	a1, -300(s0)
	sw	a1, -296(s0)
	sw	a0, -292(s0)
	.loc	2 71 255                        # rnd_output0.c:71:255
	sw	a0, -288(s0)
	sw	a1, -284(s0)
	sw	a1, -280(s0)
	sw	a1, -276(s0)
	sw	a1, -272(s0)
	sw	a1, -268(s0)
	sw	a1, -264(s0)
	.loc	2 71 308                        # rnd_output0.c:71:308
	sw	a1, -260(s0)
	sw	a1, -256(s0)
	sw	a0, -252(s0)
	sw	a1, -248(s0)
	sw	a1, -244(s0)
	sw	a1, -240(s0)
	sw	a0, -236(s0)
	.loc	2 71 363                        # rnd_output0.c:71:363
	sw	a1, -232(s0)
	sw	a1, -228(s0)
	sw	a1, -224(s0)
	sw	a1, -220(s0)
	sw	a1, -216(s0)
	sw	a1, -212(s0)
	sw	a1, -208(s0)
	.loc	2 71 414                        # rnd_output0.c:71:414
	sw	a1, -204(s0)
	sw	a1, -200(s0)
	sw	a0, -196(s0)
	sw	a1, -192(s0)
	sw	a1, -188(s0)
	sw	a0, -184(s0)
	sw	a1, -180(s0)
	.loc	2 71 471                        # rnd_output0.c:71:471
	sw	a1, -176(s0)
	sw	a1, -172(s0)
	sw	a1, -168(s0)
	sw	a1, -164(s0)
	sw	a1, -160(s0)
	sw	a1, -156(s0)
	sw	a1, -152(s0)
	.loc	2 71 522                        # rnd_output0.c:71:522
	sw	a1, -148(s0)
	sw	a1, -144(s0)
	sw	a0, -140(s0)
	sw	a0, -136(s0)
	sw	a1, -132(s0)
	sw	a1, -128(s0)
	sw	a0, -124(s0)
	.loc	2 71 579                        # rnd_output0.c:71:579
	sw	a0, -120(s0)
	sw	a1, -116(s0)
	sw	a1, -112(s0)
	sw	a1, -108(s0)
	sw	a1, -104(s0)
	sw	a1, -100(s0)
	sw	a1, -96(s0)
	.loc	2 71 632                        # rnd_output0.c:71:632
	sw	a1, -92(s0)
	sw	a0, -88(s0)
	sw	a1, -84(s0)
	sw	a1, -80(s0)
	sw	a1, -76(s0)
	sw	a0, -72(s0)
	sw	a0, -68(s0)
	.loc	2 72 15 is_stmt 1               # rnd_output0.c:72:15
	lui	a1, %hi(g_123)
	addi	a1, a1, %lo(g_123)
	sw	a1, -404(s0)
	.loc	2 74 20                         # rnd_output0.c:74:20
	lui	a1, %hi(g_8)
	addi	a1, a1, %lo(g_8)
	addi	a1, a1, 360
	sw	a1, -416(s0)
	.loc	2 75 15                         # rnd_output0.c:75:15
	sw	a0, -420(s0)
	sw	a0, -424(s0)
	li	a0, 1
	sw	a0, -428(s0)
	lui	a0, 904965
	addi	a0, a0, 1900
	sw	a0, -432(s0)
	.loc	2 76 15                         # rnd_output0.c:76:15
	lui	a0, %hi(.L__const.func_40.l_551)
	addi	a1, a0, %lo(.L__const.func_40.l_551)
	addi	a0, s0, -648
	li	a2, 216
	call	memcpy@plt
	.loc	2 77 25                         # rnd_output0.c:77:25
	addi	a0, s0, -608
	.loc	2 77 16 is_stmt 0               # rnd_output0.c:77:16
	sw	a0, -652(s0)
	.loc	2 78 15 is_stmt 1               # rnd_output0.c:78:15
	lui	a0, %hi(.L__const.func_40.l_552)
	addi	a1, a0, %lo(.L__const.func_40.l_552)
	addi	a0, s0, -1232
	li	a2, 576
	call	memcpy@plt
                                        # kill: def $x11 killed $x10
	.loc	2 79 14                         # rnd_output0.c:79:14
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 760(a0)                     # 4-byte Folded Reload
	sw	a0, -1236(s0)
	li	a0, 6
	sw	a0, -1240(s0)
	.loc	2 80 20                         # rnd_output0.c:80:20
	lui	a0, %hi(g_3)
	addi	a0, a0, %lo(g_3)
	sw	a0, -1244(s0)
	.loc	2 81 13                         # rnd_output0.c:81:13
	lui	a0, %hi(.L__const.func_40.l_775)
	addi	a1, a0, %lo(.L__const.func_40.l_775)
	addi	a0, s0, -2048
	addi	a0, a0, -168
	li	a2, 972
	call	memcpy@plt
	.loc	2 82 14                         # rnd_output0.c:82:14
	lui	a0, %hi(.L__const.func_40.l_792)
	addi	a1, a0, %lo(.L__const.func_40.l_792)
	addi	a0, s0, -2048
	addi	a0, a0, -488
	li	a2, 320
	call	memcpy@plt
	.loc	2 83 14                         # rnd_output0.c:83:14
	lui	a0, %hi(.L__const.func_40.l_969)
	addi	a1, a0, %lo(.L__const.func_40.l_969)
	addi	a0, s0, -2048
	addi	a0, a0, -848
	li	a2, 360
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 756(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 760(a0)                     # 4-byte Folded Reload
	li	a2, 83
	.loc	2 84 12                         # rnd_output0.c:84:12
	sb	a2, 627(a1)
	.loc	2 85 21                         # rnd_output0.c:85:21
	sw	a0, 620(a1)
	li	a2, 252
	.loc	2 86 13                         # rnd_output0.c:86:13
	sb	a2, 619(a1)
	.loc	2 87 14                         # rnd_output0.c:87:14
	sw	a0, 608(a1)
	li	a2, 4
	sw	a2, 604(a1)
	.loc	2 88 20                         # rnd_output0.c:88:20
	lui	a2, %hi(g_13)
	addi	a2, a2, %lo(g_13)
	sw	a2, 600(a1)
	.loc	2 89 25                         # rnd_output0.c:89:25
	sw	a0, 596(a1)
	lui	a2, 553386
	addi	a2, a2, 1876
	.loc	2 90 13                         # rnd_output0.c:90:13
	sw	a2, 592(a1)
	.loc	2 91 14                         # rnd_output0.c:91:14
	sw	a0, 576(a1)
	sw	a0, 572(a1)
	lui	a2, 218622
	addi	a2, a2, 601
	sw	a2, 568(a1)
	lui	a2, 894192
	addi	a2, a2, -662
	sw	a2, 564(a1)
	.loc	2 92 16                         # rnd_output0.c:92:16
	lui	a2, %hi(g_73)
	addi	a2, a2, %lo(g_73)
	sw	a2, 560(a1)
	.loc	2 94 14                         # rnd_output0.c:94:14
	sh	a0, 474(a1)
	.loc	2 95 24                         # rnd_output0.c:95:24
	addi	a2, s0, -960
	.loc	2 95 14 is_stmt 0               # rnd_output0.c:95:14
	sw	a2, 468(a1)
	li	a2, -1
	.loc	2 96 14 is_stmt 1               # rnd_output0.c:96:14
	sw	a2, 464(a1)
	.loc	2 98 13                         # rnd_output0.c:98:13
	sh	a2, 386(a1)
	addi	a2, s0, -432
	.loc	2 99 14                         # rnd_output0.c:99:14
	sw	a2, 380(a1)
	addi	a2, s0, -2048
	addi	a2, a2, -884
	.loc	2 100 14                        # rnd_output0.c:100:14
	sw	a2, 376(a1)
	.loc	2 101 20                        # rnd_output0.c:101:20
	lui	a2, %hi(g_147)
	addi	a2, a2, %lo(g_147)
	sw	a2, 372(a1)
.Ltmp1:
	.loc	2 103 12                        # rnd_output0.c:103:12
	sw	a0, 368(a1)
	.loc	2 103 10 is_stmt 0              # rnd_output0.c:103:10
	j	.LBB0_1
.LBB0_1:                                # =>This Inner Loop Header: Depth=1
.Ltmp2:
	.loc	2 103 17                        # rnd_output0.c:103:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 368(a0)
	li	a0, 1
.Ltmp3:
	.loc	2 103 5                         # rnd_output0.c:103:5
	blt	a0, a1, .LBB0_4
	j	.LBB0_2
.LBB0_2:                                #   in Loop: Header=BB0_1 Depth=1
.Ltmp4:
	.loc	2 104 15 is_stmt 1              # rnd_output0.c:104:15
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a0)
	.loc	2 104 9 is_stmt 0               # rnd_output0.c:104:9
	slli	a1, a0, 2
	addi	a0, s0, -412
	add	a1, a1, a0
	addi	a0, s0, -404
	.loc	2 104 18                        # rnd_output0.c:104:18
	sw	a0, 0(a1)
	.loc	2 104 9                         # rnd_output0.c:104:9
	j	.LBB0_3
.LBB0_3:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	2 103 25 is_stmt 1              # rnd_output0.c:103:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a1)
	addi	a0, a0, 1
	sw	a0, 368(a1)
	.loc	2 103 5 is_stmt 0               # rnd_output0.c:103:5
	j	.LBB0_1
.Ltmp5:
.LBB0_4:
	.loc	2 0 5                           # rnd_output0.c:0:5
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp6:
	.loc	2 105 12 is_stmt 1              # rnd_output0.c:105:12
	sw	a0, 368(a1)
	.loc	2 105 10 is_stmt 0              # rnd_output0.c:105:10
	j	.LBB0_5
.LBB0_5:                                # =>This Inner Loop Header: Depth=1
.Ltmp7:
	.loc	2 105 17                        # rnd_output0.c:105:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 368(a0)
	li	a0, 9
.Ltmp8:
	.loc	2 105 5                         # rnd_output0.c:105:5
	blt	a0, a1, .LBB0_8
	j	.LBB0_6
.LBB0_6:                                #   in Loop: Header=BB0_5 Depth=1
.Ltmp9:
	.loc	2 106 16 is_stmt 1              # rnd_output0.c:106:16
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a0)
	.loc	2 106 9 is_stmt 0               # rnd_output0.c:106:9
	slli	a1, a0, 3
	addi	a0, s0, -2048
	addi	a0, a0, -1000
	add	a1, a1, a0
	lui	a0, 519007
	addi	a0, a0, -1952
	.loc	2 106 19                        # rnd_output0.c:106:19
	sw	a0, 4(a1)
	lui	a0, 443408
	addi	a0, a0, -2023
	sw	a0, 0(a1)
	.loc	2 106 9                         # rnd_output0.c:106:9
	j	.LBB0_7
.LBB0_7:                                #   in Loop: Header=BB0_5 Depth=1
	.loc	2 105 26 is_stmt 1              # rnd_output0.c:105:26
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a1)
	addi	a0, a0, 1
	sw	a0, 368(a1)
	.loc	2 105 5 is_stmt 0               # rnd_output0.c:105:5
	j	.LBB0_5
.Ltmp10:
.LBB0_8:
	.loc	2 0 5                           # rnd_output0.c:0:5
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp11:
	.loc	2 107 12 is_stmt 1              # rnd_output0.c:107:12
	sw	a0, 368(a1)
	.loc	2 107 10 is_stmt 0              # rnd_output0.c:107:10
	j	.LBB0_9
.LBB0_9:                                # =>This Inner Loop Header: Depth=1
.Ltmp12:
	.loc	2 107 17                        # rnd_output0.c:107:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 368(a0)
	li	a0, 8
.Ltmp13:
	.loc	2 107 5                         # rnd_output0.c:107:5
	blt	a0, a1, .LBB0_12
	j	.LBB0_10
.LBB0_10:                               #   in Loop: Header=BB0_9 Depth=1
.Ltmp14:
	.loc	2 108 16 is_stmt 1              # rnd_output0.c:108:16
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a0)
	.loc	2 108 9 is_stmt 0               # rnd_output0.c:108:9
	slli	a1, a0, 3
	addi	a0, s0, -2048
	addi	a0, a0, -1088
	add	a1, a1, a0
	li	a0, -1
	.loc	2 108 19                        # rnd_output0.c:108:19
	sw	a0, 4(a1)
	li	a0, -5
	sw	a0, 0(a1)
	.loc	2 108 9                         # rnd_output0.c:108:9
	j	.LBB0_11
.LBB0_11:                               #   in Loop: Header=BB0_9 Depth=1
	.loc	2 107 25 is_stmt 1              # rnd_output0.c:107:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 368(a1)
	addi	a0, a0, 1
	sw	a0, 368(a1)
	.loc	2 107 5 is_stmt 0               # rnd_output0.c:107:5
	j	.LBB0_9
.Ltmp15:
.LBB0_12:
	.loc	2 109 52 is_stmt 1              # rnd_output0.c:109:52
	lui	a0, %hi(g_3)
	lw	a0, %lo(g_3)(a0)
	lui	a1, 484211
	addi	a1, a1, -857
	.loc	2 109 56 is_stmt 0              # rnd_output0.c:109:56
	slt	a0, a0, a1
	.loc	2 109 73                        # rnd_output0.c:109:73
	lui	a2, %hi(g_325)
	lw	a1, %lo(g_325+4)(a2)
	lw	a2, %lo(g_325)(a2)
	.loc	2 109 71                        # rnd_output0.c:109:71
	sltu	a0, a0, a2
	snez	a1, a1
	or	a2, a0, a1
	.loc	2 109 40                        # rnd_output0.c:109:40
	lw	a1, -56(s0)
	.loc	2 109 47                        # rnd_output0.c:109:47
	lw	a0, 0(a1)
	or	a0, a0, a2
	sw	a0, 0(a1)
	li	a1, 1
	.loc	2 109 81                        # rnd_output0.c:109:81
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 728(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_16
	j	.LBB0_13
.LBB0_13:
	.loc	2 109 164                       # rnd_output0.c:109:164
	lw	a1, -60(s0)
	addi	a0, s0, -24
	.loc	2 109 171                       # rnd_output0.c:109:171
	sw	a0, 0(a1)
	.loc	2 109 159                       # rnd_output0.c:109:159
	lui	a1, %hi(g_467)
	addi	a1, a1, %lo(g_467)
	sw	a0, 12(a1)
	li	a0, 1
	.loc	2 109 112                       # rnd_output0.c:109:112
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 720(a1)                     # 4-byte Folded Spill
	call	safe_unary_minus_func_uint8_t_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 720(a1)                     # 4-byte Folded Reload
	.loc	2 109 219                       # rnd_output0.c:109:219
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 724(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_15
	j	.LBB0_14
.LBB0_14:
	.loc	2 109 325                       # rnd_output0.c:109:325
	lui	a1, %hi(g_477)
	lui	a0, 4
	sub	a0, s0, a0
	sw	a1, 716(a0)                     # 4-byte Folded Spill
	addi	a0, s0, -32
	sw	a0, %lo(g_477)(a1)
	.loc	2 109 334                       # rnd_output0.c:109:334
	lui	a1, %hi(g_123)
	addi	a1, a1, %lo(g_123)
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 109 362                       # rnd_output0.c:109:362
	lw	a1, -24(s0)
	.loc	2 109 361                       # rnd_output0.c:109:361
	lw	a1, 0(a1)
	.loc	2 109 358                       # rnd_output0.c:109:358
	xor	a0, a0, a1
	.loc	2 109 291                       # rnd_output0.c:109:291
	slli	a0, a0, 24
	srai	a0, a0, 24
	li	a1, -66
	call	safe_add_func_int8_t_s_s
                                        # kill: def $x11 killed $x10
	.loc	2 109 382                       # rnd_output0.c:109:382
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 716(a0)                     # 4-byte Folded Reload
	lw	a1, %lo(g_477)(a0)
	.loc	2 109 381                       # rnd_output0.c:109:381
	lw	a0, 0(a1)
	lw	a1, 4(a1)
	.loc	2 109 287                       # rnd_output0.c:109:287
	sw	a1, -28(s0)
	sw	a0, -32(s0)
	.loc	2 109 280                       # rnd_output0.c:109:280
	or	a0, a0, a1
	seqz	a0, a0
	.loc	2 109 395                       # rnd_output0.c:109:395
	lw	a1, -48(s0)
	.loc	2 109 392                       # rnd_output0.c:109:392
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 109 410                       # rnd_output0.c:109:410
	lui	a1, %hi(g_116)
	lbu	a1, %lo(g_116)(a1)
	.loc	2 109 251                       # rnd_output0.c:109:251
	call	safe_mul_func_uint8_t_u_u
	.loc	2 109 419                       # rnd_output0.c:109:419
	lhu	a1, -48(s0)
	.loc	2 109 223                       # rnd_output0.c:109:223
	call	safe_div_func_uint16_t_u_u
	.loc	2 109 219                       # rnd_output0.c:109:219
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 724(a1)                     # 4-byte Folded Spill
	j	.LBB0_15
.LBB0_15:
	.loc	2 0 219                         # rnd_output0.c:0:219
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 724(a0)                     # 4-byte Folded Reload
	.loc	2 109 219                       # rnd_output0.c:109:219
	andi	a0, a0, 1
	li	a1, -57
	.loc	2 109 85                        # rnd_output0.c:109:85
	call	safe_sub_func_int8_t_s_s
	.loc	2 109 81                        # rnd_output0.c:109:81
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 728(a1)                     # 4-byte Folded Spill
	j	.LBB0_16
.LBB0_16:
	.loc	2 0 81                          # rnd_output0.c:0:81
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 728(a0)                     # 4-byte Folded Reload
	.loc	2 109 36                        # rnd_output0.c:109:36
	andi	a0, a0, 1
	.loc	2 109 438                       # rnd_output0.c:109:438
	lw	a3, -36(s0)
	lw	a2, -40(s0)
	li	a1, 0
	.loc	2 109 10                        # rnd_output0.c:109:10
	call	safe_mul_func_int64_t_s_s
	or	a0, a0, a1
.Ltmp16:
	.loc	2 109 9                         # rnd_output0.c:109:9
	beqz	a0, .LBB0_21
	j	.LBB0_17
.LBB0_17:
.Ltmp17:
	.loc	2 111 24 is_stmt 1              # rnd_output0.c:111:24
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_147)
	addi	a0, a0, %lo(g_147)
	sw	a0, 356(a1)
.Ltmp18:
	.loc	2 112 20                        # rnd_output0.c:112:20
	lui	a1, %hi(g_325)
	li	a0, -1
	sw	a0, %lo(g_325+4)(a1)
	li	a0, -24
	sw	a0, %lo(g_325)(a1)
	.loc	2 112 14 is_stmt 0              # rnd_output0.c:112:14
	j	.LBB0_18
.LBB0_18:
.Ltmp19:
	.loc	2 112 30                        # rnd_output0.c:112:30
	lui	a1, %hi(g_325)
	lw	a0, %lo(g_325+4)(a1)
	lw	a1, %lo(g_325)(a1)
	.loc	2 112 36                        # rnd_output0.c:112:36
	sltiu	a1, a1, 24
	seqz	a0, a0
	and	a0, a0, a1
.Ltmp20:
	.loc	2 112 9                         # rnd_output0.c:112:9
	beqz	a0, .LBB0_20
	j	.LBB0_19
.LBB0_19:
.Ltmp21:
	.loc	2 114 20 is_stmt 1              # rnd_output0.c:114:20
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 356(a0)
	.loc	2 114 13 is_stmt 0              # rnd_output0.c:114:13
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp22:
.LBB0_20:
	.loc	2 116 16 is_stmt 1              # rnd_output0.c:116:16
	lw	a0, -416(s0)
	.loc	2 116 9 is_stmt 0               # rnd_output0.c:116:9
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp23:
.LBB0_21:
	.loc	2 120 17 is_stmt 1              # rnd_output0.c:120:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_70)
	addi	a0, a0, %lo(g_70)
	addi	a0, a0, 80
	sw	a0, 352(a1)
	li	a0, 0
	.loc	2 121 18                        # rnd_output0.c:121:18
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 712(a2)                     # 4-byte Folded Spill
	sw	a0, 336(a1)
	sw	a0, 332(a1)
	li	a0, 1
	sw	a0, 328(a1)
	li	a0, -1
	sw	a0, 324(a1)
	.loc	2 123 18                        # rnd_output0.c:123:18
	lui	a0, %hi(g_111)
	addi	a0, a0, %lo(g_111)
	sw	a0, 312(a1)
	lui	a0, 257185
	addi	a0, a0, -146
	.loc	2 124 18                        # rnd_output0.c:124:18
	sw	a0, 308(a1)
	.loc	2 125 18                        # rnd_output0.c:125:18
	lui	a0, %hi(.L__const.func_40.l_646)
	addi	a1, a0, %lo(.L__const.func_40.l_646)
	addi	a0, s0, -2048
	addi	a0, a0, -1456
	li	a2, 288
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 756(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 126 29                        # rnd_output0.c:126:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 712(a0)                     # 4-byte Folded Reload
	addi	a2, s0, -572
	.loc	2 126 20 is_stmt 0              # rnd_output0.c:126:20
	sw	a2, 16(a1)
	li	a2, 142
	.loc	2 128 17 is_stmt 1              # rnd_output0.c:128:17
	sb	a2, 11(a1)
	.loc	2 129 24                        # rnd_output0.c:129:24
	lui	a2, %hi(g_333)
	addi	a2, a2, %lo(g_333)
	sw	a2, 4(a1)
.Ltmp24:
	.loc	2 131 16                        # rnd_output0.c:131:16
	sw	a0, 0(a1)
	.loc	2 131 14 is_stmt 0              # rnd_output0.c:131:14
	j	.LBB0_22
.LBB0_22:                               # =>This Inner Loop Header: Depth=1
.Ltmp25:
	.loc	2 131 21                        # rnd_output0.c:131:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 0(a0)
	li	a0, 1
.Ltmp26:
	.loc	2 131 9                         # rnd_output0.c:131:9
	blt	a0, a1, .LBB0_25
	j	.LBB0_23
.LBB0_23:                               #   in Loop: Header=BB0_22 Depth=1
.Ltmp27:
	.loc	2 132 25 is_stmt 1              # rnd_output0.c:132:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	addi	a0, s0, -408
	.loc	2 132 19 is_stmt 0              # rnd_output0.c:132:19
	lw	a1, 0(a1)
	.loc	2 132 13                        # rnd_output0.c:132:13
	slli	a2, a1, 2
	addi	a1, s0, -2048
	addi	a1, a1, -1160
	add	a1, a1, a2
	.loc	2 132 22                        # rnd_output0.c:132:22
	sw	a0, 0(a1)
	.loc	2 132 13                        # rnd_output0.c:132:13
	j	.LBB0_24
.LBB0_24:                               #   in Loop: Header=BB0_22 Depth=1
	.loc	2 131 29 is_stmt 1              # rnd_output0.c:131:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 0(a1)
	addi	a0, a0, 1
	sw	a0, 0(a1)
	.loc	2 131 9 is_stmt 0               # rnd_output0.c:131:9
	j	.LBB0_22
.Ltmp28:
.LBB0_25:
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp29:
	.loc	2 133 16 is_stmt 1              # rnd_output0.c:133:16
	sw	a0, 0(a1)
	.loc	2 133 14 is_stmt 0              # rnd_output0.c:133:14
	j	.LBB0_26
.LBB0_26:                               # =>This Inner Loop Header: Depth=1
.Ltmp30:
	.loc	2 133 21                        # rnd_output0.c:133:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 0(a0)
	li	a0, 0
.Ltmp31:
	.loc	2 133 9                         # rnd_output0.c:133:9
	blt	a0, a1, .LBB0_29
	j	.LBB0_27
.LBB0_27:                               #   in Loop: Header=BB0_26 Depth=1
.Ltmp32:
	.loc	2 134 19 is_stmt 1              # rnd_output0.c:134:19
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 0(a0)
	.loc	2 134 13 is_stmt 0              # rnd_output0.c:134:13
	slli	a1, a0, 2
	addi	a0, s0, -2048
	addi	a0, a0, -1464
	add	a1, a1, a0
	.loc	2 134 22                        # rnd_output0.c:134:22
	lui	a0, %hi(g_73)
	addi	a0, a0, %lo(g_73)
	sw	a0, 0(a1)
	.loc	2 134 13                        # rnd_output0.c:134:13
	j	.LBB0_28
.LBB0_28:                               #   in Loop: Header=BB0_26 Depth=1
	.loc	2 133 29 is_stmt 1              # rnd_output0.c:133:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 0(a1)
	addi	a0, a0, 1
	sw	a0, 0(a1)
	.loc	2 133 9 is_stmt 0               # rnd_output0.c:133:9
	j	.LBB0_26
.Ltmp33:
.LBB0_29:
	.loc	2 135 72 is_stmt 1              # rnd_output0.c:135:72
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_147)
	.loc	2 135 134 is_stmt 0             # rnd_output0.c:135:134
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 708(a2)                     # 4-byte Folded Spill
	lw	a1, 352(a0)
	.loc	2 135 106                       # rnd_output0.c:135:106
	lb	a0, -44(s0)
	.loc	2 135 141                       # rnd_output0.c:135:141
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 704(a2)                     # 4-byte Folded Spill
	sb	a0, 0(a1)
	lui	a0, 487851
	addi	a1, a0, -582
	li	a0, -1
	.loc	2 135 201                       # rnd_output0.c:135:201
	call	safe_div_func_int32_t_s_s
	.loc	2 135 171                       # rnd_output0.c:135:171
	andi	a0, a0, 255
	li	a1, 2
	call	safe_rshift_func_uint8_t_u_s
                                        # kill: def $x11 killed $x10
	.loc	2 135 106                       # rnd_output0.c:135:106
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 704(a0)                     # 4-byte Folded Reload
	li	a1, 0
	call	safe_mul_func_int8_t_s_s
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 708(a0)                     # 4-byte Folded Reload
	.loc	2 135 280                       # rnd_output0.c:135:280
	lhu	a0, -44(s0)
	.loc	2 135 296                       # rnd_output0.c:135:296
	lhu	a1, %lo(g_147)(a1)
	.loc	2 135 23                        # rnd_output0.c:135:23
	call	safe_add_func_uint16_t_u_u
	.loc	2 135 303                       # rnd_output0.c:135:303
	lui	a2, %hi(g_325)
	lw	a1, %lo(g_325+4)(a2)
	lw	a2, %lo(g_325)(a2)
	.loc	2 135 301                       # rnd_output0.c:135:301
	sltu	a0, a0, a2
	snez	a1, a1
	or	a2, a0, a1
	.loc	2 135 11                        # rnd_output0.c:135:11
	lui	a0, %hi(g_200)
	lw	a1, %lo(g_200)(a0)
	.loc	2 135 18                        # rnd_output0.c:135:18
	lw	a0, 0(a1)
	or	a0, a0, a2
	sw	a0, 0(a1)
	j	.LBB0_30
.Ltmp34:
.LBB0_30:
	.loc	2 137 16 is_stmt 1              # rnd_output0.c:137:16
	lui	a1, %hi(g_642)
	li	a0, 0
	sh	a0, %lo(g_642)(a1)
	.loc	2 137 10 is_stmt 0              # rnd_output0.c:137:10
	j	.LBB0_31
.LBB0_31:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_33 Depth 2
                                        #     Child Loop BB0_37 Depth 2
                                        #     Child Loop BB0_41 Depth 2
.Ltmp35:
	.loc	2 137 22                        # rnd_output0.c:137:22
	lui	a0, %hi(g_642)
	lhu	a1, %lo(g_642)(a0)
	li	a0, 2
.Ltmp36:
	.loc	2 137 5                         # rnd_output0.c:137:5
	blt	a0, a1, .LBB0_46
	j	.LBB0_32
.LBB0_32:                               #   in Loop: Header=BB0_31 Depth=1
.Ltmp37:
	.loc	2 139 18 is_stmt 1              # rnd_output0.c:139:18
	lui	a0, %hi(.L__const.func_40.l_764)
	addi	a1, a0, %lo(.L__const.func_40.l_764)
	addi	a0, s0, -2048
	addi	a0, a0, -1872
	li	a2, 384
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 732(a0)                     # 4-byte Folded Reload
	li	a0, 1
	.loc	2 140 17                        # rnd_output0.c:140:17
	sw	a0, 2004(a2)
	li	a1, 0
	.loc	2 141 17                        # rnd_output0.c:141:17
	lui	a0, 4
	sub	a0, s0, a0
	sw	a1, 700(a0)                     # 4-byte Folded Spill
	sw	a1, 2000(a2)
	sw	a1, 1996(a2)
	sw	a1, 1992(a2)
	sw	a1, 1988(a2)
	sw	a1, 1984(a2)
	addi	a5, s0, -2048
	addi	a5, a5, -1892
	lui	a0, 4
	sub	a0, s0, a0
	sw	a5, 664(a0)                     # 4-byte Folded Spill
	addi	a6, s0, -2048
	addi	a6, a6, -1896
	.loc	2 142 37                        # rnd_output0.c:142:37
	lui	a0, 4
	sub	a0, s0, a0
	sw	a6, 668(a0)                     # 4-byte Folded Spill
	sw	a6, 1600(a2)
	sw	a5, 1604(a2)
	sw	a6, 1608(a2)
	.loc	2 142 69 is_stmt 0              # rnd_output0.c:142:69
	sw	a1, 1612(a2)
	sw	a1, 1616(a2)
	lui	a0, %hi(g_8)
	addi	a0, a0, %lo(g_8)
	addi	a0, a0, 480
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 696(a3)                     # 4-byte Folded Spill
	sw	a0, 1620(a2)
	.loc	2 142 103                       # rnd_output0.c:142:103
	sw	a1, 1624(a2)
	sw	a1, 1628(a2)
	lui	a3, %hi(g_3)
	addi	a4, a3, %lo(g_3)
	lui	a3, 4
	sub	a3, s0, a3
	sw	a4, 672(a3)                     # 4-byte Folded Spill
	sw	a4, 1632(a2)
	.loc	2 142 128                       # rnd_output0.c:142:128
	sw	a0, 1636(a2)
	sw	a5, 1640(a2)
	sw	a0, 1644(a2)
	.loc	2 142 170                       # rnd_output0.c:142:170
	sw	a4, 1648(a2)
	sw	a0, 1652(a2)
	sw	a0, 1656(a2)
	.loc	2 142 205                       # rnd_output0.c:142:205
	sw	a0, 1660(a2)
	.loc	2 142 221                       # rnd_output0.c:142:221
	addi	a3, s0, -2048
	addi	a3, a3, -1744
	.loc	2 142 205                       # rnd_output0.c:142:205
	sw	a3, 1664(a2)
	sw	a0, 1668(a2)
	.loc	2 142 254                       # rnd_output0.c:142:254
	sw	a1, 1672(a2)
	sw	a5, 1676(a2)
	sw	a0, 1680(a2)
	.loc	2 142 289                       # rnd_output0.c:142:289
	sw	a1, 1684(a2)
	sw	a0, 1688(a2)
	sw	a0, 1692(a2)
	.loc	2 142 330                       # rnd_output0.c:142:330
	sw	a6, 1696(a2)
	sw	a4, 1700(a2)
	sw	a0, 1704(a2)
	.loc	2 142 361                       # rnd_output0.c:142:361
	sw	a0, 1708(a2)
	sw	a0, 1712(a2)
	sw	a4, 1716(a2)
	.loc	2 142 396                       # rnd_output0.c:142:396
	sw	a5, 1720(a2)
	sw	a5, 1724(a2)
	sw	a0, 1728(a2)
	.loc	2 142 432                       # rnd_output0.c:142:432
	sw	a5, 1732(a2)
	sw	a3, 1736(a2)
	sw	a6, 1740(a2)
	.loc	2 142 475                       # rnd_output0.c:142:475
	sw	a0, 1744(a2)
	sw	a0, 1748(a2)
	sw	a5, 1752(a2)
	.loc	2 142 515                       # rnd_output0.c:142:515
	sw	a6, 1756(a2)
	sw	a5, 1760(a2)
	sw	a6, 1764(a2)
	.loc	2 142 547                       # rnd_output0.c:142:547
	sw	a1, 1768(a2)
	sw	a1, 1772(a2)
	sw	a0, 1776(a2)
	.loc	2 142 581                       # rnd_output0.c:142:581
	sw	a1, 1780(a2)
	sw	a1, 1784(a2)
	sw	a4, 1788(a2)
	.loc	2 142 608                       # rnd_output0.c:142:608
	sw	a0, 1792(a2)
	sw	a5, 1796(a2)
	sw	a0, 1800(a2)
	.loc	2 142 648                       # rnd_output0.c:142:648
	sw	a4, 1804(a2)
	sw	a0, 1808(a2)
	sw	a0, 1812(a2)
	.loc	2 142 683                       # rnd_output0.c:142:683
	sw	a0, 1816(a2)
	sw	a3, 1820(a2)
	sw	a0, 1824(a2)
	.loc	2 142 732                       # rnd_output0.c:142:732
	sw	a1, 1828(a2)
	sw	a5, 1832(a2)
	sw	a0, 1836(a2)
	.loc	2 142 769                       # rnd_output0.c:142:769
	sw	a1, 1840(a2)
	sw	a0, 1844(a2)
	sw	a0, 1848(a2)
	.loc	2 142 808                       # rnd_output0.c:142:808
	sw	a6, 1852(a2)
	sw	a4, 1856(a2)
	sw	a0, 1860(a2)
	.loc	2 142 839                       # rnd_output0.c:142:839
	sw	a0, 1864(a2)
	sw	a0, 1868(a2)
	sw	a4, 1872(a2)
	.loc	2 142 874                       # rnd_output0.c:142:874
	sw	a5, 1876(a2)
	sw	a5, 1880(a2)
	sw	a0, 1884(a2)
	.loc	2 142 912                       # rnd_output0.c:142:912
	sw	a5, 1888(a2)
	sw	a3, 1892(a2)
	sw	a6, 1896(a2)
	.loc	2 142 953                       # rnd_output0.c:142:953
	sw	a0, 1900(a2)
	sw	a0, 1904(a2)
	sw	a5, 1908(a2)
	.loc	2 142 993                       # rnd_output0.c:142:993
	sw	a6, 1912(a2)
	sw	a5, 1916(a2)
	sw	a6, 1920(a2)
	.loc	2 142 1025                      # rnd_output0.c:142:1025
	sw	a1, 1924(a2)
	sw	a1, 1928(a2)
	sw	a0, 1932(a2)
	.loc	2 142 1061                      # rnd_output0.c:142:1061
	sw	a1, 1936(a2)
	sw	a1, 1940(a2)
	sw	a4, 1944(a2)
	.loc	2 142 1086                      # rnd_output0.c:142:1086
	sw	a0, 1948(a2)
	sw	a5, 1952(a2)
	sw	a0, 1956(a2)
	.loc	2 142 1126                      # rnd_output0.c:142:1126
	sw	a4, 1960(a2)
	sw	a0, 1964(a2)
	sw	a0, 1968(a2)
	.loc	2 142 1161                      # rnd_output0.c:142:1161
	sw	a0, 1972(a2)
	sw	a3, 1976(a2)
	sw	a0, 1980(a2)
	.loc	2 145 18 is_stmt 1              # rnd_output0.c:145:18
	sw	a1, 1548(a2)
	lui	a0, 2
	addi	a0, a0, -1860
	.loc	2 146 18                        # rnd_output0.c:146:18
	sh	a0, 1546(a2)
	.loc	2 147 45                        # rnd_output0.c:147:45
	sw	a1, 584(a2)
	addi	a0, s0, -1240
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 676(a3)                     # 4-byte Folded Spill
	sw	a0, 588(a2)
	lui	a3, %hi(g_325)
	addi	a4, a3, %lo(g_325)
	lui	a3, 4
	sub	a3, s0, a3
	sw	a4, 680(a3)                     # 4-byte Folded Spill
	sw	a4, 592(a2)
	sw	a1, 596(a2)
	.loc	2 147 79 is_stmt 0              # rnd_output0.c:147:79
	sw	a1, 600(a2)
	sw	a4, 604(a2)
	sw	a0, 608(a2)
	lui	a3, %hi(g_123)
	addi	a3, a3, %lo(g_123)
	lui	a5, 4
	sub	a5, s0, a5
	sw	a3, 684(a5)                     # 4-byte Folded Spill
	sw	a3, 612(a2)
	.loc	2 147 111                       # rnd_output0.c:147:111
	sw	a1, 616(a2)
	.loc	2 147 122                       # rnd_output0.c:147:122
	li	a5, 17
	slli	a5, a5, 8
	sub	t0, s0, a5
	.loc	2 147 111                       # rnd_output0.c:147:111
	sw	t0, 620(a2)
	sw	a1, 624(a2)
	sw	a0, 628(a2)
	.loc	2 147 148                       # rnd_output0.c:147:148
	sw	a0, 632(a2)
	sw	a3, 636(a2)
	sw	a0, 640(a2)
	sw	a1, 644(a2)
	.loc	2 147 180                       # rnd_output0.c:147:180
	sw	a0, 648(a2)
	sw	a3, 652(a2)
	lui	a5, 1
	addi	a5, a5, 264
	sub	a5, s0, a5
	lui	a6, 4
	sub	a6, s0, a6
	sw	a5, 688(a6)                     # 4-byte Folded Spill
	sw	a5, 656(a2)
	sw	a3, 660(a2)
	.loc	2 147 215                       # rnd_output0.c:147:215
	lui	a6, 1
	addi	a6, a6, 240
	sub	a6, s0, a6
	.loc	2 147 213                       # rnd_output0.c:147:213
	sw	a6, 664(a2)
	sw	a0, 668(a2)
	sw	a0, 672(a2)
	sw	a3, 676(a2)
	.loc	2 147 246                       # rnd_output0.c:147:246
	sw	a3, 680(a2)
	sw	a4, 684(a2)
	sw	a0, 688(a2)
	sw	a4, 692(a2)
	.loc	2 147 276                       # rnd_output0.c:147:276
	sw	a6, 696(a2)
	sw	a1, 700(a2)
	sw	a3, 704(a2)
	sw	a4, 708(a2)
	.loc	2 147 311                       # rnd_output0.c:147:311
	sw	a4, 712(a2)
	sw	a4, 716(a2)
	sw	a3, 720(a2)
	sw	a1, 724(a2)
	.loc	2 147 343                       # rnd_output0.c:147:343
	sw	a3, 728(a2)
	sw	a1, 732(a2)
	.loc	2 147 361                       # rnd_output0.c:147:361
	lui	a7, 1
	addi	a7, a7, 248
	sub	a7, s0, a7
	.loc	2 147 343                       # rnd_output0.c:147:343
	lui	t1, 4
	sub	t1, s0, t1
	sw	a7, 692(t1)                     # 4-byte Folded Spill
	sw	a7, 736(a2)
	sw	a7, 740(a2)
	.loc	2 147 383                       # rnd_output0.c:147:383
	sw	a3, 744(a2)
	sw	a0, 748(a2)
	sw	a4, 752(a2)
	sw	a0, 756(a2)
	.loc	2 147 413                       # rnd_output0.c:147:413
	sw	a0, 760(a2)
	sw	a4, 764(a2)
	sw	a5, 768(a2)
	sw	a4, 772(a2)
	.loc	2 147 446                       # rnd_output0.c:147:446
	sw	a7, 776(a2)
	sw	a0, 780(a2)
	sw	a7, 784(a2)
	sw	a5, 788(a2)
	.loc	2 147 485                       # rnd_output0.c:147:485
	sw	a4, 792(a2)
	sw	t0, 796(a2)
	sw	a0, 800(a2)
	sw	a0, 804(a2)
	.loc	2 147 518                       # rnd_output0.c:147:518
	sw	a0, 808(a2)
	sw	a0, 812(a2)
	sw	a0, 816(a2)
	sw	a0, 820(a2)
	.loc	2 147 548                       # rnd_output0.c:147:548
	sw	a7, 824(a2)
	sw	a0, 828(a2)
	sw	a0, 832(a2)
	sw	a7, 836(a2)
	.loc	2 147 584                       # rnd_output0.c:147:584
	sw	a0, 840(a2)
	sw	a4, 844(a2)
	sw	a4, 848(a2)
	sw	a4, 852(a2)
	.loc	2 147 614                       # rnd_output0.c:147:614
	sw	a1, 856(a2)
	sw	a5, 860(a2)
	sw	a7, 864(a2)
	sw	a4, 868(a2)
	.loc	2 147 652                       # rnd_output0.c:147:652
	sw	a3, 872(a2)
	sw	a4, 876(a2)
	sw	a7, 880(a2)
	sw	a7, 884(a2)
	.loc	2 147 688                       # rnd_output0.c:147:688
	sw	a3, 888(a2)
	sw	a0, 892(a2)
	sw	a3, 896(a2)
	sw	a0, 900(a2)
	.loc	2 147 720                       # rnd_output0.c:147:720
	sw	a3, 904(a2)
	sw	a0, 908(a2)
	sw	a5, 912(a2)
	sw	a0, 916(a2)
	.loc	2 147 753                       # rnd_output0.c:147:753
	sw	a7, 920(a2)
	sw	t0, 924(a2)
	sw	a1, 928(a2)
	sw	a5, 932(a2)
	.loc	2 147 794                       # rnd_output0.c:147:794
	sw	a1, 936(a2)
	sw	a0, 940(a2)
	sw	a3, 944(a2)
	sw	a4, 948(a2)
	.loc	2 147 826                       # rnd_output0.c:147:826
	sw	a0, 952(a2)
	sw	a4, 956(a2)
	sw	a0, 960(a2)
	sw	a0, 964(a2)
	.loc	2 147 856                       # rnd_output0.c:147:856
	sw	a3, 968(a2)
	sw	a0, 972(a2)
	sw	a0, 976(a2)
	sw	a7, 980(a2)
	.loc	2 147 889                       # rnd_output0.c:147:889
	sw	a0, 984(a2)
	sw	a1, 988(a2)
	sw	a4, 992(a2)
	sw	a1, 996(a2)
	.loc	2 147 923                       # rnd_output0.c:147:923
	sw	a1, 1000(a2)
	sw	a4, 1004(a2)
	sw	a1, 1008(a2)
	sw	a4, 1012(a2)
	.loc	2 147 957                       # rnd_output0.c:147:957
	sw	a7, 1016(a2)
	sw	a1, 1020(a2)
	sw	a7, 1024(a2)
	sw	a5, 1028(a2)
	.loc	2 147 998                       # rnd_output0.c:147:998
	sw	a3, 1032(a2)
	sw	a1, 1036(a2)
	sw	a0, 1040(a2)
	sw	a0, 1044(a2)
	.loc	2 147 1030                      # rnd_output0.c:147:1030
	sw	a3, 1048(a2)
	sw	a0, 1052(a2)
	sw	a7, 1056(a2)
	sw	a3, 1060(a2)
	.loc	2 147 1065                      # rnd_output0.c:147:1065
	sw	a7, 1064(a2)
	sw	a0, 1068(a2)
	sw	a1, 1072(a2)
	sw	a7, 1076(a2)
	.loc	2 147 1103                      # rnd_output0.c:147:1103
	sw	a1, 1080(a2)
	sw	t0, 1084(a2)
	sw	a4, 1088(a2)
	sw	a4, 1092(a2)
	.loc	2 147 1138                      # rnd_output0.c:147:1138
	sw	a0, 1096(a2)
	sw	a5, 1100(a2)
	sw	a0, 1104(a2)
	sw	a3, 1108(a2)
	.loc	2 147 1171                      # rnd_output0.c:147:1171
	sw	a3, 1112(a2)
	sw	a1, 1116(a2)
	sw	a0, 1120(a2)
	sw	a7, 1124(a2)
	.loc	2 147 1206                      # rnd_output0.c:147:1206
	sw	a0, 1128(a2)
	sw	a1, 1132(a2)
	sw	a3, 1136(a2)
	sw	a4, 1140(a2)
	.loc	2 147 1238                      # rnd_output0.c:147:1238
	sw	a1, 1144(a2)
	sw	a0, 1148(a2)
	sw	a1, 1152(a2)
	sw	a1, 1156(a2)
	.loc	2 147 1274                      # rnd_output0.c:147:1274
	sw	a7, 1160(a2)
	sw	a4, 1164(a2)
	sw	a5, 1168(a2)
	sw	a5, 1172(a2)
	.loc	2 147 1313                      # rnd_output0.c:147:1313
	sw	a3, 1176(a2)
	sw	a3, 1180(a2)
	sw	a3, 1184(a2)
	sw	a3, 1188(a2)
	.loc	2 147 1343                      # rnd_output0.c:147:1343
	sw	a3, 1192(a2)
	sw	a4, 1196(a2)
	sw	a7, 1200(a2)
	sw	a0, 1204(a2)
	.loc	2 147 1376                      # rnd_output0.c:147:1376
	sw	a3, 1208(a2)
	sw	a0, 1212(a2)
	sw	a7, 1216(a2)
	sw	a7, 1220(a2)
	.loc	2 147 1414                      # rnd_output0.c:147:1414
	sw	a1, 1224(a2)
	sw	a0, 1228(a2)
	sw	a4, 1232(a2)
	sw	a0, 1236(a2)
	.loc	2 147 1446                      # rnd_output0.c:147:1446
	sw	a0, 1240(a2)
	sw	a4, 1244(a2)
	sw	a0, 1248(a2)
	sw	a3, 1252(a2)
	.loc	2 147 1476                      # rnd_output0.c:147:1476
	sw	a7, 1256(a2)
	sw	a3, 1260(a2)
	sw	a0, 1264(a2)
	sw	a5, 1268(a2)
	.loc	2 147 1512                      # rnd_output0.c:147:1512
	sw	a0, 1272(a2)
	sw	a4, 1276(a2)
	sw	a0, 1280(a2)
	sw	a1, 1284(a2)
	.loc	2 147 1544                      # rnd_output0.c:147:1544
	sw	a4, 1288(a2)
	sw	a0, 1292(a2)
	sw	a7, 1296(a2)
	sw	a4, 1300(a2)
	.loc	2 147 1577                      # rnd_output0.c:147:1577
	sw	a7, 1304(a2)
	sw	a1, 1308(a2)
	sw	a5, 1312(a2)
	sw	a7, 1316(a2)
	.loc	2 147 1618                      # rnd_output0.c:147:1618
	sw	a0, 1320(a2)
	sw	a1, 1324(a2)
	sw	a4, 1328(a2)
	sw	a3, 1332(a2)
	.loc	2 147 1650                      # rnd_output0.c:147:1650
	sw	a3, 1336(a2)
	sw	a5, 1340(a2)
	sw	a7, 1344(a2)
	sw	a4, 1348(a2)
	.loc	2 147 1686                      # rnd_output0.c:147:1686
	sw	a3, 1352(a2)
	sw	t0, 1356(a2)
	sw	a3, 1360(a2)
	sw	a7, 1364(a2)
	.loc	2 147 1722                      # rnd_output0.c:147:1722
	sw	a4, 1368(a2)
	sw	a0, 1372(a2)
	sw	a3, 1376(a2)
	sw	a3, 1380(a2)
	.loc	2 147 1754                      # rnd_output0.c:147:1754
	sw	a0, 1384(a2)
	sw	a0, 1388(a2)
	sw	a0, 1392(a2)
	sw	a0, 1396(a2)
	.loc	2 147 1784                      # rnd_output0.c:147:1784
	sw	a7, 1400(a2)
	sw	a1, 1404(a2)
	sw	a0, 1408(a2)
	sw	a5, 1412(a2)
	.loc	2 147 1822                      # rnd_output0.c:147:1822
	sw	a0, 1416(a2)
	sw	a1, 1420(a2)
	sw	a3, 1424(a2)
	sw	a4, 1428(a2)
	.loc	2 147 1854                      # rnd_output0.c:147:1854
	sw	a4, 1432(a2)
	sw	a4, 1436(a2)
	sw	a3, 1440(a2)
	sw	a1, 1444(a2)
	.loc	2 147 1886                      # rnd_output0.c:147:1886
	sw	a3, 1448(a2)
	sw	a1, 1452(a2)
	sw	a7, 1456(a2)
	sw	a7, 1460(a2)
	.loc	2 147 1924                      # rnd_output0.c:147:1924
	sw	a7, 1464(a2)
	sw	a3, 1468(a2)
	sw	a1, 1472(a2)
	sw	a0, 1476(a2)
	.loc	2 147 1959                      # rnd_output0.c:147:1959
	sw	a3, 1480(a2)
	sw	a1, 1484(a2)
	sw	a6, 1488(a2)
	sw	a4, 1492(a2)
	.loc	2 147 1994                      # rnd_output0.c:147:1994
	sw	a0, 1496(a2)
	sw	a0, 1500(a2)
	sw	a3, 1504(a2)
	sw	a6, 1508(a2)
	.loc	2 147 2027                      # rnd_output0.c:147:2027
	sw	a5, 1512(a2)
	sw	a5, 1516(a2)
	sw	a4, 1520(a2)
	sw	a3, 1524(a2)
	.loc	2 147 2063                      # rnd_output0.c:147:2063
	sw	a0, 1528(a2)
	sw	a0, 1532(a2)
	sw	a0, 1536(a2)
	sw	a0, 1540(a2)
	.loc	2 147 794                       # rnd_output0.c:147:794
	lui	a0, 1
	addi	a0, a0, 892
	sub	a3, s0, a0
	.loc	2 148 41 is_stmt 1              # rnd_output0.c:148:41
	sw	a3, 512(a2)
	lui	a0, 1
	addi	a0, a0, 1316
	sub	a0, s0, a0
	sw	a1, 516(a2)
	sw	a3, 520(a2)
	sw	a1, 524(a2)
	sw	a3, 528(a2)
	sw	a1, 532(a2)
	.loc	2 147 44                        # rnd_output0.c:147:44
	lui	a4, 1
	addi	a4, a4, 1216
	sub	a4, s0, a4
	.loc	2 148 118                       # rnd_output0.c:148:118
	sw	a4, 536(a2)
	sw	a1, 540(a2)
	sw	a4, 544(a2)
	sw	a1, 548(a2)
	sw	a4, 552(a2)
	sw	a1, 556(a2)
	.loc	2 148 195 is_stmt 0             # rnd_output0.c:148:195
	sw	a3, 560(a2)
	sw	a1, 564(a2)
	sw	a3, 568(a2)
	sw	a1, 572(a2)
	sw	a3, 576(a2)
	sw	a1, 580(a2)
	.loc	2 149 27 is_stmt 1              # rnd_output0.c:149:27
	sw	a0, 508(a2)
	lui	a0, 5
	addi	a0, a0, 1793
	.loc	2 150 17                        # rnd_output0.c:150:17
	sh	a0, 504(a2)
	lui	a0, 357744
	addi	a0, a0, 343
	sw	a0, 500(a2)
	lui	a0, 1
	addi	a0, a0, 1380
	sub	a0, s0, a0
	li	a2, 48
	.loc	2 151 18                        # rnd_output0.c:151:18
	call	memset@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 696(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 732(a1)                     # 4-byte Folded Reload
                                        # kill: def $x13 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 700(a0)                     # 4-byte Folded Reload
	li	a3, -1
	sh	a3, 458(a1)
	sh	a3, 470(a1)
	sh	a3, 482(a1)
	sh	a3, 494(a1)
	.loc	2 152 18                        # rnd_output0.c:152:18
	sw	a2, 448(a1)
	li	a2, 236
	.loc	2 154 16                        # rnd_output0.c:154:16
	sb	a2, 411(a1)
.Ltmp38:
	.loc	2 156 16                        # rnd_output0.c:156:16
	sw	a0, 404(a1)
	.loc	2 156 14 is_stmt 0              # rnd_output0.c:156:14
	j	.LBB0_33
.LBB0_33:                               #   Parent Loop BB0_31 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp39:
	.loc	2 156 21                        # rnd_output0.c:156:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a1, 404(a0)
	li	a0, 3
.Ltmp40:
	.loc	2 156 9                         # rnd_output0.c:156:9
	blt	a0, a1, .LBB0_36
	j	.LBB0_34
.LBB0_34:                               #   in Loop: Header=BB0_33 Depth=2
.Ltmp41:
	.loc	2 157 19 is_stmt 1              # rnd_output0.c:157:19
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a0)
	.loc	2 157 13 is_stmt 0              # rnd_output0.c:157:13
	slli	a1, a0, 3
	lui	a0, 1
	addi	a0, a0, 264
	sub	a0, s0, a0
	add	a1, a1, a0
	lui	a0, 6985
	addi	a0, a0, 1412
	.loc	2 157 22                        # rnd_output0.c:157:22
	sw	a0, 4(a1)
	lui	a0, 157586
	addi	a0, a0, -1618
	sw	a0, 0(a1)
	.loc	2 157 13                        # rnd_output0.c:157:13
	j	.LBB0_35
.LBB0_35:                               #   in Loop: Header=BB0_33 Depth=2
	.loc	2 156 29 is_stmt 1              # rnd_output0.c:156:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a1)
	addi	a0, a0, 1
	sw	a0, 404(a1)
	.loc	2 156 9 is_stmt 0               # rnd_output0.c:156:9
	j	.LBB0_33
.Ltmp42:
.LBB0_36:                               #   in Loop: Header=BB0_31 Depth=1
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp43:
	.loc	2 158 16 is_stmt 1              # rnd_output0.c:158:16
	sw	a0, 404(a1)
	.loc	2 158 14 is_stmt 0              # rnd_output0.c:158:14
	j	.LBB0_37
.LBB0_37:                               #   Parent Loop BB0_31 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp44:
	.loc	2 158 21                        # rnd_output0.c:158:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a1, 404(a0)
	li	a0, 3
.Ltmp45:
	.loc	2 158 9                         # rnd_output0.c:158:9
	blt	a0, a1, .LBB0_40
	j	.LBB0_38
.LBB0_38:                               #   in Loop: Header=BB0_37 Depth=2
.Ltmp46:
	.loc	2 159 19 is_stmt 1              # rnd_output0.c:159:19
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a0)
	.loc	2 159 13 is_stmt 0              # rnd_output0.c:159:13
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 280
	sub	a0, s0, a0
	add	a1, a1, a0
	li	a0, 0
	.loc	2 159 22                        # rnd_output0.c:159:22
	sw	a0, 0(a1)
	.loc	2 159 13                        # rnd_output0.c:159:13
	j	.LBB0_39
.LBB0_39:                               #   in Loop: Header=BB0_37 Depth=2
	.loc	2 158 29 is_stmt 1              # rnd_output0.c:158:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a1)
	addi	a0, a0, 1
	sw	a0, 404(a1)
	.loc	2 158 9 is_stmt 0               # rnd_output0.c:158:9
	j	.LBB0_37
.Ltmp47:
.LBB0_40:                               #   in Loop: Header=BB0_31 Depth=1
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp48:
	.loc	2 160 16 is_stmt 1              # rnd_output0.c:160:16
	sw	a0, 404(a1)
	.loc	2 160 14 is_stmt 0              # rnd_output0.c:160:14
	j	.LBB0_41
.LBB0_41:                               #   Parent Loop BB0_31 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp49:
	.loc	2 160 21                        # rnd_output0.c:160:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a1, 404(a0)
	li	a0, 8
.Ltmp50:
	.loc	2 160 9                         # rnd_output0.c:160:9
	blt	a0, a1, .LBB0_44
	j	.LBB0_42
.LBB0_42:                               #   in Loop: Header=BB0_41 Depth=2
.Ltmp51:
	.loc	2 161 20 is_stmt 1              # rnd_output0.c:161:20
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a0)
	.loc	2 161 13 is_stmt 0              # rnd_output0.c:161:13
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 1420
	sub	a0, s0, a0
	add	a1, a1, a0
	lui	a0, 396117
	addi	a0, a0, 2026
	.loc	2 161 23                        # rnd_output0.c:161:23
	sw	a0, 0(a1)
	.loc	2 161 13                        # rnd_output0.c:161:13
	j	.LBB0_43
.LBB0_43:                               #   in Loop: Header=BB0_41 Depth=2
	.loc	2 160 29 is_stmt 1              # rnd_output0.c:160:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 404(a1)
	addi	a0, a0, 1
	sw	a0, 404(a1)
	.loc	2 160 9 is_stmt 0               # rnd_output0.c:160:9
	j	.LBB0_41
.Ltmp52:
.LBB0_44:                               #   in Loop: Header=BB0_31 Depth=1
	.loc	2 162 5 is_stmt 1               # rnd_output0.c:162:5
	j	.LBB0_45
.Ltmp53:
.LBB0_45:                               #   in Loop: Header=BB0_31 Depth=1
	.loc	2 137 41                        # rnd_output0.c:137:41
	lui	a1, %hi(g_642)
	lh	a0, %lo(g_642)(a1)
	addi	a0, a0, 1
	sh	a0, %lo(g_642)(a1)
	.loc	2 137 5 is_stmt 0               # rnd_output0.c:137:5
	j	.LBB0_31
.Ltmp54:
.LBB0_46:
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp55:
	.loc	2 163 19 is_stmt 1              # rnd_output0.c:163:19
	sw	a0, -432(s0)
	.loc	2 163 10 is_stmt 0              # rnd_output0.c:163:10
	j	.LBB0_47
.LBB0_47:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_49 Depth 2
                                        #     Child Loop BB0_53 Depth 2
                                        #       Child Loop BB0_76 Depth 3
                                        #     Child Loop BB0_82 Depth 2
.Ltmp56:
	.loc	2 163 31                        # rnd_output0.c:163:31
	lw	a1, -432(s0)
	li	a0, 1
.Ltmp57:
	.loc	2 163 5                         # rnd_output0.c:163:5
	blt	a0, a1, .LBB0_87
	j	.LBB0_48
.LBB0_48:                               #   in Loop: Header=BB0_47 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lui	a0, 813725
	addi	a0, a0, -1470
.Ltmp58:
	.loc	2 165 17 is_stmt 1              # rnd_output0.c:165:17
	sw	a0, 392(a1)
	.loc	2 166 17                        # rnd_output0.c:166:17
	lui	a0, %hi(.L__const.func_40.l_1053)
	addi	a1, a0, %lo(.L__const.func_40.l_1053)
	lui	a0, 1
	addi	a0, a0, 1504
	sub	a0, s0, a0
	li	a2, 64
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	.loc	2 167 28                        # rnd_output0.c:167:28
	lui	a0, 1
	addi	a0, a0, 1460
	sub	a0, s0, a0
	.loc	2 167 18 is_stmt 0              # rnd_output0.c:167:18
	sw	a0, 324(a1)
	li	a0, 92
	.loc	2 168 23 is_stmt 1              # rnd_output0.c:168:23
	sb	a0, 323(a1)
	lui	a0, 539092
	addi	a0, a0, 184
	.loc	2 169 18                        # rnd_output0.c:169:18
	sw	a0, 316(a1)
	lui	a0, 938318
	addi	a0, a0, -1587
	sw	a0, 312(a1)
	.loc	2 171 39                        # rnd_output0.c:171:39
	lui	a0, 1
	addi	a0, a0, 1524
	sub	a0, s0, a0
	.loc	2 171 29 is_stmt 0              # rnd_output0.c:171:29
	sw	a0, 276(a1)
	li	a0, 0
.Ltmp59:
	.loc	2 173 16 is_stmt 1              # rnd_output0.c:173:16
	sw	a0, 272(a1)
	.loc	2 173 14 is_stmt 0              # rnd_output0.c:173:14
	j	.LBB0_49
.LBB0_49:                               #   Parent Loop BB0_47 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp60:
	.loc	2 173 21                        # rnd_output0.c:173:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a1, 272(a0)
	li	a0, 7
.Ltmp61:
	.loc	2 173 9                         # rnd_output0.c:173:9
	blt	a0, a1, .LBB0_52
	j	.LBB0_50
.LBB0_50:                               #   in Loop: Header=BB0_49 Depth=2
.Ltmp62:
	.loc	2 174 20 is_stmt 1              # rnd_output0.c:174:20
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 272(a0)
	.loc	2 174 13 is_stmt 0              # rnd_output0.c:174:13
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 1552
	sub	a0, s0, a0
	add	a1, a1, a0
	li	a0, 0
	.loc	2 174 23                        # rnd_output0.c:174:23
	sw	a0, 0(a1)
	.loc	2 174 13                        # rnd_output0.c:174:13
	j	.LBB0_51
.LBB0_51:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 173 29 is_stmt 1              # rnd_output0.c:173:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 272(a1)
	addi	a0, a0, 1
	sw	a0, 272(a1)
	.loc	2 173 9 is_stmt 0               # rnd_output0.c:173:9
	j	.LBB0_49
.Ltmp63:
.LBB0_52:                               #   in Loop: Header=BB0_47 Depth=1
	.loc	2 175 20 is_stmt 1              # rnd_output0.c:175:20
	lui	a1, %hi(g_589)
	li	a0, 1
	sw	a0, %lo(g_589)(a1)
	.loc	2 175 14 is_stmt 0              # rnd_output0.c:175:14
	j	.LBB0_53
.LBB0_53:                               #   Parent Loop BB0_47 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_76 Depth 3
.Ltmp64:
	.loc	2 175 26                        # rnd_output0.c:175:26
	lui	a0, %hi(g_589)
	lw	a0, %lo(g_589)(a0)
.Ltmp65:
	.loc	2 175 9                         # rnd_output0.c:175:9
	bltz	a0, .LBB0_81
	j	.LBB0_54
.LBB0_54:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	li	a1, -3
.Ltmp66:
	.loc	2 177 21 is_stmt 1              # rnd_output0.c:177:21
	sh	a1, 266(a0)
	li	a1, 0
	.loc	2 178 23                        # rnd_output0.c:178:23
	sw	a1, 260(a0)
	lui	a1, 618296
	addi	a1, a1, 1377
	.loc	2 179 21                        # rnd_output0.c:179:21
	sw	a1, 256(a0)
	li	a1, 1
	.loc	2 180 21                        # rnd_output0.c:180:21
	sw	a1, 252(a0)
	lui	a1, 48142
	addi	a1, a1, -154
	.loc	2 181 21                        # rnd_output0.c:181:21
	sw	a1, 248(a0)
	sw	a1, 244(a0)
	sw	a1, 240(a0)
	sw	a1, 236(a0)
	sw	a1, 232(a0)
	sw	a1, 228(a0)
.Ltmp67:
	.loc	2 183 25                        # rnd_output0.c:183:25
	lw	a0, 392(a0)
.Ltmp68:
	.loc	2 183 17 is_stmt 0              # rnd_output0.c:183:17
	beqz	a0, .LBB0_67
	j	.LBB0_55
.LBB0_55:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lui	a0, 7
	addi	a0, a0, -2041
.Ltmp69:
	.loc	2 185 26 is_stmt 1              # rnd_output0.c:185:26
	sh	a0, 222(a1)
	.loc	2 186 42                        # rnd_output0.c:186:42
	addi	a0, s0, -960
	.loc	2 186 32 is_stmt 0              # rnd_output0.c:186:32
	sw	a0, 216(a1)
.Ltmp70:
	.loc	2 187 31 is_stmt 1              # rnd_output0.c:187:31
	lui	a1, %hi(g_733)
	li	a0, 0
	sw	a0, %lo(g_733)(a1)
	.loc	2 187 22 is_stmt 0              # rnd_output0.c:187:22
	j	.LBB0_56
.LBB0_56:                               #   in Loop: Header=BB0_53 Depth=2
.Ltmp71:
	.loc	2 187 43                        # rnd_output0.c:187:43
	lui	a0, %hi(g_733)
	lw	a1, %lo(g_733)(a0)
	li	a0, 1
.Ltmp72:
	.loc	2 187 17                        # rnd_output0.c:187:17
	bltu	a0, a1, .LBB0_66
	j	.LBB0_57
.LBB0_57:
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 732(a0)                     # 4-byte Folded Reload
	lui	a0, 187910
	addi	a0, a0, 1273
.Ltmp73:
	.loc	2 189 30 is_stmt 1              # rnd_output0.c:189:30
	sw	a0, 212(a2)
	lui	a0, 498384
	addi	a0, a0, 1841
	sw	a0, 208(a2)
	li	a0, 0
	.loc	2 190 29                        # rnd_output0.c:190:29
	sw	a0, 204(a2)
	lui	a1, 1
	addi	a1, a1, 1440
	sub	a1, s0, a1
	.loc	2 191 36                        # rnd_output0.c:191:36
	sw	a1, 200(a2)
.Ltmp74:
	.loc	2 192 32                        # rnd_output0.c:192:32
	lui	a1, %hi(g_302)
	sw	a0, %lo(g_302)(a1)
	.loc	2 192 26 is_stmt 0              # rnd_output0.c:192:26
	j	.LBB0_58
.LBB0_58:                               # =>This Inner Loop Header: Depth=1
.Ltmp75:
	.loc	2 192 38                        # rnd_output0.c:192:38
	lui	a0, %hi(g_302)
	lw	a1, %lo(g_302)(a0)
	li	a0, 3
.Ltmp76:
	.loc	2 192 21                        # rnd_output0.c:192:21
	bltu	a0, a1, .LBB0_65
	j	.LBB0_59
.LBB0_59:                               #   in Loop: Header=BB0_58 Depth=1
	.loc	2 0 21                          # rnd_output0.c:0:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp77:
	.loc	2 194 33 is_stmt 1              # rnd_output0.c:194:33
	sw	a0, 196(a1)
	.loc	2 196 31                        # rnd_output0.c:196:31
	lw	a0, 212(a1)
	lw	a2, 208(a1)
	seqz	a3, a2
	sub	a0, a0, a3
	addi	a2, a2, -1
	sw	a2, 208(a1)
	sw	a0, 212(a1)
.Ltmp78:
	.loc	2 197 42                        # rnd_output0.c:197:42
	lui	a0, %hi(g_733)
	lw	a0, %lo(g_733)(a0)
	.loc	2 197 45 is_stmt 0              # rnd_output0.c:197:45
	slli	a0, a0, 3
	.loc	2 197 29                        # rnd_output0.c:197:29
	lui	a1, %hi(g_947)
	addi	a1, a1, %lo(g_947)
	add	a0, a0, a1
	.loc	2 197 51                        # rnd_output0.c:197:51
	lui	a1, %hi(g_302)
	lw	a1, %lo(g_302)(a1)
	.loc	2 197 29                        # rnd_output0.c:197:29
	slli	a1, a1, 1
	add	a0, a0, a1
	lhu	a0, 16(a0)
.Ltmp79:
	.loc	2 197 29                        # rnd_output0.c:197:29
	beqz	a0, .LBB0_61
	j	.LBB0_60
.LBB0_60:
.Ltmp80:
	.loc	2 198 29 is_stmt 1              # rnd_output0.c:198:29
	j	.LBB0_65
.Ltmp81:
.LBB0_61:                               #   in Loop: Header=BB0_58 Depth=1
	.loc	2 199 41                        # rnd_output0.c:199:41
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_589)
	lw	a0, %lo(g_589)(a0)
	.loc	2 199 47 is_stmt 0              # rnd_output0.c:199:47
	addi	a2, a0, 1
	.loc	2 199 34                        # rnd_output0.c:199:34
	lui	a0, %hi(g_947)
	addi	a0, a0, %lo(g_947)
	slli	a3, a2, 3
	add	a0, a0, a3
	slli	a2, a2, 1
	add	a0, a0, a2
	lhu	a0, 0(a0)
	.loc	2 199 32                        # rnd_output0.c:199:32
	sw	a0, 196(a1)
.Ltmp82:
	.loc	2 200 31 is_stmt 1              # rnd_output0.c:200:31
	lw	a0, -24(s0)
	.loc	2 200 30 is_stmt 0              # rnd_output0.c:200:30
	lw	a0, 0(a0)
.Ltmp83:
	.loc	2 200 29                        # rnd_output0.c:200:29
	beqz	a0, .LBB0_63
	j	.LBB0_62
.LBB0_62:                               #   in Loop: Header=BB0_58 Depth=1
.Ltmp84:
	.loc	2 201 29 is_stmt 1              # rnd_output0.c:201:29
	j	.LBB0_64
.Ltmp85:
.LBB0_63:                               #   in Loop: Header=BB0_58 Depth=1
	.loc	2 202 21                        # rnd_output0.c:202:21
	j	.LBB0_64
.Ltmp86:
.LBB0_64:                               #   in Loop: Header=BB0_58 Depth=1
	.loc	2 192 57                        # rnd_output0.c:192:57
	lui	a1, %hi(g_302)
	lw	a0, %lo(g_302)(a1)
	addi	a0, a0, 1
	sw	a0, %lo(g_302)(a1)
	.loc	2 192 21 is_stmt 0              # rnd_output0.c:192:21
	j	.LBB0_58
.Ltmp87:
.LBB0_65:
	.loc	2 203 21 is_stmt 1              # rnd_output0.c:203:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lh	a0, 222(a1)
	addi	a0, a0, -1
	sh	a0, 222(a1)
	.loc	2 204 30                        # rnd_output0.c:204:30
	lw	a0, -64(s0)
	.loc	2 204 29 is_stmt 0              # rnd_output0.c:204:29
	lw	a0, 0(a0)
	.loc	2 204 21                        # rnd_output0.c:204:21
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp88:
.LBB0_66:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 206 28 is_stmt 1              # rnd_output0.c:206:28
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 260(a0)
	.loc	2 206 19 is_stmt 0              # rnd_output0.c:206:19
	lw	a1, -652(s0)
	.loc	2 206 26                        # rnd_output0.c:206:26
	sw	a0, 0(a1)
	.loc	2 207 13 is_stmt 1              # rnd_output0.c:207:13
	j	.LBB0_75
.Ltmp89:
.LBB0_67:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 210 32                        # rnd_output0.c:210:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_8)
	addi	a0, a0, %lo(g_8)
	addi	a0, a0, 480
	sw	a0, 184(a1)
	li	a0, -1
	.loc	2 211 25                        # rnd_output0.c:211:25
	sw	a0, 180(a1)
	.loc	2 212 26                        # rnd_output0.c:212:26
	sw	a0, 176(a1)
.Ltmp90:
	.loc	2 213 23                        # rnd_output0.c:213:23
	lw	a0, -24(s0)
	.loc	2 213 22 is_stmt 0              # rnd_output0.c:213:22
	lw	a0, 0(a0)
.Ltmp91:
	.loc	2 213 21                        # rnd_output0.c:213:21
	beqz	a0, .LBB0_71
	j	.LBB0_68
.LBB0_68:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 0 21                          # rnd_output0.c:0:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 732(a1)                     # 4-byte Folded Reload
	lui	a1, 214186
	addi	a1, a1, -679
.Ltmp92:
	.loc	2 215 30 is_stmt 1              # rnd_output0.c:215:30
	sw	a1, 172(a2)
	.loc	2 216 32                        # rnd_output0.c:216:32
	lw	a1, -24(s0)
	.loc	2 216 31 is_stmt 0              # rnd_output0.c:216:31
	lw	a1, 0(a1)
	.loc	2 216 28                        # rnd_output0.c:216:28
	sw	a1, 392(a2)
	.loc	2 217 27 is_stmt 1              # rnd_output0.c:217:27
	lw	a1, 172(a2)
	addi	a1, a1, 1
	sw	a1, 172(a2)
.Ltmp93:
	.loc	2 218 25                        # rnd_output0.c:218:25
	lw	a1, 608(a0)
	lw	a0, 604(a0)
	or	a0, a0, a1
.Ltmp94:
	.loc	2 218 25 is_stmt 0              # rnd_output0.c:218:25
	beqz	a0, .LBB0_70
	j	.LBB0_69
.LBB0_69:                               #   in Loop: Header=BB0_53 Depth=2
.Ltmp95:
	.loc	2 219 25 is_stmt 1              # rnd_output0.c:219:25
	j	.LBB0_80
.Ltmp96:
.LBB0_70:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 220 34                        # rnd_output0.c:220:34
	lui	a0, %hi(g_334)
	lw	a0, %lo(g_334)(a0)
	.loc	2 220 33 is_stmt 0              # rnd_output0.c:220:33
	lw	a0, 0(a0)
	.loc	2 220 23                        # rnd_output0.c:220:23
	lui	a1, %hi(g_200)
	lw	a1, %lo(g_200)(a1)
	.loc	2 220 30                        # rnd_output0.c:220:30
	sw	a0, 0(a1)
	.loc	2 221 17 is_stmt 1              # rnd_output0.c:221:17
	j	.LBB0_74
.Ltmp97:
.LBB0_71:
	.loc	2 224 29                        # rnd_output0.c:224:29
	lui	a0, %hi(.L__const.func_40.l_1060)
	addi	a1, a0, %lo(.L__const.func_40.l_1060)
	lui	a0, 1
	addi	a0, a0, 1696
	sub	a0, s0, a0
	li	a2, 36
	call	memcpy@plt
                                        # kill: def $x11 killed $x10
.Ltmp98:
	.loc	2 226 56                        # rnd_output0.c:226:56
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 144(a0)
	srai	a1, a0, 31
	li	a2, 6
	.loc	2 226 26 is_stmt 0              # rnd_output0.c:226:26
	call	safe_lshift_func_uint64_t_u_s
	or	a0, a0, a1
.Ltmp99:
	.loc	2 226 25                        # rnd_output0.c:226:25
	beqz	a0, .LBB0_73
	j	.LBB0_72
.LBB0_72:
.Ltmp100:
	.loc	2 228 32 is_stmt 1              # rnd_output0.c:228:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 184(a0)
	.loc	2 228 25 is_stmt 0              # rnd_output0.c:228:25
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp101:
.LBB0_73:
	.loc	2 232 32 is_stmt 1              # rnd_output0.c:232:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 600(a0)
	.loc	2 232 25 is_stmt 0              # rnd_output0.c:232:25
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp102:
.LBB0_74:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 235 24 is_stmt 1              # rnd_output0.c:235:24
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, 180(a1)
	ori	a0, a0, 9
	sw	a0, 180(a1)
	.loc	2 236 23                        # rnd_output0.c:236:23
	lw	a0, 176(a1)
	addi	a0, a0, 1
	sw	a0, 176(a1)
	j	.LBB0_75
.Ltmp103:
.LBB0_75:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 238 24                        # rnd_output0.c:238:24
	lui	a1, %hi(g_116)
	li	a0, 1
	sw	a0, %lo(g_116)(a1)
	.loc	2 238 18 is_stmt 0              # rnd_output0.c:238:18
	j	.LBB0_76
.LBB0_76:                               #   Parent Loop BB0_47 Depth=1
                                        #     Parent Loop BB0_53 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp104:
	.loc	2 238 30                        # rnd_output0.c:238:30
	lui	a0, %hi(g_116)
	lw	a0, %lo(g_116)(a0)
.Ltmp105:
	.loc	2 238 13                        # rnd_output0.c:238:13
	bltz	a0, .LBB0_79
	j	.LBB0_77
.LBB0_77:                               #   in Loop: Header=BB0_76 Depth=3
.Ltmp106:
	.loc	2 240 28 is_stmt 1              # rnd_output0.c:240:28
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lw	a0, -64(s0)
	.loc	2 240 27 is_stmt 0              # rnd_output0.c:240:27
	lw	a0, 0(a0)
	.loc	2 240 24                        # rnd_output0.c:240:24
	sw	a0, 324(a1)
	.loc	2 241 13 is_stmt 1              # rnd_output0.c:241:13
	j	.LBB0_78
.Ltmp107:
.LBB0_78:                               #   in Loop: Header=BB0_76 Depth=3
	.loc	2 238 49                        # rnd_output0.c:238:49
	lui	a1, %hi(g_116)
	lw	a0, %lo(g_116)(a1)
	addi	a0, a0, -1
	sw	a0, %lo(g_116)(a1)
	.loc	2 238 13 is_stmt 0              # rnd_output0.c:238:13
	j	.LBB0_76
.Ltmp108:
.LBB0_79:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 242 9 is_stmt 1               # rnd_output0.c:242:9
	j	.LBB0_80
.Ltmp109:
.LBB0_80:                               #   in Loop: Header=BB0_53 Depth=2
	.loc	2 175 45                        # rnd_output0.c:175:45
	lui	a1, %hi(g_589)
	lw	a0, %lo(g_589)(a1)
	addi	a0, a0, -1
	sw	a0, %lo(g_589)(a1)
	.loc	2 175 9 is_stmt 0               # rnd_output0.c:175:9
	j	.LBB0_53
.Ltmp110:
.LBB0_81:                               #   in Loop: Header=BB0_47 Depth=1
	.loc	2 243 19 is_stmt 1              # rnd_output0.c:243:19
	lui	a1, %hi(g_89)
	li	a0, 0
	sh	a0, %lo(g_89)(a1)
	.loc	2 243 14 is_stmt 0              # rnd_output0.c:243:14
	j	.LBB0_82
.LBB0_82:                               #   Parent Loop BB0_47 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp111:
	.loc	2 243 25                        # rnd_output0.c:243:25
	lui	a0, %hi(g_89)
	lhu	a1, %lo(g_89)(a0)
	li	a0, 1
.Ltmp112:
	.loc	2 243 9                         # rnd_output0.c:243:9
	blt	a0, a1, .LBB0_85
	j	.LBB0_83
.LBB0_83:                               #   in Loop: Header=BB0_82 Depth=2
.Ltmp113:
	.loc	2 245 22 is_stmt 1              # rnd_output0.c:245:22
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 732(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_588)
	addi	a0, a0, %lo(g_588)
	sw	a0, 128(a1)
	.loc	2 246 29                        # rnd_output0.c:246:29
	lui	a0, %hi(g_294)
	addi	a0, a0, %lo(g_294)
	sw	a0, 124(a1)
	li	a0, -9
	.loc	2 247 21                        # rnd_output0.c:247:21
	sw	a0, 120(a1)
	li	a0, 0
	.loc	2 248 22                        # rnd_output0.c:248:22
	sw	a0, 116(a1)
	sw	a0, 112(a1)
	li	a0, -1
	sw	a0, 108(a1)
	lui	a0, 466551
	addi	a0, a0, -1237
	sw	a0, 104(a1)
	.loc	2 250 9                         # rnd_output0.c:250:9
	j	.LBB0_84
.Ltmp114:
.LBB0_84:                               #   in Loop: Header=BB0_82 Depth=2
	.loc	2 243 42                        # rnd_output0.c:243:42
	lui	a1, %hi(g_89)
	lh	a0, %lo(g_89)(a1)
	addi	a0, a0, 1
	sh	a0, %lo(g_89)(a1)
	.loc	2 243 9 is_stmt 0               # rnd_output0.c:243:9
	j	.LBB0_82
.Ltmp115:
.LBB0_85:                               #   in Loop: Header=BB0_47 Depth=1
	.loc	2 251 5 is_stmt 1               # rnd_output0.c:251:5
	j	.LBB0_86
.Ltmp116:
.LBB0_86:                               #   in Loop: Header=BB0_47 Depth=1
	.loc	2 163 50                        # rnd_output0.c:163:50
	lw	a0, -432(s0)
	addi	a0, a0, 1
	sw	a0, -432(s0)
	.loc	2 163 5 is_stmt 0               # rnd_output0.c:163:5
	j	.LBB0_47
.Ltmp117:
.LBB0_87:
	.loc	2 252 54 is_stmt 1              # rnd_output0.c:252:54
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 596(a0)
	.loc	2 252 65 is_stmt 0              # rnd_output0.c:252:65
	lui	a1, %hi(g_1124)
	addi	a1, a1, %lo(g_1124)
	lw	a1, 100(a1)
	li	a2, 0
	.loc	2 252 82                        # rnd_output0.c:252:82
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 660(a3)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB0_89
	j	.LBB0_88
.LBB0_88:
	.loc	2 252 85                        # rnd_output0.c:252:85
	lui	a0, %hi(g_117)
	lw	a0, %lo(g_117)(a0)
	.loc	2 252 82                        # rnd_output0.c:252:82
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 660(a1)                     # 4-byte Folded Spill
	j	.LBB0_89
.LBB0_89:
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 660(a0)                     # 4-byte Folded Reload
	.loc	2 252 82                        # rnd_output0.c:252:82
	andi	a0, a0, 1
	.loc	2 252 124                       # rnd_output0.c:252:124
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 656(a1)                     # 4-byte Folded Spill
	li	a0, -3
	li	a1, 31
	call	safe_rshift_func_uint32_t_u_u
	.loc	2 252 95                        # rnd_output0.c:252:95
	slli	a0, a0, 24
	srai	a0, a0, 24
	li	a1, 6
	call	safe_rshift_func_int8_t_s_u
	mv	a1, a0
	.loc	2 252 92                        # rnd_output0.c:252:92
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 656(a0)                     # 4-byte Folded Reload
	slt	a0, a0, a1
	xori	a0, a0, 1
	li	a1, 2
	.loc	2 252 10                        # rnd_output0.c:252:10
	call	safe_lshift_func_uint8_t_u_u
.Ltmp118:
	.loc	2 252 9                         # rnd_output0.c:252:9
	bnez	a0, .LBB0_90
	j	.LBB0_248
.LBB0_90:
.Ltmp119:
	.loc	2 254 43 is_stmt 1              # rnd_output0.c:254:43
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a3, 732(a0)                     # 4-byte Folded Reload
	addi	a4, s0, -304
	.loc	2 254 41 is_stmt 0              # rnd_output0.c:254:41
	lui	a0, 4
	sub	a0, s0, a0
	sw	a4, 644(a0)                     # 4-byte Folded Spill
	sw	a4, 1572(a1)
	sw	a4, 1576(a1)
	addi	a2, s0, -60
	lui	a0, 4
	sub	a0, s0, a0
	sw	a2, 648(a0)                     # 4-byte Folded Spill
	sw	a2, 1580(a1)
	sw	a4, 1584(a1)
	.loc	2 254 98                        # rnd_output0.c:254:98
	sw	a4, 1588(a1)
	li	a0, 0
	lui	a5, 4
	sub	a5, s0, a5
	sw	a0, 652(a5)                     # 4-byte Folded Spill
	sw	a0, 1592(a1)
	sw	a0, 1596(a1)
	sw	a4, 1600(a1)
	.loc	2 254 150                       # rnd_output0.c:254:150
	sw	a0, 1604(a1)
	sw	a4, 1608(a1)
	sw	a0, 1612(a1)
	sw	a0, 1616(a1)
	.loc	2 254 195                       # rnd_output0.c:254:195
	sw	a4, 1620(a1)
	sw	a4, 1624(a1)
	sw	a2, 1628(a1)
	sw	a4, 1632(a1)
	.loc	2 254 252                       # rnd_output0.c:254:252
	sw	a4, 1636(a1)
	sw	a0, 1640(a1)
	sw	a0, 1644(a1)
	sw	a4, 1648(a1)
	.loc	2 254 304                       # rnd_output0.c:254:304
	sw	a0, 1652(a1)
	sw	a4, 1656(a1)
	sw	a0, 1660(a1)
	sw	a0, 1664(a1)
	.loc	2 254 349                       # rnd_output0.c:254:349
	sw	a4, 1668(a1)
	sw	a4, 1672(a1)
	sw	a2, 1676(a1)
	sw	a4, 1680(a1)
	.loc	2 254 406                       # rnd_output0.c:254:406
	sw	a4, 1684(a1)
	sw	a0, 1688(a1)
	sw	a0, 1692(a1)
	sw	a4, 1696(a1)
	.loc	2 254 458                       # rnd_output0.c:254:458
	sw	a0, 1700(a1)
	sw	a4, 1704(a1)
	sw	a0, 1708(a1)
	sw	a0, 1712(a1)
	.loc	2 254 505                       # rnd_output0.c:254:505
	sw	a4, 1716(a1)
	sw	a4, 1720(a1)
	sw	a2, 1724(a1)
	sw	a4, 1728(a1)
	.loc	2 254 562                       # rnd_output0.c:254:562
	sw	a4, 1732(a1)
	sw	a0, 1736(a1)
	sw	a0, 1740(a1)
	sw	a4, 1744(a1)
	.loc	2 254 614                       # rnd_output0.c:254:614
	sw	a0, 1748(a1)
	sw	a4, 1752(a1)
	sw	a0, 1756(a1)
	sw	a0, 1760(a1)
	.loc	2 254 659                       # rnd_output0.c:254:659
	sw	a4, 1764(a1)
	sw	a4, 1768(a1)
	sw	a2, 1772(a1)
	sw	a4, 1776(a1)
	.loc	2 254 716                       # rnd_output0.c:254:716
	sw	a4, 1780(a1)
	sw	a0, 1784(a1)
	sw	a0, 1788(a1)
	sw	a4, 1792(a1)
	.loc	2 254 768                       # rnd_output0.c:254:768
	sw	a0, 1796(a1)
	sw	a4, 1800(a1)
	sw	a0, 1804(a1)
	sw	a0, 1808(a1)
	.loc	2 254 813                       # rnd_output0.c:254:813
	sw	a4, 1812(a1)
	sw	a4, 1816(a1)
	sw	a2, 1820(a1)
	sw	a4, 1824(a1)
	.loc	2 254 870                       # rnd_output0.c:254:870
	sw	a4, 1828(a1)
	sw	a0, 1832(a1)
	sw	a0, 1836(a1)
	sw	a4, 1840(a1)
	.loc	2 254 922                       # rnd_output0.c:254:922
	sw	a0, 1844(a1)
	sw	a4, 1848(a1)
	sw	a0, 1852(a1)
	sw	a0, 1856(a1)
	.loc	2 254 969                       # rnd_output0.c:254:969
	sw	a4, 1860(a1)
	sw	a4, 1864(a1)
	sw	a2, 1868(a1)
	sw	a4, 1872(a1)
	.loc	2 254 1026                      # rnd_output0.c:254:1026
	sw	a4, 1876(a1)
	sw	a0, 1880(a1)
	sw	a0, 1884(a1)
	sw	a4, 1888(a1)
	.loc	2 254 1078                      # rnd_output0.c:254:1078
	sw	a0, 1892(a1)
	sw	a4, 1896(a1)
	sw	a0, 1900(a1)
	sw	a0, 1904(a1)
	.loc	2 254 1123                      # rnd_output0.c:254:1123
	sw	a4, 1908(a1)
	sw	a4, 1912(a1)
	sw	a2, 1916(a1)
	sw	a4, 1920(a1)
	.loc	2 254 1180                      # rnd_output0.c:254:1180
	sw	a4, 1924(a1)
	sw	a0, 1928(a1)
	sw	a0, 1932(a1)
	sw	a0, 1936(a1)
	.loc	2 254 1225                      # rnd_output0.c:254:1225
	sw	a2, 1940(a1)
	sw	a0, 1944(a1)
	sw	a2, 1948(a1)
	sw	a2, 1952(a1)
	.loc	2 254 1257                      # rnd_output0.c:254:1257
	sw	a0, 1956(a1)
	sw	a0, 1960(a1)
	sw	a4, 1964(a1)
	sw	a0, 1968(a1)
	.loc	2 254 1302                      # rnd_output0.c:254:1302
	sw	a0, 1972(a1)
	sw	a2, 1976(a1)
	sw	a2, 1980(a1)
	sw	a0, 1984(a1)
	.loc	2 254 1336                      # rnd_output0.c:254:1336
	sw	a2, 1988(a1)
	sw	a0, 1992(a1)
	sw	a2, 1996(a1)
	sw	a2, 2000(a1)
	.loc	2 254 1370                      # rnd_output0.c:254:1370
	sw	a0, 2004(a1)
	sw	a0, 2008(a1)
	sw	a4, 2012(a1)
	sw	a0, 2016(a1)
	.loc	2 254 1415                      # rnd_output0.c:254:1415
	sw	a0, 2020(a1)
	sw	a2, 2024(a1)
	sw	a2, 2028(a1)
	sw	a0, 2032(a1)
	.loc	2 254 1449                      # rnd_output0.c:254:1449
	sw	a2, 2036(a1)
	sw	a0, 2040(a1)
	sw	a2, 2044(a1)
	sw	a2, 0(a3)
	.loc	2 254 1481                      # rnd_output0.c:254:1481
	sw	a0, 4(a3)
	sw	a0, 8(a3)
	sw	a4, 12(a3)
	sw	a0, 16(a3)
	.loc	2 254 1526                      # rnd_output0.c:254:1526
	sw	a0, 20(a3)
	sw	a2, 24(a3)
	sw	a2, 28(a3)
	sw	a0, 32(a3)
	.loc	2 254 1560                      # rnd_output0.c:254:1560
	sw	a2, 36(a3)
	sw	a0, 40(a3)
	sw	a2, 44(a3)
	sw	a2, 48(a3)
	.loc	2 254 1592                      # rnd_output0.c:254:1592
	sw	a0, 52(a3)
	sw	a0, 56(a3)
	sw	a4, 60(a3)
	sw	a0, 64(a3)
	.loc	2 254 1637                      # rnd_output0.c:254:1637
	sw	a0, 68(a3)
	sw	a2, 72(a3)
	sw	a2, 76(a3)
	sw	a0, 80(a3)
	.loc	2 254 1671                      # rnd_output0.c:254:1671
	sw	a2, 84(a3)
	sw	a0, 88(a3)
	sw	a2, 92(a3)
	sw	a2, 96(a3)
	.loc	2 255 34 is_stmt 1              # rnd_output0.c:255:34
	sw	a0, 1568(a1)
	lui	a2, 2
	addi	a2, a2, -1784
	sub	a2, s0, a2
	.loc	2 256 35                        # rnd_output0.c:256:35
	sw	a2, 1564(a1)
	lui	a2, 2
	addi	a2, a2, -1780
	sub	a2, s0, a2
	.loc	2 257 36                        # rnd_output0.c:257:36
	sw	a2, 1560(a1)
	lui	a2, 546026
	addi	a2, a2, 1113
	.loc	2 258 18                        # rnd_output0.c:258:18
	sw	a2, 1556(a1)
	lui	a2, 259968
	addi	a2, a2, 1684
	.loc	2 259 18                        # rnd_output0.c:259:18
	sw	a2, 1552(a1)
	.loc	2 260 19                        # rnd_output0.c:260:19
	sw	a0, 1548(a1)
	sw	a0, 1544(a1)
	sw	a0, 1540(a1)
	sw	a0, 1536(a1)
	sw	a0, 1532(a1)
	sw	a0, 1528(a1)
	sw	a0, 1524(a1)
	.loc	2 261 19                        # rnd_output0.c:261:19
	lui	a0, %hi(.L__const.func_40.l_1304)
	addi	a1, a0, %lo(.L__const.func_40.l_1304)
	lui	a0, 2
	addi	a0, a0, -1620
	sub	a0, s0, a0
	li	a2, 120
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 262 19                        # rnd_output0.c:262:19
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 652(a0)                     # 4-byte Folded Reload
	sw	a0, 1396(a1)
	sw	a0, 1392(a1)
	lui	a0, 699237
	addi	a0, a0, -657
	sw	a0, 1388(a1)
	lui	a0, 934551
	addi	a0, a0, -883
	sw	a0, 1384(a1)
	li	a0, 1
	.loc	2 263 17                        # rnd_output0.c:263:17
	sw	a0, 1380(a1)
	li	a0, 7
	.loc	2 264 17                        # rnd_output0.c:264:17
	sw	a0, 1376(a1)
	.loc	2 265 34                        # rnd_output0.c:265:34
	addi	a0, s0, -960
	.loc	2 265 24 is_stmt 0              # rnd_output0.c:265:24
	sw	a0, 1372(a1)
	.loc	2 266 18 is_stmt 1              # rnd_output0.c:266:18
	lui	a0, %hi(.L__const.func_40.l_1411)
	addi	a1, a0, %lo(.L__const.func_40.l_1411)
	lui	a0, 2
	addi	a0, a0, -1152
	sub	a0, s0, a0
	li	a2, 432
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 267 34                        # rnd_output0.c:267:34
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 652(a0)                     # 4-byte Folded Reload
	sw	a0, 932(a1)
	li	a2, -6
	.loc	2 268 18                        # rnd_output0.c:268:18
	sw	a2, 928(a1)
	.loc	2 269 18                        # rnd_output0.c:269:18
	sw	a0, 924(a1)
	li	a0, -5
	.loc	2 270 17                        # rnd_output0.c:270:17
	sh	a0, 922(a1)
	li	a0, -1
	.loc	2 271 17                        # rnd_output0.c:271:17
	sw	a0, 916(a1)
	li	a0, -16
.Ltmp120:
	.loc	2 273 19                        # rnd_output0.c:273:19
	sw	a0, -48(s0)
	.loc	2 273 14 is_stmt 0              # rnd_output0.c:273:14
	j	.LBB0_91
.LBB0_91:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_93 Depth 2
                                        #       Child Loop BB0_95 Depth 3
                                        #     Child Loop BB0_101 Depth 2
                                        #     Child Loop BB0_105 Depth 2
                                        #     Child Loop BB0_126 Depth 2
.Ltmp121:
	.loc	2 273 29                        # rnd_output0.c:273:29
	lw	a0, -48(s0)
	li	a1, 30
.Ltmp122:
	.loc	2 273 9                         # rnd_output0.c:273:9
	bne	a0, a1, .LBB0_131
	j	.LBB0_92
.LBB0_92:                               #   in Loop: Header=BB0_91 Depth=1
.Ltmp123:
	.loc	2 275 23 is_stmt 1              # rnd_output0.c:275:23
	lui	a0, %hi(.L__const.func_40.l_1153)
	addi	a1, a0, %lo(.L__const.func_40.l_1153)
	lui	a0, 2
	addi	a0, a0, -992
	sub	a0, s0, a0
	li	a2, 128
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	.loc	2 276 23                        # rnd_output0.c:276:23
	lui	a0, %hi(g_947)
	addi	a0, a0, %lo(g_947)
	addi	a0, a0, 32
	sw	a0, 772(a1)
	li	a0, 0
.Ltmp124:
	.loc	2 280 20                        # rnd_output0.c:280:20
	sw	a0, 752(a1)
	.loc	2 280 18 is_stmt 0              # rnd_output0.c:280:18
	j	.LBB0_93
.LBB0_93:                               #   Parent Loop BB0_91 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_95 Depth 3
.Ltmp125:
	.loc	2 280 25                        # rnd_output0.c:280:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a1, 752(a0)
	li	a0, 1
.Ltmp126:
	.loc	2 280 13                        # rnd_output0.c:280:13
	blt	a0, a1, .LBB0_100
	j	.LBB0_94
.LBB0_94:                               #   in Loop: Header=BB0_93 Depth=2
	.loc	2 0 13                          # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp127:
	.loc	2 282 24 is_stmt 1              # rnd_output0.c:282:24
	sw	a0, 748(a1)
	.loc	2 282 22 is_stmt 0              # rnd_output0.c:282:22
	j	.LBB0_95
.LBB0_95:                               #   Parent Loop BB0_91 Depth=1
                                        #     Parent Loop BB0_93 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp128:
	.loc	2 282 29                        # rnd_output0.c:282:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a1, 748(a0)
	li	a0, 0
.Ltmp129:
	.loc	2 282 17                        # rnd_output0.c:282:17
	blt	a0, a1, .LBB0_98
	j	.LBB0_96
.LBB0_96:                               #   in Loop: Header=BB0_95 Depth=3
.Ltmp130:
	.loc	2 283 28 is_stmt 1              # rnd_output0.c:283:28
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 752(a1)
	.loc	2 283 21 is_stmt 0              # rnd_output0.c:283:21
	slli	a2, a0, 2
	lui	a0, 2
	addi	a0, a0, -980
	sub	a0, s0, a0
	add	a0, a0, a2
	.loc	2 283 31                        # rnd_output0.c:283:31
	lw	a1, 748(a1)
	.loc	2 283 21                        # rnd_output0.c:283:21
	slli	a1, a1, 2
	add	a1, a1, a0
	addi	a0, s0, -432
	.loc	2 283 34                        # rnd_output0.c:283:34
	sw	a0, 0(a1)
	.loc	2 283 21                        # rnd_output0.c:283:21
	j	.LBB0_97
.LBB0_97:                               #   in Loop: Header=BB0_95 Depth=3
	.loc	2 282 37 is_stmt 1              # rnd_output0.c:282:37
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 748(a1)
	addi	a0, a0, 1
	sw	a0, 748(a1)
	.loc	2 282 17 is_stmt 0              # rnd_output0.c:282:17
	j	.LBB0_95
.Ltmp131:
.LBB0_98:                               #   in Loop: Header=BB0_93 Depth=2
	.loc	2 284 13 is_stmt 1              # rnd_output0.c:284:13
	j	.LBB0_99
.Ltmp132:
.LBB0_99:                               #   in Loop: Header=BB0_93 Depth=2
	.loc	2 280 33                        # rnd_output0.c:280:33
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 752(a1)
	addi	a0, a0, 1
	sw	a0, 752(a1)
	.loc	2 280 13 is_stmt 0              # rnd_output0.c:280:13
	j	.LBB0_93
.Ltmp133:
.LBB0_100:                              #   in Loop: Header=BB0_91 Depth=1
	.loc	2 0 13                          # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp134:
	.loc	2 285 20 is_stmt 1              # rnd_output0.c:285:20
	sw	a0, 752(a1)
	.loc	2 285 18 is_stmt 0              # rnd_output0.c:285:18
	j	.LBB0_101
.LBB0_101:                              #   Parent Loop BB0_91 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp135:
	.loc	2 285 25                        # rnd_output0.c:285:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a1, 752(a0)
	li	a0, 1
.Ltmp136:
	.loc	2 285 13                        # rnd_output0.c:285:13
	blt	a0, a1, .LBB0_104
	j	.LBB0_102
.LBB0_102:                              #   in Loop: Header=BB0_101 Depth=2
.Ltmp137:
	.loc	2 286 24 is_stmt 1              # rnd_output0.c:286:24
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 752(a0)
	.loc	2 286 17 is_stmt 0              # rnd_output0.c:286:17
	slli	a1, a0, 2
	lui	a0, 2
	addi	a0, a0, -972
	sub	a0, s0, a0
	add	a1, a1, a0
	li	a0, 1
	.loc	2 286 27                        # rnd_output0.c:286:27
	sw	a0, 0(a1)
	.loc	2 286 17                        # rnd_output0.c:286:17
	j	.LBB0_103
.LBB0_103:                              #   in Loop: Header=BB0_101 Depth=2
	.loc	2 285 33 is_stmt 1              # rnd_output0.c:285:33
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 752(a1)
	addi	a0, a0, 1
	sw	a0, 752(a1)
	.loc	2 285 13 is_stmt 0              # rnd_output0.c:285:13
	j	.LBB0_101
.Ltmp138:
.LBB0_104:                              #   in Loop: Header=BB0_91 Depth=1
	.loc	2 287 24 is_stmt 1              # rnd_output0.c:287:24
	lui	a1, %hi(g_589)
	li	a0, -27
	sw	a0, %lo(g_589)(a1)
	.loc	2 287 18 is_stmt 0              # rnd_output0.c:287:18
	j	.LBB0_105
.LBB0_105:                              #   Parent Loop BB0_91 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp139:
	.loc	2 287 34                        # rnd_output0.c:287:34
	lui	a0, %hi(g_589)
	lw	a0, %lo(g_589)(a0)
	li	a1, 26
.Ltmp140:
	.loc	2 287 13                        # rnd_output0.c:287:13
	beq	a0, a1, .LBB0_125
	j	.LBB0_106
.LBB0_106:                              #   in Loop: Header=BB0_105 Depth=2
	.loc	2 0 13                          # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 689609
	addi	a0, a0, -851
.Ltmp141:
	.loc	2 289 25 is_stmt 1              # rnd_output0.c:289:25
	sw	a0, 744(a2)
	.loc	2 290 26                        # rnd_output0.c:290:26
	lui	a0, %hi(g_8)
	addi	a0, a0, %lo(g_8)
	addi	a0, a0, 464
	sw	a0, 740(a2)
	lui	a0, 709681
	addi	a0, a0, -1903
	.loc	2 291 26                        # rnd_output0.c:291:26
	sw	a0, 736(a2)
	.loc	2 292 27                        # rnd_output0.c:292:27
	lui	a0, %hi(g_325)
	addi	a0, a0, %lo(g_325)
	sw	a0, 732(a2)
	li	a0, 0
.Ltmp142:
	.loc	2 293 32                        # rnd_output0.c:293:32
	sb	a0, 564(a1)
	.loc	2 293 22 is_stmt 0              # rnd_output0.c:293:22
	j	.LBB0_107
.LBB0_107:                              #   in Loop: Header=BB0_105 Depth=2
.Ltmp143:
	.loc	2 293 45                        # rnd_output0.c:293:45
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a1, 564(a0)
	li	a0, -8
.Ltmp144:
	.loc	2 293 17                        # rnd_output0.c:293:17
	blt	a0, a1, .LBB0_123
	j	.LBB0_108
.LBB0_108:
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	li	a0, 3
.Ltmp145:
	.loc	2 296 29 is_stmt 1              # rnd_output0.c:296:29
	sw	a0, 700(a1)
	.loc	2 297 30                        # rnd_output0.c:297:30
	lui	a0, %hi(g_955)
	addi	a0, a0, %lo(g_955)
	addi	a0, a0, 26
	sw	a0, 696(a1)
	li	a0, 8
	.loc	2 298 30                        # rnd_output0.c:298:30
	sh	a0, 694(a1)
	.loc	2 299 47                        # rnd_output0.c:299:47
	addi	a0, s0, -428
	.loc	2 299 31 is_stmt 0              # rnd_output0.c:299:31
	sw	a0, 688(a1)
	li	a0, 1
	.loc	2 300 30 is_stmt 1              # rnd_output0.c:300:30
	sw	a0, 684(a1)
	li	a0, 0
.Ltmp146:
	.loc	2 302 28                        # rnd_output0.c:302:28
	sw	a0, 680(a1)
	.loc	2 302 26 is_stmt 0              # rnd_output0.c:302:26
	j	.LBB0_109
.LBB0_109:                              # =>This Inner Loop Header: Depth=1
.Ltmp147:
	.loc	2 302 33                        # rnd_output0.c:302:33
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a1, 680(a0)
	li	a0, 6
.Ltmp148:
	.loc	2 302 21                        # rnd_output0.c:302:21
	blt	a0, a1, .LBB0_112
	j	.LBB0_110
.LBB0_110:                              #   in Loop: Header=BB0_109 Depth=1
.Ltmp149:
	.loc	2 303 38 is_stmt 1              # rnd_output0.c:303:38
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	addi	a0, s0, -408
	.loc	2 303 32 is_stmt 0              # rnd_output0.c:303:32
	lw	a1, 680(a1)
	.loc	2 303 25                        # rnd_output0.c:303:25
	slli	a2, a1, 2
	lui	a1, 2
	addi	a1, a1, -920
	sub	a1, s0, a1
	add	a1, a1, a2
	.loc	2 303 35                        # rnd_output0.c:303:35
	sw	a0, 0(a1)
	.loc	2 303 25                        # rnd_output0.c:303:25
	j	.LBB0_111
.LBB0_111:                              #   in Loop: Header=BB0_109 Depth=1
	.loc	2 302 41 is_stmt 1              # rnd_output0.c:302:41
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 680(a1)
	addi	a0, a0, 1
	sw	a0, 680(a1)
	.loc	2 302 21 is_stmt 0              # rnd_output0.c:302:21
	j	.LBB0_109
.Ltmp150:
.LBB0_112:
	.loc	2 304 216 is_stmt 1             # rnd_output0.c:304:216
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 732(a0)                     # 4-byte Folded Reload
	lw	a0, -148(a0)
	.loc	2 304 213 is_stmt 0             # rnd_output0.c:304:213
	snez	a0, a0
	li	a1, 1
	.loc	2 304 177                       # rnd_output0.c:304:177
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 612(a2)                     # 4-byte Folded Spill
	call	safe_mul_func_int32_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 736(a1)                     # 4-byte Folded Reload
	.loc	2 304 297                       # rnd_output0.c:304:297
	lw	a1, 712(a2)
	.loc	2 304 294                       # rnd_output0.c:304:294
	snez	a1, a1
	.loc	2 304 310                       # rnd_output0.c:304:310
	lw	a3, 700(a2)
	.loc	2 304 308                       # rnd_output0.c:304:308
	or	a1, a1, a3
	.loc	2 304 280                       # rnd_output0.c:304:280
	snez	a1, a1
	.loc	2 304 257                       # rnd_output0.c:304:257
	lw	a3, 696(a2)
	.loc	2 304 265                       # rnd_output0.c:304:265
	sh	a1, 0(a3)
	.loc	2 304 322                       # rnd_output0.c:304:322
	lw	a2, 744(a2)
	.loc	2 304 320                       # rnd_output0.c:304:320
	slt	a1, a1, a2
	.loc	2 304 150                       # rnd_output0.c:304:150
	slli	a0, a0, 16
	srai	a0, a0, 16
	call	safe_mul_func_int16_t_s_s
	mv	a1, a0
	.loc	2 304 90                        # rnd_output0.c:304:90
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 612(a0)                     # 4-byte Folded Reload
	slli	a1, a1, 16
	srli	a1, a1, 16
	call	safe_mod_func_uint16_t_u_u
	.loc	2 304 337                       # rnd_output0.c:304:337
	lui	a1, %hi(g_92)
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 616(a2)                     # 4-byte Folded Spill
	lw	a1, %lo(g_92)(a1)
	.loc	2 304 336                       # rnd_output0.c:304:336
	lw	a3, 4(a1)
	lw	a2, 0(a1)
	li	a1, 0
	.loc	2 304 62                        # rnd_output0.c:304:62
	lui	a4, 4
	sub	a4, s0, a4
	sw	a1, 632(a4)                     # 4-byte Folded Spill
	call	safe_sub_func_uint64_t_u_u
	lui	a2, 4
	sub	a2, s0, a2
	lw	a2, 736(a2)                     # 4-byte Folded Reload
	.loc	2 304 348                       # rnd_output0.c:304:348
	lw	a3, 700(a2)
	srai	a2, a3, 31
	.loc	2 304 345                       # rnd_output0.c:304:345
	xor	a0, a0, a3
	xor	a1, a1, a2
	or	a0, a0, a1
	seqz	a0, a0
	li	a1, 7
	.loc	2 304 34                        # rnd_output0.c:304:34
	call	safe_add_func_int16_t_s_s
	mv	a3, a0
	.loc	2 304 23                        # rnd_output0.c:304:23
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 616(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_200)
	lw	a2, %lo(g_200)(a1)
	.loc	2 304 30                        # rnd_output0.c:304:30
	lw	a1, 0(a2)
	and	a1, a1, a3
	sw	a1, 0(a2)
.Ltmp151:
	.loc	2 305 107 is_stmt 1             # rnd_output0.c:305:107
	lw	a0, %lo(g_92)(a0)
	.loc	2 305 106 is_stmt 0             # rnd_output0.c:305:106
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 305 73                        # rnd_output0.c:305:73
	call	safe_unary_minus_func_int64_t_s
	mv	a2, a1
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 620(a3)                     # 4-byte Folded Spill
	.loc	2 305 167                       # rnd_output0.c:305:167
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 624(a2)                     # 4-byte Folded Spill
	lw	a0, 772(a1)
	.loc	2 305 240                       # rnd_output0.c:305:240
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 628(a2)                     # 4-byte Folded Spill
	lw	a0, -24(s0)
	.loc	2 305 239                       # rnd_output0.c:305:239
	lw	a0, 0(a0)
	.loc	2 305 247                       # rnd_output0.c:305:247
	lhu	a1, 694(a1)
	.loc	2 305 209                       # rnd_output0.c:305:209
	call	safe_lshift_func_int32_t_s_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 632(a1)                     # 4-byte Folded Reload
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	.loc	2 305 453                       # rnd_output0.c:305:453
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 636(a3)                     # 4-byte Folded Spill
	lw	a2, 772(a0)
	.loc	2 305 449                       # rnd_output0.c:305:449
	lh	a0, 0(a2)
	addi	a0, a0, 1
	sh	a0, 0(a2)
	.loc	2 305 462                       # rnd_output0.c:305:462
	slli	a0, a0, 16
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 640(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_114
	j	.LBB0_113
.LBB0_113:
	.loc	2 305 511                       # rnd_output0.c:305:511
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 740(a1)
	.loc	2 305 509                       # rnd_output0.c:305:509
	sw	a0, 764(a1)
	lui	a1, 2
	addi	a1, a1, -916
	sub	a1, s0, a1
	.loc	2 305 519                       # rnd_output0.c:305:519
	xor	a0, a0, a1
	seqz	a0, a0
	lui	a1, 746023
	addi	a2, a1, 1003
	lui	a1, 874314
	addi	a3, a1, 1243
	li	a1, 0
	.loc	2 305 467                       # rnd_output0.c:305:467
	call	safe_add_func_uint64_t_u_u
	.loc	2 305 565                       # rnd_output0.c:305:565
	lui	a0, %hi(g_69)
	addi	a0, a0, %lo(g_69)
	lw	a0, 36(a0)
	.loc	2 305 462                       # rnd_output0.c:305:462
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 640(a1)                     # 4-byte Folded Spill
	j	.LBB0_114
.LBB0_114:
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 640(a0)                     # 4-byte Folded Reload
	.loc	2 305 462                       # rnd_output0.c:305:462
	andi	a2, a0, 1
	.loc	2 305 444                       # rnd_output0.c:305:444
	lw	a0, 856(a1)
	or	a0, a0, a2
	sw	a0, 856(a1)
	li	a1, 0
	.loc	2 305 571                       # rnd_output0.c:305:571
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 608(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_116
	j	.LBB0_115
.LBB0_115:
	.loc	2 305 574                       # rnd_output0.c:305:574
	lw	a1, -36(s0)
	lw	a0, -40(s0)
	.loc	2 305 571                       # rnd_output0.c:305:571
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 608(a1)                     # 4-byte Folded Spill
	j	.LBB0_116
.LBB0_116:
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 608(a0)                     # 4-byte Folded Reload
	.loc	2 305 426                       # rnd_output0.c:305:426
	andi	a0, a0, 1
	lui	a1, 558220
	addi	a2, a1, -1335
	lui	a1, 798628
	addi	a3, a1, -351
	li	a1, 0
	.loc	2 305 399                       # rnd_output0.c:305:399
	lui	a4, 4
	sub	a4, s0, a4
	sw	a1, 600(a4)                     # 4-byte Folded Spill
	call	safe_div_func_uint64_t_u_u
	.loc	2 305 372                       # rnd_output0.c:305:372
	slli	a0, a0, 16
	srai	a0, a0, 16
	lui	a1, 1048568
	addi	a1, a1, 1781
	call	safe_div_func_int16_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 600(a1)                     # 4-byte Folded Reload
	mv	a3, a0
	.loc	2 305 360                       # rnd_output0.c:305:360
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a2, 688(a0)
	.loc	2 305 368                       # rnd_output0.c:305:368
	lw	a0, 0(a2)
	xor	a0, a0, a3
	sw	a0, 0(a2)
	.loc	2 305 618                       # rnd_output0.c:305:618
	lw	a3, -28(s0)
	lw	a2, -32(s0)
	.loc	2 305 329                       # rnd_output0.c:305:329
	call	safe_sub_func_int64_t_s_s
	.loc	2 305 626                       # rnd_output0.c:305:626
	lui	a1, %hi(g_391)
	lw	a1, %lo(g_391)(a1)
	.loc	2 305 300                       # rnd_output0.c:305:300
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_lshift_func_int8_t_s_u
	li	a1, 4
	.loc	2 305 272                       # rnd_output0.c:305:272
	call	safe_mul_func_uint32_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 636(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 600(a0)                     # 4-byte Folded Reload
	li	a2, 1
	.loc	2 305 665                       # rnd_output0.c:305:665
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 604(a3)                     # 4-byte Folded Spill
	blt	a0, a1, .LBB0_118
	j	.LBB0_117
.LBB0_117:
	.loc	2 305 668                       # rnd_output0.c:305:668
	lw	a1, -28(s0)
	lw	a0, -32(s0)
	.loc	2 305 665                       # rnd_output0.c:305:665
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 604(a1)                     # 4-byte Folded Spill
	j	.LBB0_118
.LBB0_118:
	.loc	2 0 665                         # rnd_output0.c:0:665
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 604(a0)                     # 4-byte Folded Reload
	.loc	2 305 665                       # rnd_output0.c:305:665
	andi	a0, a0, 1
	.loc	2 305 677                       # rnd_output0.c:305:677
	lw	a1, 736(a1)
	.loc	2 305 674                       # rnd_output0.c:305:674
	xor	a0, a0, a1
	snez	a0, a0
	lui	a1, 6
	addi	a1, a1, -1083
	.loc	2 305 179                       # rnd_output0.c:305:179
	call	safe_mul_func_int16_t_s_s
                                        # kill: def $x11 killed $x10
	.loc	2 305 174                       # rnd_output0.c:305:174
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 628(a0)                     # 4-byte Folded Reload
	snez	a1, a0
	li	a0, -7
	.loc	2 305 134                       # rnd_output0.c:305:134
	call	safe_sub_func_int8_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 620(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
	mv	a3, a0
	.loc	2 305 131                       # rnd_output0.c:305:131
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 624(a0)                     # 4-byte Folded Reload
	sw	a3, 760(a1)
	.loc	2 305 727                       # rnd_output0.c:305:727
	lw	a3, -48(s0)
	.loc	2 305 115                       # rnd_output0.c:305:115
	xor	a0, a0, a3
	or	a0, a0, a2
	seqz	a0, a0
	.loc	2 305 737                       # rnd_output0.c:305:737
	lw	a1, 740(a1)
	.loc	2 305 736                       # rnd_output0.c:305:736
	lw	a2, 0(a1)
	srai	a3, a2, 31
	li	a1, 0
	.loc	2 305 45                        # rnd_output0.c:305:45
	call	safe_add_func_int64_t_s_s
                                        # kill: def $x10 killed $x11
	.loc	2 305 760                       # rnd_output0.c:305:760
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 2
	addi	a0, a0, -928
	sub	a0, s0, a0
	.loc	2 305 774                       # rnd_output0.c:305:774
	lw	a1, 1560(a1)
.Ltmp152:
	.loc	2 305 25                        # rnd_output0.c:305:25
	beq	a0, a1, .LBB0_120
	j	.LBB0_119
.LBB0_119:
.Ltmp153:
	.loc	2 307 32 is_stmt 1              # rnd_output0.c:307:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 740(a0)
	.loc	2 307 25 is_stmt 0              # rnd_output0.c:307:25
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp154:
.LBB0_120:
	.loc	2 311 76 is_stmt 1              # rnd_output0.c:311:76
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_813)
	lw	a0, %lo(g_813)(a0)
	.loc	2 311 83 is_stmt 0              # rnd_output0.c:311:83
	lw	a1, 684(a1)
	.loc	2 311 125                       # rnd_output0.c:311:125
	lui	a2, %hi(g_556)
	lw	a2, %lo(g_556)(a2)
	.loc	2 311 90                        # rnd_output0.c:311:90
	xor	a1, a1, a2
	snez	a1, a1
	.loc	2 311 79                        # rnd_output0.c:311:79
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 311 196                       # rnd_output0.c:311:196
	lui	a0, %hi(g_645)
	lbu	a0, %lo(g_645)(a0)
	li	a1, 6
	.loc	2 311 161                       # rnd_output0.c:311:161
	call	safe_rshift_func_uint8_t_u_s
	.loc	2 311 247                       # rnd_output0.c:311:247
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 592(a1)                     # 4-byte Folded Spill
	lw	a0, -48(s0)
	li	a1, 1
	.loc	2 311 252                       # rnd_output0.c:311:252
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 596(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_122
	j	.LBB0_121
.LBB0_121:
	.loc	2 311 321                       # rnd_output0.c:311:321
	lui	a0, %hi(g_292)
	lbu	a0, %lo(g_292)(a0)
	.loc	2 311 325                       # rnd_output0.c:311:325
	lbu	a1, -32(s0)
	.loc	2 311 283                       # rnd_output0.c:311:283
	call	safe_mod_func_uint8_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
	.loc	2 311 333                       # rnd_output0.c:311:333
	lw	a1, 700(a1)
	.loc	2 311 256                       # rnd_output0.c:311:256
	call	safe_sub_func_int32_t_s_s
	.loc	2 311 252                       # rnd_output0.c:311:252
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 596(a1)                     # 4-byte Folded Spill
	j	.LBB0_122
.LBB0_122:
	.loc	2 0 252                         # rnd_output0.c:0:252
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 596(a0)                     # 4-byte Folded Reload
	.loc	2 311 345                       # rnd_output0.c:311:345
	lui	a0, %hi(g_302)
	lw	a0, %lo(g_302)(a0)
	.loc	2 311 244                       # rnd_output0.c:311:244
	seqz	a0, a0
	.loc	2 311 355                       # rnd_output0.c:311:355
	lbu	a1, -44(s0)
	.loc	2 311 206                       # rnd_output0.c:311:206
	call	safe_sub_func_uint8_t_u_u
	mv	a1, a0
	.loc	2 311 135                       # rnd_output0.c:311:135
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 592(a0)                     # 4-byte Folded Reload
	slli	a1, a1, 24
	srai	a1, a1, 24
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_mul_func_int8_t_s_s
	.loc	2 311 367                       # rnd_output0.c:311:367
	lw	a0, -36(s0)
	.loc	2 311 66                        # rnd_output0.c:311:66
	srli	a0, a0, 31
	.loc	2 311 380                       # rnd_output0.c:311:380
	lw	a2, -48(s0)
	li	a3, 0
	.loc	2 311 40                        # rnd_output0.c:311:40
	mv	a1, a3
	call	safe_mod_func_int64_t_s_s
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 588(a3)                     # 4-byte Folded Spill
                                        # kill: def $x12 killed $x11
	.loc	2 311 29                        # rnd_output0.c:311:29
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 588(a1)                     # 4-byte Folded Reload
	lui	a2, %hi(g_1126)
	lw	a2, %lo(g_1126)(a2)
	.loc	2 311 28                        # rnd_output0.c:311:28
	lw	a2, 0(a2)
	.loc	2 311 27                        # rnd_output0.c:311:27
	lw	a2, 0(a2)
	.loc	2 311 37                        # rnd_output0.c:311:37
	sw	a1, 0(a2)
	.loc	2 312 32 is_stmt 1              # rnd_output0.c:312:32
	lw	a0, 740(a0)
	.loc	2 312 25 is_stmt 0              # rnd_output0.c:312:25
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp155:
.LBB0_123:                              #   in Loop: Header=BB0_105 Depth=2
	.loc	2 315 13 is_stmt 1              # rnd_output0.c:315:13
	j	.LBB0_124
.Ltmp156:
.LBB0_124:                              #   in Loop: Header=BB0_105 Depth=2
	.loc	2 287 83                        # rnd_output0.c:287:83
	lui	a0, %hi(g_589)
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 584(a1)                     # 4-byte Folded Spill
	lw	a0, %lo(g_589)(a0)
	srai	a1, a0, 31
	li	a2, 1
	li	a3, 0
	.loc	2 287 56 is_stmt 0              # rnd_output0.c:287:56
	call	safe_add_func_uint64_t_u_u
                                        # kill: def $x12 killed $x11
	.loc	2 287 54                        # rnd_output0.c:287:54
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 584(a1)                     # 4-byte Folded Reload
	sw	a0, %lo(g_589)(a1)
	.loc	2 287 13                        # rnd_output0.c:287:13
	j	.LBB0_105
.Ltmp157:
.LBB0_125:                              #   in Loop: Header=BB0_91 Depth=1
	.loc	2 316 24 is_stmt 1              # rnd_output0.c:316:24
	lui	a1, %hi(g_252)
	li	a0, 0
	sb	a0, %lo(g_252)(a1)
	.loc	2 316 18 is_stmt 0              # rnd_output0.c:316:18
	j	.LBB0_126
.LBB0_126:                              #   Parent Loop BB0_91 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp158:
	.loc	2 316 29                        # rnd_output0.c:316:29
	lui	a0, %hi(g_252)
	lb	a1, %lo(g_252)(a0)
	li	a0, 7
.Ltmp159:
	.loc	2 316 13                        # rnd_output0.c:316:13
	blt	a0, a1, .LBB0_129
	j	.LBB0_127
.LBB0_127:                              #   in Loop: Header=BB0_126 Depth=2
	.loc	2 0 13                          # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	li	a1, 0
.Ltmp160:
	.loc	2 318 27 is_stmt 1              # rnd_output0.c:318:27
	sw	a1, 676(a0)
	sw	a1, 672(a0)
	lui	a1, 66981
	addi	a1, a1, 947
	sw	a1, 668(a0)
	lui	a1, 112217
	addi	a1, a1, -189
	sw	a1, 664(a0)
	.loc	2 319 22                        # rnd_output0.c:319:22
	lui	a1, %hi(g_252)
	lb	a2, %lo(g_252)(a1)
	.loc	2 319 17 is_stmt 0              # rnd_output0.c:319:17
	lui	a1, %hi(g_69)
	addi	a1, a1, %lo(g_69)
	slli	a2, a2, 4
	add	a1, a1, a2
	.loc	2 319 31                        # rnd_output0.c:319:31
	lw	a2, 676(a0)
	sw	a2, 12(a1)
	lw	a2, 672(a0)
	sw	a2, 8(a1)
	lw	a2, 668(a0)
	sw	a2, 4(a1)
	lw	a0, 664(a0)
	sw	a0, 0(a1)
	.loc	2 320 13 is_stmt 1              # rnd_output0.c:320:13
	j	.LBB0_128
.Ltmp161:
.LBB0_128:                              #   in Loop: Header=BB0_126 Depth=2
	.loc	2 316 46                        # rnd_output0.c:316:46
	lui	a1, %hi(g_252)
	lbu	a0, %lo(g_252)(a1)
	addi	a0, a0, 1
	sb	a0, %lo(g_252)(a1)
	.loc	2 316 13 is_stmt 0              # rnd_output0.c:316:13
	j	.LBB0_126
.Ltmp162:
.LBB0_129:                              #   in Loop: Header=BB0_91 Depth=1
	.loc	2 321 30 is_stmt 1              # rnd_output0.c:321:30
	lui	a0, %hi(g_334)
	lw	a0, %lo(g_334)(a0)
	.loc	2 321 29 is_stmt 0              # rnd_output0.c:321:29
	lw	a2, 0(a0)
	.loc	2 321 17                        # rnd_output0.c:321:17
	lui	a0, %hi(g_1126)
	lw	a0, %lo(g_1126)(a0)
	.loc	2 321 16                        # rnd_output0.c:321:16
	lw	a0, 0(a0)
	.loc	2 321 15                        # rnd_output0.c:321:15
	lw	a1, 0(a0)
	.loc	2 321 25                        # rnd_output0.c:321:25
	lw	a0, 0(a1)
	xor	a0, a0, a2
	sw	a0, 0(a1)
	.loc	2 322 9 is_stmt 1               # rnd_output0.c:322:9
	j	.LBB0_130
.Ltmp163:
.LBB0_130:                              #   in Loop: Header=BB0_91 Depth=1
	.loc	2 273 46                        # rnd_output0.c:273:46
	lw	a0, -48(s0)
	addi	a0, a0, 1
	sw	a0, -48(s0)
	.loc	2 273 9 is_stmt 0               # rnd_output0.c:273:9
	j	.LBB0_91
.Ltmp164:
.LBB0_131:
	.loc	2 322 9 is_stmt 1               # rnd_output0.c:322:9
	j	.LBB0_132
.Ltmp165:
.LBB0_132:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_133 Depth 2
                                        #       Child Loop BB0_147 Depth 3
                                        #         Child Loop BB0_154 Depth 4
                                        #     Child Loop BB0_179 Depth 2
                                        #       Child Loop BB0_181 Depth 3
                                        #       Child Loop BB0_187 Depth 3
	#DEBUG_LABEL: lbl_1307
	.loc	2 324 21                        # rnd_output0.c:324:21
	lui	a1, %hi(g_1000)
	li	a0, -29
	sw	a0, %lo(g_1000)(a1)
	.loc	2 324 14 is_stmt 0              # rnd_output0.c:324:14
	j	.LBB0_133
.LBB0_133:                              #   Parent Loop BB0_132 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_147 Depth 3
                                        #         Child Loop BB0_154 Depth 4
.Ltmp166:
	.loc	2 324 31                        # rnd_output0.c:324:31
	lui	a0, %hi(g_1000)
	lw	a0, %lo(g_1000)(a0)
	li	a1, 15
.Ltmp167:
	.loc	2 324 9                         # rnd_output0.c:324:9
	bne	a0, a1, .LBB0_178
	j	.LBB0_134
.LBB0_134:                              #   in Loop: Header=BB0_133 Depth=2
.Ltmp168:
	.loc	2 326 28 is_stmt 1              # rnd_output0.c:326:28
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_13)
	addi	a0, a0, %lo(g_13)
	sw	a0, 660(a1)
	li	a0, -1
	.loc	2 327 21                        # rnd_output0.c:327:21
	sw	a0, 656(a1)
	.loc	2 328 33                        # rnd_output0.c:328:33
	addi	a0, s0, -2048
	addi	a0, a0, -960
	.loc	2 328 23 is_stmt 0              # rnd_output0.c:328:23
	sw	a0, 652(a1)
	.loc	2 329 20 is_stmt 1              # rnd_output0.c:329:20
	lui	a0, %hi(.L__const.func_40.l_1246)
	addi	a1, a0, %lo(.L__const.func_40.l_1246)
	lui	a0, 2
	addi	a0, a0, -833
	sub	a0, s0, a0
	li	a2, 35
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 736(a1)                     # 4-byte Folded Reload
                                        # kill: def $x11 killed $x10
	.loc	2 330 23                        # rnd_output0.c:330:23
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_1292)
	addi	a1, a1, %lo(g_1292)
	sw	a1, 612(a2)
	.loc	2 332 16                        # rnd_output0.c:332:16
	lui	a1, %hi(g_1126)
	lw	a1, %lo(g_1126)(a1)
	.loc	2 332 15 is_stmt 0              # rnd_output0.c:332:15
	lw	a2, 0(a1)
	li	a1, 0
	.loc	2 332 24                        # rnd_output0.c:332:24
	sw	a1, 0(a2)
.Ltmp169:
	.loc	2 333 30 is_stmt 1              # rnd_output0.c:333:30
	lw	a0, 560(a0)
.Ltmp170:
	.loc	2 333 17 is_stmt 0              # rnd_output0.c:333:17
	beqz	a0, .LBB0_146
	j	.LBB0_135
.LBB0_135:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 865574
	addi	a0, a0, 2013
.Ltmp171:
	.loc	2 335 25 is_stmt 1              # rnd_output0.c:335:25
	sw	a0, 600(a1)
.Ltmp172:
	.loc	2 336 23                        # rnd_output0.c:336:23
	lui	a0, %hi(g_334)
	lw	a0, %lo(g_334)(a0)
	.loc	2 336 22 is_stmt 0              # rnd_output0.c:336:22
	lw	a0, 0(a0)
.Ltmp173:
	.loc	2 336 21                        # rnd_output0.c:336:21
	beqz	a0, .LBB0_137
	j	.LBB0_136
.LBB0_136:                              #   in Loop: Header=BB0_132 Depth=1
.Ltmp174:
	.loc	2 337 21 is_stmt 1              # rnd_output0.c:337:21
	j	.LBB0_178
.Ltmp175:
.LBB0_137:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 338 26                        # rnd_output0.c:338:26
	lw	a0, -24(s0)
	.loc	2 338 25 is_stmt 0              # rnd_output0.c:338:25
	lw	a0, 0(a0)
	.loc	2 338 22                        # rnd_output0.c:338:22
	sw	a0, -44(s0)
	addi	a0, s0, -2048
	addi	a0, a0, -857
.Ltmp176:
	.loc	2 339 130 is_stmt 1             # rnd_output0.c:339:130
	seqz	a0, a0
	.loc	2 339 174 is_stmt 0             # rnd_output0.c:339:174
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 568(a1)                     # 4-byte Folded Spill
	li	a0, 1
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 580(a1)                     # 4-byte Folded Spill
	call	safe_unary_minus_func_int32_t_s
	mv	a1, a0
	.loc	2 339 173                       # rnd_output0.c:339:173
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 564(a2)                     # 4-byte Folded Spill
	srai	a1, a1, 31
	.loc	2 339 241                       # rnd_output0.c:339:241
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 560(a2)                     # 4-byte Folded Spill
	lw	a0, 600(a0)
	.loc	2 339 283                       # rnd_output0.c:339:283
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 556(a1)                     # 4-byte Folded Spill
	lui	a0, %hi(g_152)
	lb	a0, %lo(g_152)(a0)
	.loc	2 339 252                       # rnd_output0.c:339:252
	call	safe_unary_minus_func_int8_t_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 556(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 560(a1)                     # 4-byte Folded Reload
	mv	a3, a0
	.loc	2 339 248                       # rnd_output0.c:339:248
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 564(a0)                     # 4-byte Folded Reload
	slt	a2, a2, a3
	xori	a2, a2, 1
	li	a3, 0
	.loc	2 339 146                       # rnd_output0.c:339:146
	call	safe_sub_func_uint64_t_u_u
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 568(a0)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 572(a3)                     # 4-byte Folded Spill
                                        # kill: def $x12 killed $x11
	.loc	2 339 94                        # rnd_output0.c:339:94
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 572(a1)                     # 4-byte Folded Reload
	not	a1, a1
	andi	a1, a1, 255
	call	safe_mul_func_uint8_t_u_u
	.loc	2 339 91                        # rnd_output0.c:339:91
	sw	a0, -44(s0)
	lui	a1, 142919
	addi	a1, a1, -1229
	.loc	2 339 59                        # rnd_output0.c:339:59
	call	safe_sub_func_int32_t_s_s
	.loc	2 339 348                       # rnd_output0.c:339:348
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 576(a1)                     # 4-byte Folded Spill
	lui	a0, %hi(g_92)
	lw	a1, %lo(g_92)(a0)
	.loc	2 339 347                       # rnd_output0.c:339:347
	lw	a2, 4(a1)
	lw	a1, 0(a1)
	.loc	2 339 358                       # rnd_output0.c:339:358
	lw	a0, %lo(g_92)(a0)
	.loc	2 339 357                       # rnd_output0.c:339:357
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	li	a2, 58
	.loc	2 339 316                       # rnd_output0.c:339:316
	call	safe_lshift_func_int64_t_s_u
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 576(a0)                     # 4-byte Folded Reload
	.loc	2 339 373                       # rnd_output0.c:339:373
	lb	a1, -48(s0)
	.loc	2 339 33                        # rnd_output0.c:339:33
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_add_func_int8_t_s_s
.Ltmp177:
                                        # kill: def $x11 killed $x10
	.loc	2 339 21                        # rnd_output0.c:339:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 580(a0)                     # 4-byte Folded Reload
	bnez	a0, .LBB0_141
	j	.LBB0_138
.LBB0_138:                              #   in Loop: Header=BB0_133 Depth=2
.Ltmp178:
	.loc	2 341 27 is_stmt 1              # rnd_output0.c:341:27
	lw	a0, -24(s0)
	.loc	2 341 26 is_stmt 0              # rnd_output0.c:341:26
	lw	a0, 0(a0)
.Ltmp179:
	.loc	2 341 25                        # rnd_output0.c:341:25
	beqz	a0, .LBB0_140
	j	.LBB0_139
.LBB0_139:                              #   in Loop: Header=BB0_132 Depth=1
.Ltmp180:
	.loc	2 342 25 is_stmt 1              # rnd_output0.c:342:25
	j	.LBB0_178
.Ltmp181:
.LBB0_140:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 343 17                        # rnd_output0.c:343:17
	j	.LBB0_145
.Ltmp182:
.LBB0_141:
	.loc	2 346 46                        # rnd_output0.c:346:46
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 736(a0)                     # 4-byte Folded Reload
	addi	a0, s0, -960
	.loc	2 346 36 is_stmt 0              # rnd_output0.c:346:36
	sw	a0, 596(a2)
	li	a0, 239
.Ltmp183:
	.loc	2 347 36 is_stmt 1              # rnd_output0.c:347:36
	sb	a0, 564(a1)
	.loc	2 347 26 is_stmt 0              # rnd_output0.c:347:26
	j	.LBB0_142
.LBB0_142:
.Ltmp184:
	.loc	2 347 53                        # rnd_output0.c:347:53
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a0, 564(a0)
	li	a1, -17
.Ltmp185:
	.loc	2 347 21                        # rnd_output0.c:347:21
	beq	a0, a1, .LBB0_144
	j	.LBB0_143
.LBB0_143:
.Ltmp186:
	.loc	2 349 40 is_stmt 1              # rnd_output0.c:349:40
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_589)
	addi	a1, a1, %lo(g_589)
	sw	a1, 592(a0)
	.loc	2 350 32                        # rnd_output0.c:350:32
	lw	a0, 592(a0)
	.loc	2 350 25 is_stmt 0              # rnd_output0.c:350:25
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp187:
.LBB0_144:
	.loc	2 352 28 is_stmt 1              # rnd_output0.c:352:28
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 660(a0)
	.loc	2 352 21 is_stmt 0              # rnd_output0.c:352:21
	sw	a0, -20(s0)
	j	.LBB0_254
.Ltmp188:
.LBB0_145:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 354 20 is_stmt 1              # rnd_output0.c:354:20
	lui	a0, %hi(g_1126)
	lw	a0, %lo(g_1126)(a0)
	.loc	2 354 19 is_stmt 0              # rnd_output0.c:354:19
	lw	a1, 0(a0)
	addi	a0, s0, -44
	.loc	2 354 28                        # rnd_output0.c:354:28
	sw	a0, 0(a1)
	.loc	2 355 13 is_stmt 1              # rnd_output0.c:355:13
	j	.LBB0_174
.Ltmp189:
.LBB0_146:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 13 is_stmt 0                # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp190:
	.loc	2 358 27 is_stmt 1              # rnd_output0.c:358:27
	sw	a0, 580(a1)
	sw	a0, 576(a1)
	lui	a0, 303035
	addi	a0, a0, 159
	sw	a0, 572(a1)
	lui	a0, 18665
	addi	a0, a0, 1513
	sw	a0, 568(a1)
	addi	a0, s0, -2048
	addi	a0, a0, -872
	.loc	2 359 27                        # rnd_output0.c:359:27
	sw	a0, 564(a1)
	.loc	2 360 29                        # rnd_output0.c:360:29
	lui	a0, %hi(g_672)
	addi	a0, a0, %lo(g_672)
	addi	a0, a0, 424
	sw	a0, 560(a1)
.Ltmp191:
	.loc	2 361 31                        # rnd_output0.c:361:31
	lui	a1, %hi(g_645)
	li	a0, -7
	sw	a0, %lo(g_645)(a1)
	.loc	2 361 22 is_stmt 0              # rnd_output0.c:361:22
	j	.LBB0_147
.LBB0_147:                              #   Parent Loop BB0_132 Depth=1
                                        #     Parent Loop BB0_133 Depth=2
                                        # =>    This Loop Header: Depth=3
                                        #         Child Loop BB0_154 Depth 4
.Ltmp192:
	.loc	2 361 46                        # rnd_output0.c:361:46
	lui	a0, %hi(g_645)
	lw	a1, %lo(g_645)(a0)
	li	a0, 57
.Ltmp193:
	.loc	2 361 17                        # rnd_output0.c:361:17
	bltu	a0, a1, .LBB0_167
	j	.LBB0_148
.LBB0_148:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 69761
	addi	a0, a0, 583
.Ltmp194:
	.loc	2 363 30 is_stmt 1              # rnd_output0.c:363:30
	sw	a0, 556(a1)
	lui	a0, 94454
	addi	a0, a0, -244
	sw	a0, 552(a1)
	li	a0, 0
	.loc	2 364 31                        # rnd_output0.c:364:31
	sw	a0, 548(a1)
	li	a0, 8
	.loc	2 365 29                        # rnd_output0.c:365:29
	sw	a0, 544(a1)
.Ltmp195:
	.loc	2 366 26                        # rnd_output0.c:366:26
	lw	a0, 552(a1)
	.loc	2 366 48 is_stmt 0              # rnd_output0.c:366:48
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 552(a2)                     # 4-byte Folded Spill
	lw	a2, 660(a1)
	.loc	2 366 47                        # rnd_output0.c:366:47
	lw	a2, 0(a2)
	.loc	2 366 72                        # rnd_output0.c:366:72
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 548(a3)                     # 4-byte Folded Spill
	sw	a0, 568(a1)
	.loc	2 366 112                       # rnd_output0.c:366:112
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	lh	a0, 1496(a0)
	.loc	2 366 135                       # rnd_output0.c:366:135
	lui	a1, %hi(g_1113)
	lh	a1, %lo(g_1113)(a1)
	.loc	2 366 86                        # rnd_output0.c:366:86
	call	safe_div_func_int16_t_s_s
                                        # kill: def $x11 killed $x10
	.loc	2 366 208                       # rnd_output0.c:366:208
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 1556(a0)
	.loc	2 366 216                       # rnd_output0.c:366:216
	lw	a1, -40(s0)
	.loc	2 366 181                       # rnd_output0.c:366:181
	call	safe_div_func_uint32_t_u_u
	mv	a1, a0
	li	a0, -7
	.loc	2 366 144                       # rnd_output0.c:366:144
	call	safe_rshift_func_int16_t_s_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 548(a1)                     # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 366 56                        # rnd_output0.c:366:56
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 552(a0)                     # 4-byte Folded Reload
	xor	a1, a1, a2
	snez	a1, a1
	.loc	2 366 33                        # rnd_output0.c:366:33
	and	a0, a0, a1
.Ltmp196:
	.loc	2 366 25                        # rnd_output0.c:366:25
	beqz	a0, .LBB0_150
	j	.LBB0_149
.LBB0_149:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 0 25                          # rnd_output0.c:0:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 257366
	addi	a0, a0, -1358
.Ltmp197:
	.loc	2 368 34 is_stmt 1              # rnd_output0.c:368:34
	sw	a0, 540(a1)
	.loc	2 369 31                        # rnd_output0.c:369:31
	lw	a0, 540(a1)
	addi	a0, a0, -1
	sw	a0, 540(a1)
	.loc	2 370 21                        # rnd_output0.c:370:21
	j	.LBB0_153
.Ltmp198:
.LBB0_150:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 373 35                        # rnd_output0.c:373:35
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_200)
	addi	a1, a1, %lo(g_200)
	sw	a1, 536(a0)
	.loc	2 374 38                        # rnd_output0.c:374:38
	lw	a0, 660(a0)
	.loc	2 374 37 is_stmt 0              # rnd_output0.c:374:37
	lw	a0, 0(a0)
	li	a1, 0
	.loc	2 374 46                        # rnd_output0.c:374:46
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 544(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_152
	j	.LBB0_151
.LBB0_151:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 374 50                        # rnd_output0.c:374:50
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 564(a1)
	.loc	2 374 103                       # rnd_output0.c:374:103
	lw	a1, 652(a1)
	.loc	2 374 57                        # rnd_output0.c:374:57
	xor	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 544(a1)                     # 4-byte Folded Spill
	j	.LBB0_152
.LBB0_152:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 544(a0)                     # 4-byte Folded Reload
	.loc	2 374 32                        # rnd_output0.c:374:32
	lw	a2, 656(a1)
	.loc	2 374 46                        # rnd_output0.c:374:46
	and	a0, a0, a2
	.loc	2 374 32                        # rnd_output0.c:374:32
	andi	a0, a0, 1
	sw	a0, 656(a1)
	.loc	2 375 42 is_stmt 1              # rnd_output0.c:375:42
	lw	a0, -24(s0)
	.loc	2 375 41 is_stmt 0              # rnd_output0.c:375:41
	lw	a0, 0(a0)
	.loc	2 375 38                        # rnd_output0.c:375:38
	sb	a0, 634(a1)
	.loc	2 376 32 is_stmt 1              # rnd_output0.c:376:32
	lui	a0, %hi(g_733)
	addi	a0, a0, %lo(g_733)
	lui	a1, %hi(g_1247)
	sw	a0, %lo(g_1247)(a1)
	j	.LBB0_153
.Ltmp199:
.LBB0_153:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 0 32 is_stmt 0                # rnd_output0.c:0:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 238
.Ltmp200:
	.loc	2 378 32 is_stmt 1              # rnd_output0.c:378:32
	sb	a0, 627(a1)
	.loc	2 378 26 is_stmt 0              # rnd_output0.c:378:26
	j	.LBB0_154
.LBB0_154:                              #   Parent Loop BB0_132 Depth=1
                                        #     Parent Loop BB0_133 Depth=2
                                        #       Parent Loop BB0_147 Depth=3
                                        # =>      This Inner Loop Header: Depth=4
.Ltmp201:
	.loc	2 378 42                        # rnd_output0.c:378:42
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a0, 627(a0)
	li	a1, -5
.Ltmp202:
	.loc	2 378 21                        # rnd_output0.c:378:21
	beq	a0, a1, .LBB0_165
	j	.LBB0_155
.LBB0_155:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 0 21                          # rnd_output0.c:0:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 595964
	addi	a0, a0, -964
.Ltmp203:
	.loc	2 380 34 is_stmt 1              # rnd_output0.c:380:34
	sw	a0, 532(a1)
	addi	a0, s0, -2048
	addi	a0, a0, -912
	.loc	2 381 34                        # rnd_output0.c:381:34
	sw	a0, 528(a1)
	.loc	2 382 34                        # rnd_output0.c:382:34
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	addi	a0, a0, 552
	sw	a0, 524(a1)
	li	a0, 0
	.loc	2 383 33                        # rnd_output0.c:383:33
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 528(a2)                     # 4-byte Folded Spill
	sw	a0, 520(a1)
	lui	a2, 293663
	addi	a2, a2, 1008
	.loc	2 384 33                        # rnd_output0.c:384:33
	sw	a2, 516(a1)
	.loc	2 385 35                        # rnd_output0.c:385:35
	sw	a0, 500(a1)
	sw	a0, 496(a1)
	li	a2, -1
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 516(a3)                     # 4-byte Folded Spill
	sw	a2, 492(a1)
	li	a2, -9
	sw	a2, 488(a1)
	addi	a2, s0, -432
	.loc	2 386 36                        # rnd_output0.c:386:36
	sw	a2, 484(a1)
	.loc	2 387 43                        # rnd_output0.c:387:43
	lui	a2, 2
	addi	a2, a2, -842
	sub	a2, s0, a2
	.loc	2 387 33 is_stmt 0              # rnd_output0.c:387:33
	sw	a2, 480(a1)
	.loc	2 388 64 is_stmt 1              # rnd_output0.c:388:64
	lw	a2, 660(a1)
	.loc	2 388 63 is_stmt 0              # rnd_output0.c:388:63
	lw	a2, 0(a2)
	.loc	2 388 184                       # rnd_output0.c:388:184
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 532(a3)                     # 4-byte Folded Spill
	lbu	a2, 532(a1)
	.loc	2 388 174                       # rnd_output0.c:388:174
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 520(a3)                     # 4-byte Folded Spill
	lw	a3, 528(a1)
	.loc	2 388 182                       # rnd_output0.c:388:182
	sb	a2, 0(a3)
	.loc	2 388 169                       # rnd_output0.c:388:169
	sw	a2, 656(a1)
	.loc	2 388 197                       # rnd_output0.c:388:197
	addi	a2, s0, -2048
	addi	a2, a2, -288
	.loc	2 388 215                       # rnd_output0.c:388:215
	lui	a3, %hi(g_1258)
	lw	a3, %lo(g_1258)(a3)
	.loc	2 388 212                       # rnd_output0.c:388:212
	xor	a2, a2, a3
	seqz	a2, a2
	.loc	2 388 353                       # rnd_output0.c:388:353
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 524(a3)                     # 4-byte Folded Spill
	lw	a2, 524(a1)
	.loc	2 388 361                       # rnd_output0.c:388:361
	sw	a0, 4(a2)
	sw	a0, 0(a2)
	.loc	2 388 430                       # rnd_output0.c:388:430
	lui	a0, %hi(g_252)
	lb	a0, %lo(g_252)(a0)
	.loc	2 388 441                       # rnd_output0.c:388:441
	lw	a1, 660(a1)
	.loc	2 388 440                       # rnd_output0.c:388:440
	lw	a1, 0(a1)
	.loc	2 388 437                       # rnd_output0.c:388:437
	slt	a0, a0, a1
	.loc	2 388 453                       # rnd_output0.c:388:453
	lw	a1, -24(s0)
	.loc	2 388 452                       # rnd_output0.c:388:452
	lw	a1, 0(a1)
	.loc	2 388 371                       # rnd_output0.c:388:371
	call	safe_div_func_int32_t_s_s
	li	a0, 1
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 536(a1)                     # 4-byte Folded Spill
	li	a1, 5
	.loc	2 388 322                       # rnd_output0.c:388:322
	call	safe_add_func_int32_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a3, 528(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 736(a1)                     # 4-byte Folded Reload
	.loc	2 388 321                       # rnd_output0.c:388:321
	srai	a1, a0, 31
	.loc	2 388 477                       # rnd_output0.c:388:477
	lw	a2, 572(a2)
	.loc	2 388 294                       # rnd_output0.c:388:294
	call	safe_add_func_uint64_t_u_u
	lui	a2, 4
	sub	a2, s0, a2
	lw	a3, 516(a2)                     # 4-byte Folded Reload
	li	a2, -3
	.loc	2 388 267                       # rnd_output0.c:388:267
	call	safe_mul_func_int64_t_s_s
	.loc	2 388 510                       # rnd_output0.c:388:510
	lui	a2, %hi(g_1000)
	lw	a2, %lo(g_1000)(a2)
	.loc	2 388 227                       # rnd_output0.c:388:227
	call	safe_rshift_func_uint64_t_u_u
	mv	a3, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 520(a0)                     # 4-byte Folded Reload
	mv	a2, a1
	.loc	2 388 223                       # rnd_output0.c:388:223
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 524(a1)                     # 4-byte Folded Reload
	seqz	a2, a2
	sltu	a1, a1, a3
	not	a1, a1
	and	a1, a1, a2
	.loc	2 388 135                       # rnd_output0.c:388:135
	call	safe_add_func_uint8_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 528(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
	mv	a3, a0
	.loc	2 388 522                       # rnd_output0.c:388:522
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 532(a0)                     # 4-byte Folded Reload
	slt	a2, a2, a3
	.loc	2 388 531                       # rnd_output0.c:388:531
	lw	a3, -36(s0)
	lw	a4, -40(s0)
	.loc	2 388 529                       # rnd_output0.c:388:529
	or	a2, a2, a4
	lui	a4, 9
	addi	a4, a4, -695
	.loc	2 388 537                       # rnd_output0.c:388:537
	xor	a2, a2, a4
	or	a2, a2, a3
	snez	a2, a2
	.loc	2 388 552                       # rnd_output0.c:388:552
	lw	a3, 532(a1)
	.loc	2 388 549                       # rnd_output0.c:388:549
	xor	a2, a2, a3
	snez	a2, a2
	.loc	2 388 127                       # rnd_output0.c:388:127
	slt	a0, a0, a2
	xori	a2, a0, 1
	.loc	2 388 113                       # rnd_output0.c:388:113
	lw	a0, 516(a1)
	or	a0, a0, a2
	sw	a0, 516(a1)
	.loc	2 388 77                        # rnd_output0.c:388:77
	slli	a0, a0, 24
	srai	a0, a0, 24
	li	a1, 6
	call	safe_rshift_func_int8_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 536(a1)                     # 4-byte Folded Reload
	.loc	2 388 567                       # rnd_output0.c:388:567
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 540(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_157
	j	.LBB0_156
.LBB0_156:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 388 577                       # rnd_output0.c:388:577
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 572(a0)
	.loc	2 388 567                       # rnd_output0.c:388:567
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 540(a1)                     # 4-byte Folded Spill
	j	.LBB0_157
.LBB0_157:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 0 567                         # rnd_output0.c:0:567
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 540(a1)                     # 4-byte Folded Reload
	.loc	2 388 586                       # rnd_output0.c:388:586
	lw	a0, 600(a0)
	.loc	2 388 585                       # rnd_output0.c:388:585
	lw	a1, 0(a0)
	.loc	2 388 599                       # rnd_output0.c:388:599
	lw	a0, -24(s0)
	.loc	2 388 598                       # rnd_output0.c:388:598
	lw	a0, 0(a0)
	.loc	2 388 595                       # rnd_output0.c:388:595
	slt	a0, a0, a1
	lui	a1, 323800
	addi	a2, a1, -891
	lui	a1, 1012168
	addi	a3, a1, 2023
	li	a1, 0
	.loc	2 388 33                        # rnd_output0.c:388:33
	call	safe_mul_func_int64_t_s_s
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 512(a3)                     # 4-byte Folded Spill
                                        # kill: def $x12 killed $x11
	.loc	2 388 30                        # rnd_output0.c:388:30
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 512(a1)                     # 4-byte Folded Reload
	sw	a1, -44(s0)
.Ltmp204:
	.loc	2 389 29 is_stmt 1              # rnd_output0.c:389:29
	lw	a0, 1552(a0)
.Ltmp205:
	.loc	2 389 29 is_stmt 0              # rnd_output0.c:389:29
	beqz	a0, .LBB0_159
	j	.LBB0_158
.LBB0_158:                              #   in Loop: Header=BB0_147 Depth=3
.Ltmp206:
	.loc	2 390 29 is_stmt 1              # rnd_output0.c:390:29
	j	.LBB0_165
.Ltmp207:
.LBB0_159:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 391 132                       # rnd_output0.c:391:132
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a1, -416(s0)
	.loc	2 391 131 is_stmt 0             # rnd_output0.c:391:131
	lw	a3, 0(a1)
	.loc	2 391 119                       # rnd_output0.c:391:119
	lw	a2, 528(a0)
	.loc	2 391 127                       # rnd_output0.c:391:127
	lbu	a1, 0(a2)
	and	a1, a1, a3
	lui	a3, 4
	sub	a3, s0, a3
	sw	a1, 496(a3)                     # 4-byte Folded Spill
	sb	a1, 0(a2)
	.loc	2 391 145                       # rnd_output0.c:391:145
	lw	a2, 484(a0)
	.loc	2 391 155                       # rnd_output0.c:391:155
	lw	a1, 500(a0)
	sw	a1, 12(a2)
	lw	a1, 496(a0)
	sw	a1, 8(a2)
	lw	a1, 492(a0)
	sw	a1, 4(a2)
	lw	a1, 488(a0)
	sw	a1, 0(a2)
	.loc	2 391 296                       # rnd_output0.c:391:296
	lw	a0, 560(a0)
	.loc	2 391 293                       # rnd_output0.c:391:293
	seqz	a0, a0
	.loc	2 391 307                       # rnd_output0.c:391:307
	lw	a1, -28(s0)
	lw	a2, -32(s0)
	.loc	2 391 304                       # rnd_output0.c:391:304
	sltu	a0, a0, a2
	not	a0, a0
	seqz	a1, a1
	and	a0, a0, a1
	.loc	2 391 315                       # rnd_output0.c:391:315
	lw	a1, -40(s0)
	.loc	2 391 282                       # rnd_output0.c:391:282
	and	a0, a0, a1
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 500(a1)                     # 4-byte Folded Spill
	li	a1, 0
                                        # kill: def $x10 killed $x11
	.loc	2 391 327                       # rnd_output0.c:391:327
	lw	a0, -56(s0)
	.loc	2 391 334                       # rnd_output0.c:391:334
	lw	a0, 0(a0)
	.loc	2 391 382                       # rnd_output0.c:391:382
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 504(a2)                     # 4-byte Folded Spill
	lui	a0, %hi(g_813)
	lw	a0, %lo(g_813)(a0)
	.loc	2 391 385                       # rnd_output0.c:391:385
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 508(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_161
	j	.LBB0_160
.LBB0_160:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 391 397                       # rnd_output0.c:391:397
	lui	a0, %hi(g_147)
	lw	a0, %lo(g_147)(a0)
	.loc	2 391 385                       # rnd_output0.c:391:385
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 508(a1)                     # 4-byte Folded Spill
	j	.LBB0_161
.LBB0_161:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 508(a0)                     # 4-byte Folded Reload
	.loc	2 391 385                       # rnd_output0.c:391:385
	andi	a0, a0, 1
	.loc	2 391 408                       # rnd_output0.c:391:408
	lui	a1, %hi(g_556)
	lb	a1, %lo(g_556+4)(a1)
	.loc	2 391 350                       # rnd_output0.c:391:350
	call	safe_div_func_int8_t_s_s
	mv	a1, a0
	li	a2, 0
	lui	a0, 15
	addi	a0, a0, -261
	.loc	2 391 424                       # rnd_output0.c:391:424
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 492(a3)                     # 4-byte Folded Spill
	blt	a0, a1, .LBB0_163
	j	.LBB0_162
.LBB0_162:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 0 424                         # rnd_output0.c:0:424
	li	a0, 1
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 492(a1)                     # 4-byte Folded Spill
	j	.LBB0_163
.LBB0_163:                              #   in Loop: Header=BB0_154 Depth=4
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 500(a0)                     # 4-byte Folded Reload
	lui	a2, 4
	sub	a2, s0, a2
	lw	a2, 504(a2)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	lw	a3, 492(a3)                     # 4-byte Folded Reload
	.loc	2 391 451                       # rnd_output0.c:391:451
	lw	a3, 612(a1)
	.loc	2 391 448                       # rnd_output0.c:391:448
	seqz	a3, a3
	.loc	2 391 342                       # rnd_output0.c:391:342
	xor	a2, a2, a3
	seqz	a2, a2
	.loc	2 391 321                       # rnd_output0.c:391:321
	or	a0, a0, a2
	.loc	2 391 270                       # rnd_output0.c:391:270
	lw	a1, 480(a1)
	.loc	2 391 278                       # rnd_output0.c:391:278
	sb	a0, 0(a1)
	.loc	2 391 236                       # rnd_output0.c:391:236
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_unary_minus_func_int8_t_s
	mv	a1, a0
	li	a0, -7
	.loc	2 391 194                       # rnd_output0.c:391:194
	call	safe_div_func_uint32_t_u_u
	.loc	2 391 166                       # rnd_output0.c:391:166
	slli	a0, a0, 16
	srli	a0, a0, 16
	lui	a1, 5
	addi	a1, a1, -722
	call	safe_mod_func_uint16_t_u_u
	mv	a1, a0
	.loc	2 391 90                        # rnd_output0.c:391:90
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 496(a0)                     # 4-byte Folded Reload
	andi	a1, a1, 255
	andi	a0, a0, 255
	call	safe_div_func_uint8_t_u_u
	.loc	2 391 481                       # rnd_output0.c:391:481
	lb	a1, -40(s0)
	.loc	2 391 64                        # rnd_output0.c:391:64
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_div_func_int8_t_s_s
	.loc	2 391 490                       # rnd_output0.c:391:490
	lui	a1, %hi(g_8)
	addi	a1, a1, %lo(g_8)
	lw	a1, 480(a1)
	.loc	2 391 488                       # rnd_output0.c:391:488
	xor	a0, a0, a1
	.loc	2 391 34                        # rnd_output0.c:391:34
	slli	a0, a0, 24
	srai	a0, a0, 24
	li	a1, 4
	call	safe_rshift_func_int8_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 756(a1)                     # 4-byte Folded Reload
	.loc	2 391 511                       # rnd_output0.c:391:511
	lhu	a1, 474(a1)
	.loc	2 391 509                       # rnd_output0.c:391:509
	or	a0, a0, a1
	.loc	2 391 30                        # rnd_output0.c:391:30
	sw	a0, -44(s0)
	.loc	2 392 21 is_stmt 1              # rnd_output0.c:392:21
	j	.LBB0_164
.Ltmp208:
.LBB0_164:                              #   in Loop: Header=BB0_154 Depth=4
	.loc	2 378 63                        # rnd_output0.c:378:63
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lbu	a0, 627(a1)
	addi	a0, a0, 1
	sb	a0, 627(a1)
	.loc	2 378 21 is_stmt 0              # rnd_output0.c:378:21
	j	.LBB0_154
.Ltmp209:
.LBB0_165:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 393 32 is_stmt 1              # rnd_output0.c:393:32
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lw	a0, -24(s0)
	.loc	2 393 31 is_stmt 0              # rnd_output0.c:393:31
	lw	a0, 0(a0)
	.loc	2 393 28                        # rnd_output0.c:393:28
	sw	a0, 544(a1)
	.loc	2 394 17 is_stmt 1              # rnd_output0.c:394:17
	j	.LBB0_166
.Ltmp210:
.LBB0_166:                              #   in Loop: Header=BB0_147 Depth=3
	.loc	2 361 64                        # rnd_output0.c:361:64
	lui	a1, %hi(g_645)
	lw	a0, %lo(g_645)(a1)
	addi	a0, a0, 1
	sw	a0, %lo(g_645)(a1)
	.loc	2 361 17 is_stmt 0              # rnd_output0.c:361:17
	j	.LBB0_147
.Ltmp211:
.LBB0_167:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 395 69 is_stmt 1              # rnd_output0.c:395:69
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_903)
	lw	a1, %lo(g_903)(a1)
	.loc	2 395 68 is_stmt 0              # rnd_output0.c:395:68
	lw	a1, 0(a1)
	.loc	2 395 67                        # rnd_output0.c:395:67
	lw	a1, 0(a1)
	.loc	2 395 63                        # rnd_output0.c:395:63
	snez	a1, a1
	.loc	2 395 110                       # rnd_output0.c:395:110
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 484(a2)                     # 4-byte Folded Spill
	lw	a0, 572(a0)
	li	a1, 1
	.loc	2 395 113                       # rnd_output0.c:395:113
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 488(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_171
	j	.LBB0_168
.LBB0_168:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 395 191                       # rnd_output0.c:395:191
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_645)
	lw	a2, %lo(g_645)(a0)
	.loc	2 395 196                       # rnd_output0.c:395:196
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 472(a3)                     # 4-byte Folded Spill
	lw	a2, -48(s0)
	.loc	2 395 220                       # rnd_output0.c:395:220
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 476(a3)                     # 4-byte Folded Spill
	lw	a2, 560(a1)
	li	a1, 0
	.loc	2 395 228                       # rnd_output0.c:395:228
	sw	a1, 0(a2)
	.loc	2 395 262                       # rnd_output0.c:395:262
	lw	a0, %lo(g_645)(a0)
	li	a1, 1
	.loc	2 395 266                       # rnd_output0.c:395:266
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 480(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_170
	j	.LBB0_169
.LBB0_169:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 266                         # rnd_output0.c:0:266
	li	a0, 0
	.loc	2 395 266                       # rnd_output0.c:395:266
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 480(a1)                     # 4-byte Folded Spill
	j	.LBB0_170
.LBB0_170:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 266                         # rnd_output0.c:0:266
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 472(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 476(a1)                     # 4-byte Folded Reload
	lui	a2, 4
	sub	a2, s0, a2
	lw	a2, 480(a2)                     # 4-byte Folded Reload
	.loc	2 395 266                       # rnd_output0.c:395:266
	andi	a2, a2, 1
	lui	a3, 5
	addi	a3, a3, -662
	.loc	2 395 212                       # rnd_output0.c:395:212
	or	a2, a2, a3
	.loc	2 395 201                       # rnd_output0.c:395:201
	xor	a1, a1, a2
	.loc	2 395 155                       # rnd_output0.c:395:155
	slli	a0, a0, 16
	srli	a0, a0, 16
	call	safe_lshift_func_uint16_t_u_u
	li	a0, 255
	.loc	2 395 117                       # rnd_output0.c:395:117
	call	safe_unary_minus_func_uint8_t_u
	.loc	2 395 113                       # rnd_output0.c:395:113
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 488(a1)                     # 4-byte Folded Spill
	j	.LBB0_171
.LBB0_171:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 113                         # rnd_output0.c:0:113
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 484(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 488(a1)                     # 4-byte Folded Reload
	.loc	2 395 113                       # rnd_output0.c:395:113
	andi	a1, a1, 1
	.loc	2 395 27                        # rnd_output0.c:395:27
	andi	a0, a0, 255
	call	safe_mul_func_uint8_t_u_u
	li	a1, 1
	.loc	2 395 300                       # rnd_output0.c:395:300
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 468(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_173
	j	.LBB0_172
.LBB0_172:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 395 305                       # rnd_output0.c:395:305
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 660(a0)
	.loc	2 395 304                       # rnd_output0.c:395:304
	lw	a0, 0(a0)
	.loc	2 395 300                       # rnd_output0.c:395:300
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 468(a1)                     # 4-byte Folded Spill
	j	.LBB0_173
.LBB0_173:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 0 300                         # rnd_output0.c:0:300
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 468(a0)                     # 4-byte Folded Reload
	.loc	2 395 323                       # rnd_output0.c:395:323
	lw	a1, 568(a1)
	.loc	2 395 300                       # rnd_output0.c:395:300
	and	a0, a0, a1
	.loc	2 395 314                       # rnd_output0.c:395:314
	andi	a0, a0, 1
	.loc	2 395 22                        # rnd_output0.c:395:22
	sw	a0, -44(s0)
	j	.LBB0_174
.Ltmp212:
.LBB0_174:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 397 24 is_stmt 1              # rnd_output0.c:397:24
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 1404(a0)
	.loc	2 397 15 is_stmt 0              # rnd_output0.c:397:15
	lw	a1, -652(s0)
	.loc	2 397 22                        # rnd_output0.c:397:22
	sw	a0, 0(a1)
.Ltmp213:
	.loc	2 398 19 is_stmt 1              # rnd_output0.c:398:19
	lw	a0, -24(s0)
	.loc	2 398 18 is_stmt 0              # rnd_output0.c:398:18
	lw	a0, 0(a0)
.Ltmp214:
	.loc	2 398 17                        # rnd_output0.c:398:17
	beqz	a0, .LBB0_176
	j	.LBB0_175
.LBB0_175:                              #   in Loop: Header=BB0_132 Depth=1
.Ltmp215:
	.loc	2 399 17 is_stmt 1              # rnd_output0.c:399:17
	j	.LBB0_178
.Ltmp216:
.LBB0_176:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 400 9                         # rnd_output0.c:400:9
	j	.LBB0_177
.Ltmp217:
.LBB0_177:                              #   in Loop: Header=BB0_133 Depth=2
	.loc	2 324 81                        # rnd_output0.c:324:81
	lui	a0, %hi(g_1000)
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 464(a1)                     # 4-byte Folded Spill
	lw	a0, %lo(g_1000)(a0)
	srai	a1, a0, 31
	li	a2, 3
	li	a3, 0
	.loc	2 324 55 is_stmt 0              # rnd_output0.c:324:55
	call	safe_add_func_int64_t_s_s
                                        # kill: def $x12 killed $x11
	.loc	2 324 53                        # rnd_output0.c:324:53
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 464(a1)                     # 4-byte Folded Reload
	sw	a0, %lo(g_1000)(a1)
	.loc	2 324 9                         # rnd_output0.c:324:9
	j	.LBB0_133
.Ltmp218:
.LBB0_178:                              #   in Loop: Header=BB0_132 Depth=1
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp219:
	.loc	2 401 24 is_stmt 1              # rnd_output0.c:401:24
	sb	a0, 564(a1)
	.loc	2 401 14 is_stmt 0              # rnd_output0.c:401:14
	j	.LBB0_179
.LBB0_179:                              #   Parent Loop BB0_132 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_181 Depth 3
                                        #       Child Loop BB0_187 Depth 3
.Ltmp220:
	.loc	2 401 37                        # rnd_output0.c:401:37
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a0, 564(a0)
.Ltmp221:
	.loc	2 401 9                         # rnd_output0.c:401:9
	beqz	a0, .LBB0_199
	j	.LBB0_180
.LBB0_180:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 740(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 2
	addi	a0, a0, -692
	sub	a0, s0, a0
.Ltmp222:
	.loc	2 404 57 is_stmt 1              # rnd_output0.c:404:57
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 420(a3)                     # 4-byte Folded Spill
	sw	a0, 380(a2)
	.loc	2 404 70 is_stmt 0              # rnd_output0.c:404:70
	sw	a0, 384(a2)
	.loc	2 404 83                        # rnd_output0.c:404:83
	sw	a0, 388(a2)
	.loc	2 404 96                        # rnd_output0.c:404:96
	sw	a0, 392(a2)
	.loc	2 404 109                       # rnd_output0.c:404:109
	sw	a0, 396(a2)
	.loc	2 404 122                       # rnd_output0.c:404:122
	sw	a0, 400(a2)
	.loc	2 404 137                       # rnd_output0.c:404:137
	sw	a0, 404(a2)
	.loc	2 404 150                       # rnd_output0.c:404:150
	sw	a0, 408(a2)
	.loc	2 404 163                       # rnd_output0.c:404:163
	sw	a0, 412(a2)
	.loc	2 404 176                       # rnd_output0.c:404:176
	sw	a0, 416(a2)
	.loc	2 404 189                       # rnd_output0.c:404:189
	sw	a0, 420(a2)
	.loc	2 404 202                       # rnd_output0.c:404:202
	sw	a0, 424(a2)
	.loc	2 404 217                       # rnd_output0.c:404:217
	sw	a0, 428(a2)
	.loc	2 404 230                       # rnd_output0.c:404:230
	sw	a0, 432(a2)
	.loc	2 404 243                       # rnd_output0.c:404:243
	sw	a0, 436(a2)
	.loc	2 404 256                       # rnd_output0.c:404:256
	sw	a0, 440(a2)
	.loc	2 404 269                       # rnd_output0.c:404:269
	sw	a0, 444(a2)
	.loc	2 404 282                       # rnd_output0.c:404:282
	sw	a0, 448(a2)
	.loc	2 404 297                       # rnd_output0.c:404:297
	sw	a0, 452(a2)
	.loc	2 404 310                       # rnd_output0.c:404:310
	sw	a0, 456(a2)
	.loc	2 404 323                       # rnd_output0.c:404:323
	sw	a0, 460(a2)
	.loc	2 404 336                       # rnd_output0.c:404:336
	sw	a0, 464(a2)
	.loc	2 404 349                       # rnd_output0.c:404:349
	sw	a0, 468(a2)
	.loc	2 404 362                       # rnd_output0.c:404:362
	sw	a0, 472(a2)
	li	a7, 0
	.loc	2 405 22 is_stmt 1              # rnd_output0.c:405:22
	lui	a0, 4
	sub	a0, s0, a0
	sw	a7, 460(a0)                     # 4-byte Folded Spill
	sw	a7, 372(a2)
	sw	a7, 368(a2)
	lui	a0, 640220
	addi	a0, a0, 2021
	sw	a0, 364(a2)
	li	a0, 1
	sw	a0, 360(a2)
	li	a0, -1
	.loc	2 406 21                        # rnd_output0.c:406:21
	sw	a0, 356(a2)
	lui	a0, 851453
	addi	a0, a0, 881
	.loc	2 407 21                        # rnd_output0.c:407:21
	sw	a0, 352(a2)
	.loc	2 408 49                        # rnd_output0.c:408:49
	lui	a0, %hi(g_147)
	addi	a6, a0, %lo(g_147)
	lui	a0, 4
	sub	a0, s0, a0
	sw	a6, 424(a0)                     # 4-byte Folded Spill
	sw	a6, 1840(a1)
	lui	a0, %hi(g_8)
	addi	s1, a0, %lo(g_8)
	addi	t6, s1, 480
	sw	t6, 1844(a1)
	lui	a0, 2
	addi	a0, a0, -576
	sub	t3, s0, a0
	lui	a0, 4
	sub	a0, s0, a0
	sw	t3, 428(a0)                     # 4-byte Folded Spill
	sw	t3, 1848(a1)
	lui	a0, %hi(g_13)
	addi	a0, a0, %lo(g_13)
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 432(a3)                     # 4-byte Folded Spill
	sw	a0, 1852(a1)
	sw	t3, 1856(a1)
	sw	a0, 1860(a1)
	sw	a6, 1864(a1)
	sw	a6, 1868(a1)
	sw	a0, 1872(a1)
	sw	t3, 1876(a1)
	lui	a3, 2
	addi	a3, a3, -572
	sub	t4, s0, a3
	.loc	2 408 164 is_stmt 0             # rnd_output0.c:408:164
	lui	a3, 4
	sub	a3, s0, a3
	sw	t4, 436(a3)                     # 4-byte Folded Spill
	sw	t4, 1880(a1)
	lui	a3, %hi(g_556)
	addi	a4, a3, %lo(g_556)
	lui	a3, 4
	sub	a3, s0, a3
	sw	a4, 440(a3)                     # 4-byte Folded Spill
	sw	a4, 1884(a1)
	sw	a4, 1888(a1)
	sw	t4, 1892(a1)
	addi	a3, s0, -2048
	addi	a3, a3, -884
	lui	a5, 4
	sub	a5, s0, a5
	sw	a3, 444(a5)                     # 4-byte Folded Spill
	sw	a3, 1896(a1)
	lui	a5, 2
	addi	a5, a5, -568
	sub	t0, s0, a5
	sw	t0, 1900(a1)
	lui	a5, %hi(g_589)
	addi	t1, a5, %lo(g_589)
	sw	t1, 1904(a1)
	lui	a5, %hi(g_333)
	addi	t2, a5, %lo(g_333)
	lui	a5, 4
	sub	a5, s0, a5
	sw	t2, 448(a5)                     # 4-byte Folded Spill
	sw	t2, 1908(a1)
	sw	t2, 1912(a1)
	.loc	2 408 239                       # rnd_output0.c:408:239
	addi	a5, s0, -960
	.loc	2 408 164                       # rnd_output0.c:408:164
	lui	t5, 4
	sub	t5, s0, t5
	sw	a5, 452(t5)                     # 4-byte Folded Spill
	sw	a5, 1916(a1)
	.loc	2 408 255                       # rnd_output0.c:408:255
	sw	t6, 1920(a1)
	sw	a7, 1924(a1)
	sw	t4, 1928(a1)
	addi	t5, s0, -432
	sw	t5, 1932(a1)
	sw	a0, 1936(a1)
	sw	a5, 1940(a1)
	sw	a4, 1944(a1)
	sw	t1, 1948(a1)
	sw	t2, 1952(a1)
	sw	t4, 1956(a1)
	.loc	2 408 352                       # rnd_output0.c:408:352
	sw	t4, 1960(a1)
	sw	t3, 1964(a1)
	sw	t2, 1968(a1)
	sw	t4, 1972(a1)
	lui	t1, %hi(g_3)
	addi	t1, t1, %lo(g_3)
	lui	ra, 4
	sub	ra, s0, ra
	sw	t1, 456(ra)                     # 4-byte Folded Spill
	sw	t1, 1976(a1)
	sw	a6, 1980(a1)
	sw	a0, 1984(a1)
	sw	a0, 1988(a1)
	sw	a0, 1992(a1)
	sw	a6, 1996(a1)
	.loc	2 408 440                       # rnd_output0.c:408:440
	sw	a4, 2000(a1)
	sw	a0, 2004(a1)
	sw	a6, 2008(a1)
	sw	a0, 2012(a1)
	sw	a4, 2016(a1)
	sw	t3, 2020(a1)
	sw	t0, 2024(a1)
	sw	a6, 2028(a1)
	sw	t3, 2032(a1)
	sw	t5, 2036(a1)
	.loc	2 408 546                       # rnd_output0.c:408:546
	sw	t1, 2040(a1)
	addi	s1, s1, 252
	sw	s1, 2044(a1)
	sw	a7, 0(a2)
	sw	t2, 4(a2)
	sw	t0, 8(a2)
	sw	a6, 12(a2)
	sw	a5, 16(a2)
	sw	t3, 20(a2)
	sw	t3, 24(a2)
	sw	t5, 28(a2)
	.loc	2 408 658                       # rnd_output0.c:408:658
	sw	a5, 32(a2)
	sw	t2, 36(a2)
	sw	a0, 40(a2)
	sw	a3, 44(a2)
	sw	a4, 48(a2)
	sw	a5, 52(a2)
	sw	a6, 56(a2)
	sw	a7, 60(a2)
	sw	a7, 64(a2)
	sw	a6, 68(a2)
	.loc	2 408 769                       # rnd_output0.c:408:769
	sw	t2, 72(a2)
	sw	t1, 76(a2)
	lui	t0, 2
	addi	t0, t0, -1600
	sub	t0, s0, t0
	sw	t0, 80(a2)
	sw	t0, 84(a2)
	sw	t1, 88(a2)
	sw	t2, 92(a2)
	sw	t3, 96(a2)
	sw	a5, 100(a2)
	sw	a7, 104(a2)
	sw	t4, 108(a2)
	.loc	2 408 864                       # rnd_output0.c:408:864
	sw	a7, 112(a2)
	sw	t0, 116(a2)
	sw	a3, 120(a2)
	sw	a6, 124(a2)
	sw	a0, 128(a2)
	sw	t2, 132(a2)
	sw	a6, 136(a2)
	sw	t5, 140(a2)
	sw	t1, 144(a2)
	sw	a5, 148(a2)
	.loc	2 408 964                       # rnd_output0.c:408:964
	sw	a7, 152(a2)
	sw	a3, 156(a2)
	sw	t1, 160(a2)
	sw	t6, 164(a2)
	sw	a3, 168(a2)
	sw	t2, 172(a2)
	sw	a5, 176(a2)
	sw	t3, 180(a2)
	sw	a6, 184(a2)
	sw	t3, 188(a2)
	.loc	2 408 1074                      # rnd_output0.c:408:1074
	sw	t2, 192(a2)
	sw	a5, 196(a2)
	sw	t3, 200(a2)
	sw	a6, 204(a2)
	sw	t3, 208(a2)
	sw	a5, 212(a2)
	sw	t2, 216(a2)
	sw	a3, 220(a2)
	sw	t6, 224(a2)
	sw	t1, 228(a2)
	.loc	2 408 1190                      # rnd_output0.c:408:1190
	sw	a5, 232(a2)
	sw	a0, 236(a2)
	sw	a5, 240(a2)
	sw	t1, 244(a2)
	sw	t5, 248(a2)
	sw	a6, 252(a2)
	sw	t2, 256(a2)
	sw	a0, 260(a2)
	sw	a6, 264(a2)
	sw	a3, 268(a2)
	.loc	2 408 1292                      # rnd_output0.c:408:1292
	sw	t1, 272(a2)
	sw	a0, 276(a2)
	sw	t4, 280(a2)
	sw	a7, 284(a2)
	sw	a5, 288(a2)
	sw	t3, 292(a2)
	sw	t2, 296(a2)
	sw	t1, 300(a2)
	sw	t0, 304(a2)
	sw	t0, 308(a2)
	.loc	2 408 1386                      # rnd_output0.c:408:1386
	sw	a4, 312(a2)
	sw	a5, 316(a2)
	sw	a6, 320(a2)
	sw	a7, 324(a2)
	sw	a7, 328(a2)
	sw	a6, 332(a2)
	sw	a5, 336(a2)
	sw	a4, 340(a2)
	sw	a3, 344(a2)
	sw	a0, 348(a2)
	lui	a0, 4
	addi	a0, a0, -1943
	.loc	2 409 22 is_stmt 1              # rnd_output0.c:409:22
	sh	a0, 1838(a1)
	li	a0, 6
	.loc	2 410 20                        # rnd_output0.c:410:20
	sb	a0, 1837(a1)
	lui	a0, 880040
	addi	a0, a0, 286
	.loc	2 411 21                        # rnd_output0.c:411:21
	sw	a0, 1832(a1)
	lui	a0, 623604
	addi	a0, a0, 1721
	.loc	2 412 21                        # rnd_output0.c:412:21
	sw	a0, 1828(a1)
	.loc	2 413 21                        # rnd_output0.c:413:21
	lui	a0, %hi(.L__const.func_40.l_1433)
	addi	a1, a0, %lo(.L__const.func_40.l_1433)
	lui	a0, 2
	addi	a0, a0, 220
	sub	a0, s0, a0
	li	a2, 216
	call	memcpy@plt
	.loc	2 414 24                        # rnd_output0.c:414:24
	lui	a0, %hi(.L__const.func_40.l_1437)
	addi	a1, a0, %lo(.L__const.func_40.l_1437)
	lui	a0, 2
	addi	a0, a0, 340
	sub	a0, s0, a0
	li	a2, 120
	call	memcpy@plt
	.loc	2 415 22                        # rnd_output0.c:415:22
	lui	a0, %hi(.L__const.func_40.l_1516)
	addi	a1, a0, %lo(.L__const.func_40.l_1516)
	lui	a0, 2
	addi	a0, a0, 468
	sub	a0, s0, a0
	li	a2, 128
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
.Ltmp223:
	.loc	2 417 20                        # rnd_output0.c:417:20
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 460(a0)                     # 4-byte Folded Reload
	sw	a0, 1360(a1)
	.loc	2 417 18 is_stmt 0              # rnd_output0.c:417:18
	j	.LBB0_181
.LBB0_181:                              #   Parent Loop BB0_132 Depth=1
                                        #     Parent Loop BB0_179 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp224:
	.loc	2 417 25                        # rnd_output0.c:417:25
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lw	a1, 1360(a0)
	li	a0, 0
.Ltmp225:
	.loc	2 417 13                        # rnd_output0.c:417:13
	blt	a0, a1, .LBB0_184
	j	.LBB0_182
.LBB0_182:                              #   in Loop: Header=BB0_181 Depth=3
.Ltmp226:
	.loc	2 418 24 is_stmt 1              # rnd_output0.c:418:24
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lw	a0, 1360(a0)
	.loc	2 418 17 is_stmt 0              # rnd_output0.c:418:17
	slli	a1, a0, 2
	lui	a0, 2
	addi	a0, a0, -692
	sub	a0, s0, a0
	add	a1, a1, a0
	.loc	2 418 27                        # rnd_output0.c:418:27
	lui	a0, %hi(g_294)
	addi	a0, a0, %lo(g_294)
	sw	a0, 0(a1)
	.loc	2 418 17                        # rnd_output0.c:418:17
	j	.LBB0_183
.LBB0_183:                              #   in Loop: Header=BB0_181 Depth=3
	.loc	2 417 33 is_stmt 1              # rnd_output0.c:417:33
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 740(a0)                     # 4-byte Folded Reload
	lw	a0, 1360(a1)
	addi	a0, a0, 1
	sw	a0, 1360(a1)
	.loc	2 417 13 is_stmt 0              # rnd_output0.c:417:13
	j	.LBB0_181
.Ltmp227:
.LBB0_184:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 419 17 is_stmt 1              # rnd_output0.c:419:17
	lui	a0, %hi(g_388)
	lhu	a0, %lo(g_388)(a0)
.Ltmp228:
	.loc	2 419 17 is_stmt 0              # rnd_output0.c:419:17
	beqz	a0, .LBB0_186
	j	.LBB0_185
.LBB0_185:                              #   in Loop: Header=BB0_132 Depth=1
.Ltmp229:
	.loc	2 420 17 is_stmt 1              # rnd_output0.c:420:17
	j	.LBB0_132
.Ltmp230:
.LBB0_186:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 421 24                        # rnd_output0.c:421:24
	lui	a1, %hi(g_117)
	li	a0, -16
	sw	a0, %lo(g_117)(a1)
	.loc	2 421 18 is_stmt 0              # rnd_output0.c:421:18
	j	.LBB0_187
.LBB0_187:                              #   Parent Loop BB0_132 Depth=1
                                        #     Parent Loop BB0_179 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp231:
	.loc	2 421 34                        # rnd_output0.c:421:34
	lui	a0, %hi(g_117)
	lw	a0, %lo(g_117)(a0)
	li	a1, 43
.Ltmp232:
	.loc	2 421 13                        # rnd_output0.c:421:13
	bltu	a0, a1, .LBB0_190
	j	.LBB0_188
.LBB0_188:                              #   in Loop: Header=BB0_187 Depth=3
.Ltmp233:
	.loc	2 423 48 is_stmt 1              # rnd_output0.c:423:48
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 740(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(.Lconstinit)
	lw	a2, %lo(.Lconstinit)(a0)
	sw	a2, 680(a1)
	addi	a0, a0, %lo(.Lconstinit)
	lw	a2, 20(a0)
	sw	a2, 700(a1)
	lw	a2, 16(a0)
	sw	a2, 696(a1)
	lw	a2, 12(a0)
	sw	a2, 692(a1)
	lw	a2, 8(a0)
	sw	a2, 688(a1)
	lw	a0, 4(a0)
	sw	a0, 684(a1)
	.loc	2 423 120 is_stmt 0             # rnd_output0.c:423:120
	lui	a0, %hi(.Lconstinit.1)
	addi	a2, a0, %lo(.Lconstinit.1)
	lw	a3, 20(a2)
	sw	a3, 724(a1)
	lw	a3, 16(a2)
	sw	a3, 720(a1)
	lw	a3, 12(a2)
	sw	a3, 716(a1)
	lw	a3, 8(a2)
	sw	a3, 712(a1)
	lw	a2, 4(a2)
	sw	a2, 708(a1)
	lw	a0, %lo(.Lconstinit.1)(a0)
	sw	a0, 704(a1)
	.loc	2 423 186                       # rnd_output0.c:423:186
	lui	a0, %hi(g_467)
	addi	t0, a0, %lo(g_467)
	lui	a0, 4
	sub	a0, s0, a0
	sw	t0, 388(a0)                     # 4-byte Folded Spill
	addi	a5, t0, 8
	lui	a0, 4
	sub	a0, s0, a0
	sw	a5, 392(a0)                     # 4-byte Folded Spill
	sw	a5, 728(a1)
	addi	a4, t0, 4
	lui	a0, 4
	sub	a0, s0, a0
	sw	a4, 396(a0)                     # 4-byte Folded Spill
	sw	a4, 732(a1)
	sw	t0, 736(a1)
	addi	a3, s0, -64
	lui	a0, 4
	sub	a0, s0, a0
	sw	a3, 400(a0)                     # 4-byte Folded Spill
	sw	a3, 740(a1)
	addi	a2, t0, 12
	lui	a0, 4
	sub	a0, s0, a0
	sw	a2, 404(a0)                     # 4-byte Folded Spill
	sw	a2, 744(a1)
	sw	a2, 748(a1)
	.loc	2 423 260                       # rnd_output0.c:423:260
	sw	a3, 752(a1)
	lui	a0, %hi(g_71)
	addi	a6, a0, %lo(g_71)
	lui	a0, 4
	sub	a0, s0, a0
	sw	a6, 408(a0)                     # 4-byte Folded Spill
	sw	a6, 756(a1)
	sw	a6, 760(a1)
	sw	a6, 764(a1)
	addi	t1, t0, 20
	sw	t1, 768(a1)
	sw	a2, 772(a1)
	.loc	2 423 315                       # rnd_output0.c:423:315
	sw	a6, 776(a1)
	li	a0, 0
	lui	a7, 4
	sub	a7, s0, a7
	sw	a0, 416(a7)                     # 4-byte Folded Spill
	sw	a0, 780(a1)
	sw	a4, 784(a1)
	sw	a3, 788(a1)
	sw	a5, 792(a1)
	addi	a7, t0, 24
	lui	t2, 4
	sub	t2, s0, t2
	sw	a7, 412(t2)                     # 4-byte Folded Spill
	sw	a7, 796(a1)
	.loc	2 423 378                       # rnd_output0.c:423:378
	sw	a2, 800(a1)
	sw	a3, 804(a1)
	sw	a4, 808(a1)
	sw	a4, 812(a1)
	sw	a3, 816(a1)
	sw	a2, 820(a1)
	.loc	2 423 446                       # rnd_output0.c:423:446
	lui	t2, %hi(.Lconstinit.2)
	addi	t3, t2, %lo(.Lconstinit.2)
	lw	t4, 20(t3)
	sw	t4, 844(a1)
	lw	t4, 16(t3)
	sw	t4, 840(a1)
	lw	t4, 12(t3)
	sw	t4, 836(a1)
	lw	t4, 8(t3)
	sw	t4, 832(a1)
	lw	t3, 4(t3)
	sw	t3, 828(a1)
	lw	t2, %lo(.Lconstinit.2)(t2)
	sw	t2, 824(a1)
	.loc	2 423 512                       # rnd_output0.c:423:512
	sw	a3, 848(a1)
	sw	a3, 852(a1)
	sw	t0, 856(a1)
	sw	a6, 860(a1)
	sw	a2, 864(a1)
	sw	a5, 868(a1)
	.loc	2 423 575                       # rnd_output0.c:423:575
	sw	a3, 872(a1)
	sw	a0, 876(a1)
	sw	a6, 880(a1)
	sw	a2, 884(a1)
	sw	a7, 888(a1)
	sw	a7, 892(a1)
	.loc	2 423 638                       # rnd_output0.c:423:638
	sw	a7, 896(a1)
	sw	a6, 900(a1)
	sw	a0, 904(a1)
	sw	a4, 908(a1)
	sw	a3, 912(a1)
	sw	a5, 916(a1)
	.loc	2 423 701                       # rnd_output0.c:423:701
	sw	a2, 920(a1)
	sw	a4, 924(a1)
	sw	a2, 928(a1)
	sw	a3, 932(a1)
	sw	a3, 936(a1)
	sw	a2, 940(a1)
	.loc	2 423 769                       # rnd_output0.c:423:769
	lui	t2, %hi(.Lconstinit.3)
	addi	t3, t2, %lo(.Lconstinit.3)
	lw	t4, 20(t3)
	sw	t4, 964(a1)
	lw	t4, 16(t3)
	sw	t4, 960(a1)
	lw	t4, 12(t3)
	sw	t4, 956(a1)
	lw	t4, 8(t3)
	sw	t4, 952(a1)
	lw	t3, 4(t3)
	sw	t3, 948(a1)
	lw	t2, %lo(.Lconstinit.3)(t2)
	sw	t2, 944(a1)
	.loc	2 423 830                       # rnd_output0.c:423:830
	sw	a3, 968(a1)
	sw	a0, 972(a1)
	sw	a2, 976(a1)
	sw	a3, 980(a1)
	sw	a2, 984(a1)
	sw	a7, 988(a1)
	.loc	2 423 894                       # rnd_output0.c:423:894
	sw	a5, 992(a1)
	sw	a3, 996(a1)
	sw	a2, 1000(a1)
	sw	a4, 1004(a1)
	sw	a6, 1008(a1)
	sw	a2, 1012(a1)
	.loc	2 423 961                       # rnd_output0.c:423:961
	sw	t1, 1016(a1)
	sw	a4, 1020(a1)
	sw	a7, 1024(a1)
	sw	a2, 1028(a1)
	sw	a3, 1032(a1)
	sw	a2, 1036(a1)
	.loc	2 423 1035                      # rnd_output0.c:423:1035
	sw	a2, 1040(a1)
	sw	a3, 1044(a1)
	sw	a2, 1048(a1)
	sw	a6, 1052(a1)
	sw	a5, 1056(a1)
	sw	a5, 1060(a1)
	.loc	2 423 1104                      # rnd_output0.c:423:1104
	lui	t2, %hi(.Lconstinit.4)
	addi	t3, t2, %lo(.Lconstinit.4)
	lw	t4, 20(t3)
	sw	t4, 1084(a1)
	lw	t4, 16(t3)
	sw	t4, 1080(a1)
	lw	t4, 12(t3)
	sw	t4, 1076(a1)
	lw	t4, 8(t3)
	sw	t4, 1072(a1)
	lw	t3, 4(t3)
	sw	t3, 1068(a1)
	lw	t2, %lo(.Lconstinit.4)(t2)
	sw	t2, 1064(a1)
	.loc	2 423 1176                      # rnd_output0.c:423:1176
	lui	t2, %hi(.Lconstinit.5)
	addi	t3, t2, %lo(.Lconstinit.5)
	lw	t4, 20(t3)
	sw	t4, 1108(a1)
	lw	t4, 16(t3)
	sw	t4, 1104(a1)
	lw	t4, 12(t3)
	sw	t4, 1100(a1)
	lw	t4, 8(t3)
	sw	t4, 1096(a1)
	lw	t3, 4(t3)
	sw	t3, 1092(a1)
	lw	t2, %lo(.Lconstinit.5)(t2)
	sw	t2, 1088(a1)
	.loc	2 423 1242                      # rnd_output0.c:423:1242
	sw	a5, 1112(a1)
	sw	a4, 1116(a1)
	sw	t0, 1120(a1)
	sw	a3, 1124(a1)
	sw	a2, 1128(a1)
	sw	a2, 1132(a1)
	.loc	2 423 1316                      # rnd_output0.c:423:1316
	sw	a3, 1136(a1)
	sw	a6, 1140(a1)
	sw	a6, 1144(a1)
	sw	a6, 1148(a1)
	sw	t1, 1152(a1)
	sw	a2, 1156(a1)
	.loc	2 423 1371                      # rnd_output0.c:423:1371
	sw	a6, 1160(a1)
	sw	a0, 1164(a1)
	sw	a4, 1168(a1)
	sw	a3, 1172(a1)
	sw	a5, 1176(a1)
	sw	a7, 1180(a1)
	.loc	2 423 1434                      # rnd_output0.c:423:1434
	sw	a2, 1184(a1)
	sw	a3, 1188(a1)
	sw	a4, 1192(a1)
	sw	a4, 1196(a1)
	sw	a3, 1200(a1)
	sw	a2, 1204(a1)
	.loc	2 423 1502                      # rnd_output0.c:423:1502
	lui	t1, %hi(.Lconstinit.6)
	addi	t2, t1, %lo(.Lconstinit.6)
	lw	t3, 20(t2)
	sw	t3, 1228(a1)
	lw	t3, 16(t2)
	sw	t3, 1224(a1)
	lw	t3, 12(t2)
	sw	t3, 1220(a1)
	lw	t3, 8(t2)
	sw	t3, 1216(a1)
	lw	t2, 4(t2)
	sw	t2, 1212(a1)
	lw	t1, %lo(.Lconstinit.6)(t1)
	sw	t1, 1208(a1)
	.loc	2 423 1568                      # rnd_output0.c:423:1568
	sw	a3, 1232(a1)
	sw	a3, 1236(a1)
	sw	t0, 1240(a1)
	sw	a6, 1244(a1)
	sw	a2, 1248(a1)
	sw	a5, 1252(a1)
	.loc	2 423 1631                      # rnd_output0.c:423:1631
	sw	a3, 1256(a1)
	sw	a0, 1260(a1)
	sw	a6, 1264(a1)
	sw	a2, 1268(a1)
	sw	a7, 1272(a1)
	sw	a7, 1276(a1)
	.loc	2 423 1694                      # rnd_output0.c:423:1694
	sw	a7, 1280(a1)
	sw	a6, 1284(a1)
	sw	a0, 1288(a1)
	sw	a4, 1292(a1)
	sw	a3, 1296(a1)
	sw	a5, 1300(a1)
	.loc	2 423 1757                      # rnd_output0.c:423:1757
	sw	a2, 1304(a1)
	sw	a4, 1308(a1)
	sw	a2, 1312(a1)
	sw	a3, 1316(a1)
	sw	a3, 1320(a1)
	sw	a2, 1324(a1)
	.loc	2 423 1825                      # rnd_output0.c:423:1825
	lui	a2, %hi(.Lconstinit.7)
	addi	a3, a2, %lo(.Lconstinit.7)
	lw	a4, 20(a3)
	sw	a4, 1348(a1)
	lw	a4, 16(a3)
	sw	a4, 1344(a1)
	lw	a4, 12(a3)
	sw	a4, 1340(a1)
	lw	a4, 8(a3)
	sw	a4, 1336(a1)
	lw	a3, 4(a3)
	sw	a3, 1332(a1)
	lw	a2, %lo(.Lconstinit.7)(a2)
	sw	a2, 1328(a1)
	lui	a2, 12
	addi	a2, a2, -242
	.loc	2 424 26 is_stmt 1              # rnd_output0.c:424:26
	sh	a2, 678(a1)
	.loc	2 425 26                        # rnd_output0.c:425:26
	lui	a2, %hi(g_70)
	addi	a2, a2, %lo(g_70)
	addi	a2, a2, 80
	sw	a2, 672(a1)
	.loc	2 426 27                        # rnd_output0.c:426:27
	sw	a0, 660(a1)
	sw	a0, 656(a1)
	lui	a0, 381712
	addi	a0, a0, -19
	sw	a0, 652(a1)
	li	a0, 9
	sw	a0, 648(a1)
	.loc	2 427 25                        # rnd_output0.c:427:25
	lui	a0, %hi(.L__const.func_40.l_1431)
	addi	a1, a0, %lo(.L__const.func_40.l_1431)
	lui	a0, 2
	addi	a0, a0, 1604
	sub	a0, s0, a0
	li	a2, 420
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 416(a0)                     # 4-byte Folded Reload
	lui	a2, 2
	addi	a2, a2, -1843
	.loc	2 428 26                        # rnd_output0.c:428:26
	sh	a2, 226(a1)
	li	a2, -4
	.loc	2 429 25                        # rnd_output0.c:429:25
	sh	a2, 224(a1)
	.loc	2 430 28                        # rnd_output0.c:430:28
	sw	a0, 220(a1)
	.loc	2 431 25                        # rnd_output0.c:431:25
	lui	a0, %hi(g_197)
	addi	a0, a0, %lo(g_197)
	addi	a0, a0, 19
	sw	a0, 216(a1)
	.loc	2 433 13                        # rnd_output0.c:433:13
	j	.LBB0_189
.Ltmp234:
.LBB0_189:                              #   in Loop: Header=BB0_187 Depth=3
	.loc	2 421 48                        # rnd_output0.c:421:48
	lui	a1, %hi(g_117)
	lw	a0, %lo(g_117)(a1)
	addi	a0, a0, 1
	sw	a0, %lo(g_117)(a1)
	.loc	2 421 13 is_stmt 0              # rnd_output0.c:421:13
	j	.LBB0_187
.Ltmp235:
.LBB0_190:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 434 101 is_stmt 1             # rnd_output0.c:434:101
	lw	a0, -44(s0)
	.loc	2 434 99 is_stmt 0              # rnd_output0.c:434:99
	xori	a0, a0, 1
	.loc	2 434 44                        # rnd_output0.c:434:44
	call	safe_unary_minus_func_uint32_t_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 736(a1)                     # 4-byte Folded Reload
	.loc	2 434 142                       # rnd_output0.c:434:142
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 384(a2)                     # 4-byte Folded Spill
	lw	a0, -24(s0)
	.loc	2 434 141                       # rnd_output0.c:434:141
	lw	a0, 0(a0)
	.loc	2 434 150                       # rnd_output0.c:434:150
	lw	a1, 924(a1)
	.loc	2 434 157                       # rnd_output0.c:434:157
	seqz	a1, a1
	.loc	2 434 111                       # rnd_output0.c:434:111
	call	safe_rshift_func_int32_t_s_u
	mv	a1, a0
	.loc	2 434 18                        # rnd_output0.c:434:18
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 384(a0)                     # 4-byte Folded Reload
	slli	a1, a1, 24
	srai	a1, a1, 24
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_div_func_int8_t_s_s
.Ltmp236:
	.loc	2 434 17                        # rnd_output0.c:434:17
	beqz	a0, .LBB0_192
	j	.LBB0_191
.LBB0_191:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lui	a2, 16665
	addi	a2, a2, 734
.Ltmp237:
	.loc	2 436 26 is_stmt 1              # rnd_output0.c:436:26
	sw	a2, 200(a0)
	lui	a2, 183323
	addi	a2, a2, -1747
	.loc	2 437 25                        # rnd_output0.c:437:25
	sw	a2, 196(a0)
	li	a2, 1
	.loc	2 438 25                        # rnd_output0.c:438:25
	sw	a2, 192(a0)
	.loc	2 439 23                        # rnd_output0.c:439:23
	lw	a2, 200(a0)
	addi	a2, a2, -1
	sw	a2, 200(a0)
	.loc	2 440 40                        # rnd_output0.c:440:40
	lw	a2, 1448(a0)
	.loc	2 440 37 is_stmt 0              # rnd_output0.c:440:37
	lui	a0, %hi(g_152)
	addi	a0, a0, %lo(g_152)
	xor	a0, a0, a2
	snez	a0, a0
	.loc	2 440 19                        # rnd_output0.c:440:19
	lw	a2, 468(a1)
	.loc	2 440 27                        # rnd_output0.c:440:27
	sw	a0, 0(a2)
	.loc	2 441 17 is_stmt 1              # rnd_output0.c:441:17
	lw	a0, 464(a1)
	addi	a0, a0, -1
	sw	a0, 464(a1)
	.loc	2 442 13                        # rnd_output0.c:442:13
	j	.LBB0_197
.Ltmp238:
.LBB0_192:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 445 25                        # rnd_output0.c:445:25
	lui	a0, %hi(.L__const.func_40.l_1532)
	addi	a1, a0, %lo(.L__const.func_40.l_1532)
	lui	a0, 2
	addi	a0, a0, 1680
	sub	a0, s0, a0
	li	a2, 40
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 740(a0)                     # 4-byte Folded Reload
	.loc	2 446 27                        # rnd_output0.c:446:27
	lui	a0, %hi(g_642)
	addi	a0, a0, %lo(g_642)
	sw	a0, 148(a2)
	.loc	2 447 26                        # rnd_output0.c:447:26
	lui	a0, %hi(.L__const.func_40.l_1543)
	addi	a1, a0, %lo(.L__const.func_40.l_1543)
	lw	a3, 20(a1)
	sw	a3, 144(a2)
	lw	a3, 16(a1)
	sw	a3, 140(a2)
	lw	a3, 12(a1)
	sw	a3, 136(a2)
	lw	a3, 8(a1)
	sw	a3, 132(a2)
	lw	a1, 4(a1)
	sw	a1, 128(a2)
	lw	a0, %lo(.L__const.func_40.l_1543)(a0)
	sw	a0, 124(a2)
	.loc	2 448 27                        # rnd_output0.c:448:27
	lui	a0, %hi(g_200)
	addi	a0, a0, %lo(g_200)
	sw	a0, 120(a2)
	.loc	2 449 27                        # rnd_output0.c:449:27
	lui	a0, %hi(g_1548)
	addi	a0, a0, %lo(g_1548)
	sw	a0, 116(a2)
	lui	a0, 390946
	addi	a0, a0, -1669
	.loc	2 450 25                        # rnd_output0.c:450:25
	sw	a0, 112(a2)
	lui	a0, 597604
	addi	a0, a0, -9
	.loc	2 451 26                        # rnd_output0.c:451:26
	sw	a0, 108(a2)
	li	a3, 0
	.loc	2 452 25                        # rnd_output0.c:452:25
	lui	a0, 4
	sub	a0, s0, a0
	sw	a3, 372(a0)                     # 4-byte Folded Spill
	sw	a3, 104(a2)
	.loc	2 454 117                       # rnd_output0.c:454:117
	lw	a1, -28(s0)
	lw	a0, -32(s0)
	addi	a0, a0, 1
	seqz	a4, a0
	add	a1, a1, a4
	sw	a0, -32(s0)
	sw	a1, -28(s0)
	.loc	2 454 142 is_stmt 0             # rnd_output0.c:454:142
	lw	a2, 184(a2)
	lui	a4, 717544
	addi	a4, a4, -1304
	.loc	2 454 139                       # rnd_output0.c:454:139
	xor	a2, a2, a4
	seqz	a2, a2
	.loc	2 454 89                        # rnd_output0.c:454:89
	call	safe_add_func_uint64_t_u_u
	lui	a2, 4
	sub	a2, s0, a2
	lw	a4, 756(a2)                     # 4-byte Folded Reload
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	.loc	2 454 170                       # rnd_output0.c:454:170
	lw	a3, 184(a0)
	srai	a0, a3, 31
	.loc	2 454 160                       # rnd_output0.c:454:160
	lw	a4, 468(a4)
	.loc	2 454 168                       # rnd_output0.c:454:168
	sw	a3, 0(a4)
	.loc	2 454 155                       # rnd_output0.c:454:155
	sltu	a2, a2, a3
	sltu	a3, a1, a0
	lui	a4, 4
	sub	a4, s0, a4
	sw	a3, 376(a4)                     # 4-byte Folded Spill
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 380(a3)                     # 4-byte Folded Spill
	beq	a1, a0, .LBB0_194
# %bb.193:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 0 155                         # rnd_output0.c:0:155
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 376(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 380(a1)                     # 4-byte Folded Spill
.LBB0_194:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 454 155                       # rnd_output0.c:454:155
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 380(a0)                     # 4-byte Folded Reload
	li	a1, 12
	.loc	2 454 58                        # rnd_output0.c:454:58
	call	safe_rshift_func_int32_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
	.loc	2 454 234                       # rnd_output0.c:454:234
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 360(a2)                     # 4-byte Folded Spill
	lui	a0, %hi(g_1374)
	lw	a0, %lo(g_1374)(a0)
	.loc	2 454 233                       # rnd_output0.c:454:233
	lhu	a0, 0(a0)
	.loc	2 454 222                       # rnd_output0.c:454:222
	lw	a1, 148(a1)
	.loc	2 454 230                       # rnd_output0.c:454:230
	sh	a0, 0(a1)
	.loc	2 454 244                       # rnd_output0.c:454:244
	lhu	a1, -48(s0)
	.loc	2 454 192                       # rnd_output0.c:454:192
	call	safe_mod_func_uint16_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
	.loc	2 454 397                       # rnd_output0.c:454:397
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 356(a2)                     # 4-byte Folded Spill
	lui	a3, %hi(g_588)
	lbu	a0, %lo(g_588)(a3)
	addi	a2, a0, -1
	sb	a2, %lo(g_588)(a3)
	.loc	2 454 389                       # rnd_output0.c:454:389
	lui	a2, %hi(g_70)
	addi	a2, a2, %lo(g_70)
	sb	a0, 80(a2)
	.loc	2 454 417                       # rnd_output0.c:454:417
	lui	a0, %hi(g_532)
	lw	a0, %lo(g_532)(a0)
	.loc	2 454 416                       # rnd_output0.c:454:416
	lw	a0, 0(a0)
	.loc	2 454 413                       # rnd_output0.c:454:413
	sw	a0, 120(a1)
	.loc	2 454 468                       # rnd_output0.c:454:468
	lui	a0, %hi(g_1247)
	lw	a0, %lo(g_1247)(a0)
	.loc	2 454 459                       # rnd_output0.c:454:459
	lw	a2, -652(s0)
	.loc	2 454 466                       # rnd_output0.c:454:466
	sw	a0, 0(a2)
	.loc	2 454 479                       # rnd_output0.c:454:479
	lw	a2, 116(a1)
	.loc	2 454 476                       # rnd_output0.c:454:476
	xor	a0, a0, a2
	seqz	a0, a0
	.loc	2 454 453                       # rnd_output0.c:454:453
	sw	a0, 112(a1)
	.loc	2 454 529                       # rnd_output0.c:454:529
	lw	a0, -48(s0)
	.loc	2 454 373                       # rnd_output0.c:454:373
	not	a1, a0
	.loc	2 454 541                       # rnd_output0.c:454:541
	lw	a0, -1244(s0)
	.loc	2 454 540                       # rnd_output0.c:454:540
	lw	a0, 0(a0)
	.loc	2 454 536                       # rnd_output0.c:454:536
	sltu	a0, a0, a1
	xori	a0, a0, 1
	.loc	2 454 550                       # rnd_output0.c:454:550
	lw	a1, -44(s0)
	.loc	2 454 342                       # rnd_output0.c:454:342
	call	safe_rshift_func_int16_t_s_u
                                        # kill: def $x11 killed $x10
	.loc	2 454 326                       # rnd_output0.c:454:326
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 372(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_197)
	addi	a1, a1, %lo(g_197)
	sb	a0, 16(a1)
	.loc	2 454 587                       # rnd_output0.c:454:587
	lw	a0, -24(s0)
	.loc	2 454 586                       # rnd_output0.c:454:586
	lw	a1, 0(a0)
	li	a0, 1
	.loc	2 454 286                       # rnd_output0.c:454:286
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 364(a2)                     # 4-byte Folded Spill
	call	safe_div_func_int32_t_s_s
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 364(a0)                     # 4-byte Folded Reload
	.loc	2 454 597                       # rnd_output0.c:454:597
	lbu	a0, -44(s0)
	.loc	2 454 255                       # rnd_output0.c:454:255
	call	safe_rshift_func_uint8_t_u_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 356(a1)                     # 4-byte Folded Reload
	mv	a1, a0
	.loc	2 454 251                       # rnd_output0.c:454:251
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 360(a0)                     # 4-byte Folded Reload
	slt	a1, a1, a2
	xori	a1, a1, 1
	.loc	2 454 188                       # rnd_output0.c:454:188
	slt	a0, a0, a1
	lui	a1, 6
	addi	a1, a1, 1425
	.loc	2 454 30                        # rnd_output0.c:454:30
	call	safe_div_func_int16_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 364(a1)                     # 4-byte Folded Reload
	mv	a1, a0
	.loc	2 454 624                       # rnd_output0.c:454:624
	lui	a0, %hi(g_955)
	addi	a0, a0, %lo(g_955)
	lh	a0, 26(a0)
	.loc	2 454 640                       # rnd_output0.c:454:640
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 368(a3)                     # 4-byte Folded Spill
	bge	a0, a1, .LBB0_196
	j	.LBB0_195
.LBB0_195:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 0 640                         # rnd_output0.c:0:640
	li	a0, 1
	.loc	2 454 640                       # rnd_output0.c:454:640
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 368(a1)                     # 4-byte Folded Spill
	j	.LBB0_196
.LBB0_196:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 0 640                         # rnd_output0.c:0:640
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 736(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 368(a0)                     # 4-byte Folded Reload
	.loc	2 454 24                        # rnd_output0.c:454:24
	lhu	a2, 922(a1)
	.loc	2 454 640                       # rnd_output0.c:454:640
	and	a0, a0, a2
	.loc	2 454 24                        # rnd_output0.c:454:24
	andi	a0, a0, 1
	sh	a0, 922(a1)
	j	.LBB0_197
.Ltmp239:
.LBB0_197:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 456 15 is_stmt 1              # rnd_output0.c:456:15
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a1, 468(a0)
	.loc	2 456 23 is_stmt 0              # rnd_output0.c:456:23
	lw	a0, 0(a1)
	ori	a0, a0, 1
	sw	a0, 0(a1)
	.loc	2 457 9 is_stmt 1               # rnd_output0.c:457:9
	j	.LBB0_198
.Ltmp240:
.LBB0_198:                              #   in Loop: Header=BB0_179 Depth=2
	.loc	2 401 91                        # rnd_output0.c:401:91
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a0, 564(a0)
	li	a1, 8
	.loc	2 401 59 is_stmt 0              # rnd_output0.c:401:59
	call	safe_add_func_int8_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 756(a1)                     # 4-byte Folded Reload
	.loc	2 401 57                        # rnd_output0.c:401:57
	sb	a0, 564(a1)
	.loc	2 401 9                         # rnd_output0.c:401:9
	j	.LBB0_179
.Ltmp241:
.LBB0_199:
	.loc	2 458 19 is_stmt 1              # rnd_output0.c:458:19
	lui	a1, %hi(g_89)
	li	a0, -23
	sh	a0, %lo(g_89)(a1)
	.loc	2 458 14 is_stmt 0              # rnd_output0.c:458:14
	j	.LBB0_200
.LBB0_200:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_206 Depth 2
                                        #       Child Loop BB0_208 Depth 3
                                        #       Child Loop BB0_212 Depth 3
                                        #       Child Loop BB0_230 Depth 3
.Ltmp242:
	.loc	2 458 29                        # rnd_output0.c:458:29
	lui	a0, %hi(g_89)
	lhu	a1, %lo(g_89)(a0)
	li	a0, 36
.Ltmp243:
	.loc	2 458 9                         # rnd_output0.c:458:9
	blt	a0, a1, .LBB0_247
	j	.LBB0_201
.LBB0_201:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 0 9                           # rnd_output0.c:0:9
	lui	a0, 4
	sub	a0, s0, a0
	lw	a3, 740(a0)                     # 4-byte Folded Reload
	li	a0, -1
.Ltmp244:
	.loc	2 460 22 is_stmt 1              # rnd_output0.c:460:22
	sw	a0, 92(a3)
	li	a1, -9
	sw	a1, 88(a3)
	lui	a1, 987226
	addi	a1, a1, 417
	.loc	2 461 21                        # rnd_output0.c:461:21
	sw	a1, 84(a3)
	.loc	2 462 22                        # rnd_output0.c:462:22
	sw	a0, 80(a3)
	li	a0, 0
	.loc	2 463 22                        # rnd_output0.c:463:22
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 344(a1)                     # 4-byte Folded Spill
	sw	a0, 76(a3)
	lui	a1, 1048366
	addi	a1, a1, 1075
	.loc	2 464 21                        # rnd_output0.c:464:21
	sw	a1, 72(a3)
	li	a1, -4
	.loc	2 465 21                        # rnd_output0.c:465:21
	sh	a1, 68(a3)
	lui	a2, 1048528
	addi	a2, a2, -4
	sw	a2, 64(a3)
	sw	a2, 60(a3)
	sw	a2, 56(a3)
	.loc	2 466 22                        # rnd_output0.c:466:22
	sw	a0, 52(a3)
	sw	a0, 48(a3)
	sw	a0, 44(a3)
	li	a2, 2
	sw	a2, 40(a3)
	.loc	2 467 33                        # rnd_output0.c:467:33
	sw	a0, 36(a3)
	.loc	2 468 36                        # rnd_output0.c:468:36
	lui	a2, 1
	addi	a2, a2, 1892
	sub	a2, s0, a2
	.loc	2 468 26 is_stmt 0              # rnd_output0.c:468:26
	sw	a2, 32(a3)
	.loc	2 470 45 is_stmt 1              # rnd_output0.c:470:45
	lw	a4, 88(a3)
	.loc	2 470 42 is_stmt 0              # rnd_output0.c:470:42
	lw	a2, 84(a3)
	or	a2, a2, a4
	sw	a2, 84(a3)
	.loc	2 470 102                       # rnd_output0.c:470:102
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 340(a2)                     # 4-byte Folded Spill
	lui	a0, %hi(g_8)
	addi	a0, a0, %lo(g_8)
	lw	a0, 480(a0)
	.loc	2 470 75                        # rnd_output0.c:470:75
	call	safe_mod_func_uint32_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 344(a1)                     # 4-byte Folded Reload
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	.loc	2 470 220                       # rnd_output0.c:470:220
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 348(a3)                     # 4-byte Folded Spill
	lw	a2, 456(a0)
	lw	a0, 452(a0)
	or	a0, a0, a2
	.loc	2 470 230                       # rnd_output0.c:470:230
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 352(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_203
	j	.LBB0_202
.LBB0_202:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 470 260                       # rnd_output0.c:470:260
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 740(a0)                     # 4-byte Folded Reload
	lw	a0, -48(s0)
	.loc	2 470 266                       # rnd_output0.c:470:266
	lw	a2, 80(a1)
	li	a3, 0
	.loc	2 470 234                       # rnd_output0.c:470:234
	mv	a1, a3
	call	safe_add_func_int64_t_s_s
	.loc	2 470 230                       # rnd_output0.c:470:230
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 352(a1)                     # 4-byte Folded Spill
	j	.LBB0_203
.LBB0_203:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 352(a0)                     # 4-byte Folded Reload
	.loc	2 470 219                       # rnd_output0.c:470:219
	andi	a2, a0, 1
	lui	a0, 180224
	addi	a0, a0, 77
	lui	a1, 979832
	addi	a1, a1, 1483
	li	a3, 0
	.loc	2 470 170                       # rnd_output0.c:470:170
	lui	a4, 4
	sub	a4, s0, a4
	sw	a3, 332(a4)                     # 4-byte Folded Spill
	call	safe_mul_func_uint64_t_u_u
	mv	a2, a1
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 332(a1)                     # 4-byte Folded Reload
	or	a0, a0, a2
	.loc	2 470 278                       # rnd_output0.c:470:278
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 336(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_205
	j	.LBB0_204
.LBB0_204:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 470 281                       # rnd_output0.c:470:281
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lw	a1, 92(a0)
	lw	a0, 88(a0)
	.loc	2 470 278                       # rnd_output0.c:470:278
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 336(a1)                     # 4-byte Folded Spill
	j	.LBB0_205
.LBB0_205:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 336(a0)                     # 4-byte Folded Reload
	.loc	2 470 278                       # rnd_output0.c:470:278
	andi	a1, a0, 1
	li	a0, 0
	.loc	2 470 135                       # rnd_output0.c:470:135
	call	safe_lshift_func_int32_t_s_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a3, 348(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 340(a1)                     # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 470 291                       # rnd_output0.c:470:291
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	sltiu	a2, a2, 8
	xor	a2, a2, a3
	.loc	2 470 131                       # rnd_output0.c:470:131
	xori	a2, a2, 1
	.loc	2 470 70                        # rnd_output0.c:470:70
	xor	a1, a1, a2
	seqz	a2, a1
	.loc	2 470 15                        # rnd_output0.c:470:15
	lw	a1, 468(a0)
	.loc	2 470 23                        # rnd_output0.c:470:23
	lw	a0, 0(a1)
	or	a0, a0, a2
	sw	a0, 0(a1)
.Ltmp245:
	.loc	2 471 23 is_stmt 1              # rnd_output0.c:471:23
	lui	a1, %hi(g_13)
	li	a0, 17
	sw	a0, %lo(g_13)(a1)
	.loc	2 471 18 is_stmt 0              # rnd_output0.c:471:18
	j	.LBB0_206
.LBB0_206:                              #   Parent Loop BB0_200 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_208 Depth 3
                                        #       Child Loop BB0_212 Depth 3
                                        #       Child Loop BB0_230 Depth 3
.Ltmp246:
	.loc	2 471 30                        # rnd_output0.c:471:30
	lui	a0, %hi(g_13)
	lw	a0, %lo(g_13)(a0)
	li	a1, -15
.Ltmp247:
	.loc	2 471 13                        # rnd_output0.c:471:13
	beq	a0, a1, .LBB0_245
	j	.LBB0_207
.LBB0_207:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 13                          # rnd_output0.c:0:13
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 740(a0)                     # 4-byte Folded Reload
	li	a0, 0
.Ltmp248:
	.loc	2 473 26 is_stmt 1              # rnd_output0.c:473:26
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 328(a2)                     # 4-byte Folded Spill
	sw	a0, 20(a1)
	sw	a0, 16(a1)
	li	a0, -2
	sw	a0, 12(a1)
	lui	a0, 40081
	addi	a0, a0, -173
	sw	a0, 8(a1)
	.loc	2 474 27                        # rnd_output0.c:474:27
	lui	a0, %hi(g_1548)
	addi	a0, a0, %lo(g_1548)
	sw	a0, 4(a1)
	li	a0, -5
	.loc	2 475 25                        # rnd_output0.c:475:25
	sw	a0, 0(a1)
	.loc	2 476 27                        # rnd_output0.c:476:27
	lui	a0, %hi(.L__const.func_40.l_1619)
	addi	a1, a0, %lo(.L__const.func_40.l_1619)
	li	a0, 25
	slli	a2, a0, 7
	lui	a0, 3
	addi	a0, a0, 944
	sub	a0, s0, a0
	call	memcpy@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 744(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 328(a0)                     # 4-byte Folded Reload
	addi	a2, s0, -2048
	addi	a2, a2, -849
	.loc	2 477 25                        # rnd_output0.c:477:25
	sw	a2, 24(a1)
	lui	a2, 3
	addi	a2, a2, 948
	sub	a2, s0, a2
	.loc	2 478 26                        # rnd_output0.c:478:26
	sw	a2, 20(a1)
	.loc	2 479 26                        # rnd_output0.c:479:26
	sw	a2, 16(a1)
	lui	a2, 3
	addi	a2, a2, 956
	sub	a2, s0, a2
	.loc	2 480 27                        # rnd_output0.c:480:27
	sw	a2, 12(a1)
.Ltmp249:
	.loc	2 483 24                        # rnd_output0.c:483:24
	sw	a0, 0(a1)
	.loc	2 483 22 is_stmt 0              # rnd_output0.c:483:22
	j	.LBB0_208
.LBB0_208:                              #   Parent Loop BB0_200 Depth=1
                                        #     Parent Loop BB0_206 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp250:
	.loc	2 483 29                        # rnd_output0.c:483:29
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 744(a0)                     # 4-byte Folded Reload
	lw	a1, 0(a0)
	li	a0, 1
.Ltmp251:
	.loc	2 483 17                        # rnd_output0.c:483:17
	blt	a0, a1, .LBB0_211
	j	.LBB0_209
.LBB0_209:                              #   in Loop: Header=BB0_208 Depth=3
.Ltmp252:
	.loc	2 484 34 is_stmt 1              # rnd_output0.c:484:34
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 744(a0)                     # 4-byte Folded Reload
	lui	a0, 1
	addi	a0, a0, 2032
	sub	a0, s0, a0
	.loc	2 484 28 is_stmt 0              # rnd_output0.c:484:28
	lw	a1, 0(a1)
	.loc	2 484 21                        # rnd_output0.c:484:21
	slli	a2, a1, 2
	lui	a1, 3
	addi	a1, a1, 968
	sub	a1, s0, a1
	add	a1, a1, a2
	.loc	2 484 31                        # rnd_output0.c:484:31
	sw	a0, 0(a1)
	.loc	2 484 21                        # rnd_output0.c:484:21
	j	.LBB0_210
.LBB0_210:                              #   in Loop: Header=BB0_208 Depth=3
	.loc	2 483 37 is_stmt 1              # rnd_output0.c:483:37
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 744(a0)                     # 4-byte Folded Reload
	lw	a0, 0(a1)
	addi	a0, a0, 1
	sw	a0, 0(a1)
	.loc	2 483 17 is_stmt 0              # rnd_output0.c:483:17
	j	.LBB0_208
.Ltmp253:
.LBB0_211:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 17                          # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	li	a0, 244
.Ltmp254:
	.loc	2 485 32 is_stmt 1              # rnd_output0.c:485:32
	sb	a0, 564(a1)
	.loc	2 485 22 is_stmt 0              # rnd_output0.c:485:22
	j	.LBB0_212
.LBB0_212:                              #   Parent Loop BB0_200 Depth=1
                                        #     Parent Loop BB0_206 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp255:
	.loc	2 485 49                        # rnd_output0.c:485:49
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lbu	a0, 564(a0)
	li	a1, 48
.Ltmp256:
	.loc	2 485 17                        # rnd_output0.c:485:17
	blt	a0, a1, .LBB0_219
	j	.LBB0_213
.LBB0_213:                              #   in Loop: Header=BB0_212 Depth=3
.Ltmp257:
	.loc	2 487 30 is_stmt 1              # rnd_output0.c:487:30
	lui	a0, %hi(.L__const.func_40.l_1586)
	addi	a1, a0, %lo(.L__const.func_40.l_1586)
	lui	a0, 3
	addi	a0, a0, 1016
	sub	a0, s0, a0
	li	a2, 36
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 748(a0)                     # 4-byte Folded Reload
	li	a0, 4
	.loc	2 488 29                        # rnd_output0.c:488:29
	sw	a0, 2020(a1)
	lui	a0, 2
	addi	a0, a0, 1824
	sub	a0, s0, a0
	.loc	2 489 30                        # rnd_output0.c:489:30
	sw	a0, 2016(a1)
	addi	a2, s0, -2048
	addi	a2, a2, -1002
	.loc	2 490 31                        # rnd_output0.c:490:31
	sw	a2, 2012(a1)
	.loc	2 491 29                        # rnd_output0.c:491:29
	sw	a0, 2008(a1)
	.loc	2 492 29                        # rnd_output0.c:492:29
	lui	a0, %hi(g_70)
	addi	a0, a0, %lo(g_70)
	addi	a0, a0, 80
	sw	a0, 2004(a1)
	addi	a0, s0, -2048
	addi	a0, a0, -849
	.loc	2 493 29                        # rnd_output0.c:493:29
	sw	a0, 2000(a1)
	.loc	2 495 42                        # rnd_output0.c:495:42
	lui	a2, %hi(g_1571)
	addi	a0, s0, -40
	sw	a0, %lo(g_1571)(a2)
	.loc	2 495 305 is_stmt 0             # rnd_output0.c:495:305
	lw	a0, 2036(a1)
	.loc	2 495 303                       # rnd_output0.c:495:303
	sw	a0, 2020(a1)
	.loc	2 495 388                       # rnd_output0.c:495:388
	lw	a0, -32(s0)
	.loc	2 495 393                       # rnd_output0.c:495:393
	andi	a0, a0, 1
	li	a1, 0
	li	a3, -1
	.loc	2 495 360                       # rnd_output0.c:495:360
	mv	a2, a3
	call	safe_add_func_int64_t_s_s
	lui	a2, 4
	sub	a2, s0, a2
	lw	a2, 748(a2)                     # 4-byte Folded Reload
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 320(a3)                     # 4-byte Folded Spill
                                        # kill: def $x10 killed $x11
	.loc	2 495 359                       # rnd_output0.c:495:359
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 320(a0)                     # 4-byte Folded Reload
	andi	a0, a1, 255
	.loc	2 495 349                       # rnd_output0.c:495:349
	lw	a2, 2016(a2)
	.loc	2 495 357                       # rnd_output0.c:495:357
	sb	a1, 0(a2)
	li	a1, 1
	.loc	2 495 432                       # rnd_output0.c:495:432
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 324(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_215
	j	.LBB0_214
.LBB0_214:                              #   in Loop: Header=BB0_212 Depth=3
	.loc	2 495 442                       # rnd_output0.c:495:442
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lbu	a0, 8(a0)
	.loc	2 495 432                       # rnd_output0.c:495:432
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 324(a1)                     # 4-byte Folded Spill
	j	.LBB0_215
.LBB0_215:                              #   in Loop: Header=BB0_212 Depth=3
	.loc	2 0 432                         # rnd_output0.c:0:432
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 324(a0)                     # 4-byte Folded Reload
	.loc	2 495 432                       # rnd_output0.c:495:432
	andi	a0, a0, 1
	lui	a1, 4
	addi	a1, a1, 1713
	.loc	2 495 319                       # rnd_output0.c:495:319
	call	safe_sub_func_int16_t_s_s
	mv	a2, a0
	.loc	2 495 294                       # rnd_output0.c:495:294
	srai	a3, a2, 31
	li	a1, 0
	.loc	2 495 239                       # rnd_output0.c:495:239
	mv	a0, a1
	call	safe_div_func_int64_t_s_s
	.loc	2 495 461                       # rnd_output0.c:495:461
	lui	a1, %hi(g_388)
	lh	a1, %lo(g_388)(a1)
	.loc	2 495 212                       # rnd_output0.c:495:212
	slli	a0, a0, 16
	srai	a0, a0, 16
	call	safe_add_func_int16_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 756(a1)                     # 4-byte Folded Reload
	.loc	2 495 201                       # rnd_output0.c:495:201
	srai	a1, a0, 31
	.loc	2 495 473                       # rnd_output0.c:495:473
	lw	a2, 468(a2)
	.loc	2 495 472                       # rnd_output0.c:495:472
	lw	a2, 0(a2)
	srai	a3, a2, 31
	.loc	2 495 174                       # rnd_output0.c:495:174
	call	safe_add_func_uint64_t_u_u
	lui	a0, 942150
	addi	a0, a0, -1892
	lui	a1, 68149
	addi	a1, a1, 1672
	lui	a2, 757209
	addi	a2, a2, -1529
	lui	a3, 1023773
	addi	a3, a3, 1922
	.loc	2 495 146                       # rnd_output0.c:495:146
	call	safe_mod_func_int64_t_s_s
	.loc	2 495 143                       # rnd_output0.c:495:143
	slti	a2, a1, -1
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 312(a3)                     # 4-byte Folded Spill
	sltiu	a2, a0, -2
	li	a0, -1
	lui	a3, 4
	sub	a3, s0, a3
	sw	a2, 316(a3)                     # 4-byte Folded Spill
	beq	a1, a0, .LBB0_217
# %bb.216:                              #   in Loop: Header=BB0_212 Depth=3
	.loc	2 0 143                         # rnd_output0.c:0:143
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 312(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 316(a1)                     # 4-byte Folded Spill
.LBB0_217:                              #   in Loop: Header=BB0_212 Depth=3
	.loc	2 495 143                       # rnd_output0.c:495:143
	lui	a0, 4
	sub	a0, s0, a0
	lw	a3, 316(a0)                     # 4-byte Folded Reload
	.loc	2 495 125                       # rnd_output0.c:495:125
	lui	a0, %hi(g_1571)
	lw	a2, %lo(g_1571)(a0)
	.loc	2 495 133                       # rnd_output0.c:495:133
	lw	a1, 4(a2)
	lw	a0, 0(a2)
	xor	a0, a0, a3
	sw	a1, 4(a2)
	sw	a0, 0(a2)
	lui	a2, 213010
	addi	a2, a2, 1648
	.loc	2 495 533                       # rnd_output0.c:495:533
	xor	a0, a0, a2
	lui	a2, 466005
	addi	a2, a2, 28
	xor	a1, a1, a2
	or	a0, a0, a1
	seqz	a0, a0
	.loc	2 495 559                       # rnd_output0.c:495:559
	lh	a1, -48(s0)
	.loc	2 495 95                        # rnd_output0.c:495:95
	call	safe_sub_func_int16_t_s_s
	.loc	2 495 93                        # rnd_output0.c:495:93
	not	a0, a0
	lui	a1, 9
	addi	a1, a1, 1738
	.loc	2 495 567                       # rnd_output0.c:495:567
	and	a0, a0, a1
	.loc	2 495 65                        # rnd_output0.c:495:65
	slli	a0, a0, 16
	srai	a0, a0, 16
	lui	a1, 1048574
	addi	a1, a1, -121
	call	safe_mod_func_int16_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 495 591                       # rnd_output0.c:495:591
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 748(a0)                     # 4-byte Folded Reload
	lw	a0, 2036(a0)
	.loc	2 495 605                       # rnd_output0.c:495:605
	lw	a2, -44(s0)
	.loc	2 495 603                       # rnd_output0.c:495:603
	xor	a2, a2, a0
	.loc	2 495 28                        # rnd_output0.c:495:28
	lw	a0, 0(a1)
	xor	a0, a0, a2
	sw	a0, 0(a1)
	addi	a0, s0, -44
	.loc	2 496 36 is_stmt 1              # rnd_output0.c:496:36
	sw	a0, -24(s0)
	.loc	2 496 28 is_stmt 0              # rnd_output0.c:496:28
	sw	a0, 76(a1)
	.loc	2 497 17 is_stmt 1              # rnd_output0.c:497:17
	j	.LBB0_218
.Ltmp258:
.LBB0_218:                              #   in Loop: Header=BB0_212 Depth=3
	.loc	2 485 59                        # rnd_output0.c:485:59
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lbu	a0, 564(a1)
	addi	a0, a0, 1
	sb	a0, 564(a1)
	.loc	2 485 17 is_stmt 0              # rnd_output0.c:485:17
	j	.LBB0_212
.Ltmp259:
.LBB0_219:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 498 67 is_stmt 1              # rnd_output0.c:498:67
	lw	a1, -28(s0)
	lw	a0, -32(s0)
	or	a0, a0, a1
	.loc	2 498 72 is_stmt 0              # rnd_output0.c:498:72
	bnez	a0, .LBB0_221
	j	.LBB0_220
.LBB0_220:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 72                          # rnd_output0.c:0:72
	li	a0, 0
	mv	a1, a0
	.loc	2 498 82                        # rnd_output0.c:498:82
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 308(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_222
	j	.LBB0_221
.LBB0_221:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 498 91                        # rnd_output0.c:498:91
	lui	a0, %hi(g_813)
	lw	a0, %lo(g_813)(a0)
	.loc	2 498 82                        # rnd_output0.c:498:82
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 308(a1)                     # 4-byte Folded Spill
	j	.LBB0_222
.LBB0_222:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 756(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 308(a1)                     # 4-byte Folded Reload
	.loc	2 498 82                        # rnd_output0.c:498:82
	andi	a1, a1, 1
	.loc	2 498 55                        # rnd_output0.c:498:55
	lui	a3, 4
	sub	a3, s0, a3
	sw	a1, 304(a3)                     # 4-byte Folded Spill
	lw	a2, 468(a2)
	.loc	2 498 63                        # rnd_output0.c:498:63
	sw	a1, 0(a2)
	.loc	2 498 124                       # rnd_output0.c:498:124
	lbu	a0, 916(a0)
	.loc	2 498 132                       # rnd_output0.c:498:132
	lui	a1, %hi(g_588)
	lbu	a1, %lo(g_588)(a1)
	.loc	2 498 98                        # rnd_output0.c:498:98
	call	safe_mul_func_uint8_t_u_u
	mv	a1, a0
	.loc	2 498 26                        # rnd_output0.c:498:26
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 304(a0)                     # 4-byte Folded Reload
	call	safe_mul_func_int32_t_s_s
	mv	a1, a0
	.loc	2 498 22                        # rnd_output0.c:498:22
	lw	a0, -44(s0)
	and	a0, a0, a1
	sw	a0, -44(s0)
.Ltmp260:
	.loc	2 499 23 is_stmt 1              # rnd_output0.c:499:23
	lw	a0, -24(s0)
	.loc	2 499 22 is_stmt 0              # rnd_output0.c:499:22
	lw	a0, 0(a0)
.Ltmp261:
	.loc	2 499 21                        # rnd_output0.c:499:21
	beqz	a0, .LBB0_224
	j	.LBB0_223
.LBB0_223:                              #   in Loop: Header=BB0_206 Depth=2
.Ltmp262:
	.loc	2 500 21 is_stmt 1              # rnd_output0.c:500:21
	j	.LBB0_244
.Ltmp263:
.LBB0_224:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 501 22                        # rnd_output0.c:501:22
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 744(a0)                     # 4-byte Folded Reload
	lw	a0, 20(a1)
	.loc	2 501 35 is_stmt 0              # rnd_output0.c:501:35
	lw	a2, 12(a1)
	lui	a1, 3
	addi	a1, a1, 948
	sub	a1, s0, a1
	.loc	2 501 43                        # rnd_output0.c:501:43
	sw	a1, 0(a2)
.Ltmp264:
	.loc	2 501 21                        # rnd_output0.c:501:21
	beq	a0, a1, .LBB0_238
	j	.LBB0_225
.LBB0_225:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 21                          # rnd_output0.c:0:21
	lui	a0, 3
	addi	a0, a0, 1088
	sub	a0, s0, a0
	li	a1, 0
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 280(a2)                     # 4-byte Folded Spill
	li	a2, 40
.Ltmp265:
	.loc	2 503 36 is_stmt 1              # rnd_output0.c:503:36
	call	memset@plt
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 748(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 280(a0)                     # 4-byte Folded Reload
	lui	a2, 978916
	addi	a3, a2, -1255
	sw	a3, 1956(a1)
	lui	a2, 689785
	addi	a2, a2, 1507
	sw	a2, 1952(a1)
	sw	a3, 1964(a1)
	sw	a2, 1960(a1)
	sw	a3, 1972(a1)
	sw	a2, 1968(a1)
	sw	a3, 1980(a1)
	sw	a2, 1976(a1)
	sw	a3, 1988(a1)
	sw	a2, 1984(a1)
	.loc	2 504 30                        # rnd_output0.c:504:30
	lui	a2, %hi(g_133)
	addi	a2, a2, %lo(g_133)
	addi	a2, a2, 496
	sw	a2, 1948(a1)
	.loc	2 505 40                        # rnd_output0.c:505:40
	addi	a2, s0, -2048
	addi	a2, a2, -1048
	.loc	2 505 30 is_stmt 0              # rnd_output0.c:505:30
	sw	a2, 1944(a1)
	li	a2, 6
	.loc	2 506 29 is_stmt 1              # rnd_output0.c:506:29
	sw	a2, 1940(a1)
	.loc	2 507 30                        # rnd_output0.c:507:30
	sw	a0, 1932(a1)
	sw	a0, 1928(a1)
	sw	a0, 1924(a1)
	lui	a0, 535799
	addi	a0, a0, -1169
	sw	a0, 1920(a1)
	.loc	2 509 122                       # rnd_output0.c:509:122
	lw	a0, -48(s0)
	.loc	2 509 130 is_stmt 0             # rnd_output0.c:509:130
	lw	a1, -28(s0)
	lw	a2, -32(s0)
	.loc	2 509 127                       # rnd_output0.c:509:127
	sltu	a0, a0, a2
	not	a0, a0
	seqz	a1, a1
	and	a0, a0, a1
	.loc	2 509 140                       # rnd_output0.c:509:140
	lw	a3, -56(s0)
	.loc	2 509 146                       # rnd_output0.c:509:146
	lw	a1, 0(a3)
	addi	a2, a1, 1
	sw	a2, 0(a3)
	.loc	2 509 95                        # rnd_output0.c:509:95
	call	safe_sub_func_int32_t_s_s
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 748(a1)                     # 4-byte Folded Reload
	.loc	2 509 154                       # rnd_output0.c:509:154
	lui	a2, %hi(g_3)
	lw	a2, %lo(g_3)(a2)
	.loc	2 509 152                       # rnd_output0.c:509:152
	xor	a0, a0, a2
	.loc	2 509 93                        # rnd_output0.c:509:93
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 284(a2)                     # 4-byte Folded Spill
	srai	a0, a0, 31
	.loc	2 509 211                       # rnd_output0.c:509:211
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 288(a2)                     # 4-byte Folded Spill
	lui	a0, %hi(g_1374)
	lw	a0, %lo(g_1374)(a0)
	.loc	2 509 210                       # rnd_output0.c:509:210
	lhu	a0, 0(a0)
	.loc	2 509 383                       # rnd_output0.c:509:383
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 292(a2)                     # 4-byte Folded Spill
	lui	a0, %hi(g_117)
	lw	a0, %lo(g_117)(a0)
	.loc	2 509 423                       # rnd_output0.c:509:423
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 296(a2)                     # 4-byte Folded Spill
	lhu	a0, 1984(a1)
	.loc	2 509 440                       # rnd_output0.c:509:440
	lhu	a1, 1960(a1)
	.loc	2 509 455                       # rnd_output0.c:509:455
	lhu	a2, -40(s0)
	.loc	2 509 440                       # rnd_output0.c:509:440
	and	a1, a1, a2
	.loc	2 509 463                       # rnd_output0.c:509:463
	lhu	a2, -44(s0)
	.loc	2 509 461                       # rnd_output0.c:509:461
	or	a1, a1, a2
	.loc	2 509 436                       # rnd_output0.c:509:436
	and	a0, a0, a1
	.loc	2 509 471                       # rnd_output0.c:509:471
	lhu	a1, -32(s0)
	.loc	2 509 395                       # rnd_output0.c:509:395
	call	safe_add_func_uint16_t_u_u
                                        # kill: def $x11 killed $x10
	.loc	2 509 502                       # rnd_output0.c:509:502
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 296(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_197)
	addi	a1, a1, %lo(g_197)
	lb	a1, 16(a1)
	.loc	2 509 389                       # rnd_output0.c:509:389
	sltu	a0, a0, a1
	xori	a1, a0, 1
	li	a0, -1
	.loc	2 509 347                       # rnd_output0.c:509:347
	call	safe_rshift_func_int8_t_s_s
	.loc	2 509 346                       # rnd_output0.c:509:346
	srai	a1, a0, 31
	li	a2, 56
	.loc	2 509 316                       # rnd_output0.c:509:316
	call	safe_rshift_func_uint64_t_u_s
	.loc	2 509 525                       # rnd_output0.c:509:525
	lw	a3, -36(s0)
	lw	a2, -40(s0)
	.loc	2 509 288                       # rnd_output0.c:509:288
	call	safe_sub_func_uint64_t_u_u
	.loc	2 509 286                       # rnd_output0.c:509:286
	or	a0, a0, a1
	seqz	a0, a0
	.loc	2 509 535                       # rnd_output0.c:509:535
	lui	a1, %hi(g_152)
	lw	a1, %lo(g_152)(a1)
	.loc	2 509 285                       # rnd_output0.c:509:285
	and	a0, a0, a1
	.loc	2 509 251                       # rnd_output0.c:509:251
	call	safe_unary_minus_func_uint32_t_u
	lui	a1, 107015
	addi	a1, a1, 301
	.loc	2 509 544                       # rnd_output0.c:509:544
	xor	a0, a0, a1
	li	a1, 4
	.loc	2 509 223                       # rnd_output0.c:509:223
	call	safe_div_func_int32_t_s_s
	li	a1, 1
	.loc	2 509 565                       # rnd_output0.c:509:565
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 300(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_227
	j	.LBB0_226
.LBB0_226:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 565                         # rnd_output0.c:0:565
	li	a0, 1
	.loc	2 509 565                       # rnd_output0.c:509:565
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 300(a1)                     # 4-byte Folded Spill
	j	.LBB0_227
.LBB0_227:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 565                         # rnd_output0.c:0:565
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 288(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 284(a0)                     # 4-byte Folded Reload
	lui	a2, 4
	sub	a2, s0, a2
	lw	a3, 748(a2)                     # 4-byte Folded Reload
	lui	a2, 4
	sub	a2, s0, a2
	lw	a2, 292(a2)                     # 4-byte Folded Reload
	lui	a4, 4
	sub	a4, s0, a4
	lw	a4, 300(a4)                     # 4-byte Folded Reload
	.loc	2 509 565                       # rnd_output0.c:509:565
	andi	a4, a4, 1
	.loc	2 509 219                       # rnd_output0.c:509:219
	slt	a2, a2, a4
	lui	a4, 349993
	addi	a4, a4, -340
	.loc	2 509 579                       # rnd_output0.c:509:579
	or	a7, a2, a4
	.loc	2 509 188                       # rnd_output0.c:509:188
	lw	a2, 1948(a3)
	lui	a4, 816261
	addi	a6, a4, -1594
	.loc	2 509 196                       # rnd_output0.c:509:196
	sw	a6, 4(a2)
	sw	a7, 0(a2)
	.loc	2 509 174                       # rnd_output0.c:509:174
	lw	a2, 1944(a3)
	.loc	2 509 182                       # rnd_output0.c:509:182
	lw	a5, 4(a2)
	lw	a4, 0(a2)
	and	a4, a4, a7
	and	a5, a5, a6
	sw	a5, 4(a2)
	sw	a4, 0(a2)
	.loc	2 509 168                       # rnd_output0.c:509:168
	lw	a2, 1940(a3)
	and	a2, a2, a4
	sw	a2, 1940(a3)
	li	a3, 0
	.loc	2 509 67                        # rnd_output0.c:509:67
	lui	a4, 4
	sub	a4, s0, a4
	sw	a3, 272(a4)                     # 4-byte Folded Spill
	call	safe_mod_func_int64_t_s_s
	mv	a2, a1
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 272(a1)                     # 4-byte Folded Reload
	or	a0, a0, a2
	.loc	2 509 608                       # rnd_output0.c:509:608
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 276(a2)                     # 4-byte Folded Spill
	beqz	a0, .LBB0_229
	j	.LBB0_228
.LBB0_228:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 509 611                       # rnd_output0.c:509:611
	lw	a1, -28(s0)
	lw	a0, -32(s0)
	.loc	2 509 608                       # rnd_output0.c:509:608
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 276(a1)                     # 4-byte Folded Spill
	j	.LBB0_229
.LBB0_229:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 0                           # rnd_output0.c:0:0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 748(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 276(a1)                     # 4-byte Folded Reload
	.loc	2 509 625                       # rnd_output0.c:509:625
	lw	a1, -48(s0)
	.loc	2 509 62                        # rnd_output0.c:509:62
	seqz	a1, a1
	.loc	2 509 636                       # rnd_output0.c:509:636
	lw	a3, -1244(s0)
	.loc	2 509 635                       # rnd_output0.c:509:635
	lw	a3, 0(a3)
	.loc	2 509 632                       # rnd_output0.c:509:632
	and	a1, a1, a3
	.loc	2 509 646                       # rnd_output0.c:509:646
	lw	a3, 72(a0)
	.loc	2 509 644                       # rnd_output0.c:509:644
	slt	a3, a1, a3
	.loc	2 509 656                       # rnd_output0.c:509:656
	lw	a1, 1964(a2)
	lw	a2, 1960(a2)
	.loc	2 509 654                       # rnd_output0.c:509:654
	sltu	a2, a2, a3
	seqz	a1, a1
	and	a1, a1, a2
	.loc	2 509 672                       # rnd_output0.c:509:672
	lh	a0, 60(a0)
	.loc	2 509 670                       # rnd_output0.c:509:670
	slt	a0, a0, a1
	.loc	2 509 684                       # rnd_output0.c:509:684
	lbu	a1, -40(s0)
	.loc	2 509 31                        # rnd_output0.c:509:31
	call	safe_sub_func_uint8_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 756(a1)                     # 4-byte Folded Reload
	.loc	2 509 28                        # rnd_output0.c:509:28
	lui	a2, %hi(g_1662)
	sw	a0, %lo(g_1662)(a2)
	li	a0, 0
.Ltmp266:
	.loc	2 510 36 is_stmt 1              # rnd_output0.c:510:36
	sb	a0, 564(a1)
	.loc	2 510 26 is_stmt 0              # rnd_output0.c:510:26
	j	.LBB0_230
.LBB0_230:                              #   Parent Loop BB0_200 Depth=1
                                        #     Parent Loop BB0_206 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp267:
	.loc	2 510 49                        # rnd_output0.c:510:49
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lb	a0, 564(a0)
	li	a1, 29
.Ltmp268:
	.loc	2 510 21                        # rnd_output0.c:510:21
	beq	a0, a1, .LBB0_235
	j	.LBB0_231
.LBB0_231:                              #   in Loop: Header=BB0_230 Depth=3
	.loc	2 0 21                          # rnd_output0.c:0:21
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 744(a0)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 756(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a4, 748(a1)                     # 4-byte Folded Reload
	lui	a1, 1648
	addi	a1, a1, 1300
.Ltmp269:
	.loc	2 512 34 is_stmt 1              # rnd_output0.c:512:34
	sw	a1, 1908(a4)
	.loc	2 513 55                        # rnd_output0.c:513:55
	lui	a3, %hi(g_588)
	addi	a6, a3, %lo(g_588)
	lui	a1, 4
	sub	a1, s0, a1
	sw	a6, 260(a1)                     # 4-byte Folded Spill
	sw	a6, 1668(a4)
	sw	a6, 1672(a4)
	addi	a5, s0, -2048
	addi	a5, a5, -857
	.loc	2 513 71 is_stmt 0              # rnd_output0.c:513:71
	lui	a1, 4
	sub	a1, s0, a1
	sw	a5, 264(a1)                     # 4-byte Folded Spill
	sw	a5, 1676(a4)
	sw	a6, 1680(a4)
	.loc	2 513 88                        # rnd_output0.c:513:88
	sw	a6, 1684(a4)
	sw	a5, 1688(a4)
	.loc	2 513 105                       # rnd_output0.c:513:105
	sw	a6, 1692(a4)
	sw	a6, 1696(a4)
	li	a1, 0
	.loc	2 513 121                       # rnd_output0.c:513:121
	sw	a1, 1700(a4)
	sw	a6, 1704(a4)
	.loc	2 513 139                       # rnd_output0.c:513:139
	sw	a6, 1708(a4)
	sw	a5, 1712(a4)
	.loc	2 513 156                       # rnd_output0.c:513:156
	sw	a6, 1716(a4)
	sw	a6, 1720(a4)
	.loc	2 513 172                       # rnd_output0.c:513:172
	sw	a5, 1724(a4)
	sw	a6, 1728(a4)
	.loc	2 513 189                       # rnd_output0.c:513:189
	sw	a6, 1732(a4)
	sw	a5, 1736(a4)
	.loc	2 513 206                       # rnd_output0.c:513:206
	sw	a6, 1740(a4)
	sw	a6, 1744(a4)
	.loc	2 513 224                       # rnd_output0.c:513:224
	sw	a1, 1748(a4)
	sw	a6, 1752(a4)
	.loc	2 513 242                       # rnd_output0.c:513:242
	sw	a6, 1756(a4)
	sw	a5, 1760(a4)
	.loc	2 513 259                       # rnd_output0.c:513:259
	sw	a6, 1764(a4)
	sw	a6, 1768(a4)
	.loc	2 513 275                       # rnd_output0.c:513:275
	sw	a5, 1772(a4)
	sw	a6, 1776(a4)
	.loc	2 513 292                       # rnd_output0.c:513:292
	sw	a6, 1780(a4)
	sw	a5, 1784(a4)
	.loc	2 513 309                       # rnd_output0.c:513:309
	sw	a6, 1788(a4)
	sw	a6, 1792(a4)
	.loc	2 513 325                       # rnd_output0.c:513:325
	sw	a1, 1796(a4)
	sw	a6, 1800(a4)
	.loc	2 513 343                       # rnd_output0.c:513:343
	sw	a6, 1804(a4)
	sw	a5, 1808(a4)
	.loc	2 513 360                       # rnd_output0.c:513:360
	sw	a6, 1812(a4)
	sw	a6, 1816(a4)
	.loc	2 513 376                       # rnd_output0.c:513:376
	sw	a5, 1820(a4)
	sw	a6, 1824(a4)
	.loc	2 513 395                       # rnd_output0.c:513:395
	sw	a6, 1828(a4)
	sw	a5, 1832(a4)
	.loc	2 513 412                       # rnd_output0.c:513:412
	sw	a6, 1836(a4)
	sw	a6, 1840(a4)
	.loc	2 513 428                       # rnd_output0.c:513:428
	sw	a1, 1844(a4)
	sw	a6, 1848(a4)
	.loc	2 513 446                       # rnd_output0.c:513:446
	sw	a6, 1852(a4)
	sw	a5, 1856(a4)
	.loc	2 513 463                       # rnd_output0.c:513:463
	sw	a6, 1860(a4)
	sw	a6, 1864(a4)
	.loc	2 513 479                       # rnd_output0.c:513:479
	sw	a5, 1868(a4)
	sw	a6, 1872(a4)
	.loc	2 513 496                       # rnd_output0.c:513:496
	sw	a6, 1876(a4)
	sw	a5, 1880(a4)
	.loc	2 513 513                       # rnd_output0.c:513:513
	sw	a6, 1884(a4)
	sw	a6, 1888(a4)
	.loc	2 513 529                       # rnd_output0.c:513:529
	sw	a1, 1892(a4)
	sw	a6, 1896(a4)
	.loc	2 513 547                       # rnd_output0.c:513:547
	sw	a6, 1900(a4)
	sw	a5, 1904(a4)
	li	a5, 3
	.loc	2 514 33 is_stmt 1              # rnd_output0.c:514:33
	sw	a5, 1664(a4)
	lui	a5, 603653
	addi	a5, a5, 836
	.loc	2 515 33                        # rnd_output0.c:515:33
	sw	a5, 1660(a4)
	li	a5, -5
	.loc	2 516 33                        # rnd_output0.c:516:33
	sw	a5, 1656(a4)
	lui	a5, 404086
	addi	a5, a5, -1146
	.loc	2 517 33                        # rnd_output0.c:517:33
	sw	a5, 1652(a4)
	.loc	2 518 34                        # rnd_output0.c:518:34
	sw	a1, 1648(a4)
	.loc	2 520 40                        # rnd_output0.c:520:40
	lbu	a3, %lo(g_588)(a3)
	.loc	2 520 49 is_stmt 0              # rnd_output0.c:520:49
	lw	a6, -48(s0)
	.loc	2 520 88                        # rnd_output0.c:520:88
	lw	a5, 1920(a4)
	.loc	2 520 54                        # rnd_output0.c:520:54
	sltu	a5, a5, a6
	xori	a5, a5, 1
	.loc	2 520 46                        # rnd_output0.c:520:46
	and	a3, a3, a5
	.loc	2 520 96                        # rnd_output0.c:520:96
	lw	a4, 1908(a4)
	.loc	2 520 94                        # rnd_output0.c:520:94
	sltu	a4, a3, a4
	.loc	2 520 27                        # rnd_output0.c:520:27
	lw	a3, 468(a2)
	.loc	2 520 35                        # rnd_output0.c:520:35
	lw	a2, 0(a3)
	or	a2, a2, a4
	sw	a2, 0(a3)
	.loc	2 521 193 is_stmt 1             # rnd_output0.c:521:193
	lw	a2, 700(a0)
	.loc	2 521 201 is_stmt 0             # rnd_output0.c:521:201
	lui	a0, %hi(g_1374)
	lw	a0, %lo(g_1374)(a0)
	.loc	2 521 200                       # rnd_output0.c:521:200
	lhu	a0, 0(a0)
	.loc	2 521 196                       # rnd_output0.c:521:196
	slt	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 521 211                       # rnd_output0.c:521:211
	lw	a3, -36(s0)
	lw	a2, -40(s0)
	.loc	2 521 150                       # rnd_output0.c:521:150
	call	safe_add_func_int64_t_s_s
	.loc	2 521 117                       # rnd_output0.c:521:117
	slli	a0, a0, 24
	srai	a1, a0, 24
	li	a0, -120
	call	safe_mod_func_int8_t_s_s
	li	a1, 1
	.loc	2 521 220                       # rnd_output0.c:521:220
	lui	a2, 4
	sub	a2, s0, a2
	sw	a1, 268(a2)                     # 4-byte Folded Spill
	bnez	a0, .LBB0_233
	j	.LBB0_232
.LBB0_232:                              #   in Loop: Header=BB0_230 Depth=3
	.loc	2 521 259                       # rnd_output0.c:521:259
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 748(a0)                     # 4-byte Folded Reload
	lw	a0, 1648(a1)
	addi	a0, a0, 1
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 256(a2)                     # 4-byte Folded Spill
	sw	a0, 1648(a1)
	.loc	2 521 329                       # rnd_output0.c:521:329
	lui	a0, %hi(g_1662)
	lb	a0, %lo(g_1662)(a0)
	.loc	2 521 345                       # rnd_output0.c:521:345
	lui	a1, %hi(g_69)
	addi	a1, a1, %lo(g_69)
	lb	a1, 36(a1)
	.loc	2 521 304                       # rnd_output0.c:521:304
	call	safe_mul_func_int8_t_s_s
	.loc	2 521 353                       # rnd_output0.c:521:353
	lw	a1, -44(s0)
	.loc	2 521 358                       # rnd_output0.c:521:358
	slti	a1, a1, 2
	.loc	2 521 350                       # rnd_output0.c:521:350
	xor	a0, a0, a1
	li	a1, 20
	.loc	2 521 273                       # rnd_output0.c:521:273
	call	safe_rshift_func_int32_t_s_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a2, 256(a1)                     # 4-byte Folded Reload
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
	.loc	2 521 269                       # rnd_output0.c:521:269
	sltu	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 521 405                       # rnd_output0.c:521:405
	lw	a1, 0(a1)
	.loc	2 521 402                       # rnd_output0.c:521:402
	xor	a0, a0, a1
	snez	a0, a0
	.loc	2 521 415                       # rnd_output0.c:521:415
	lw	a1, -28(s0)
	lw	a2, -32(s0)
	.loc	2 521 413                       # rnd_output0.c:521:413
	xor	a2, a2, a0
	lui	a0, 16
	addi	a0, a0, -6
	.loc	2 521 421                       # rnd_output0.c:521:421
	sltu	a0, a0, a2
	snez	a1, a1
	or	a0, a0, a1
	.loc	2 521 434                       # rnd_output0.c:521:434
	lw	a1, -40(s0)
	.loc	2 521 225                       # rnd_output0.c:521:225
	call	safe_lshift_func_int32_t_s_u
	.loc	2 521 441                       # rnd_output0.c:521:441
	slti	a0, a0, 103
	.loc	2 521 220                       # rnd_output0.c:521:220
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 268(a1)                     # 4-byte Folded Spill
	j	.LBB0_233
.LBB0_233:                              #   in Loop: Header=BB0_230 Depth=3
	.loc	2 0 220                         # rnd_output0.c:0:220
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 268(a0)                     # 4-byte Folded Reload
	.loc	2 521 220                       # rnd_output0.c:521:220
	andi	a0, a0, 1
	li	a1, 1
	.loc	2 521 89                        # rnd_output0.c:521:89
	call	safe_div_func_uint8_t_u_u
	.loc	2 521 462                       # rnd_output0.c:521:462
	lw	a1, -28(s0)
	lw	a2, -32(s0)
	.loc	2 521 459                       # rnd_output0.c:521:459
	xor	a0, a0, a2
	or	a0, a0, a1
	seqz	a2, a0
	lui	a0, 361022
	addi	a0, a0, 1565
	lui	a1, 360308
	addi	a1, a1, 1787
	li	a3, 0
	.loc	2 521 39                        # rnd_output0.c:521:39
	call	safe_mul_func_int64_t_s_s
	mv	a2, a0
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	.loc	2 521 27                        # rnd_output0.c:521:27
	lw	a1, 468(a0)
	.loc	2 521 35                        # rnd_output0.c:521:35
	lw	a0, 0(a1)
	and	a0, a0, a2
	sw	a0, 0(a1)
	.loc	2 522 21 is_stmt 1              # rnd_output0.c:522:21
	j	.LBB0_234
.Ltmp270:
.LBB0_234:                              #   in Loop: Header=BB0_230 Depth=3
	.loc	2 510 60                        # rnd_output0.c:510:60
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 756(a0)                     # 4-byte Folded Reload
	lbu	a0, 564(a1)
	addi	a0, a0, 1
	sb	a0, 564(a1)
	.loc	2 510 21 is_stmt 0              # rnd_output0.c:510:21
	j	.LBB0_230
.Ltmp271:
.LBB0_235:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 523 27 is_stmt 1              # rnd_output0.c:523:27
	lw	a0, -24(s0)
	.loc	2 523 26 is_stmt 0              # rnd_output0.c:523:26
	lw	a0, 0(a0)
.Ltmp272:
	.loc	2 523 25                        # rnd_output0.c:523:25
	beqz	a0, .LBB0_237
	j	.LBB0_236
.LBB0_236:                              #   in Loop: Header=BB0_200 Depth=1
.Ltmp273:
	.loc	2 524 25 is_stmt 1              # rnd_output0.c:524:25
	j	.LBB0_245
.Ltmp274:
.LBB0_237:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 525 17                        # rnd_output0.c:525:17
	j	.LBB0_243
.Ltmp275:
.LBB0_238:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 17 is_stmt 0                # rnd_output0.c:0:17
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 748(a0)                     # 4-byte Folded Reload
	lui	a1, 287220
	addi	a1, a1, 1567
.Ltmp276:
	.loc	2 528 30 is_stmt 1              # rnd_output0.c:528:30
	sw	a1, 1632(a0)
	sw	a1, 1628(a0)
	sw	a1, 1624(a0)
	sw	a1, 1620(a0)
	.loc	2 530 21                        # rnd_output0.c:530:21
	lh	a1, 1622(a0)
	addi	a1, a1, -1
	sh	a1, 1622(a0)
.Ltmp277:
	.loc	2 531 26                        # rnd_output0.c:531:26
	lhu	a0, 1622(a0)
	.loc	2 531 36 is_stmt 0              # rnd_output0.c:531:36
	beqz	a0, .LBB0_241
	j	.LBB0_239
.LBB0_239:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 531 41                        # rnd_output0.c:531:41
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 736(a0)                     # 4-byte Folded Reload
	lw	a0, 1372(a0)
	.loc	2 531 40                        # rnd_output0.c:531:40
	lw	a0, 0(a0)
.Ltmp278:
	.loc	2 531 25                        # rnd_output0.c:531:25
	beqz	a0, .LBB0_241
	j	.LBB0_240
.LBB0_240:                              #   in Loop: Header=BB0_206 Depth=2
.Ltmp279:
	.loc	2 533 33 is_stmt 1              # rnd_output0.c:533:33
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 748(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 744(a0)                     # 4-byte Folded Reload
	lui	a0, %hi(g_197)
	addi	a0, a0, %lo(g_197)
	addi	a3, a0, 10
	sw	a3, 1612(a1)
	lui	a3, 3
	addi	a3, a3, 1428
	sub	a3, s0, a3
	.loc	2 534 34                        # rnd_output0.c:534:34
	sw	a3, 1608(a1)
	.loc	2 535 35                        # rnd_output0.c:535:35
	lui	a3, %hi(g_388)
	addi	a3, a3, %lo(g_388)
	sw	a3, 1604(a1)
	.loc	2 536 47                        # rnd_output0.c:536:47
	lw	a2, 20(a2)
	.loc	2 536 55 is_stmt 0              # rnd_output0.c:536:55
	addi	a0, a0, 16
	sw	a0, 0(a2)
	.loc	2 536 77                        # rnd_output0.c:536:77
	lw	a1, 1608(a1)
	.loc	2 536 85                        # rnd_output0.c:536:85
	sw	a0, 0(a1)
	.loc	2 536 152                       # rnd_output0.c:536:152
	lw	a0, -40(s0)
	li	a1, 7
	.loc	2 536 122                       # rnd_output0.c:536:122
	call	safe_rshift_func_uint32_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 744(a1)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 536 188                       # rnd_output0.c:536:188
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 740(a0)                     # 4-byte Folded Reload
	lw	a0, 32(a0)
	.loc	2 536 186                       # rnd_output0.c:536:186
	sw	a0, 8(a1)
	lui	a0, 1030560
	addi	a0, a0, 759
	lui	a1, 870637
	addi	a1, a1, 872
	.loc	2 536 227                       # rnd_output0.c:536:227
	call	safe_unary_minus_func_int64_t_s
                                        # kill: def $x12 killed $x10
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 748(a0)                     # 4-byte Folded Reload
                                        # kill: def $x12 killed $x11
	.loc	2 536 108                       # rnd_output0.c:536:108
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 740(a1)                     # 4-byte Folded Reload
	lw	a2, 1604(a0)
	li	a0, 1
	.loc	2 536 116                       # rnd_output0.c:536:116
	sh	a0, 0(a2)
	.loc	2 536 32                        # rnd_output0.c:536:32
	lw	a0, 0(a1)
	andi	a0, a0, 1
	sw	a0, 0(a1)
	.loc	2 537 28 is_stmt 1              # rnd_output0.c:537:28
	lui	a0, %hi(g_1126)
	lw	a0, %lo(g_1126)(a0)
	.loc	2 537 27 is_stmt 0              # rnd_output0.c:537:27
	lw	a1, 0(a0)
	addi	a0, s0, -44
	.loc	2 537 36                        # rnd_output0.c:537:36
	sw	a0, 0(a1)
	.loc	2 538 21 is_stmt 1              # rnd_output0.c:538:21
	j	.LBB0_242
.Ltmp280:
.LBB0_241:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 541 35                        # rnd_output0.c:541:35
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 748(a0)                     # 4-byte Folded Reload
	lui	a1, %hi(g_1292)
	addi	a1, a1, %lo(g_1292)
	sw	a1, 1600(a0)
	.loc	2 542 36                        # rnd_output0.c:542:36
	lw	a0, 1600(a0)
	.loc	2 542 27 is_stmt 0              # rnd_output0.c:542:27
	lw	a1, -652(s0)
	.loc	2 542 34                        # rnd_output0.c:542:34
	sw	a0, 0(a1)
	j	.LBB0_242
.Ltmp281:
.LBB0_242:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 0 34                          # rnd_output0.c:0:34
	j	.LBB0_243
.LBB0_243:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 545 13 is_stmt 1              # rnd_output0.c:545:13
	j	.LBB0_244
.Ltmp282:
.LBB0_244:                              #   in Loop: Header=BB0_206 Depth=2
	.loc	2 471 79                        # rnd_output0.c:471:79
	lui	a0, %hi(g_13)
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 252(a1)                     # 4-byte Folded Spill
	lw	a0, %lo(g_13)(a0)
	srai	a1, a0, 31
	li	a2, 8
	li	a3, 0
	.loc	2 471 53 is_stmt 0              # rnd_output0.c:471:53
	call	safe_sub_func_int64_t_s_s
                                        # kill: def $x12 killed $x11
	.loc	2 471 51                        # rnd_output0.c:471:51
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 252(a1)                     # 4-byte Folded Reload
	sw	a0, %lo(g_13)(a1)
	.loc	2 471 13                        # rnd_output0.c:471:13
	j	.LBB0_206
.Ltmp283:
.LBB0_245:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 546 9 is_stmt 1               # rnd_output0.c:546:9
	j	.LBB0_246
.Ltmp284:
.LBB0_246:                              #   in Loop: Header=BB0_200 Depth=1
	.loc	2 458 75                        # rnd_output0.c:458:75
	lui	a0, %hi(g_89)
	lui	a1, 4
	sub	a1, s0, a1
	sw	a0, 248(a1)                     # 4-byte Folded Spill
	lhu	a0, %lo(g_89)(a0)
	li	a1, 4
	.loc	2 458 48 is_stmt 0              # rnd_output0.c:458:48
	call	safe_add_func_uint16_t_u_u
	lui	a1, 4
	sub	a1, s0, a1
	lw	a1, 248(a1)                     # 4-byte Folded Reload
	.loc	2 458 46                        # rnd_output0.c:458:46
	sh	a0, %lo(g_89)(a1)
	.loc	2 458 9                         # rnd_output0.c:458:9
	j	.LBB0_200
.Ltmp285:
.LBB0_247:
	.loc	2 547 5 is_stmt 1               # rnd_output0.c:547:5
	j	.LBB0_253
.Ltmp286:
.LBB0_248:
	.loc	2 0 5 is_stmt 0                 # rnd_output0.c:0:5
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 748(a0)                     # 4-byte Folded Reload
	li	a0, -1
.Ltmp287:
	.loc	2 550 18 is_stmt 1              # rnd_output0.c:550:18
	sw	a0, 1596(a1)
	li	a0, -9
	.loc	2 551 17                        # rnd_output0.c:551:17
	sw	a0, 1592(a1)
	.loc	2 552 26                        # rnd_output0.c:552:26
	lui	a0, %hi(.L__const.func_40.l_1752)
	lw	a0, %lo(.L__const.func_40.l_1752)(a0)
	sw	a0, 1588(a1)
.Ltmp288:
	.loc	2 554 19                        # rnd_output0.c:554:19
	lui	a1, %hi(g_13)
	li	a0, 0
	sw	a0, %lo(g_13)(a1)
	.loc	2 554 14 is_stmt 0              # rnd_output0.c:554:14
	j	.LBB0_249
.LBB0_249:                              # =>This Inner Loop Header: Depth=1
.Ltmp289:
	.loc	2 554 25                        # rnd_output0.c:554:25
	lui	a0, %hi(g_13)
	lw	a0, %lo(g_13)(a0)
	li	a1, -13
.Ltmp290:
	.loc	2 554 9                         # rnd_output0.c:554:9
	bne	a0, a1, .LBB0_252
	j	.LBB0_250
.LBB0_250:                              #   in Loop: Header=BB0_249 Depth=1
.Ltmp291:
	.loc	2 556 21 is_stmt 1              # rnd_output0.c:556:21
	lui	a0, %hi(.L__const.func_40.l_1708)
	addi	a1, a0, %lo(.L__const.func_40.l_1708)
	lui	a0, 3
	addi	a0, a0, 1512
	sub	a0, s0, a0
	li	a2, 56
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 748(a0)                     # 4-byte Folded Reload
	li	a0, 0
	.loc	2 557 22                        # rnd_output0.c:557:22
	lui	a2, 4
	sub	a2, s0, a2
	sw	a0, 224(a2)                     # 4-byte Folded Spill
	sw	a0, 1524(a1)
	li	a0, -1
	.loc	2 558 21                        # rnd_output0.c:558:21
	sw	a0, 1520(a1)
	.loc	2 559 22                        # rnd_output0.c:559:22
	lui	a0, %hi(.L__const.func_40.l_1775)
	addi	a1, a0, %lo(.L__const.func_40.l_1775)
	lui	a0, 4
	addi	a0, a0, -1616
	sub	a0, s0, a0
	li	a2, 960
	call	memcpy@plt
	lui	a0, 4
	sub	a0, s0, a0
	lw	a2, 748(a0)                     # 4-byte Folded Reload
	lui	a0, 4
	sub	a0, s0, a0
	lw	a1, 224(a0)                     # 4-byte Folded Reload
	.loc	2 560 45                        # rnd_output0.c:560:45
	addi	a6, s0, -2048
	addi	a6, a6, -404
	.loc	2 560 43 is_stmt 0              # rnd_output0.c:560:43
	lui	a0, 4
	sub	a0, s0, a0
	sw	a6, 228(a0)                     # 4-byte Folded Spill
	sw	a6, 0(a2)
	lui	a0, %hi(g_1548)
	addi	a5, a0, %lo(g_1548)
	sw	a5, 4(a2)
	lui	a0, 3
	addi	a0, a0, 1444
	sub	a0, s0, a0
	lui	a3, 4
	sub	a3, s0, a3
	sw	a0, 232(a3)                     # 4-byte Folded Spill
	sw	a0, 8(a2)
	addi	a3, s0, -2048
	addi	a3, a3, -1012
	lui	a4, 4
	sub	a4, s0, a4
	sw	a3, 236(a4)                     # 4-byte Folded Spill
	sw	a3, 12(a2)
	sw	a3, 16(a2)
	.loc	2 560 98                        # rnd_output0.c:560:98
	addi	a7, s0, -2048
	addi	a7, a7, -396
	.loc	2 560 96                        # rnd_output0.c:560:96
	lui	a4, 4
	sub	a4, s0, a4
	sw	a7, 240(a4)                     # 4-byte Folded Spill
	sw	a7, 20(a2)
	sw	a0, 24(a2)
	sw	a7, 28(a2)
	lui	a4, %hi(g_1662)
	addi	t0, a4, %lo(g_1662)
	sw	t0, 32(a2)
	lui	a4, %hi(g_302)
	addi	a4, a4, %lo(g_302)
	lui	t1, 4
	sub	t1, s0, t1
	sw	a4, 244(t1)                     # 4-byte Folded Spill
	sw	a4, 36(a2)
	.loc	2 560 153                       # rnd_output0.c:560:153
	sw	a6, 40(a2)
	sw	a3, 44(a2)
	sw	a0, 48(a2)
	sw	a3, 52(a2)
	sw	a3, 56(a2)
	.loc	2 560 203                       # rnd_output0.c:560:203
	sw	a0, 60(a2)
	sw	a0, 64(a2)
	sw	a0, 68(a2)
	sw	t0, 72(a2)
	sw	a4, 76(a2)
	.loc	2 560 244                       # rnd_output0.c:560:244
	sw	a6, 80(a2)
	sw	a5, 84(a2)
	sw	a0, 88(a2)
	sw	a3, 92(a2)
	sw	a3, 96(a2)
	.loc	2 560 297                       # rnd_output0.c:560:297
	sw	a7, 100(a2)
	sw	a0, 104(a2)
	sw	a7, 108(a2)
	sw	t0, 112(a2)
	sw	a4, 116(a2)
	.loc	2 560 354                       # rnd_output0.c:560:354
	sw	a6, 120(a2)
	sw	a3, 124(a2)
	sw	a0, 128(a2)
	sw	a3, 132(a2)
	sw	a3, 136(a2)
	.loc	2 560 406                       # rnd_output0.c:560:406
	sw	a0, 140(a2)
	sw	a0, 144(a2)
	sw	a0, 148(a2)
	sw	t0, 152(a2)
	sw	a4, 156(a2)
	.loc	2 560 447                       # rnd_output0.c:560:447
	sw	a6, 160(a2)
	sw	a5, 164(a2)
	sw	a0, 168(a2)
	sw	a3, 172(a2)
	sw	a3, 176(a2)
	.loc	2 560 500                       # rnd_output0.c:560:500
	sw	a7, 180(a2)
	sw	a0, 184(a2)
	sw	a7, 188(a2)
	sw	t0, 192(a2)
	sw	a4, 196(a2)
	.loc	2 560 557                       # rnd_output0.c:560:557
	sw	a6, 200(a2)
	sw	a3, 204(a2)
	sw	a0, 208(a2)
	sw	a3, 212(a2)
	sw	a3, 216(a2)
	.loc	2 560 607                       # rnd_output0.c:560:607
	sw	a0, 220(a2)
	sw	a0, 224(a2)
	sw	a0, 228(a2)
	sw	t0, 232(a2)
	sw	a4, 236(a2)
	.loc	2 560 648                       # rnd_output0.c:560:648
	sw	a6, 240(a2)
	sw	a5, 244(a2)
	sw	a0, 248(a2)
	sw	a3, 252(a2)
	sw	a3, 256(a2)
	.loc	2 560 701                       # rnd_output0.c:560:701
	sw	a7, 260(a2)
	sw	a0, 264(a2)
	sw	a7, 268(a2)
	sw	a3, 272(a2)
	sw	a7, 276(a2)
	.loc	2 560 769                       # rnd_output0.c:560:769
	sw	a1, 280(a2)
	sw	a3, 284(a2)
	sw	a3, 288(a2)
	sw	a0, 292(a2)
	sw	a6, 296(a2)
	.loc	2 560 820                       # rnd_output0.c:560:820
	sw	a4, 300(a2)
	.loc	2 560 829                       # rnd_output0.c:560:829
	addi	a5, s0, -2048
	addi	a5, a5, -460
	.loc	2 560 820                       # rnd_output0.c:560:820
	sw	a5, 304(a2)
	sw	a4, 308(a2)
	sw	a3, 312(a2)
	sw	a0, 316(a2)
	.loc	2 560 868                       # rnd_output0.c:560:868
	sw	a1, 320(a2)
	sw	a1, 324(a2)
	sw	a3, 328(a2)
	sw	a6, 332(a2)
	sw	a6, 336(a2)
	.loc	2 560 928                       # rnd_output0.c:560:928
	sw	a1, 340(a2)
	sw	a5, 344(a2)
	sw	a1, 348(a2)
	sw	a3, 352(a2)
	sw	a7, 356(a2)
	.loc	2 560 988                       # rnd_output0.c:560:988
	sw	a1, 360(a2)
	sw	a3, 364(a2)
	sw	a3, 368(a2)
	sw	a0, 372(a2)
	sw	a6, 376(a2)
	.loc	2 560 1039                      # rnd_output0.c:560:1039
	sw	a4, 380(a2)
	sw	a5, 384(a2)
	sw	a4, 388(a2)
	sw	a3, 392(a2)
	sw	a0, 396(a2)
	.loc	2 560 1087                      # rnd_output0.c:560:1087
	sw	a1, 400(a2)
	sw	a1, 404(a2)
	sw	a3, 408(a2)
	sw	a6, 412(a2)
	sw	a6, 416(a2)
	.loc	2 560 1149                      # rnd_output0.c:560:1149
	sw	a1, 420(a2)
	sw	a5, 424(a2)
	sw	a1, 428(a2)
	sw	a3, 432(a2)
	sw	a7, 436(a2)
	.loc	2 560 1209                      # rnd_output0.c:560:1209
	sw	a1, 440(a2)
	sw	a3, 444(a2)
	sw	a3, 448(a2)
	sw	a0, 452(a2)
	sw	a6, 456(a2)
	.loc	2 560 1260                      # rnd_output0.c:560:1260
	sw	a4, 460(a2)
	sw	a5, 464(a2)
	sw	a4, 468(a2)
	sw	a3, 472(a2)
	sw	a0, 476(a2)
	.loc	2 560 1308                      # rnd_output0.c:560:1308
	sw	a1, 480(a2)
	sw	a1, 484(a2)
	sw	a3, 488(a2)
	sw	a6, 492(a2)
	sw	a6, 496(a2)
	.loc	2 560 1368                      # rnd_output0.c:560:1368
	sw	a1, 500(a2)
	sw	a5, 504(a2)
	sw	a1, 508(a2)
	sw	a3, 512(a2)
	sw	a7, 516(a2)
	.loc	2 560 1428                      # rnd_output0.c:560:1428
	sw	a1, 520(a2)
	sw	a3, 524(a2)
	sw	a3, 528(a2)
	sw	a0, 532(a2)
	sw	a6, 536(a2)
	.loc	2 560 1479                      # rnd_output0.c:560:1479
	sw	a4, 540(a2)
	sw	a5, 544(a2)
	sw	a4, 548(a2)
	sw	a3, 552(a2)
	sw	a0, 556(a2)
	lui	a0, 4
	addi	a0, a0, -1016
	sub	a0, s0, a0
	li	a2, 40
	.loc	2 561 24 is_stmt 1              # rnd_output0.c:561:24
	call	memset@plt
	.loc	2 562 21                        # rnd_output0.c:562:21
	lui	a0, %hi(.L__const.func_40.l_1827)
	addi	a1, a0, %lo(.L__const.func_40.l_1827)
	lui	a0, 4
	addi	a0, a0, -776
	sub	a0, s0, a0
	li	a2, 240
	call	memcpy@plt
	.loc	2 564 9                         # rnd_output0.c:564:9
	j	.LBB0_251
.Ltmp292:
.LBB0_251:                              #   in Loop: Header=BB0_249 Depth=1
	.loc	2 554 41                        # rnd_output0.c:554:41
	lui	a1, %hi(g_13)
	lw	a0, %lo(g_13)(a1)
	addi	a0, a0, -1
	sw	a0, %lo(g_13)(a1)
	.loc	2 554 9 is_stmt 0               # rnd_output0.c:554:9
	j	.LBB0_249
.Ltmp293:
.LBB0_252:
	.loc	2 0 9                           # rnd_output0.c:0:9
	j	.LBB0_253
.LBB0_253:
	.loc	2 566 12 is_stmt 1              # rnd_output0.c:566:12
	lui	a0, 4
	sub	a0, s0, a0
	lw	a0, 756(a0)                     # 4-byte Folded Reload
	lw	a0, 372(a0)
	.loc	2 566 5 is_stmt 0               # rnd_output0.c:566:5
	sw	a0, -20(s0)
	j	.LBB0_254
.LBB0_254:
	.loc	2 567 1 is_stmt 1               # rnd_output0.c:567:1
	lw	a0, -20(s0)
	.loc	2 567 1 epilogue_begin is_stmt 0 # rnd_output0.c:567:1
	lui	a1, 3
	addi	a1, a1, 1840
	add	sp, sp, a1
	lw	ra, 2028(sp)                    # 4-byte Folded Reload
	lw	s0, 2024(sp)                    # 4-byte Folded Reload
	lw	s1, 2020(sp)                    # 4-byte Folded Reload
	addi	sp, sp, 2032
	ret
.Ltmp294:
.Lfunc_end0:
	.size	func_40, .Lfunc_end0-func_40
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int64_t_s_s
	.type	safe_mul_func_int64_t_s_s,@function
safe_mul_func_int64_t_s_s:              # @safe_mul_func_int64_t_s_s
.Lfunc_begin1:
	.file	6 "/home/shiyanchu/outline_test" "linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h"
	.loc	6 448 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:448:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -160
	.cfi_def_cfa_offset 160
	sw	ra, 156(sp)                     # 4-byte Folded Spill
	sw	s0, 152(sp)                     # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 160
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp295:
	.loc	6 453 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:8
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	6 453 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:12
	slti	a2, a0, 0
	sw	a2, -32(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB1_2
# %bb.1:
	.loc	6 0 12                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:12
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -28(s0)                     # 4-byte Folded Spill
.LBB1_2:
	.loc	6 453 12                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:12
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	.loc	6 453 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:17
	bnez	a0, .LBB1_9
	j	.LBB1_3
.LBB1_3:
	.loc	6 453 21                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:21
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	6 453 25                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:25
	slti	a2, a0, 0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -36(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB1_5
# %bb.4:
	.loc	6 0 25                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:25
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -36(s0)                     # 4-byte Folded Spill
.LBB1_5:
	.loc	6 453 25                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:25
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	.loc	6 453 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:30
	bnez	a0, .LBB1_9
	j	.LBB1_6
.LBB1_6:
	.loc	6 453 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:34
	lw	a0, -16(s0)
	sw	a0, -56(s0)                     # 4-byte Folded Spill
	lw	a0, -12(s0)
	.loc	6 453 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:53
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	lui	a0, 524288
	addi	a1, a0, -1
	li	a0, -1
	.loc	6 453 51                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:51
	call	__divdi3@plt
	lw	a3, -56(s0)                     # 4-byte Folded Reload
	mv	a2, a0
	lw	a0, -52(s0)                     # 4-byte Folded Reload
	.loc	6 453 38                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:38
	slt	a4, a1, a0
	sw	a4, -48(s0)                     # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB1_8
# %bb.7:
	.loc	6 0 38                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:38
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB1_8:
	.loc	6 453 38                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:38
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	6 453 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:60
	bnez	a0, .LBB1_37
	j	.LBB1_9
.LBB1_9:
	.loc	6 453 65                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:65
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	6 453 69                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:69
	slti	a2, a0, 0
	sw	a2, -64(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -60(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB1_11
# %bb.10:
	.loc	6 0 69                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:69
	lw	a0, -64(s0)                     # 4-byte Folded Reload
	sw	a0, -60(s0)                     # 4-byte Folded Spill
.LBB1_11:
	.loc	6 453 69                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:69
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	.loc	6 453 74                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:74
	bnez	a0, .LBB1_18
	j	.LBB1_12
.LBB1_12:
	.loc	6 453 78                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:78
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	li	a2, 0
	.loc	6 453 82                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:82
	slt	a2, a2, a0
	sw	a2, -72(s0)                     # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -68(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB1_14
# %bb.13:
	.loc	6 0 82                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:82
	lw	a0, -72(s0)                     # 4-byte Folded Reload
	sw	a0, -68(s0)                     # 4-byte Folded Spill
.LBB1_14:
	.loc	6 453 82                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:82
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	.loc	6 453 88                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:88
	bnez	a0, .LBB1_18
	j	.LBB1_15
.LBB1_15:
	.loc	6 453 92                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:92
	lw	a0, -24(s0)
	sw	a0, -88(s0)                     # 4-byte Folded Spill
	lw	a0, -20(s0)
	.loc	6 453 111                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:111
	sw	a0, -84(s0)                     # 4-byte Folded Spill
	lw	a2, -16(s0)
	lw	a3, -12(s0)
	li	a0, 0
	lui	a1, 524288
	.loc	6 453 109                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:109
	call	__divdi3@plt
	lw	a2, -88(s0)                     # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -84(s0)                     # 4-byte Folded Reload
	.loc	6 453 96                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:96
	slt	a4, a0, a1
	sw	a4, -80(s0)                     # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -76(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB1_17
# %bb.16:
	.loc	6 0 96                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:96
	lw	a0, -80(s0)                     # 4-byte Folded Reload
	sw	a0, -76(s0)                     # 4-byte Folded Spill
.LBB1_17:
	.loc	6 453 96                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:96
	lw	a0, -76(s0)                     # 4-byte Folded Reload
	.loc	6 453 118                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:118
	bnez	a0, .LBB1_37
	j	.LBB1_18
.LBB1_18:
	.loc	6 453 123                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:123
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	li	a2, 0
	.loc	6 453 127                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:127
	slt	a2, a2, a0
	sw	a2, -96(s0)                     # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -92(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB1_20
# %bb.19:
	.loc	6 0 127                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:127
	lw	a0, -96(s0)                     # 4-byte Folded Reload
	sw	a0, -92(s0)                     # 4-byte Folded Spill
.LBB1_20:
	.loc	6 453 127                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:127
	lw	a0, -92(s0)                     # 4-byte Folded Reload
	.loc	6 453 133                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:133
	bnez	a0, .LBB1_27
	j	.LBB1_21
.LBB1_21:
	.loc	6 453 137                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:137
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	6 453 141                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:141
	slti	a2, a0, 0
	sw	a2, -104(s0)                    # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -100(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB1_23
# %bb.22:
	.loc	6 0 141                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:141
	lw	a0, -104(s0)                    # 4-byte Folded Reload
	sw	a0, -100(s0)                    # 4-byte Folded Spill
.LBB1_23:
	.loc	6 453 141                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:141
	lw	a0, -100(s0)                    # 4-byte Folded Reload
	.loc	6 453 146                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:146
	bnez	a0, .LBB1_27
	j	.LBB1_24
.LBB1_24:
	.loc	6 453 150                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:150
	lw	a0, -16(s0)
	sw	a0, -120(s0)                    # 4-byte Folded Spill
	lw	a0, -12(s0)
	.loc	6 453 169                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:169
	sw	a0, -116(s0)                    # 4-byte Folded Spill
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	li	a0, 0
	lui	a1, 524288
	.loc	6 453 167                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:167
	call	__divdi3@plt
	lw	a2, -120(s0)                    # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -116(s0)                    # 4-byte Folded Reload
	.loc	6 453 154                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:154
	slt	a4, a0, a1
	sw	a4, -112(s0)                    # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -108(s0)                    # 4-byte Folded Spill
	beq	a0, a1, .LBB1_26
# %bb.25:
	.loc	6 0 154                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:154
	lw	a0, -112(s0)                    # 4-byte Folded Reload
	sw	a0, -108(s0)                    # 4-byte Folded Spill
.LBB1_26:
	.loc	6 453 154                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:154
	lw	a0, -108(s0)                    # 4-byte Folded Reload
	.loc	6 453 176                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:176
	bnez	a0, .LBB1_37
	j	.LBB1_27
.LBB1_27:
	.loc	6 453 181                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:181
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	li	a2, 0
	.loc	6 453 185                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:185
	slt	a2, a2, a0
	sw	a2, -128(s0)                    # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -124(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB1_29
# %bb.28:
	.loc	6 0 185                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:185
	lw	a0, -128(s0)                    # 4-byte Folded Reload
	sw	a0, -124(s0)                    # 4-byte Folded Spill
.LBB1_29:
	.loc	6 453 185                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:185
	lw	a0, -124(s0)                    # 4-byte Folded Reload
	.loc	6 453 191                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:191
	bnez	a0, .LBB1_38
	j	.LBB1_30
.LBB1_30:
	.loc	6 453 195                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:195
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	li	a2, 0
	.loc	6 453 199                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:199
	slt	a2, a2, a0
	sw	a2, -136(s0)                    # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -132(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB1_32
# %bb.31:
	.loc	6 0 199                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:199
	lw	a0, -136(s0)                    # 4-byte Folded Reload
	sw	a0, -132(s0)                    # 4-byte Folded Spill
.LBB1_32:
	.loc	6 453 199                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:199
	lw	a0, -132(s0)                    # 4-byte Folded Reload
	.loc	6 453 205                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:205
	bnez	a0, .LBB1_38
	j	.LBB1_33
.LBB1_33:
	.loc	6 453 209                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:209
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	.loc	6 453 213                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:213
	or	a0, a0, a1
	.loc	6 453 219                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:219
	beqz	a0, .LBB1_38
	j	.LBB1_34
.LBB1_34:
	.loc	6 453 223                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:223
	lw	a0, -24(s0)
	sw	a0, -152(s0)                    # 4-byte Folded Spill
	lw	a0, -20(s0)
	.loc	6 453 242                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:242
	sw	a0, -148(s0)                    # 4-byte Folded Spill
	lw	a2, -16(s0)
	lw	a3, -12(s0)
	lui	a0, 524288
	addi	a1, a0, -1
	li	a0, -1
	.loc	6 453 240                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:240
	call	__divdi3@plt
	lw	a2, -152(s0)                    # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -148(s0)                    # 4-byte Folded Reload
	.loc	6 453 227                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:227
	slt	a4, a0, a1
	xori	a4, a4, 1
	sw	a4, -144(s0)                    # 4-byte Folded Spill
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sw	a2, -140(s0)                    # 4-byte Folded Spill
	beq	a0, a1, .LBB1_36
# %bb.35:
	.loc	6 0 227                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:227
	lw	a0, -144(s0)                    # 4-byte Folded Reload
	sw	a0, -140(s0)                    # 4-byte Folded Spill
.LBB1_36:
	.loc	6 453 227                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:227
	lw	a0, -140(s0)                    # 4-byte Folded Reload
	.loc	6 453 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	bnez	a0, .LBB1_38
	j	.LBB1_37
.LBB1_37:
	.loc	6 454 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:454:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -160(s0)                    # 4-byte Folded Spill
	.loc	6 453 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	sw	a0, -156(s0)                    # 4-byte Folded Spill
	j	.LBB1_39
.LBB1_38:
	.loc	6 457 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:5
	lw	a3, -12(s0)
	lw	a1, -16(s0)
	.loc	6 457 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:11
	lw	a2, -24(s0)
	lw	a0, -20(s0)
	.loc	6 457 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:9
	mul	a4, a1, a0
	mulhu	a0, a1, a2
	add	a0, a0, a4
	mul	a3, a3, a2
	add	a0, a0, a3
	mul	a1, a1, a2
	sw	a1, -160(s0)                    # 4-byte Folded Spill
	.loc	6 453 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	sw	a0, -156(s0)                    # 4-byte Folded Spill
	j	.LBB1_39
.LBB1_39:
	lw	a0, -160(s0)                    # 4-byte Folded Reload
	lw	a1, -156(s0)                    # 4-byte Folded Reload
	.loc	6 450 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:450:3
	lw	ra, 156(sp)                     # 4-byte Folded Reload
	lw	s0, 152(sp)                     # 4-byte Folded Reload
	.loc	6 450 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:450:3
	addi	sp, sp, 160
	ret
.Ltmp296:
.Lfunc_end1:
	.size	safe_mul_func_int64_t_s_s, .Lfunc_end1-safe_mul_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int8_t_s_s
	.type	safe_sub_func_int8_t_s_s,@function
safe_sub_func_int8_t_s_s:               # @safe_sub_func_int8_t_s_s
.Lfunc_begin2:
	.loc	6 43 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:43:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp297:
	.loc	6 52 6 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:6
	lbu	a0, -9(s0)
	.loc	6 52 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:12
	lbu	a1, -10(s0)
	.loc	6 52 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:10
	sub	a0, a0, a1
	.loc	6 45 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:45:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 45 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:45:3
	addi	sp, sp, 16
	ret
.Ltmp298:
.Lfunc_end2:
	.size	safe_sub_func_int8_t_s_s, .Lfunc_end2-safe_sub_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_uint8_t_u
	.type	safe_unary_minus_func_uint8_t_u,@function
safe_unary_minus_func_uint8_t_u:        # @safe_unary_minus_func_uint8_t_u
.Lfunc_begin3:
	.loc	6 540 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:540:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x11 killed $x10
	sb	a0, -9(s0)
.Ltmp299:
	.loc	6 542 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:11
	lbu	a1, -9(s0)
	li	a0, 0
	.loc	6 542 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:10
	sub	a0, a0, a1
	.loc	6 542 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 542 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:3
	addi	sp, sp, 16
	ret
.Ltmp300:
.Lfunc_end3:
	.size	safe_unary_minus_func_uint8_t_u, .Lfunc_end3-safe_unary_minus_func_uint8_t_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint16_t_u_u
	.type	safe_div_func_uint16_t_u_u,@function
safe_div_func_uint16_t_u_u:             # @safe_div_func_uint16_t_u_u
.Lfunc_begin4:
	.loc	6 682 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:682:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp301:
	.loc	6 686 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:686:6
	lhu	a0, -12(s0)
	.loc	6 686 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:686:5
	bnez	a0, .LBB4_2
	j	.LBB4_1
.LBB4_1:
	.loc	6 687 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:687:6
	lhu	a0, -10(s0)
	.loc	6 686 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:686:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB4_3
.LBB4_2:
	.loc	6 689 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:689:6
	lhu	a0, -10(s0)
	.loc	6 689 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:689:12
	lhu	a1, -12(s0)
	.loc	6 689 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:689:10
	divu	a0, a0, a1
	.loc	6 686 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:686:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB4_3
.LBB4_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 684 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:684:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 684 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:684:3
	addi	sp, sp, 16
	ret
.Ltmp302:
.Lfunc_end4:
	.size	safe_div_func_uint16_t_u_u, .Lfunc_end4-safe_div_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint8_t_u_u
	.type	safe_mul_func_uint8_t_u_u,@function
safe_mul_func_uint8_t_u_u:              # @safe_mul_func_uint8_t_u_u
.Lfunc_begin5:
	.loc	6 561 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:561:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp303:
	.loc	6 563 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:11
	lbu	a0, -9(s0)
	.loc	6 563 33 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:33
	lbu	a1, -10(s0)
	.loc	6 563 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:30
	mul	a0, a0, a1
	.loc	6 563 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 563 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:3
	addi	sp, sp, 16
	ret
.Ltmp304:
.Lfunc_end5:
	.size	safe_mul_func_uint8_t_u_u, .Lfunc_end5-safe_mul_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int8_t_s_s
	.type	safe_add_func_int8_t_s_s,@function
safe_add_func_int8_t_s_s:               # @safe_add_func_int8_t_s_s
.Lfunc_begin6:
	.loc	6 29 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:29:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp305:
	.loc	6 38 6 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:6
	lbu	a0, -9(s0)
	.loc	6 38 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:12
	lbu	a1, -10(s0)
	.loc	6 38 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:10
	add	a0, a0, a1
	.loc	6 31 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:31:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 31 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:31:3
	addi	sp, sp, 16
	ret
.Ltmp306:
.Lfunc_end6:
	.size	safe_add_func_int8_t_s_s, .Lfunc_end6-safe_add_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint16_t_u_u
	.type	safe_add_func_uint16_t_u_u,@function
safe_add_func_uint16_t_u_u:             # @safe_add_func_uint16_t_u_u
.Lfunc_begin7:
	.loc	6 649 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:649:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp307:
	.loc	6 651 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:10
	lh	a0, -10(s0)
	.loc	6 651 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:16
	lh	a1, -12(s0)
	.loc	6 651 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:14
	add	a0, a0, a1
	.loc	6 651 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 651 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:3
	addi	sp, sp, 16
	ret
.Ltmp308:
.Lfunc_end7:
	.size	safe_add_func_uint16_t_u_u, .Lfunc_end7-safe_add_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int8_t_s_s
	.type	safe_mul_func_int8_t_s_s,@function
safe_mul_func_int8_t_s_s:               # @safe_mul_func_int8_t_s_s
.Lfunc_begin8:
	.loc	6 57 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:57:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp309:
	.loc	6 66 5 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:66:5
	lbu	a0, -9(s0)
	.loc	6 66 11 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:66:11
	lbu	a1, -10(s0)
	.loc	6 66 9                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:66:9
	mul	a0, a0, a1
	.loc	6 59 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:59:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 59 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:59:3
	addi	sp, sp, 16
	ret
.Ltmp310:
.Lfunc_end8:
	.size	safe_mul_func_int8_t_s_s, .Lfunc_end8-safe_mul_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint8_t_u_s
	.type	safe_rshift_func_uint8_t_u_s,@function
safe_rshift_func_uint8_t_u_s:           # @safe_rshift_func_uint8_t_u_s
.Lfunc_begin9:
	.loc	6 616 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:616:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sw	a1, -16(s0)
.Ltmp311:
	.loc	6 620 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:13
	lw	a0, -16(s0)
	.loc	6 620 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:25
	bltz	a0, .LBB9_2
	j	.LBB9_1
.LBB9_1:
	.loc	6 620 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:35
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 620 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	blt	a0, a1, .LBB9_3
	j	.LBB9_2
.LBB9_2:
	.loc	6 621 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:621:6
	lbu	a0, -9(s0)
	.loc	6 620 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB9_4
.LBB9_3:
	.loc	6 623 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:6
	lbu	a0, -9(s0)
	.loc	6 623 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:20
	lw	a1, -16(s0)
	.loc	6 623 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:11
	srl	a0, a0, a1
	.loc	6 620 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB9_4
.LBB9_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 618 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:618:3
	andi	a0, a0, 255
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 618 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:618:3
	addi	sp, sp, 32
	ret
.Ltmp312:
.Lfunc_end9:
	.size	safe_rshift_func_uint8_t_u_s, .Lfunc_end9-safe_rshift_func_uint8_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int32_t_s_s
	.type	safe_div_func_int32_t_s_s,@function
safe_div_func_int32_t_s_s:              # @safe_div_func_int32_t_s_s
.Lfunc_begin10:
	.loc	6 343 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:343:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp313:
	.loc	6 347 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:7
	lw	a0, -16(s0)
	.loc	6 347 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:17
	beqz	a0, .LBB10_3
	j	.LBB10_1
.LBB10_1:
	.loc	6 347 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:22
	lw	a0, -12(s0)
	lui	a1, 524288
	.loc	6 347 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:40
	bne	a0, a1, .LBB10_4
	j	.LBB10_2
.LBB10_2:
	.loc	6 347 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:44
	lw	a0, -16(s0)
	li	a1, -1
	.loc	6 347 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:5
	bne	a0, a1, .LBB10_4
	j	.LBB10_3
.LBB10_3:
	.loc	6 348 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:348:6
	lw	a0, -12(s0)
	.loc	6 347 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB10_5
.LBB10_4:
	.loc	6 350 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:350:6
	lw	a0, -12(s0)
	.loc	6 350 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:350:12
	lw	a1, -16(s0)
	.loc	6 350 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:350:10
	div	a0, a0, a1
	.loc	6 347 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:347:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB10_5
.LBB10_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 345 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:345:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 345 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:345:3
	addi	sp, sp, 32
	ret
.Ltmp314:
.Lfunc_end10:
	.size	safe_div_func_int32_t_s_s, .Lfunc_end10-safe_div_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_uint64_t_u_s
	.type	safe_lshift_func_uint64_t_u_s,@function
safe_lshift_func_uint64_t_u_s:          # @safe_lshift_func_uint64_t_u_s
.Lfunc_begin11:
	.loc	6 899 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:899:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -80
	.cfi_def_cfa_offset 80
	sw	ra, 76(sp)                      # 4-byte Folded Spill
	sw	s0, 72(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 80
	.cfi_def_cfa s0, 0
                                        # kill: def $x13 killed $x11
                                        # kill: def $x13 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a2, -20(s0)
.Ltmp315:
	.loc	6 903 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:13
	lw	a0, -20(s0)
	.loc	6 903 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:25
	bltz	a0, .LBB11_7
	j	.LBB11_1
.LBB11_1:
	.loc	6 903 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:35
	lw	a1, -20(s0)
	li	a0, 31
	.loc	6 903 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:49
	blt	a0, a1, .LBB11_7
	j	.LBB11_2
.LBB11_2:
	.loc	6 903 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:53
	lw	a0, -12(s0)
	sw	a0, -40(s0)                     # 4-byte Folded Spill
	lw	a0, -16(s0)
	.loc	6 903 81                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:81
	sw	a0, -36(s0)                     # 4-byte Folded Spill
	lw	a0, -20(s0)
	li	a1, -1
	.loc	6 903 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:72
	srl	a1, a1, a0
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	not	a3, a0
	li	a2, -2
	sll	a2, a2, a3
	or	a1, a1, a2
	addi	a0, a0, -32
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	sw	a1, -24(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB11_4
# %bb.3:
	.loc	6 0 72                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:72
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -24(s0)                     # 4-byte Folded Spill
.LBB11_4:
	.loc	6 903 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:72
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	lw	a3, -36(s0)                     # 4-byte Folded Reload
	lw	a4, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	lw	a2, -24(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a4
	.loc	6 903 58                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:58
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sltu	a3, a1, a0
	xori	a3, a3, 1
	sw	a3, -48(s0)                     # 4-byte Folded Spill
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB11_6
# %bb.5:
	.loc	6 0 58                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:58
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB11_6:
	.loc	6 903 58                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:58
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	6 903 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:5
	bnez	a0, .LBB11_8
	j	.LBB11_7
.LBB11_7:
	.loc	6 904 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:904:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	6 903 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB11_11
.LBB11_8:
	.loc	6 906 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:906:6
	lw	a2, -16(s0)
	lw	a1, -12(s0)
	.loc	6 906 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:906:20
	lw	a0, -20(s0)
	.loc	6 906 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:906:11
	sll	a1, a1, a0
	not	a4, a0
	srli	a3, a2, 1
	srl	a3, a3, a4
	or	a1, a1, a3
	sll	a2, a2, a0
	sw	a2, -68(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	sw	a0, -64(s0)                     # 4-byte Folded Spill
	sw	a1, -60(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB11_10
# %bb.9:
	.loc	6 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	sw	a0, -60(s0)                     # 4-byte Folded Spill
.LBB11_10:
	.loc	6 906 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:906:11
	lw	a2, -68(s0)                     # 4-byte Folded Reload
	lw	a1, -64(s0)                     # 4-byte Folded Reload
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a2
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	6 903 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:903:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB11_11
.LBB11_11:
	lw	a0, -56(s0)                     # 4-byte Folded Reload
	lw	a1, -52(s0)                     # 4-byte Folded Reload
	.loc	6 901 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:901:3
	lw	ra, 76(sp)                      # 4-byte Folded Reload
	lw	s0, 72(sp)                      # 4-byte Folded Reload
	.loc	6 901 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:901:3
	addi	sp, sp, 80
	ret
.Ltmp316:
.Lfunc_end11:
	.size	safe_lshift_func_uint64_t_u_s, .Lfunc_end11-safe_lshift_func_uint64_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_uint8_t_u_u
	.type	safe_lshift_func_uint8_t_u_u,@function
safe_lshift_func_uint8_t_u_u:           # @safe_lshift_func_uint8_t_u_u
.Lfunc_begin12:
	.loc	6 604 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:604:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sw	a1, -16(s0)
.Ltmp317:
	.loc	6 608 22 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:22
	lw	a1, -16(s0)
	li	a0, 31
	.loc	6 608 36 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:36
	bltu	a0, a1, .LBB12_2
	j	.LBB12_1
.LBB12_1:
	.loc	6 608 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:40
	lbu	a1, -9(s0)
	.loc	6 608 76                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:76
	lw	a2, -16(s0)
	li	a0, 255
	.loc	6 608 58                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:58
	srl	a0, a0, a2
	.loc	6 608 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:5
	bge	a0, a1, .LBB12_3
	j	.LBB12_2
.LBB12_2:
	.loc	6 609 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:609:6
	lbu	a0, -9(s0)
	.loc	6 608 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB12_4
.LBB12_3:
	.loc	6 611 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:611:6
	lbu	a0, -9(s0)
	.loc	6 611 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:611:29
	lw	a1, -16(s0)
	.loc	6 611 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:611:11
	sll	a0, a0, a1
	.loc	6 608 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:608:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB12_4
.LBB12_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 606 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:606:3
	andi	a0, a0, 255
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 606 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:606:3
	addi	sp, sp, 32
	ret
.Ltmp318:
.Lfunc_end12:
	.size	safe_lshift_func_uint8_t_u_u, .Lfunc_end12-safe_lshift_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int8_t_s_u
	.type	safe_rshift_func_int8_t_s_u,@function
safe_rshift_func_int8_t_s_u:            # @safe_rshift_func_int8_t_s_u
.Lfunc_begin13:
	.loc	6 131 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:131:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sw	a1, -16(s0)
.Ltmp319:
	.loc	6 135 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:7
	lb	a0, -9(s0)
	.loc	6 135 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:17
	bltz	a0, .LBB13_2
	j	.LBB13_1
.LBB13_1:
	.loc	6 135 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 135 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	bltu	a0, a1, .LBB13_3
	j	.LBB13_2
.LBB13_2:
	.loc	6 136 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:136:6
	lb	a0, -9(s0)
	.loc	6 135 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB13_4
.LBB13_3:
	.loc	6 138 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:6
	lb	a0, -9(s0)
	.loc	6 138 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:29
	lw	a1, -16(s0)
	.loc	6 138 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:11
	sra	a0, a0, a1
	.loc	6 135 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB13_4
.LBB13_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 133 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:133:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 133 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:133:3
	addi	sp, sp, 32
	ret
.Ltmp320:
.Lfunc_end13:
	.size	safe_rshift_func_int8_t_s_u, .Lfunc_end13-safe_rshift_func_int8_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint32_t_u_u
	.type	safe_rshift_func_uint32_t_u_u,@function
safe_rshift_func_uint32_t_u_u:          # @safe_rshift_func_uint32_t_u_u
.Lfunc_begin14:
	.loc	6 832 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:832:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp321:
	.loc	6 836 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:21
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 836 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	bltu	a0, a1, .LBB14_2
	j	.LBB14_1
.LBB14_1:
	.loc	6 837 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:837:6
	lw	a0, -12(s0)
	.loc	6 836 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB14_3
.LBB14_2:
	.loc	6 839 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:6
	lw	a0, -12(s0)
	.loc	6 839 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:29
	lw	a1, -16(s0)
	.loc	6 839 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:11
	srl	a0, a0, a1
	.loc	6 836 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB14_3
.LBB14_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 834 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:834:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 834 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:834:3
	addi	sp, sp, 32
	ret
.Ltmp322:
.Lfunc_end14:
	.size	safe_rshift_func_uint32_t_u_u, .Lfunc_end14-safe_rshift_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int16_t_s_s
	.type	safe_add_func_int16_t_s_s,@function
safe_add_func_int16_t_s_s:              # @safe_add_func_int16_t_s_s
.Lfunc_begin15:
	.loc	6 159 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:159:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp323:
	.loc	6 168 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:168:6
	lh	a0, -10(s0)
	.loc	6 168 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:168:12
	lh	a1, -12(s0)
	.loc	6 168 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:168:10
	add	a0, a0, a1
	.loc	6 161 3 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:161:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 161 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:161:3
	addi	sp, sp, 16
	ret
.Ltmp324:
.Lfunc_end15:
	.size	safe_add_func_int16_t_s_s, .Lfunc_end15-safe_add_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint64_t_u_u
	.type	safe_sub_func_uint64_t_u_u,@function
safe_sub_func_uint64_t_u_u:             # @safe_sub_func_uint64_t_u_u
.Lfunc_begin16:
	.loc	6 861 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:861:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp325:
	.loc	6 863 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:10
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	.loc	6 863 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:16
	lw	a4, -20(s0)
	lw	a2, -24(s0)
	.loc	6 863 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:14
	sltu	a3, a0, a2
	sub	a1, a1, a4
	sub	a1, a1, a3
	sub	a0, a0, a2
	.loc	6 863 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 863 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:3
	addi	sp, sp, 32
	ret
.Ltmp326:
.Lfunc_end16:
	.size	safe_sub_func_uint64_t_u_u, .Lfunc_end16-safe_sub_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint16_t_u_u
	.type	safe_mod_func_uint16_t_u_u,@function
safe_mod_func_uint16_t_u_u:             # @safe_mod_func_uint16_t_u_u
.Lfunc_begin17:
	.loc	6 670 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:670:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp327:
	.loc	6 674 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:674:6
	lhu	a0, -12(s0)
	.loc	6 674 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:674:5
	bnez	a0, .LBB17_2
	j	.LBB17_1
.LBB17_1:
	.loc	6 675 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:675:6
	lhu	a0, -10(s0)
	.loc	6 674 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:674:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB17_3
.LBB17_2:
	.loc	6 677 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:677:6
	lhu	a0, -10(s0)
	.loc	6 677 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:677:12
	lhu	a1, -12(s0)
	.loc	6 677 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:677:10
	remu	a0, a0, a1
	.loc	6 674 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:674:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB17_3
.LBB17_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 672 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:672:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 672 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:672:3
	addi	sp, sp, 16
	ret
.Ltmp328:
.Lfunc_end17:
	.size	safe_mod_func_uint16_t_u_u, .Lfunc_end17-safe_mod_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int16_t_s_s
	.type	safe_mul_func_int16_t_s_s,@function
safe_mul_func_int16_t_s_s:              # @safe_mul_func_int16_t_s_s
.Lfunc_begin18:
	.loc	6 187 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:187:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp329:
	.loc	6 196 5 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:5
	lh	a0, -10(s0)
	.loc	6 196 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:11
	lh	a1, -12(s0)
	.loc	6 196 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:9
	mul	a0, a0, a1
	.loc	6 189 3 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:189:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 189 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:189:3
	addi	sp, sp, 16
	ret
.Ltmp330:
.Lfunc_end18:
	.size	safe_mul_func_int16_t_s_s, .Lfunc_end18-safe_mul_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int32_t_s_s
	.type	safe_mul_func_int32_t_s_s,@function
safe_mul_func_int32_t_s_s:              # @safe_mul_func_int32_t_s_s
.Lfunc_begin19:
	.loc	6 317 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:317:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp331:
	.loc	6 322 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:8
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 322 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:17
	bge	a0, a1, .LBB19_3
	j	.LBB19_1
.LBB19_1:
	.loc	6 322 21                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:21
	lw	a1, -16(s0)
	li	a0, 0
	.loc	6 322 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:30
	bge	a0, a1, .LBB19_3
	j	.LBB19_2
.LBB19_2:
	.loc	6 322 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:34
	lw	a1, -12(s0)
	.loc	6 322 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:53
	lw	a2, -16(s0)
	lui	a0, 524288
	addi	a0, a0, -1
	.loc	6 322 51                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:51
	div	a0, a0, a2
	.loc	6 322 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:60
	blt	a0, a1, .LBB19_13
	j	.LBB19_3
.LBB19_3:
	.loc	6 322 65                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:65
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 322 74                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:74
	bge	a0, a1, .LBB19_6
	j	.LBB19_4
.LBB19_4:
	.loc	6 322 78                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:78
	lw	a1, -16(s0)
	li	a0, 0
	.loc	6 322 88                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:88
	blt	a0, a1, .LBB19_6
	j	.LBB19_5
.LBB19_5:
	.loc	6 322 92                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:92
	lw	a0, -16(s0)
	.loc	6 322 111                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:111
	lw	a2, -12(s0)
	lui	a1, 524288
	.loc	6 322 109                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:109
	div	a1, a1, a2
	.loc	6 322 118                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:118
	blt	a0, a1, .LBB19_13
	j	.LBB19_6
.LBB19_6:
	.loc	6 322 123                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:123
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 322 133                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:133
	blt	a0, a1, .LBB19_9
	j	.LBB19_7
.LBB19_7:
	.loc	6 322 137                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:137
	lw	a1, -16(s0)
	li	a0, 0
	.loc	6 322 146                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:146
	bge	a0, a1, .LBB19_9
	j	.LBB19_8
.LBB19_8:
	.loc	6 322 150                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:150
	lw	a0, -12(s0)
	.loc	6 322 169                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:169
	lw	a2, -16(s0)
	lui	a1, 524288
	.loc	6 322 167                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:167
	div	a1, a1, a2
	.loc	6 322 176                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:176
	blt	a0, a1, .LBB19_13
	j	.LBB19_9
.LBB19_9:
	.loc	6 322 181                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:181
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 322 191                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:191
	blt	a0, a1, .LBB19_14
	j	.LBB19_10
.LBB19_10:
	.loc	6 322 195                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:195
	lw	a1, -16(s0)
	li	a0, 0
	.loc	6 322 205                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:205
	blt	a0, a1, .LBB19_14
	j	.LBB19_11
.LBB19_11:
	.loc	6 322 209                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:209
	lw	a0, -12(s0)
	.loc	6 322 219                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:219
	beqz	a0, .LBB19_14
	j	.LBB19_12
.LBB19_12:
	.loc	6 322 223                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:223
	lw	a0, -16(s0)
	.loc	6 322 242                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:242
	lw	a2, -12(s0)
	lui	a1, 524288
	addi	a1, a1, -1
	.loc	6 322 240                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:240
	div	a1, a1, a2
	.loc	6 322 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	bge	a0, a1, .LBB19_14
	j	.LBB19_13
.LBB19_13:
	.loc	6 323 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:323:6
	lw	a0, -12(s0)
	.loc	6 322 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB19_15
.LBB19_14:
	.loc	6 326 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:5
	lw	a0, -12(s0)
	.loc	6 326 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:11
	lw	a1, -16(s0)
	.loc	6 326 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:9
	mul	a0, a0, a1
	.loc	6 322 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB19_15
.LBB19_15:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 319 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:319:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 319 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:319:3
	addi	sp, sp, 32
	ret
.Ltmp332:
.Lfunc_end19:
	.size	safe_mul_func_int32_t_s_s, .Lfunc_end19-safe_mul_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int64_t_s_s
	.type	safe_add_func_int64_t_s_s,@function
safe_add_func_int64_t_s_s:              # @safe_add_func_int64_t_s_s
.Lfunc_begin20:
	.loc	6 420 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:420:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -64
	.cfi_def_cfa_offset 64
	sw	ra, 60(sp)                      # 4-byte Folded Spill
	sw	s0, 56(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 64
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp333:
	.loc	6 425 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:8
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	6 425 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:11
	slti	a2, a0, 0
	sw	a2, -32(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB20_2
# %bb.1:
	.loc	6 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -28(s0)                     # 4-byte Folded Spill
.LBB20_2:
	.loc	6 425 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:11
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	.loc	6 425 15                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:15
	bnez	a0, .LBB20_9
	j	.LBB20_3
.LBB20_3:
	.loc	6 425 19                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:19
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	6 425 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:22
	slti	a2, a0, 0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -36(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB20_5
# %bb.4:
	.loc	6 0 22                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:22
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -36(s0)                     # 4-byte Folded Spill
.LBB20_5:
	.loc	6 425 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:22
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	.loc	6 425 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:26
	bnez	a0, .LBB20_9
	j	.LBB20_6
.LBB20_6:
	.loc	6 425 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:30
	lw	a0, -12(s0)
	lw	a3, -16(s0)
	.loc	6 425 47                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:47
	lw	a2, -24(s0)
	lw	a1, -20(s0)
	lui	a4, 524288
	addi	a4, a4, -1
	.loc	6 425 46                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:46
	xor	a1, a1, a4
	not	a2, a2
	.loc	6 425 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:34
	sltu	a2, a2, a3
	slt	a3, a1, a0
	sw	a3, -48(s0)                     # 4-byte Folded Spill
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB20_8
# %bb.7:
	.loc	6 0 34                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:34
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB20_8:
	.loc	6 425 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:34
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	6 425 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:54
	bnez	a0, .LBB20_14
	j	.LBB20_9
.LBB20_9:
	.loc	6 425 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:59
	lw	a0, -12(s0)
	.loc	6 425 66                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:66
	bgez	a0, .LBB20_15
	j	.LBB20_10
.LBB20_10:
	.loc	6 425 70                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:70
	lw	a0, -20(s0)
	.loc	6 425 77                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:77
	bgez	a0, .LBB20_15
	j	.LBB20_11
.LBB20_11:
	.loc	6 425 81                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:81
	lw	a0, -12(s0)
	lw	a2, -16(s0)
	.loc	6 425 98                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:98
	lw	a1, -20(s0)
	lw	a4, -24(s0)
	.loc	6 425 97                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:97
	snez	a3, a4
	add	a3, a3, a1
	lui	a1, 524288
	sub	a1, a1, a3
	li	a3, 0
	sub	a3, a3, a4
	.loc	6 425 85                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:85
	sltu	a2, a2, a3
	xori	a2, a2, 1
	slt	a3, a0, a1
	xori	a3, a3, 1
	sw	a3, -56(s0)                     # 4-byte Folded Spill
	sw	a2, -52(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB20_13
# %bb.12:
	.loc	6 0 85                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:85
	lw	a0, -56(s0)                     # 4-byte Folded Reload
	sw	a0, -52(s0)                     # 4-byte Folded Spill
.LBB20_13:
	.loc	6 425 85                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:85
	lw	a0, -52(s0)                     # 4-byte Folded Reload
	.loc	6 425 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	bnez	a0, .LBB20_15
	j	.LBB20_14
.LBB20_14:
	.loc	6 426 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:426:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -64(s0)                     # 4-byte Folded Spill
	.loc	6 425 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	sw	a0, -60(s0)                     # 4-byte Folded Spill
	j	.LBB20_16
.LBB20_15:
	.loc	6 429 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:6
	lw	a2, -16(s0)
	lw	a0, -12(s0)
	.loc	6 429 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:12
	lw	a1, -24(s0)
	lw	a3, -20(s0)
	.loc	6 429 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:10
	add	a0, a0, a3
	add	a1, a1, a2
	sltu	a2, a1, a2
	add	a0, a0, a2
	sw	a1, -64(s0)                     # 4-byte Folded Spill
	.loc	6 425 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	sw	a0, -60(s0)                     # 4-byte Folded Spill
	j	.LBB20_16
.LBB20_16:
	lw	a0, -64(s0)                     # 4-byte Folded Reload
	lw	a1, -60(s0)                     # 4-byte Folded Reload
	.loc	6 422 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:422:3
	lw	ra, 60(sp)                      # 4-byte Folded Reload
	lw	s0, 56(sp)                      # 4-byte Folded Reload
	.loc	6 422 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:422:3
	addi	sp, sp, 64
	ret
.Ltmp334:
.Lfunc_end20:
	.size	safe_add_func_int64_t_s_s, .Lfunc_end20-safe_add_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_int64_t_s
	.type	safe_unary_minus_func_int64_t_s,@function
safe_unary_minus_func_int64_t_s:        # @safe_unary_minus_func_int64_t_s
.Lfunc_begin21:
	.loc	6 406 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:406:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
.Ltmp335:
	.loc	6 411 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:411:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	lui	a2, 524288
	.loc	6 411 8 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:411:8
	xor	a1, a1, a2
	or	a0, a0, a1
	.loc	6 411 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:411:5
	bnez	a0, .LBB21_2
	j	.LBB21_1
.LBB21_1:
	.loc	6 412 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:412:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -24(s0)                     # 4-byte Folded Spill
	.loc	6 411 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:411:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB21_3
.LBB21_2:
	.loc	6 415 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:415:6
	lw	a2, -12(s0)
	lw	a3, -16(s0)
	li	a0, 0
	.loc	6 415 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:415:5
	sub	a1, a0, a3
	snez	a3, a3
	add	a2, a2, a3
	sub	a0, a0, a2
	sw	a1, -24(s0)                     # 4-byte Folded Spill
	.loc	6 411 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:411:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB21_3
.LBB21_3:
	lw	a0, -24(s0)                     # 4-byte Folded Reload
	lw	a1, -20(s0)                     # 4-byte Folded Reload
	.loc	6 408 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:408:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 408 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:408:3
	addi	sp, sp, 32
	ret
.Ltmp336:
.Lfunc_end21:
	.size	safe_unary_minus_func_int64_t_s, .Lfunc_end21-safe_unary_minus_func_int64_t_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int32_t_s_u
	.type	safe_lshift_func_int32_t_s_u,@function
safe_lshift_func_int32_t_s_u:           # @safe_lshift_func_int32_t_s_u
.Lfunc_begin22:
	.loc	6 367 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:367:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp337:
	.loc	6 371 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:7
	lw	a0, -12(s0)
	.loc	6 371 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:17
	bltz	a0, .LBB22_3
	j	.LBB22_1
.LBB22_1:
	.loc	6 371 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:36
	lw	a1, -16(s0)
	li	a0, 31
	.loc	6 371 50                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:50
	bltu	a0, a1, .LBB22_3
	j	.LBB22_2
.LBB22_2:
	.loc	6 371 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:54
	lw	a1, -12(s0)
	.loc	6 371 90                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:90
	lw	a2, -16(s0)
	lui	a0, 524288
	addi	a0, a0, -1
	.loc	6 371 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:72
	srl	a0, a0, a2
	.loc	6 371 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	bge	a0, a1, .LBB22_4
	j	.LBB22_3
.LBB22_3:
	.loc	6 372 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:372:6
	lw	a0, -12(s0)
	.loc	6 371 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB22_5
.LBB22_4:
	.loc	6 374 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:6
	lw	a0, -12(s0)
	.loc	6 374 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:29
	lw	a1, -16(s0)
	.loc	6 374 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:11
	sll	a0, a0, a1
	.loc	6 371 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB22_5
.LBB22_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 369 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:369:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 369 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:369:3
	addi	sp, sp, 32
	ret
.Ltmp338:
.Lfunc_end22:
	.size	safe_lshift_func_int32_t_s_u, .Lfunc_end22-safe_lshift_func_int32_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint32_t_u_u
	.type	safe_mul_func_uint32_t_u_u,@function
safe_mul_func_uint32_t_u_u:             # @safe_mul_func_uint32_t_u_u
.Lfunc_begin23:
	.loc	6 765 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:765:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp339:
	.loc	6 767 25 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:25
	lw	a0, -12(s0)
	.loc	6 767 47 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:47
	lw	a1, -16(s0)
	.loc	6 767 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:30
	mul	a0, a0, a1
	.loc	6 767 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 767 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:3
	addi	sp, sp, 16
	ret
.Ltmp340:
.Lfunc_end23:
	.size	safe_mul_func_uint32_t_u_u, .Lfunc_end23-safe_mul_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int8_t_s_u
	.type	safe_lshift_func_int8_t_s_u,@function
safe_lshift_func_int8_t_s_u:            # @safe_lshift_func_int8_t_s_u
.Lfunc_begin24:
	.loc	6 107 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:107:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sw	a1, -16(s0)
.Ltmp341:
	.loc	6 111 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:7
	lb	a0, -9(s0)
	.loc	6 111 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:17
	bltz	a0, .LBB24_3
	j	.LBB24_1
.LBB24_1:
	.loc	6 111 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:36
	lw	a1, -16(s0)
	li	a0, 31
	.loc	6 111 50                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:50
	bltu	a0, a1, .LBB24_3
	j	.LBB24_2
.LBB24_2:
	.loc	6 111 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:54
	lb	a1, -9(s0)
	.loc	6 111 89                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:89
	lw	a2, -16(s0)
	li	a0, 127
	.loc	6 111 71                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:71
	srl	a0, a0, a2
	.loc	6 111 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	bge	a0, a1, .LBB24_4
	j	.LBB24_3
.LBB24_3:
	.loc	6 112 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:112:6
	lb	a0, -9(s0)
	.loc	6 111 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB24_5
.LBB24_4:
	.loc	6 114 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:6
	lb	a0, -9(s0)
	.loc	6 114 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:29
	lw	a1, -16(s0)
	.loc	6 114 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:11
	sll	a0, a0, a1
	.loc	6 111 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB24_5
.LBB24_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 109 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:109:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 109 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:109:3
	addi	sp, sp, 32
	ret
.Ltmp342:
.Lfunc_end24:
	.size	safe_lshift_func_int8_t_s_u, .Lfunc_end24-safe_lshift_func_int8_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int64_t_s_s
	.type	safe_sub_func_int64_t_s_s,@function
safe_sub_func_int64_t_s_s:              # @safe_sub_func_int64_t_s_s
.Lfunc_begin25:
	.loc	6 434 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:434:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp343:
	.loc	6 439 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:8
	lw	a3, -16(s0)
	lw	a1, -12(s0)
	.loc	6 439 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:12
	lw	a4, -24(s0)
	lw	a2, -20(s0)
	.loc	6 439 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:11
	xor	a0, a1, a2
	lui	a5, 524288
	.loc	6 439 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:39
	and	a5, a5, a0
	.loc	6 439 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:26
	xor	a1, a1, a5
	.loc	6 439 55                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:55
	sltu	a3, a3, a4
	sub	a1, a1, a2
	sub	a1, a1, a3
	.loc	6 439 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:60
	xor	a1, a1, a2
	.loc	6 439 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:17
	and	a0, a0, a1
	.loc	6 439 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	bgez	a0, .LBB25_2
	j	.LBB25_1
.LBB25_1:
	.loc	6 440 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:440:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	.loc	6 439 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	j	.LBB25_3
.LBB25_2:
	.loc	6 443 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	.loc	6 443 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:12
	lw	a4, -20(s0)
	lw	a2, -24(s0)
	.loc	6 443 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:10
	sltu	a3, a1, a2
	sub	a0, a0, a4
	sub	a0, a0, a3
	sub	a1, a1, a2
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	.loc	6 439 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	j	.LBB25_3
.LBB25_3:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	6 436 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:436:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 436 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:436:3
	addi	sp, sp, 32
	ret
.Ltmp344:
.Lfunc_end25:
	.size	safe_sub_func_int64_t_s_s, .Lfunc_end25-safe_sub_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int16_t_s_s
	.type	safe_div_func_int16_t_s_s,@function
safe_div_func_int16_t_s_s:              # @safe_div_func_int16_t_s_s
.Lfunc_begin26:
	.loc	6 213 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:213:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp345:
	.loc	6 217 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:7
	lh	a0, -12(s0)
	.loc	6 217 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:17
	beqz	a0, .LBB26_3
	j	.LBB26_1
.LBB26_1:
	.loc	6 217 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:22
	lh	a0, -10(s0)
	lui	a1, 1048568
	.loc	6 217 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:40
	bne	a0, a1, .LBB26_4
	j	.LBB26_2
.LBB26_2:
	.loc	6 217 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:44
	lh	a0, -12(s0)
	li	a1, -1
	.loc	6 217 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	bne	a0, a1, .LBB26_4
	j	.LBB26_3
.LBB26_3:
	.loc	6 218 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:218:6
	lh	a0, -10(s0)
	.loc	6 217 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB26_5
.LBB26_4:
	.loc	6 220 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:6
	lh	a0, -10(s0)
	.loc	6 220 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:12
	lh	a1, -12(s0)
	.loc	6 220 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:10
	div	a0, a0, a1
	.loc	6 217 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB26_5
.LBB26_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 215 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:215:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 215 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:215:3
	addi	sp, sp, 16
	ret
.Ltmp346:
.Lfunc_end26:
	.size	safe_div_func_int16_t_s_s, .Lfunc_end26-safe_div_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint64_t_u_u
	.type	safe_div_func_uint64_t_u_u,@function
safe_div_func_uint64_t_u_u:             # @safe_div_func_uint64_t_u_u
.Lfunc_begin27:
	.loc	6 887 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:887:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp347:
	.loc	6 891 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:6
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	6 891 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:10
	or	a0, a0, a1
	.loc	6 891 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	bnez	a0, .LBB27_2
	j	.LBB27_1
.LBB27_1:
	.loc	6 892 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:892:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 891 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB27_3
.LBB27_2:
	.loc	6 894 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	6 894 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	6 894 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:10
	call	__udivdi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 891 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB27_3
.LBB27_3:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	6 889 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:889:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 889 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:889:3
	addi	sp, sp, 32
	ret
.Ltmp348:
.Lfunc_end27:
	.size	safe_div_func_uint64_t_u_u, .Lfunc_end27-safe_div_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint64_t_u_u
	.type	safe_add_func_uint64_t_u_u,@function
safe_add_func_uint64_t_u_u:             # @safe_add_func_uint64_t_u_u
.Lfunc_begin28:
	.loc	6 854 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:854:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp349:
	.loc	6 856 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:10
	lw	a2, -16(s0)
	lw	a1, -12(s0)
	.loc	6 856 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:16
	lw	a0, -24(s0)
	lw	a3, -20(s0)
	.loc	6 856 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:14
	add	a1, a1, a3
	add	a0, a0, a2
	sltu	a2, a0, a2
	add	a1, a1, a2
	.loc	6 856 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 856 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:3
	addi	sp, sp, 32
	ret
.Ltmp350:
.Lfunc_end28:
	.size	safe_add_func_uint64_t_u_u, .Lfunc_end28-safe_add_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_int64_t_s_s
	.type	safe_mod_func_int64_t_s_s,@function
safe_mod_func_int64_t_s_s:              # @safe_mod_func_int64_t_s_s
.Lfunc_begin29:
	.loc	6 462 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:462:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp351:
	.loc	6 466 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:7
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	6 466 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:11
	or	a0, a0, a1
	.loc	6 466 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:17
	beqz	a0, .LBB29_3
	j	.LBB29_1
.LBB29_1:
	.loc	6 466 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:22
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	lui	a2, 524288
	.loc	6 466 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:26
	xor	a1, a1, a2
	or	a0, a0, a1
	.loc	6 466 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:40
	bnez	a0, .LBB29_4
	j	.LBB29_2
.LBB29_2:
	.loc	6 466 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:44
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	6 466 48                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:48
	and	a0, a0, a1
	li	a1, -1
	.loc	6 466 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	bne	a0, a1, .LBB29_4
	j	.LBB29_3
.LBB29_3:
	.loc	6 467 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:467:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 466 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB29_5
.LBB29_4:
	.loc	6 469 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	6 469 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	6 469 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:10
	call	__moddi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 466 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB29_5
.LBB29_5:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	6 464 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:464:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 464 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:464:3
	addi	sp, sp, 32
	ret
.Ltmp352:
.Lfunc_end29:
	.size	safe_mod_func_int64_t_s_s, .Lfunc_end29-safe_mod_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint8_t_u_u
	.type	safe_sub_func_uint8_t_u_u,@function
safe_sub_func_uint8_t_u_u:              # @safe_sub_func_uint8_t_u_u
.Lfunc_begin30:
	.loc	6 554 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:554:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp353:
	.loc	6 556 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:10
	lbu	a0, -9(s0)
	.loc	6 556 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:16
	lbu	a1, -10(s0)
	.loc	6 556 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:14
	sub	a0, a0, a1
	.loc	6 556 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 556 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:3
	addi	sp, sp, 16
	ret
.Ltmp354:
.Lfunc_end30:
	.size	safe_sub_func_uint8_t_u_u, .Lfunc_end30-safe_sub_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int32_t_s_s
	.type	safe_sub_func_int32_t_s_s,@function
safe_sub_func_int32_t_s_s:              # @safe_sub_func_int32_t_s_s
.Lfunc_begin31:
	.loc	6 303 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:303:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp355:
	.loc	6 308 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:8
	lw	a1, -12(s0)
	.loc	6 308 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:12
	lw	a2, -16(s0)
	.loc	6 308 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:11
	xor	a0, a1, a2
	lui	a3, 524288
	.loc	6 308 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:39
	and	a3, a3, a0
	.loc	6 308 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:26
	xor	a1, a1, a3
	.loc	6 308 55                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:55
	sub	a1, a1, a2
	.loc	6 308 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:60
	xor	a1, a1, a2
	.loc	6 308 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:17
	and	a0, a0, a1
	.loc	6 308 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	bgez	a0, .LBB31_2
	j	.LBB31_1
.LBB31_1:
	.loc	6 309 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:309:6
	lw	a0, -12(s0)
	.loc	6 308 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB31_3
.LBB31_2:
	.loc	6 312 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:6
	lw	a0, -12(s0)
	.loc	6 312 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:12
	lw	a1, -16(s0)
	.loc	6 312 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:10
	sub	a0, a0, a1
	.loc	6 308 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB31_3
.LBB31_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 305 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:305:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 305 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:305:3
	addi	sp, sp, 32
	ret
.Ltmp356:
.Lfunc_end31:
	.size	safe_sub_func_int32_t_s_s, .Lfunc_end31-safe_sub_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint8_t_u_u
	.type	safe_mod_func_uint8_t_u_u,@function
safe_mod_func_uint8_t_u_u:              # @safe_mod_func_uint8_t_u_u
.Lfunc_begin32:
	.loc	6 568 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:568:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp357:
	.loc	6 572 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:6
	lbu	a0, -10(s0)
	.loc	6 572 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	bnez	a0, .LBB32_2
	j	.LBB32_1
.LBB32_1:
	.loc	6 573 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:573:6
	lbu	a0, -9(s0)
	.loc	6 572 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB32_3
.LBB32_2:
	.loc	6 575 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:6
	lbu	a0, -9(s0)
	.loc	6 575 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:12
	lbu	a1, -10(s0)
	.loc	6 575 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:10
	remu	a0, a0, a1
	.loc	6 572 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB32_3
.LBB32_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 570 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:570:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 570 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:570:3
	addi	sp, sp, 16
	ret
.Ltmp358:
.Lfunc_end32:
	.size	safe_mod_func_uint8_t_u_u, .Lfunc_end32-safe_mod_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_int32_t_s
	.type	safe_unary_minus_func_int32_t_s,@function
safe_unary_minus_func_int32_t_s:        # @safe_unary_minus_func_int32_t_s
.Lfunc_begin33:
	.loc	6 275 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:275:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
.Ltmp359:
	.loc	6 280 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:6
	lw	a0, -12(s0)
	lui	a1, 524288
	.loc	6 280 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	bne	a0, a1, .LBB33_2
	j	.LBB33_1
.LBB33_1:
	.loc	6 281 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:281:6
	lw	a0, -12(s0)
	.loc	6 280 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB33_3
.LBB33_2:
	.loc	6 284 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:284:6
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 284 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:284:5
	sub	a0, a0, a1
	.loc	6 280 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB33_3
.LBB33_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 277 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:277:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 277 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:277:3
	addi	sp, sp, 16
	ret
.Ltmp360:
.Lfunc_end33:
	.size	safe_unary_minus_func_int32_t_s, .Lfunc_end33-safe_unary_minus_func_int32_t_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_int8_t_s
	.type	safe_unary_minus_func_int8_t_s,@function
safe_unary_minus_func_int8_t_s:         # @safe_unary_minus_func_int8_t_s
.Lfunc_begin34:
	.loc	6 15 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:15:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x11 killed $x10
	sb	a0, -9(s0)
.Ltmp361:
	.loc	6 24 6 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:24:6
	lbu	a1, -9(s0)
	li	a0, 0
	.loc	6 24 5 is_stmt 0                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:24:5
	sub	a0, a0, a1
	.loc	6 17 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:17:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 17 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:17:3
	addi	sp, sp, 16
	ret
.Ltmp362:
.Lfunc_end34:
	.size	safe_unary_minus_func_int8_t_s, .Lfunc_end34-safe_unary_minus_func_int8_t_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int64_t_s_u
	.type	safe_lshift_func_int64_t_s_u,@function
safe_lshift_func_int64_t_s_u:           # @safe_lshift_func_int64_t_s_u
.Lfunc_begin35:
	.loc	6 498 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:498:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -80
	.cfi_def_cfa_offset 80
	sw	ra, 76(sp)                      # 4-byte Folded Spill
	sw	s0, 72(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 80
	.cfi_def_cfa s0, 0
                                        # kill: def $x13 killed $x11
                                        # kill: def $x13 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a2, -20(s0)
.Ltmp363:
	.loc	6 502 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:7
	lw	a0, -12(s0)
	.loc	6 502 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:17
	bltz	a0, .LBB35_7
	j	.LBB35_1
.LBB35_1:
	.loc	6 502 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:36
	lw	a1, -20(s0)
	li	a0, 31
	.loc	6 502 50                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:50
	bltu	a0, a1, .LBB35_7
	j	.LBB35_2
.LBB35_2:
	.loc	6 502 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:54
	lw	a0, -12(s0)
	sw	a0, -40(s0)                     # 4-byte Folded Spill
	lw	a0, -16(s0)
	.loc	6 502 90                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:90
	sw	a0, -36(s0)                     # 4-byte Folded Spill
	lw	a0, -20(s0)
	li	a1, -1
	.loc	6 502 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:72
	srl	a1, a1, a0
	not	a3, a0
	li	a2, -2
	sll	a2, a2, a3
	or	a1, a1, a2
	lui	a2, 524288
	addi	a2, a2, -1
	srl	a2, a2, a0
	sw	a2, -32(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	sw	a1, -24(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB35_4
# %bb.3:
	.loc	6 0 72                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:72
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -24(s0)                     # 4-byte Folded Spill
.LBB35_4:
	.loc	6 502 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:72
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	lw	a3, -36(s0)                     # 4-byte Folded Reload
	lw	a4, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	lw	a2, -24(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a4
	.loc	6 502 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:59
	sltu	a2, a2, a3
	xori	a2, a2, 1
	slt	a3, a1, a0
	xori	a3, a3, 1
	sw	a3, -48(s0)                     # 4-byte Folded Spill
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB35_6
# %bb.5:
	.loc	6 0 59                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:59
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB35_6:
	.loc	6 502 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:59
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	6 502 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:5
	bnez	a0, .LBB35_8
	j	.LBB35_7
.LBB35_7:
	.loc	6 503 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:503:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	6 502 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB35_11
.LBB35_8:
	.loc	6 505 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:505:6
	lw	a2, -16(s0)
	lw	a1, -12(s0)
	.loc	6 505 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:505:29
	lw	a0, -20(s0)
	.loc	6 505 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:505:11
	sll	a1, a1, a0
	not	a4, a0
	srli	a3, a2, 1
	srl	a3, a3, a4
	or	a1, a1, a3
	sll	a2, a2, a0
	sw	a2, -68(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	sw	a0, -64(s0)                     # 4-byte Folded Spill
	sw	a1, -60(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB35_10
# %bb.9:
	.loc	6 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	sw	a0, -60(s0)                     # 4-byte Folded Spill
.LBB35_10:
	.loc	6 505 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:505:11
	lw	a2, -68(s0)                     # 4-byte Folded Reload
	lw	a1, -64(s0)                     # 4-byte Folded Reload
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a2
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	6 502 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:502:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB35_11
.LBB35_11:
	lw	a0, -56(s0)                     # 4-byte Folded Reload
	lw	a1, -52(s0)                     # 4-byte Folded Reload
	.loc	6 500 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:500:3
	lw	ra, 76(sp)                      # 4-byte Folded Reload
	lw	s0, 72(sp)                      # 4-byte Folded Reload
	.loc	6 500 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:500:3
	addi	sp, sp, 80
	ret
.Ltmp364:
.Lfunc_end35:
	.size	safe_lshift_func_int64_t_s_u, .Lfunc_end35-safe_lshift_func_int64_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int16_t_s_u
	.type	safe_rshift_func_int16_t_s_u,@function
safe_rshift_func_int16_t_s_u:           # @safe_rshift_func_int16_t_s_u
.Lfunc_begin36:
	.loc	6 261 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:261:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sw	a1, -16(s0)
.Ltmp365:
	.loc	6 265 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:7
	lh	a0, -10(s0)
	.loc	6 265 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:17
	bltz	a0, .LBB36_2
	j	.LBB36_1
.LBB36_1:
	.loc	6 265 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 265 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	bltu	a0, a1, .LBB36_3
	j	.LBB36_2
.LBB36_2:
	.loc	6 266 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:266:6
	lh	a0, -10(s0)
	.loc	6 265 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB36_4
.LBB36_3:
	.loc	6 268 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:6
	lh	a0, -10(s0)
	.loc	6 268 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:29
	lw	a1, -16(s0)
	.loc	6 268 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:11
	sra	a0, a0, a1
	.loc	6 265 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB36_4
.LBB36_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 263 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:263:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 263 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:263:3
	addi	sp, sp, 32
	ret
.Ltmp366:
.Lfunc_end36:
	.size	safe_rshift_func_int16_t_s_u, .Lfunc_end36-safe_rshift_func_int16_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint32_t_u_u
	.type	safe_div_func_uint32_t_u_u,@function
safe_div_func_uint32_t_u_u:             # @safe_div_func_uint32_t_u_u
.Lfunc_begin37:
	.loc	6 784 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:784:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp367:
	.loc	6 788 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:6
	lw	a0, -16(s0)
	.loc	6 788 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	bnez	a0, .LBB37_2
	j	.LBB37_1
.LBB37_1:
	.loc	6 789 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:789:6
	lw	a0, -12(s0)
	.loc	6 788 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB37_3
.LBB37_2:
	.loc	6 791 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:6
	lw	a0, -12(s0)
	.loc	6 791 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:12
	lw	a1, -16(s0)
	.loc	6 791 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:10
	divu	a0, a0, a1
	.loc	6 788 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB37_3
.LBB37_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 786 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:786:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 786 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:786:3
	addi	sp, sp, 32
	ret
.Ltmp368:
.Lfunc_end37:
	.size	safe_div_func_uint32_t_u_u, .Lfunc_end37-safe_div_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int8_t_s_s
	.type	safe_rshift_func_int8_t_s_s,@function
safe_rshift_func_int8_t_s_s:            # @safe_rshift_func_int8_t_s_s
.Lfunc_begin38:
	.loc	6 119 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:119:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sw	a1, -16(s0)
.Ltmp369:
	.loc	6 123 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:7
	lb	a0, -9(s0)
	.loc	6 123 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:17
	bltz	a0, .LBB38_3
	j	.LBB38_1
.LBB38_1:
	.loc	6 123 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:27
	lw	a0, -16(s0)
	.loc	6 123 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:39
	bltz	a0, .LBB38_3
	j	.LBB38_2
.LBB38_2:
	.loc	6 123 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:49
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 123 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	blt	a0, a1, .LBB38_4
	j	.LBB38_3
.LBB38_3:
	.loc	6 124 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:124:6
	lb	a0, -9(s0)
	.loc	6 123 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB38_5
.LBB38_4:
	.loc	6 126 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:6
	lb	a0, -9(s0)
	.loc	6 126 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:20
	lw	a1, -16(s0)
	.loc	6 126 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:11
	sra	a0, a0, a1
	.loc	6 123 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB38_5
.LBB38_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 121 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:121:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 121 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:121:3
	addi	sp, sp, 32
	ret
.Ltmp370:
.Lfunc_end38:
	.size	safe_rshift_func_int8_t_s_s, .Lfunc_end38-safe_rshift_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint8_t_u_u
	.type	safe_add_func_uint8_t_u_u,@function
safe_add_func_uint8_t_u_u:              # @safe_add_func_uint8_t_u_u
.Lfunc_begin39:
	.loc	6 547 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:547:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp371:
	.loc	6 549 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:10
	lbu	a0, -9(s0)
	.loc	6 549 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:16
	lbu	a1, -10(s0)
	.loc	6 549 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:14
	add	a0, a0, a1
	.loc	6 549 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 549 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:3
	addi	sp, sp, 16
	ret
.Ltmp372:
.Lfunc_end39:
	.size	safe_add_func_uint8_t_u_u, .Lfunc_end39-safe_add_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint64_t_u_u
	.type	safe_rshift_func_uint64_t_u_u,@function
safe_rshift_func_uint64_t_u_u:          # @safe_rshift_func_uint64_t_u_u
.Lfunc_begin40:
	.loc	6 935 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:935:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -48
	.cfi_def_cfa_offset 48
	sw	ra, 44(sp)                      # 4-byte Folded Spill
	sw	s0, 40(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 48
	.cfi_def_cfa s0, 0
                                        # kill: def $x13 killed $x11
                                        # kill: def $x13 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a2, -20(s0)
.Ltmp373:
	.loc	6 939 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:21
	lw	a0, -20(s0)
	li	a1, 32
	.loc	6 939 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	bltu	a0, a1, .LBB40_2
	j	.LBB40_1
.LBB40_1:
	.loc	6 940 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:940:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	6 939 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB40_5
.LBB40_2:
	.loc	6 942 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:6
	lw	a2, -12(s0)
	lw	a1, -16(s0)
	.loc	6 942 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:29
	lw	a0, -20(s0)
	.loc	6 942 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:11
	srl	a1, a1, a0
	not	a4, a0
	slli	a3, a2, 1
	sll	a3, a3, a4
	or	a1, a1, a3
	srl	a2, a2, a0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	sw	a0, -36(s0)                     # 4-byte Folded Spill
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB40_4
# %bb.3:
	.loc	6 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -32(s0)                     # 4-byte Folded Spill
.LBB40_4:
	.loc	6 942 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:11
	lw	a2, -40(s0)                     # 4-byte Folded Reload
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	lw	a1, -32(s0)                     # 4-byte Folded Reload
	srai	a0, a0, 31
	and	a0, a0, a2
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	6 939 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB40_5
.LBB40_5:
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	lw	a1, -24(s0)                     # 4-byte Folded Reload
	.loc	6 937 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:937:3
	lw	ra, 44(sp)                      # 4-byte Folded Reload
	lw	s0, 40(sp)                      # 4-byte Folded Reload
	.loc	6 937 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:937:3
	addi	sp, sp, 48
	ret
.Ltmp374:
.Lfunc_end40:
	.size	safe_rshift_func_uint64_t_u_u, .Lfunc_end40-safe_rshift_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int32_t_s_s
	.type	safe_add_func_int32_t_s_s,@function
safe_add_func_int32_t_s_s:              # @safe_add_func_int32_t_s_s
.Lfunc_begin41:
	.loc	6 289 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:289:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp375:
	.loc	6 294 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:8
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 294 15 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:15
	bge	a0, a1, .LBB41_3
	j	.LBB41_1
.LBB41_1:
	.loc	6 294 19                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:19
	lw	a1, -16(s0)
	li	a0, 0
	.loc	6 294 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:26
	bge	a0, a1, .LBB41_3
	j	.LBB41_2
.LBB41_2:
	.loc	6 294 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:30
	lw	a1, -12(s0)
	.loc	6 294 47                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:47
	lw	a0, -16(s0)
	lui	a2, 524288
	addi	a2, a2, -1
	.loc	6 294 46                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:46
	xor	a0, a0, a2
	.loc	6 294 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:54
	blt	a0, a1, .LBB41_6
	j	.LBB41_3
.LBB41_3:
	.loc	6 294 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:59
	lw	a0, -12(s0)
	.loc	6 294 66                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:66
	bgez	a0, .LBB41_7
	j	.LBB41_4
.LBB41_4:
	.loc	6 294 70                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:70
	lw	a0, -16(s0)
	.loc	6 294 77                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:77
	bgez	a0, .LBB41_7
	j	.LBB41_5
.LBB41_5:
	.loc	6 294 81                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:81
	lw	a0, -12(s0)
	.loc	6 294 98                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:98
	lw	a2, -16(s0)
	lui	a1, 524288
	.loc	6 294 97                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:97
	sub	a1, a1, a2
	.loc	6 294 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:5
	bge	a0, a1, .LBB41_7
	j	.LBB41_6
.LBB41_6:
	.loc	6 295 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:295:6
	lw	a0, -12(s0)
	.loc	6 294 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB41_8
.LBB41_7:
	.loc	6 298 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:298:6
	lw	a0, -12(s0)
	.loc	6 298 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:298:12
	lw	a1, -16(s0)
	.loc	6 298 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:298:10
	add	a0, a0, a1
	.loc	6 294 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:294:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB41_8
.LBB41_8:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 291 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:291:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 291 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:291:3
	addi	sp, sp, 32
	ret
.Ltmp376:
.Lfunc_end41:
	.size	safe_add_func_int32_t_s_s, .Lfunc_end41-safe_add_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int8_t_s_s
	.type	safe_div_func_int8_t_s_s,@function
safe_div_func_int8_t_s_s:               # @safe_div_func_int8_t_s_s
.Lfunc_begin42:
	.loc	6 83 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:83:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp377:
	.loc	6 87 7 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:7
	lb	a0, -10(s0)
	.loc	6 87 17 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:17
	beqz	a0, .LBB42_3
	j	.LBB42_1
.LBB42_1:
	.loc	6 87 22                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:22
	lb	a0, -9(s0)
	li	a1, -128
	.loc	6 87 39                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:39
	bne	a0, a1, .LBB42_4
	j	.LBB42_2
.LBB42_2:
	.loc	6 87 43                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:43
	lb	a0, -10(s0)
	li	a1, -1
	.loc	6 87 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	bne	a0, a1, .LBB42_4
	j	.LBB42_3
.LBB42_3:
	.loc	6 88 6 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:88:6
	lb	a0, -9(s0)
	.loc	6 87 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB42_5
.LBB42_4:
	.loc	6 90 6                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:6
	lb	a0, -9(s0)
	.loc	6 90 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:12
	lb	a1, -10(s0)
	.loc	6 90 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:10
	div	a0, a0, a1
	.loc	6 87 5 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB42_5
.LBB42_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 85 3                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:85:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 85 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:85:3
	addi	sp, sp, 16
	ret
.Ltmp378:
.Lfunc_end42:
	.size	safe_div_func_int8_t_s_s, .Lfunc_end42-safe_div_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint8_t_u_u
	.type	safe_div_func_uint8_t_u_u,@function
safe_div_func_uint8_t_u_u:              # @safe_div_func_uint8_t_u_u
.Lfunc_begin43:
	.loc	6 580 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:580:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp379:
	.loc	6 584 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:584:6
	lbu	a0, -10(s0)
	.loc	6 584 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:584:5
	bnez	a0, .LBB43_2
	j	.LBB43_1
.LBB43_1:
	.loc	6 585 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:585:6
	lbu	a0, -9(s0)
	.loc	6 584 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:584:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB43_3
.LBB43_2:
	.loc	6 587 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:587:6
	lbu	a0, -9(s0)
	.loc	6 587 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:587:12
	lbu	a1, -10(s0)
	.loc	6 587 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:587:10
	divu	a0, a0, a1
	.loc	6 584 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:584:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB43_3
.LBB43_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 582 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:582:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 582 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:582:3
	addi	sp, sp, 16
	ret
.Ltmp380:
.Lfunc_end43:
	.size	safe_div_func_uint8_t_u_u, .Lfunc_end43-safe_div_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_uint16_t_u_u
	.type	safe_lshift_func_uint16_t_u_u,@function
safe_lshift_func_uint16_t_u_u:          # @safe_lshift_func_uint16_t_u_u
.Lfunc_begin44:
	.loc	6 706 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:706:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sw	a1, -16(s0)
.Ltmp381:
	.loc	6 710 22 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:22
	lw	a1, -16(s0)
	li	a0, 31
	.loc	6 710 36 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:36
	bltu	a0, a1, .LBB44_2
	j	.LBB44_1
.LBB44_1:
	.loc	6 710 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:40
	lhu	a1, -10(s0)
	.loc	6 710 77                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:77
	lw	a2, -16(s0)
	lui	a0, 16
	addi	a0, a0, -1
	.loc	6 710 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:59
	srl	a0, a0, a2
	.loc	6 710 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:5
	bge	a0, a1, .LBB44_3
	j	.LBB44_2
.LBB44_2:
	.loc	6 711 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:711:6
	lhu	a0, -10(s0)
	.loc	6 710 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB44_4
.LBB44_3:
	.loc	6 713 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:713:6
	lhu	a0, -10(s0)
	.loc	6 713 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:713:29
	lw	a1, -16(s0)
	.loc	6 713 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:713:11
	sll	a0, a0, a1
	.loc	6 710 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:710:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB44_4
.LBB44_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 708 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:708:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 708 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:708:3
	addi	sp, sp, 32
	ret
.Ltmp382:
.Lfunc_end44:
	.size	safe_lshift_func_uint16_t_u_u, .Lfunc_end44-safe_lshift_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_uint32_t_u
	.type	safe_unary_minus_func_uint32_t_u,@function
safe_unary_minus_func_uint32_t_u:       # @safe_unary_minus_func_uint32_t_u
.Lfunc_begin45:
	.loc	6 744 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:744:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
.Ltmp383:
	.loc	6 746 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:746:11
	lw	a1, -12(s0)
	li	a0, 0
	.loc	6 746 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:746:10
	sub	a0, a0, a1
	.loc	6 746 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:746:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 746 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:746:3
	addi	sp, sp, 16
	ret
.Ltmp384:
.Lfunc_end45:
	.size	safe_unary_minus_func_uint32_t_u, .Lfunc_end45-safe_unary_minus_func_uint32_t_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int32_t_s_u
	.type	safe_rshift_func_int32_t_s_u,@function
safe_rshift_func_int32_t_s_u:           # @safe_rshift_func_int32_t_s_u
.Lfunc_begin46:
	.loc	6 391 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:391:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp385:
	.loc	6 395 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:7
	lw	a0, -12(s0)
	.loc	6 395 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:17
	bltz	a0, .LBB46_2
	j	.LBB46_1
.LBB46_1:
	.loc	6 395 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 395 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	bltu	a0, a1, .LBB46_3
	j	.LBB46_2
.LBB46_2:
	.loc	6 396 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:396:6
	lw	a0, -12(s0)
	.loc	6 395 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB46_4
.LBB46_3:
	.loc	6 398 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:6
	lw	a0, -12(s0)
	.loc	6 398 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:29
	lw	a1, -16(s0)
	.loc	6 398 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:11
	sra	a0, a0, a1
	.loc	6 395 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB46_4
.LBB46_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 393 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:393:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 393 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:393:3
	addi	sp, sp, 32
	ret
.Ltmp386:
.Lfunc_end46:
	.size	safe_rshift_func_int32_t_s_u, .Lfunc_end46-safe_rshift_func_int32_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int32_t_s_s
	.type	safe_rshift_func_int32_t_s_s,@function
safe_rshift_func_int32_t_s_s:           # @safe_rshift_func_int32_t_s_s
.Lfunc_begin47:
	.loc	6 379 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:379:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp387:
	.loc	6 383 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:7
	lw	a0, -12(s0)
	.loc	6 383 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:17
	bltz	a0, .LBB47_3
	j	.LBB47_1
.LBB47_1:
	.loc	6 383 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:27
	lw	a0, -16(s0)
	.loc	6 383 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:39
	bltz	a0, .LBB47_3
	j	.LBB47_2
.LBB47_2:
	.loc	6 383 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:49
	lw	a0, -16(s0)
	li	a1, 32
	.loc	6 383 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	blt	a0, a1, .LBB47_4
	j	.LBB47_3
.LBB47_3:
	.loc	6 384 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:384:6
	lw	a0, -12(s0)
	.loc	6 383 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB47_5
.LBB47_4:
	.loc	6 386 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:6
	lw	a0, -12(s0)
	.loc	6 386 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:20
	lw	a1, -16(s0)
	.loc	6 386 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:11
	sra	a0, a0, a1
	.loc	6 383 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB47_5
.LBB47_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 381 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:381:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 381 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:381:3
	addi	sp, sp, 32
	ret
.Ltmp388:
.Lfunc_end47:
	.size	safe_rshift_func_int32_t_s_s, .Lfunc_end47-safe_rshift_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint32_t_u_u
	.type	safe_mod_func_uint32_t_u_u,@function
safe_mod_func_uint32_t_u_u:             # @safe_mod_func_uint32_t_u_u
.Lfunc_begin48:
	.loc	6 772 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:772:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp389:
	.loc	6 776 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:6
	lw	a0, -16(s0)
	.loc	6 776 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	bnez	a0, .LBB48_2
	j	.LBB48_1
.LBB48_1:
	.loc	6 777 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:777:6
	lw	a0, -12(s0)
	.loc	6 776 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB48_3
.LBB48_2:
	.loc	6 779 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:6
	lw	a0, -12(s0)
	.loc	6 779 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:12
	lw	a1, -16(s0)
	.loc	6 779 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:10
	remu	a0, a0, a1
	.loc	6 776 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB48_3
.LBB48_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	6 774 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:774:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 774 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:774:3
	addi	sp, sp, 32
	ret
.Ltmp390:
.Lfunc_end48:
	.size	safe_mod_func_uint32_t_u_u, .Lfunc_end48-safe_mod_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint64_t_u_u
	.type	safe_mul_func_uint64_t_u_u,@function
safe_mul_func_uint64_t_u_u:             # @safe_mul_func_uint64_t_u_u
.Lfunc_begin49:
	.loc	6 868 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:868:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp391:
	.loc	6 870 31 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:870:31
	lw	a3, -12(s0)
	lw	a0, -16(s0)
	.loc	6 870 59 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:870:59
	lw	a2, -24(s0)
	lw	a1, -20(s0)
	.loc	6 870 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:870:36
	mul	a4, a0, a1
	mulhu	a1, a0, a2
	add	a1, a1, a4
	mul	a3, a3, a2
	add	a1, a1, a3
	mul	a0, a0, a2
	.loc	6 870 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:870:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 870 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:870:3
	addi	sp, sp, 32
	ret
.Ltmp392:
.Lfunc_end49:
	.size	safe_mul_func_uint64_t_u_u, .Lfunc_end49-safe_mul_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_int16_t_s_s
	.type	safe_mod_func_int16_t_s_s,@function
safe_mod_func_int16_t_s_s:              # @safe_mod_func_int16_t_s_s
.Lfunc_begin50:
	.loc	6 201 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:201:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp393:
	.loc	6 205 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:7
	lh	a0, -12(s0)
	.loc	6 205 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:17
	beqz	a0, .LBB50_3
	j	.LBB50_1
.LBB50_1:
	.loc	6 205 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:22
	lh	a0, -10(s0)
	lui	a1, 1048568
	.loc	6 205 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:40
	bne	a0, a1, .LBB50_4
	j	.LBB50_2
.LBB50_2:
	.loc	6 205 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:44
	lh	a0, -12(s0)
	li	a1, -1
	.loc	6 205 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:5
	bne	a0, a1, .LBB50_4
	j	.LBB50_3
.LBB50_3:
	.loc	6 206 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:206:6
	lh	a0, -10(s0)
	.loc	6 205 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB50_5
.LBB50_4:
	.loc	6 208 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:208:6
	lh	a0, -10(s0)
	.loc	6 208 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:208:12
	lh	a1, -12(s0)
	.loc	6 208 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:208:10
	rem	a0, a0, a1
	.loc	6 205 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:205:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB50_5
.LBB50_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 203 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:203:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 203 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:203:3
	addi	sp, sp, 16
	ret
.Ltmp394:
.Lfunc_end50:
	.size	safe_mod_func_int16_t_s_s, .Lfunc_end50-safe_mod_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int16_t_s_s
	.type	safe_sub_func_int16_t_s_s,@function
safe_sub_func_int16_t_s_s:              # @safe_sub_func_int16_t_s_s
.Lfunc_begin51:
	.loc	6 173 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:173:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sh	a0, -10(s0)
	sh	a1, -12(s0)
.Ltmp395:
	.loc	6 182 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:182:6
	lh	a0, -10(s0)
	.loc	6 182 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:182:12
	lh	a1, -12(s0)
	.loc	6 182 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:182:10
	sub	a0, a0, a1
	.loc	6 175 3 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:175:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 175 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:175:3
	addi	sp, sp, 16
	ret
.Ltmp396:
.Lfunc_end51:
	.size	safe_sub_func_int16_t_s_s, .Lfunc_end51-safe_sub_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int64_t_s_s
	.type	safe_div_func_int64_t_s_s,@function
safe_div_func_int64_t_s_s:              # @safe_div_func_int64_t_s_s
.Lfunc_begin52:
	.loc	6 474 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:474:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x13
                                        # kill: def $x14 killed $x12
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a3, -20(s0)
	sw	a2, -24(s0)
.Ltmp397:
	.loc	6 478 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:7
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	6 478 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:11
	or	a0, a0, a1
	.loc	6 478 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:17
	beqz	a0, .LBB52_3
	j	.LBB52_1
.LBB52_1:
	.loc	6 478 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:22
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	lui	a2, 524288
	.loc	6 478 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:26
	xor	a1, a1, a2
	or	a0, a0, a1
	.loc	6 478 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:40
	bnez	a0, .LBB52_4
	j	.LBB52_2
.LBB52_2:
	.loc	6 478 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:44
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	6 478 48                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:48
	and	a0, a0, a1
	li	a1, -1
	.loc	6 478 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	bne	a0, a1, .LBB52_4
	j	.LBB52_3
.LBB52_3:
	.loc	6 479 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:479:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 478 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB52_5
.LBB52_4:
	.loc	6 481 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	6 481 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	6 481 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:10
	call	__divdi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	6 478 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB52_5
.LBB52_5:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	6 476 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:476:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	6 476 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:476:3
	addi	sp, sp, 32
	ret
.Ltmp398:
.Lfunc_end52:
	.size	safe_div_func_int64_t_s_s, .Lfunc_end52-safe_div_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint64_t_u_s
	.type	safe_rshift_func_uint64_t_u_s,@function
safe_rshift_func_uint64_t_u_s:          # @safe_rshift_func_uint64_t_u_s
.Lfunc_begin53:
	.loc	6 923 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:923:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -48
	.cfi_def_cfa_offset 48
	sw	ra, 44(sp)                      # 4-byte Folded Spill
	sw	s0, 40(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 48
	.cfi_def_cfa s0, 0
                                        # kill: def $x13 killed $x11
                                        # kill: def $x13 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a2, -20(s0)
.Ltmp399:
	.loc	6 927 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:13
	lw	a0, -20(s0)
	.loc	6 927 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:25
	bltz	a0, .LBB53_2
	j	.LBB53_1
.LBB53_1:
	.loc	6 927 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:35
	lw	a0, -20(s0)
	li	a1, 32
	.loc	6 927 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	blt	a0, a1, .LBB53_3
	j	.LBB53_2
.LBB53_2:
	.loc	6 928 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:928:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	6 927 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB53_6
.LBB53_3:
	.loc	6 930 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:6
	lw	a2, -12(s0)
	lw	a1, -16(s0)
	.loc	6 930 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:20
	lw	a0, -20(s0)
	.loc	6 930 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:11
	srl	a1, a1, a0
	not	a4, a0
	slli	a3, a2, 1
	sll	a3, a3, a4
	or	a1, a1, a3
	srl	a2, a2, a0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	sw	a0, -36(s0)                     # 4-byte Folded Spill
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB53_5
# %bb.4:
	.loc	6 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -32(s0)                     # 4-byte Folded Spill
.LBB53_5:
	.loc	6 930 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:11
	lw	a2, -40(s0)                     # 4-byte Folded Reload
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	lw	a1, -32(s0)                     # 4-byte Folded Reload
	srai	a0, a0, 31
	and	a0, a0, a2
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	6 927 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB53_6
.LBB53_6:
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	lw	a1, -24(s0)                     # 4-byte Folded Reload
	.loc	6 925 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:925:3
	lw	ra, 44(sp)                      # 4-byte Folded Reload
	lw	s0, 40(sp)                      # 4-byte Folded Reload
	.loc	6 925 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:925:3
	addi	sp, sp, 48
	ret
.Ltmp400:
.Lfunc_end53:
	.size	safe_rshift_func_uint64_t_u_s, .Lfunc_end53-safe_rshift_func_uint64_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_int8_t_s_s
	.type	safe_mod_func_int8_t_s_s,@function
safe_mod_func_int8_t_s_s:               # @safe_mod_func_int8_t_s_s
.Lfunc_begin54:
	.loc	6 71 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:71:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sb	a0, -9(s0)
	sb	a1, -10(s0)
.Ltmp401:
	.loc	6 75 7 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:7
	lb	a0, -10(s0)
	.loc	6 75 17 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:17
	beqz	a0, .LBB54_3
	j	.LBB54_1
.LBB54_1:
	.loc	6 75 22                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:22
	lb	a0, -9(s0)
	li	a1, -128
	.loc	6 75 39                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:39
	bne	a0, a1, .LBB54_4
	j	.LBB54_2
.LBB54_2:
	.loc	6 75 43                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:43
	lb	a0, -10(s0)
	li	a1, -1
	.loc	6 75 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:5
	bne	a0, a1, .LBB54_4
	j	.LBB54_3
.LBB54_3:
	.loc	6 76 6 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:76:6
	lb	a0, -9(s0)
	.loc	6 75 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB54_5
.LBB54_4:
	.loc	6 78 6                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:78:6
	lb	a0, -9(s0)
	.loc	6 78 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:78:12
	lb	a1, -10(s0)
	.loc	6 78 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:78:10
	rem	a0, a0, a1
	.loc	6 75 5 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:75:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB54_5
.LBB54_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	6 73 3                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:73:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	6 73 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:73:3
	addi	sp, sp, 16
	ret
.Ltmp402:
.Lfunc_end54:
	.size	safe_mod_func_int8_t_s_s, .Lfunc_end54-safe_mod_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.globl	func_57                         # -- Begin function func_57
	.p2align	1
	.type	func_57,@function
func_57:                                # @func_57
.Lfunc_begin55:
	.loc	2 577 0 is_stmt 1               # rnd_output0.c:577:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -1616
	.cfi_def_cfa_offset 1616
	sw	ra, 1612(sp)                    # 4-byte Folded Spill
	sw	s0, 1608(sp)                    # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 1616
	.cfi_def_cfa s0, 0
	sw	a0, -16(s0)
	sw	a1, -20(s0)
	sw	a2, -24(s0)
	sw	a3, -28(s0)
	sw	a4, -32(s0)
.Ltmp403:
	.loc	2 578 15 prologue_end           # rnd_output0.c:578:15
	lui	a0, %hi(.L__const.func_57.l_74)
	addi	a1, a0, %lo(.L__const.func_57.l_74)
	addi	a0, s0, -1012
	li	a2, 980
	call	memcpy@plt
	li	a0, 0
	.loc	2 579 21                        # rnd_output0.c:579:21
	sw	a0, -1616(s0)                   # 4-byte Folded Spill
	sw	a0, -1016(s0)
	.loc	2 580 15                        # rnd_output0.c:580:15
	lui	a1, %hi(g_89)
	addi	a1, a1, %lo(g_89)
	sw	a1, -1020(s0)
	.loc	2 581 14                        # rnd_output0.c:581:14
	sw	a0, -1024(s0)
	.loc	2 582 14                        # rnd_output0.c:582:14
	lui	a1, %hi(g_133)
	addi	a1, a1, %lo(g_133)
	addi	a1, a1, 288
	sw	a1, -1028(s0)
	.loc	2 583 13                        # rnd_output0.c:583:13
	lui	a1, %hi(g_197)
	addi	a1, a1, %lo(g_197)
	addi	a1, a1, 16
	sw	a1, -1032(s0)
	.loc	2 584 14                        # rnd_output0.c:584:14
	sw	a0, -1036(s0)
	.loc	2 585 21                        # rnd_output0.c:585:21
	sw	a0, -1044(s0)
	sw	a0, -1048(s0)
	lui	a1, 770085
	addi	a1, a1, -899
	sw	a1, -1052(s0)
	lui	a1, 974259
	addi	a1, a1, -1564
	sw	a1, -1056(s0)
	lui	a1, 682997
	addi	a1, a1, -529
	.loc	2 586 13                        # rnd_output0.c:586:13
	sw	a1, -1060(s0)
	li	a1, 3
	.loc	2 587 13                        # rnd_output0.c:587:13
	sw	a1, -1064(s0)
	.loc	2 588 13                        # rnd_output0.c:588:13
	sw	a0, -1068(s0)
	lui	a0, 925483
	addi	a0, a0, -896
	.loc	2 589 13                        # rnd_output0.c:589:13
	sw	a0, -1072(s0)
	li	a0, -4
	.loc	2 590 13                        # rnd_output0.c:590:13
	sw	a0, -1076(s0)
	li	a0, -5
	.loc	2 591 13                        # rnd_output0.c:591:13
	sw	a0, -1080(s0)
	.loc	2 593 13                        # rnd_output0.c:593:13
	lui	a0, %hi(.L__const.func_57.l_219)
	addi	a1, a0, %lo(.L__const.func_57.l_219)
	addi	a0, s0, -1576
	li	a2, 480
	call	memcpy@plt
                                        # kill: def $x11 killed $x10
	lw	a0, -1616(s0)                   # 4-byte Folded Reload
	lui	a1, 138985
	addi	a1, a1, -1291
	.loc	2 594 14                        # rnd_output0.c:594:14
	sw	a1, -1580(s0)
	lui	a1, 4
	addi	a1, a1, -1701
	.loc	2 595 13                        # rnd_output0.c:595:13
	sh	a1, -1582(s0)
	lui	a1, 758737
	addi	a1, a1, 156
	.loc	2 596 14                        # rnd_output0.c:596:14
	sw	a1, -1588(s0)
	lui	a1, 355321
	addi	a1, a1, 16
	sw	a1, -1592(s0)
	.loc	2 597 21                        # rnd_output0.c:597:21
	lui	a1, %hi(g_136)
	addi	a1, a1, %lo(g_136)
	addi	a1, a1, 28
	sw	a1, -1596(s0)
	.loc	2 598 21                        # rnd_output0.c:598:21
	lui	a1, %hi(g_294)
	addi	a1, a1, %lo(g_294)
	sw	a1, -1600(s0)
.Ltmp404:
	.loc	2 600 12                        # rnd_output0.c:600:12
	sw	a0, -1604(s0)
	.loc	2 600 10 is_stmt 0              # rnd_output0.c:600:10
	j	.LBB55_1
.LBB55_1:                               # =>This Inner Loop Header: Depth=1
.Ltmp405:
	.loc	2 600 17                        # rnd_output0.c:600:17
	lw	a1, -1604(s0)
	li	a0, 2
.Ltmp406:
	.loc	2 600 5                         # rnd_output0.c:600:5
	blt	a0, a1, .LBB55_4
	j	.LBB55_2
.LBB55_2:                               #   in Loop: Header=BB55_1 Depth=1
.Ltmp407:
	.loc	2 601 15 is_stmt 1              # rnd_output0.c:601:15
	lw	a0, -1604(s0)
	.loc	2 601 9 is_stmt 0               # rnd_output0.c:601:9
	slli	a1, a0, 2
	addi	a0, s0, -1092
	add	a1, a1, a0
	lui	a0, 510852
	addi	a0, a0, -1586
	.loc	2 601 18                        # rnd_output0.c:601:18
	sw	a0, 0(a1)
	.loc	2 601 9                         # rnd_output0.c:601:9
	j	.LBB55_3
.LBB55_3:                               #   in Loop: Header=BB55_1 Depth=1
	.loc	2 600 25 is_stmt 1              # rnd_output0.c:600:25
	lw	a0, -1604(s0)
	addi	a0, a0, 1
	sw	a0, -1604(s0)
	.loc	2 600 5 is_stmt 0               # rnd_output0.c:600:5
	j	.LBB55_1
.Ltmp408:
.LBB55_4:
	.loc	2 602 19 is_stmt 1              # rnd_output0.c:602:19
	lui	a0, %hi(g_70)
	addi	a0, a0, %lo(g_70)
	addi	a0, a0, 80
	sw	a0, -932(s0)
	.loc	2 603 14                        # rnd_output0.c:603:14
	lui	a0, %hi(g_92)
	lw	a0, %lo(g_92)(a0)
	.loc	2 603 13 is_stmt 0              # rnd_output0.c:603:13
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 603 5                         # rnd_output0.c:603:5
	lw	ra, 1612(sp)                    # 4-byte Folded Reload
	lw	s0, 1608(sp)                    # 4-byte Folded Reload
	.loc	2 603 5 epilogue_begin          # rnd_output0.c:603:5
	addi	sp, sp, 1616
	ret
.Ltmp409:
.Lfunc_end55:
	.size	func_57, .Lfunc_end55-func_57
	.cfi_endproc
                                        # -- End function
	.globl	main                            # -- Begin function main
	.p2align	1
	.type	main,@function
main:                                   # @main
.Lfunc_begin56:
	.loc	2 609 0 is_stmt 1               # rnd_output0.c:609:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -96
	.cfi_def_cfa_offset 96
	sw	ra, 92(sp)                      # 4-byte Folded Spill
	sw	s0, 88(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 96
	.cfi_def_cfa s0, 0
	mv	a2, a0
	li	a0, 0
	sw	a0, -12(s0)
	sw	a2, -16(s0)
	sw	a1, -20(s0)
.Ltmp410:
	.loc	2 611 9 prologue_end            # rnd_output0.c:611:9
	sw	a0, -36(s0)
.Ltmp411:
	.loc	2 612 9                         # rnd_output0.c:612:9
	lw	a0, -16(s0)
	li	a1, 2
	.loc	2 612 19 is_stmt 0              # rnd_output0.c:612:19
	bne	a0, a1, .LBB56_3
	j	.LBB56_1
.LBB56_1:
	.loc	2 612 29                        # rnd_output0.c:612:29
	lw	a0, -20(s0)
	lw	a0, 4(a0)
	.loc	2 612 22                        # rnd_output0.c:612:22
	lui	a1, %hi(.L.str)
	addi	a1, a1, %lo(.L.str)
	call	strcmp
.Ltmp412:
	.loc	2 612 9                         # rnd_output0.c:612:9
	bnez	a0, .LBB56_3
	j	.LBB56_2
.LBB56_2:
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 1
.Ltmp413:
	.loc	2 612 66                        # rnd_output0.c:612:66
	sw	a0, -36(s0)
	.loc	2 612 49                        # rnd_output0.c:612:49
	j	.LBB56_3
.Ltmp414:
.LBB56_3:
	.loc	2 613 5 is_stmt 1               # rnd_output0.c:613:5
	call	platform_main_begin
	.loc	2 614 5                         # rnd_output0.c:614:5
	call	crc32_gentab
	.loc	2 615 5                         # rnd_output0.c:615:5
	call	func_1
	li	a0, 0
.Ltmp415:
	.loc	2 616 12                        # rnd_output0.c:616:12
	sw	a0, -24(s0)
	.loc	2 616 10 is_stmt 0              # rnd_output0.c:616:10
	j	.LBB56_4
.LBB56_4:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_6 Depth 2
                                        #       Child Loop BB56_8 Depth 3
.Ltmp416:
	.loc	2 616 17                        # rnd_output0.c:616:17
	lw	a1, -24(s0)
	li	a0, 0
.Ltmp417:
	.loc	2 616 5                         # rnd_output0.c:616:5
	blt	a0, a1, .LBB56_17
	j	.LBB56_5
.LBB56_5:                               #   in Loop: Header=BB56_4 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp418:
	.loc	2 618 16 is_stmt 1              # rnd_output0.c:618:16
	sw	a0, -28(s0)
	.loc	2 618 14 is_stmt 0              # rnd_output0.c:618:14
	j	.LBB56_6
.LBB56_6:                               #   Parent Loop BB56_4 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB56_8 Depth 3
.Ltmp419:
	.loc	2 618 21                        # rnd_output0.c:618:21
	lw	a1, -28(s0)
	li	a0, 9
.Ltmp420:
	.loc	2 618 9                         # rnd_output0.c:618:9
	blt	a0, a1, .LBB56_15
	j	.LBB56_7
.LBB56_7:                               #   in Loop: Header=BB56_6 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 0
.Ltmp421:
	.loc	2 620 20 is_stmt 1              # rnd_output0.c:620:20
	sw	a0, -32(s0)
	.loc	2 620 18 is_stmt 0              # rnd_output0.c:620:18
	j	.LBB56_8
.LBB56_8:                               #   Parent Loop BB56_4 Depth=1
                                        #     Parent Loop BB56_6 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp422:
	.loc	2 620 25                        # rnd_output0.c:620:25
	lw	a1, -32(s0)
	li	a0, 6
.Ltmp423:
	.loc	2 620 13                        # rnd_output0.c:620:13
	blt	a0, a1, .LBB56_13
	j	.LBB56_9
.LBB56_9:                               #   in Loop: Header=BB56_8 Depth=3
.Ltmp424:
	.loc	2 622 37 is_stmt 1              # rnd_output0.c:622:37
	lw	a0, -24(s0)
	li	a1, 280
	.loc	2 622 33 is_stmt 0              # rnd_output0.c:622:33
	mul	a1, a0, a1
	lui	a0, %hi(g_2)
	addi	a0, a0, %lo(g_2)
	add	a0, a0, a1
	.loc	2 622 40                        # rnd_output0.c:622:40
	lw	a1, -28(s0)
	li	a2, 28
	.loc	2 622 33                        # rnd_output0.c:622:33
	mul	a1, a1, a2
	add	a0, a0, a1
	.loc	2 622 43                        # rnd_output0.c:622:43
	lw	a1, -32(s0)
	.loc	2 622 33                        # rnd_output0.c:622:33
	slli	a1, a1, 2
	add	a0, a0, a1
	lw	a0, 0(a0)
	srai	a1, a0, 31
	.loc	2 622 63                        # rnd_output0.c:622:63
	lw	a3, -36(s0)
	.loc	2 622 17                        # rnd_output0.c:622:17
	lui	a2, %hi(.L.str.8)
	addi	a2, a2, %lo(.L.str.8)
	call	transparent_crc
.Ltmp425:
	.loc	2 623 21 is_stmt 1              # rnd_output0.c:623:21
	lw	a0, -36(s0)
.Ltmp426:
	.loc	2 623 21 is_stmt 0              # rnd_output0.c:623:21
	beqz	a0, .LBB56_11
	j	.LBB56_10
.LBB56_10:                              #   in Loop: Header=BB56_8 Depth=3
.Ltmp427:
	.loc	2 623 72                        # rnd_output0.c:623:72
	lw	a1, -24(s0)
	.loc	2 623 75                        # rnd_output0.c:623:75
	lw	a2, -28(s0)
	.loc	2 623 78                        # rnd_output0.c:623:78
	lw	a3, -32(s0)
	.loc	2 623 39                        # rnd_output0.c:623:39
	lui	a0, %hi(.L.str.9)
	addi	a0, a0, %lo(.L.str.9)
	call	printf
	j	.LBB56_11
.Ltmp428:
.LBB56_11:                              #   in Loop: Header=BB56_8 Depth=3
	.loc	2 625 13 is_stmt 1              # rnd_output0.c:625:13
	j	.LBB56_12
.Ltmp429:
.LBB56_12:                              #   in Loop: Header=BB56_8 Depth=3
	.loc	2 620 33                        # rnd_output0.c:620:33
	lw	a0, -32(s0)
	addi	a0, a0, 1
	sw	a0, -32(s0)
	.loc	2 620 13 is_stmt 0              # rnd_output0.c:620:13
	j	.LBB56_8
.Ltmp430:
.LBB56_13:                              #   in Loop: Header=BB56_6 Depth=2
	.loc	2 626 9 is_stmt 1               # rnd_output0.c:626:9
	j	.LBB56_14
.Ltmp431:
.LBB56_14:                              #   in Loop: Header=BB56_6 Depth=2
	.loc	2 618 30                        # rnd_output0.c:618:30
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 618 9 is_stmt 0               # rnd_output0.c:618:9
	j	.LBB56_6
.Ltmp432:
.LBB56_15:                              #   in Loop: Header=BB56_4 Depth=1
	.loc	2 627 5 is_stmt 1               # rnd_output0.c:627:5
	j	.LBB56_16
.Ltmp433:
.LBB56_16:                              #   in Loop: Header=BB56_4 Depth=1
	.loc	2 616 25                        # rnd_output0.c:616:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 616 5 is_stmt 0               # rnd_output0.c:616:5
	j	.LBB56_4
.Ltmp434:
.LBB56_17:
	.loc	2 628 21 is_stmt 1              # rnd_output0.c:628:21
	lui	a0, %hi(g_3)
	lw	a0, %lo(g_3)(a0)
	srai	a1, a0, 31
	.loc	2 628 33 is_stmt 0              # rnd_output0.c:628:33
	lw	a3, -36(s0)
	.loc	2 628 5                         # rnd_output0.c:628:5
	lui	a2, %hi(.L.str.10)
	addi	a2, a2, %lo(.L.str.10)
	call	transparent_crc
	.loc	2 629 21 is_stmt 1              # rnd_output0.c:629:21
	lui	a0, %hi(g_6)
	lw	a0, %lo(g_6)(a0)
	srai	a1, a0, 31
	.loc	2 629 33 is_stmt 0              # rnd_output0.c:629:33
	lw	a3, -36(s0)
	.loc	2 629 5                         # rnd_output0.c:629:5
	lui	a2, %hi(.L.str.11)
	addi	a2, a2, %lo(.L.str.11)
	call	transparent_crc
	.loc	2 630 21 is_stmt 1              # rnd_output0.c:630:21
	lui	a0, %hi(g_7)
	lw	a0, %lo(g_7)(a0)
	srai	a1, a0, 31
	.loc	2 630 33 is_stmt 0              # rnd_output0.c:630:33
	lw	a3, -36(s0)
	.loc	2 630 5                         # rnd_output0.c:630:5
	lui	a2, %hi(.L.str.12)
	addi	a2, a2, %lo(.L.str.12)
	call	transparent_crc
	li	a0, 0
.Ltmp435:
	.loc	2 631 12 is_stmt 1              # rnd_output0.c:631:12
	sw	a0, -24(s0)
	.loc	2 631 10 is_stmt 0              # rnd_output0.c:631:10
	j	.LBB56_18
.LBB56_18:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_20 Depth 2
                                        #       Child Loop BB56_22 Depth 3
.Ltmp436:
	.loc	2 631 17                        # rnd_output0.c:631:17
	lw	a1, -24(s0)
	li	a0, 7
.Ltmp437:
	.loc	2 631 5                         # rnd_output0.c:631:5
	blt	a0, a1, .LBB56_31
	j	.LBB56_19
.LBB56_19:                              #   in Loop: Header=BB56_18 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp438:
	.loc	2 633 16 is_stmt 1              # rnd_output0.c:633:16
	sw	a0, -28(s0)
	.loc	2 633 14 is_stmt 0              # rnd_output0.c:633:14
	j	.LBB56_20
.LBB56_20:                              #   Parent Loop BB56_18 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB56_22 Depth 3
.Ltmp439:
	.loc	2 633 21                        # rnd_output0.c:633:21
	lw	a1, -28(s0)
	li	a0, 5
.Ltmp440:
	.loc	2 633 9                         # rnd_output0.c:633:9
	blt	a0, a1, .LBB56_29
	j	.LBB56_21
.LBB56_21:                              #   in Loop: Header=BB56_20 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 0
.Ltmp441:
	.loc	2 635 20 is_stmt 1              # rnd_output0.c:635:20
	sw	a0, -32(s0)
	.loc	2 635 18 is_stmt 0              # rnd_output0.c:635:18
	j	.LBB56_22
.LBB56_22:                              #   Parent Loop BB56_18 Depth=1
                                        #     Parent Loop BB56_20 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp442:
	.loc	2 635 25                        # rnd_output0.c:635:25
	lw	a1, -32(s0)
	li	a0, 4
.Ltmp443:
	.loc	2 635 13                        # rnd_output0.c:635:13
	blt	a0, a1, .LBB56_27
	j	.LBB56_23
.LBB56_23:                              #   in Loop: Header=BB56_22 Depth=3
.Ltmp444:
	.loc	2 637 37 is_stmt 1              # rnd_output0.c:637:37
	lw	a0, -24(s0)
	li	a1, 120
	.loc	2 637 33 is_stmt 0              # rnd_output0.c:637:33
	mul	a1, a0, a1
	lui	a0, %hi(g_8)
	addi	a0, a0, %lo(g_8)
	add	a0, a0, a1
	.loc	2 637 40                        # rnd_output0.c:637:40
	lw	a1, -28(s0)
	li	a2, 20
	.loc	2 637 33                        # rnd_output0.c:637:33
	mul	a1, a1, a2
	add	a0, a0, a1
	.loc	2 637 43                        # rnd_output0.c:637:43
	lw	a1, -32(s0)
	.loc	2 637 33                        # rnd_output0.c:637:33
	slli	a1, a1, 2
	add	a0, a0, a1
	lw	a0, 0(a0)
	srai	a1, a0, 31
	.loc	2 637 63                        # rnd_output0.c:637:63
	lw	a3, -36(s0)
	.loc	2 637 17                        # rnd_output0.c:637:17
	lui	a2, %hi(.L.str.13)
	addi	a2, a2, %lo(.L.str.13)
	call	transparent_crc
.Ltmp445:
	.loc	2 638 21 is_stmt 1              # rnd_output0.c:638:21
	lw	a0, -36(s0)
.Ltmp446:
	.loc	2 638 21 is_stmt 0              # rnd_output0.c:638:21
	beqz	a0, .LBB56_25
	j	.LBB56_24
.LBB56_24:                              #   in Loop: Header=BB56_22 Depth=3
.Ltmp447:
	.loc	2 638 72                        # rnd_output0.c:638:72
	lw	a1, -24(s0)
	.loc	2 638 75                        # rnd_output0.c:638:75
	lw	a2, -28(s0)
	.loc	2 638 78                        # rnd_output0.c:638:78
	lw	a3, -32(s0)
	.loc	2 638 39                        # rnd_output0.c:638:39
	lui	a0, %hi(.L.str.9)
	addi	a0, a0, %lo(.L.str.9)
	call	printf
	j	.LBB56_25
.Ltmp448:
.LBB56_25:                              #   in Loop: Header=BB56_22 Depth=3
	.loc	2 640 13 is_stmt 1              # rnd_output0.c:640:13
	j	.LBB56_26
.Ltmp449:
.LBB56_26:                              #   in Loop: Header=BB56_22 Depth=3
	.loc	2 635 33                        # rnd_output0.c:635:33
	lw	a0, -32(s0)
	addi	a0, a0, 1
	sw	a0, -32(s0)
	.loc	2 635 13 is_stmt 0              # rnd_output0.c:635:13
	j	.LBB56_22
.Ltmp450:
.LBB56_27:                              #   in Loop: Header=BB56_20 Depth=2
	.loc	2 641 9 is_stmt 1               # rnd_output0.c:641:9
	j	.LBB56_28
.Ltmp451:
.LBB56_28:                              #   in Loop: Header=BB56_20 Depth=2
	.loc	2 633 29                        # rnd_output0.c:633:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 633 9 is_stmt 0               # rnd_output0.c:633:9
	j	.LBB56_20
.Ltmp452:
.LBB56_29:                              #   in Loop: Header=BB56_18 Depth=1
	.loc	2 642 5 is_stmt 1               # rnd_output0.c:642:5
	j	.LBB56_30
.Ltmp453:
.LBB56_30:                              #   in Loop: Header=BB56_18 Depth=1
	.loc	2 631 25                        # rnd_output0.c:631:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 631 5 is_stmt 0               # rnd_output0.c:631:5
	j	.LBB56_18
.Ltmp454:
.LBB56_31:
	.loc	2 643 21 is_stmt 1              # rnd_output0.c:643:21
	lui	a0, %hi(g_13)
	lw	a0, %lo(g_13)(a0)
	srai	a1, a0, 31
	.loc	2 643 35 is_stmt 0              # rnd_output0.c:643:35
	lw	a3, -36(s0)
	.loc	2 643 5                         # rnd_output0.c:643:5
	lui	a2, %hi(.L.str.14)
	addi	a2, a2, %lo(.L.str.14)
	call	transparent_crc
	li	a0, 0
.Ltmp455:
	.loc	2 644 12 is_stmt 1              # rnd_output0.c:644:12
	sw	a0, -24(s0)
	.loc	2 644 10 is_stmt 0              # rnd_output0.c:644:10
	j	.LBB56_32
.LBB56_32:                              # =>This Inner Loop Header: Depth=1
.Ltmp456:
	.loc	2 644 17                        # rnd_output0.c:644:17
	lw	a1, -24(s0)
	li	a0, 7
.Ltmp457:
	.loc	2 644 5                         # rnd_output0.c:644:5
	blt	a0, a1, .LBB56_37
	j	.LBB56_33
.LBB56_33:                              #   in Loop: Header=BB56_32 Depth=1
.Ltmp458:
	.loc	2 646 30 is_stmt 1              # rnd_output0.c:646:30
	lw	a0, -24(s0)
	.loc	2 646 25 is_stmt 0              # rnd_output0.c:646:25
	slli	a1, a0, 4
	lui	a0, %hi(g_69)
	addi	a0, a0, %lo(g_69)
	sw	a0, -40(s0)                     # 4-byte Folded Spill
	add	a0, a0, a1
	.loc	2 646 33                        # rnd_output0.c:646:33
	lw	a0, 0(a0)
	srai	a1, a0, 31
	.loc	2 646 51                        # rnd_output0.c:646:51
	lw	a3, -36(s0)
	.loc	2 646 9                         # rnd_output0.c:646:9
	lui	a2, %hi(.L.str.15)
	addi	a2, a2, %lo(.L.str.15)
	call	transparent_crc
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	.loc	2 647 30 is_stmt 1              # rnd_output0.c:647:30
	lw	a1, -24(s0)
	.loc	2 647 25 is_stmt 0              # rnd_output0.c:647:25
	slli	a1, a1, 4
	add	a0, a0, a1
	.loc	2 647 33                        # rnd_output0.c:647:33
	lw	a0, 4(a0)
	.loc	2 647 51                        # rnd_output0.c:647:51
	lw	a3, -36(s0)
	.loc	2 647 9                         # rnd_output0.c:647:9
	lui	a1, %hi(.L.str.16)
	addi	a2, a1, %lo(.L.str.16)
	li	a1, 0
	call	transparent_crc
.Ltmp459:
	.loc	2 648 13 is_stmt 1              # rnd_output0.c:648:13
	lw	a0, -36(s0)
.Ltmp460:
	.loc	2 648 13 is_stmt 0              # rnd_output0.c:648:13
	beqz	a0, .LBB56_35
	j	.LBB56_34
.LBB56_34:                              #   in Loop: Header=BB56_32 Depth=1
.Ltmp461:
	.loc	2 648 56                        # rnd_output0.c:648:56
	lw	a1, -24(s0)
	.loc	2 648 31                        # rnd_output0.c:648:31
	lui	a0, %hi(.L.str.17)
	addi	a0, a0, %lo(.L.str.17)
	call	printf
	j	.LBB56_35
.Ltmp462:
.LBB56_35:                              #   in Loop: Header=BB56_32 Depth=1
	.loc	2 650 5 is_stmt 1               # rnd_output0.c:650:5
	j	.LBB56_36
.Ltmp463:
.LBB56_36:                              #   in Loop: Header=BB56_32 Depth=1
	.loc	2 644 25                        # rnd_output0.c:644:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 644 5 is_stmt 0               # rnd_output0.c:644:5
	j	.LBB56_32
.Ltmp464:
.LBB56_37:
	.loc	2 651 21 is_stmt 1              # rnd_output0.c:651:21
	lui	a0, %hi(g_89)
	lhu	a0, %lo(g_89)(a0)
	.loc	2 651 35 is_stmt 0              # rnd_output0.c:651:35
	lw	a3, -36(s0)
	.loc	2 651 5                         # rnd_output0.c:651:5
	lui	a1, %hi(.L.str.18)
	addi	a2, a1, %lo(.L.str.18)
	li	a1, 0
	sw	a1, -44(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	.loc	2 652 21 is_stmt 1              # rnd_output0.c:652:21
	lui	a0, %hi(g_93)
	lw	a1, %lo(g_93+4)(a0)
	lw	a0, %lo(g_93)(a0)
	.loc	2 652 35 is_stmt 0              # rnd_output0.c:652:35
	lw	a3, -36(s0)
	.loc	2 652 5                         # rnd_output0.c:652:5
	lui	a2, %hi(.L.str.19)
	addi	a2, a2, %lo(.L.str.19)
	call	transparent_crc
	.loc	2 653 21 is_stmt 1              # rnd_output0.c:653:21
	lui	a0, %hi(g_111)
	lh	a0, %lo(g_111)(a0)
	srai	a1, a0, 31
	.loc	2 653 37 is_stmt 0              # rnd_output0.c:653:37
	lw	a3, -36(s0)
	.loc	2 653 5                         # rnd_output0.c:653:5
	lui	a2, %hi(.L.str.20)
	addi	a2, a2, %lo(.L.str.20)
	call	transparent_crc
	.loc	2 654 21 is_stmt 1              # rnd_output0.c:654:21
	lui	a0, %hi(g_116)
	lw	a0, %lo(g_116)(a0)
	srai	a1, a0, 31
	.loc	2 654 37 is_stmt 0              # rnd_output0.c:654:37
	lw	a3, -36(s0)
	.loc	2 654 5                         # rnd_output0.c:654:5
	lui	a2, %hi(.L.str.21)
	addi	a2, a2, %lo(.L.str.21)
	call	transparent_crc
	lw	a1, -44(s0)                     # 4-byte Folded Reload
	.loc	2 655 21 is_stmt 1              # rnd_output0.c:655:21
	lui	a0, %hi(g_117)
	lw	a0, %lo(g_117)(a0)
	.loc	2 655 37 is_stmt 0              # rnd_output0.c:655:37
	lw	a3, -36(s0)
	.loc	2 655 5                         # rnd_output0.c:655:5
	lui	a2, %hi(.L.str.22)
	addi	a2, a2, %lo(.L.str.22)
	call	transparent_crc
	.loc	2 656 21 is_stmt 1              # rnd_output0.c:656:21
	lui	a0, %hi(g_123)
	lw	a1, %lo(g_123+4)(a0)
	lw	a0, %lo(g_123)(a0)
	.loc	2 656 37 is_stmt 0              # rnd_output0.c:656:37
	lw	a3, -36(s0)
	.loc	2 656 5                         # rnd_output0.c:656:5
	lui	a2, %hi(.L.str.23)
	addi	a2, a2, %lo(.L.str.23)
	call	transparent_crc
	lw	a1, -44(s0)                     # 4-byte Folded Reload
	.loc	2 657 27 is_stmt 1              # rnd_output0.c:657:27
	lui	a0, %hi(g_124)
	lw	a0, %lo(g_124)(a0)
	.loc	2 657 43 is_stmt 0              # rnd_output0.c:657:43
	lw	a3, -36(s0)
	.loc	2 657 5                         # rnd_output0.c:657:5
	lui	a2, %hi(.L.str.24)
	addi	a2, a2, %lo(.L.str.24)
	call	transparent_crc
	lw	a0, -44(s0)                     # 4-byte Folded Reload
.Ltmp465:
	.loc	2 658 12 is_stmt 1              # rnd_output0.c:658:12
	sw	a0, -24(s0)
	.loc	2 658 10 is_stmt 0              # rnd_output0.c:658:10
	j	.LBB56_38
.LBB56_38:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_40 Depth 2
                                        #       Child Loop BB56_42 Depth 3
.Ltmp466:
	.loc	2 658 17                        # rnd_output0.c:658:17
	lw	a1, -24(s0)
	li	a0, 9
.Ltmp467:
	.loc	2 658 5                         # rnd_output0.c:658:5
	blt	a0, a1, .LBB56_51
	j	.LBB56_39
.LBB56_39:                              #   in Loop: Header=BB56_38 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp468:
	.loc	2 660 16 is_stmt 1              # rnd_output0.c:660:16
	sw	a0, -28(s0)
	.loc	2 660 14 is_stmt 0              # rnd_output0.c:660:14
	j	.LBB56_40
.LBB56_40:                              #   Parent Loop BB56_38 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB56_42 Depth 3
.Ltmp469:
	.loc	2 660 21                        # rnd_output0.c:660:21
	lw	a1, -28(s0)
	li	a0, 5
.Ltmp470:
	.loc	2 660 9                         # rnd_output0.c:660:9
	blt	a0, a1, .LBB56_49
	j	.LBB56_41
.LBB56_41:                              #   in Loop: Header=BB56_40 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 0
.Ltmp471:
	.loc	2 662 20 is_stmt 1              # rnd_output0.c:662:20
	sw	a0, -32(s0)
	.loc	2 662 18 is_stmt 0              # rnd_output0.c:662:18
	j	.LBB56_42
.LBB56_42:                              #   Parent Loop BB56_38 Depth=1
                                        #     Parent Loop BB56_40 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp472:
	.loc	2 662 25                        # rnd_output0.c:662:25
	lw	a1, -32(s0)
	li	a0, 3
.Ltmp473:
	.loc	2 662 13                        # rnd_output0.c:662:13
	blt	a0, a1, .LBB56_47
	j	.LBB56_43
.LBB56_43:                              #   in Loop: Header=BB56_42 Depth=3
.Ltmp474:
	.loc	2 664 39 is_stmt 1              # rnd_output0.c:664:39
	lw	a0, -24(s0)
	li	a1, 192
	.loc	2 664 33 is_stmt 0              # rnd_output0.c:664:33
	mul	a1, a0, a1
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	add	a0, a0, a1
	.loc	2 664 42                        # rnd_output0.c:664:42
	lw	a1, -28(s0)
	.loc	2 664 33                        # rnd_output0.c:664:33
	slli	a1, a1, 5
	add	a0, a0, a1
	.loc	2 664 45                        # rnd_output0.c:664:45
	lw	a1, -32(s0)
	.loc	2 664 33                        # rnd_output0.c:664:33
	slli	a1, a1, 3
	add	a0, a0, a1
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 664 67                        # rnd_output0.c:664:67
	lw	a3, -36(s0)
	.loc	2 664 17                        # rnd_output0.c:664:17
	lui	a2, %hi(.L.str.25)
	addi	a2, a2, %lo(.L.str.25)
	call	transparent_crc
.Ltmp475:
	.loc	2 665 21 is_stmt 1              # rnd_output0.c:665:21
	lw	a0, -36(s0)
.Ltmp476:
	.loc	2 665 21 is_stmt 0              # rnd_output0.c:665:21
	beqz	a0, .LBB56_45
	j	.LBB56_44
.LBB56_44:                              #   in Loop: Header=BB56_42 Depth=3
.Ltmp477:
	.loc	2 665 72                        # rnd_output0.c:665:72
	lw	a1, -24(s0)
	.loc	2 665 75                        # rnd_output0.c:665:75
	lw	a2, -28(s0)
	.loc	2 665 78                        # rnd_output0.c:665:78
	lw	a3, -32(s0)
	.loc	2 665 39                        # rnd_output0.c:665:39
	lui	a0, %hi(.L.str.9)
	addi	a0, a0, %lo(.L.str.9)
	call	printf
	j	.LBB56_45
.Ltmp478:
.LBB56_45:                              #   in Loop: Header=BB56_42 Depth=3
	.loc	2 667 13 is_stmt 1              # rnd_output0.c:667:13
	j	.LBB56_46
.Ltmp479:
.LBB56_46:                              #   in Loop: Header=BB56_42 Depth=3
	.loc	2 662 33                        # rnd_output0.c:662:33
	lw	a0, -32(s0)
	addi	a0, a0, 1
	sw	a0, -32(s0)
	.loc	2 662 13 is_stmt 0              # rnd_output0.c:662:13
	j	.LBB56_42
.Ltmp480:
.LBB56_47:                              #   in Loop: Header=BB56_40 Depth=2
	.loc	2 668 9 is_stmt 1               # rnd_output0.c:668:9
	j	.LBB56_48
.Ltmp481:
.LBB56_48:                              #   in Loop: Header=BB56_40 Depth=2
	.loc	2 660 29                        # rnd_output0.c:660:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 660 9 is_stmt 0               # rnd_output0.c:660:9
	j	.LBB56_40
.Ltmp482:
.LBB56_49:                              #   in Loop: Header=BB56_38 Depth=1
	.loc	2 669 5 is_stmt 1               # rnd_output0.c:669:5
	j	.LBB56_50
.Ltmp483:
.LBB56_50:                              #   in Loop: Header=BB56_38 Depth=1
	.loc	2 658 26                        # rnd_output0.c:658:26
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 658 5 is_stmt 0               # rnd_output0.c:658:5
	j	.LBB56_38
.Ltmp484:
.LBB56_51:
	.loc	2 670 30 is_stmt 1              # rnd_output0.c:670:30
	lui	a0, %hi(g_147)
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	lw	a0, %lo(g_147)(a0)
	srai	a1, a0, 31
	.loc	2 670 49 is_stmt 0              # rnd_output0.c:670:49
	lw	a3, -36(s0)
	.loc	2 670 5                         # rnd_output0.c:670:5
	lui	a2, %hi(.L.str.26)
	addi	a2, a2, %lo(.L.str.26)
	call	transparent_crc
	lw	a0, -52(s0)                     # 4-byte Folded Reload
	.loc	2 671 30 is_stmt 1              # rnd_output0.c:671:30
	lw	a0, %lo(g_147+4)(a0)
	.loc	2 671 49 is_stmt 0              # rnd_output0.c:671:49
	lw	a3, -36(s0)
	.loc	2 671 5                         # rnd_output0.c:671:5
	lui	a1, %hi(.L.str.27)
	addi	a2, a1, %lo(.L.str.27)
	li	a1, 0
	sw	a1, -48(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	.loc	2 672 21 is_stmt 1              # rnd_output0.c:672:21
	lui	a0, %hi(g_152)
	lw	a1, %lo(g_152+4)(a0)
	lw	a0, %lo(g_152)(a0)
	.loc	2 672 37 is_stmt 0              # rnd_output0.c:672:37
	lw	a3, -36(s0)
	.loc	2 672 5                         # rnd_output0.c:672:5
	lui	a2, %hi(.L.str.28)
	addi	a2, a2, %lo(.L.str.28)
	call	transparent_crc
	lw	a0, -48(s0)                     # 4-byte Folded Reload
.Ltmp485:
	.loc	2 673 12 is_stmt 1              # rnd_output0.c:673:12
	sw	a0, -24(s0)
	.loc	2 673 10 is_stmt 0              # rnd_output0.c:673:10
	j	.LBB56_52
.LBB56_52:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_54 Depth 2
.Ltmp486:
	.loc	2 673 17                        # rnd_output0.c:673:17
	lw	a1, -24(s0)
	li	a0, 9
.Ltmp487:
	.loc	2 673 5                         # rnd_output0.c:673:5
	blt	a0, a1, .LBB56_61
	j	.LBB56_53
.LBB56_53:                              #   in Loop: Header=BB56_52 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp488:
	.loc	2 675 16 is_stmt 1              # rnd_output0.c:675:16
	sw	a0, -28(s0)
	.loc	2 675 14 is_stmt 0              # rnd_output0.c:675:14
	j	.LBB56_54
.LBB56_54:                              #   Parent Loop BB56_52 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp489:
	.loc	2 675 21                        # rnd_output0.c:675:21
	lw	a1, -28(s0)
	li	a0, 3
.Ltmp490:
	.loc	2 675 9                         # rnd_output0.c:675:9
	blt	a0, a1, .LBB56_59
	j	.LBB56_55
.LBB56_55:                              #   in Loop: Header=BB56_54 Depth=2
.Ltmp491:
	.loc	2 677 35 is_stmt 1              # rnd_output0.c:677:35
	lw	a0, -24(s0)
	.loc	2 677 29 is_stmt 0              # rnd_output0.c:677:29
	slli	a1, a0, 2
	lui	a0, %hi(g_197)
	addi	a0, a0, %lo(g_197)
	add	a0, a0, a1
	.loc	2 677 38                        # rnd_output0.c:677:38
	lw	a1, -28(s0)
	.loc	2 677 29                        # rnd_output0.c:677:29
	add	a0, a0, a1
	lb	a0, 0(a0)
	srai	a1, a0, 31
	.loc	2 677 57                        # rnd_output0.c:677:57
	lw	a3, -36(s0)
	.loc	2 677 13                        # rnd_output0.c:677:13
	lui	a2, %hi(.L.str.29)
	addi	a2, a2, %lo(.L.str.29)
	call	transparent_crc
.Ltmp492:
	.loc	2 678 17 is_stmt 1              # rnd_output0.c:678:17
	lw	a0, -36(s0)
.Ltmp493:
	.loc	2 678 17 is_stmt 0              # rnd_output0.c:678:17
	beqz	a0, .LBB56_57
	j	.LBB56_56
.LBB56_56:                              #   in Loop: Header=BB56_54 Depth=2
.Ltmp494:
	.loc	2 678 64                        # rnd_output0.c:678:64
	lw	a1, -24(s0)
	.loc	2 678 67                        # rnd_output0.c:678:67
	lw	a2, -28(s0)
	.loc	2 678 35                        # rnd_output0.c:678:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_57
.Ltmp495:
.LBB56_57:                              #   in Loop: Header=BB56_54 Depth=2
	.loc	2 680 9 is_stmt 1               # rnd_output0.c:680:9
	j	.LBB56_58
.Ltmp496:
.LBB56_58:                              #   in Loop: Header=BB56_54 Depth=2
	.loc	2 675 29                        # rnd_output0.c:675:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 675 9 is_stmt 0               # rnd_output0.c:675:9
	j	.LBB56_54
.Ltmp497:
.LBB56_59:                              #   in Loop: Header=BB56_52 Depth=1
	.loc	2 681 5 is_stmt 1               # rnd_output0.c:681:5
	j	.LBB56_60
.Ltmp498:
.LBB56_60:                              #   in Loop: Header=BB56_52 Depth=1
	.loc	2 673 26                        # rnd_output0.c:673:26
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 673 5 is_stmt 0               # rnd_output0.c:673:5
	j	.LBB56_52
.Ltmp499:
.LBB56_61:
	.loc	2 682 21 is_stmt 1              # rnd_output0.c:682:21
	lui	a0, %hi(g_230)
	lh	a0, %lo(g_230)(a0)
	srai	a1, a0, 31
	.loc	2 682 37 is_stmt 0              # rnd_output0.c:682:37
	lw	a3, -36(s0)
	.loc	2 682 5                         # rnd_output0.c:682:5
	lui	a2, %hi(.L.str.31)
	addi	a2, a2, %lo(.L.str.31)
	call	transparent_crc
	.loc	2 683 21 is_stmt 1              # rnd_output0.c:683:21
	lui	a0, %hi(g_252)
	lb	a0, %lo(g_252)(a0)
	srai	a1, a0, 31
	.loc	2 683 37 is_stmt 0              # rnd_output0.c:683:37
	lw	a3, -36(s0)
	.loc	2 683 5                         # rnd_output0.c:683:5
	lui	a2, %hi(.L.str.32)
	addi	a2, a2, %lo(.L.str.32)
	call	transparent_crc
	li	a0, 0
.Ltmp500:
	.loc	2 684 12 is_stmt 1              # rnd_output0.c:684:12
	sw	a0, -24(s0)
	.loc	2 684 10 is_stmt 0              # rnd_output0.c:684:10
	j	.LBB56_62
.LBB56_62:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_64 Depth 2
.Ltmp501:
	.loc	2 684 17                        # rnd_output0.c:684:17
	lw	a1, -24(s0)
	li	a0, 4
.Ltmp502:
	.loc	2 684 5                         # rnd_output0.c:684:5
	blt	a0, a1, .LBB56_71
	j	.LBB56_63
.LBB56_63:                              #   in Loop: Header=BB56_62 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp503:
	.loc	2 686 16 is_stmt 1              # rnd_output0.c:686:16
	sw	a0, -28(s0)
	.loc	2 686 14 is_stmt 0              # rnd_output0.c:686:14
	j	.LBB56_64
.LBB56_64:                              #   Parent Loop BB56_62 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp504:
	.loc	2 686 21                        # rnd_output0.c:686:21
	lw	a1, -28(s0)
	li	a0, 7
.Ltmp505:
	.loc	2 686 9                         # rnd_output0.c:686:9
	blt	a0, a1, .LBB56_69
	j	.LBB56_65
.LBB56_65:                              #   in Loop: Header=BB56_64 Depth=2
.Ltmp506:
	.loc	2 688 35 is_stmt 1              # rnd_output0.c:688:35
	lw	a0, -24(s0)
	.loc	2 688 29 is_stmt 0              # rnd_output0.c:688:29
	slli	a1, a0, 5
	lui	a0, %hi(g_292)
	addi	a0, a0, %lo(g_292)
	add	a0, a0, a1
	.loc	2 688 38                        # rnd_output0.c:688:38
	lw	a1, -28(s0)
	.loc	2 688 29                        # rnd_output0.c:688:29
	slli	a1, a1, 2
	add	a0, a0, a1
	.loc	2 688 41                        # rnd_output0.c:688:41
	lw	a0, 0(a0)
	.loc	2 688 63                        # rnd_output0.c:688:63
	lw	a3, -36(s0)
	.loc	2 688 13                        # rnd_output0.c:688:13
	lui	a1, %hi(.L.str.33)
	addi	a2, a1, %lo(.L.str.33)
	li	a1, 0
	call	transparent_crc
.Ltmp507:
	.loc	2 689 17 is_stmt 1              # rnd_output0.c:689:17
	lw	a0, -36(s0)
.Ltmp508:
	.loc	2 689 17 is_stmt 0              # rnd_output0.c:689:17
	beqz	a0, .LBB56_67
	j	.LBB56_66
.LBB56_66:                              #   in Loop: Header=BB56_64 Depth=2
.Ltmp509:
	.loc	2 689 64                        # rnd_output0.c:689:64
	lw	a1, -24(s0)
	.loc	2 689 67                        # rnd_output0.c:689:67
	lw	a2, -28(s0)
	.loc	2 689 35                        # rnd_output0.c:689:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_67
.Ltmp510:
.LBB56_67:                              #   in Loop: Header=BB56_64 Depth=2
	.loc	2 691 9 is_stmt 1               # rnd_output0.c:691:9
	j	.LBB56_68
.Ltmp511:
.LBB56_68:                              #   in Loop: Header=BB56_64 Depth=2
	.loc	2 686 29                        # rnd_output0.c:686:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 686 9 is_stmt 0               # rnd_output0.c:686:9
	j	.LBB56_64
.Ltmp512:
.LBB56_69:                              #   in Loop: Header=BB56_62 Depth=1
	.loc	2 692 5 is_stmt 1               # rnd_output0.c:692:5
	j	.LBB56_70
.Ltmp513:
.LBB56_70:                              #   in Loop: Header=BB56_62 Depth=1
	.loc	2 684 25                        # rnd_output0.c:684:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 684 5 is_stmt 0               # rnd_output0.c:684:5
	j	.LBB56_62
.Ltmp514:
.LBB56_71:
	.loc	2 693 27 is_stmt 1              # rnd_output0.c:693:27
	lui	a0, %hi(g_294)
	lw	a0, %lo(g_294)(a0)
	.loc	2 693 43 is_stmt 0              # rnd_output0.c:693:43
	lw	a3, -36(s0)
	.loc	2 693 5                         # rnd_output0.c:693:5
	lui	a1, %hi(.L.str.34)
	addi	a2, a1, %lo(.L.str.34)
	li	a1, 0
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 694 21 is_stmt 1              # rnd_output0.c:694:21
	lui	a0, %hi(g_302)
	lw	a0, %lo(g_302)(a0)
	.loc	2 694 37 is_stmt 0              # rnd_output0.c:694:37
	lw	a3, -36(s0)
	.loc	2 694 5                         # rnd_output0.c:694:5
	lui	a2, %hi(.L.str.35)
	addi	a2, a2, %lo(.L.str.35)
	call	transparent_crc
	.loc	2 695 21 is_stmt 1              # rnd_output0.c:695:21
	lui	a0, %hi(g_325)
	lw	a1, %lo(g_325+4)(a0)
	lw	a0, %lo(g_325)(a0)
	.loc	2 695 37 is_stmt 0              # rnd_output0.c:695:37
	lw	a3, -36(s0)
	.loc	2 695 5                         # rnd_output0.c:695:5
	lui	a2, %hi(.L.str.36)
	addi	a2, a2, %lo(.L.str.36)
	call	transparent_crc
	.loc	2 696 21 is_stmt 1              # rnd_output0.c:696:21
	lui	a0, %hi(g_333)
	lw	a0, %lo(g_333)(a0)
	srai	a1, a0, 31
	.loc	2 696 37 is_stmt 0              # rnd_output0.c:696:37
	lw	a3, -36(s0)
	.loc	2 696 5                         # rnd_output0.c:696:5
	lui	a2, %hi(.L.str.37)
	addi	a2, a2, %lo(.L.str.37)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 697 21 is_stmt 1              # rnd_output0.c:697:21
	lui	a0, %hi(g_388)
	lhu	a0, %lo(g_388)(a0)
	.loc	2 697 37 is_stmt 0              # rnd_output0.c:697:37
	lw	a3, -36(s0)
	.loc	2 697 5                         # rnd_output0.c:697:5
	lui	a2, %hi(.L.str.38)
	addi	a2, a2, %lo(.L.str.38)
	call	transparent_crc
	.loc	2 698 21 is_stmt 1              # rnd_output0.c:698:21
	lui	a0, %hi(g_391)
	lw	a1, %lo(g_391+4)(a0)
	lw	a0, %lo(g_391)(a0)
	.loc	2 698 37 is_stmt 0              # rnd_output0.c:698:37
	lw	a3, -36(s0)
	.loc	2 698 5                         # rnd_output0.c:698:5
	lui	a2, %hi(.L.str.39)
	addi	a2, a2, %lo(.L.str.39)
	call	transparent_crc
	.loc	2 699 27 is_stmt 1              # rnd_output0.c:699:27
	lui	a0, %hi(g_556)
	sw	a0, -60(s0)                     # 4-byte Folded Spill
	lw	a0, %lo(g_556)(a0)
	srai	a1, a0, 31
	.loc	2 699 43 is_stmt 0              # rnd_output0.c:699:43
	lw	a3, -36(s0)
	.loc	2 699 5                         # rnd_output0.c:699:5
	lui	a2, %hi(.L.str.40)
	addi	a2, a2, %lo(.L.str.40)
	call	transparent_crc
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 700 27 is_stmt 1              # rnd_output0.c:700:27
	lw	a0, %lo(g_556+4)(a0)
	.loc	2 700 43 is_stmt 0              # rnd_output0.c:700:43
	lw	a3, -36(s0)
	.loc	2 700 5                         # rnd_output0.c:700:5
	lui	a2, %hi(.L.str.41)
	addi	a2, a2, %lo(.L.str.41)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 701 21 is_stmt 1              # rnd_output0.c:701:21
	lui	a0, %hi(g_588)
	lbu	a0, %lo(g_588)(a0)
	.loc	2 701 37 is_stmt 0              # rnd_output0.c:701:37
	lw	a3, -36(s0)
	.loc	2 701 5                         # rnd_output0.c:701:5
	lui	a2, %hi(.L.str.42)
	addi	a2, a2, %lo(.L.str.42)
	call	transparent_crc
	.loc	2 702 21 is_stmt 1              # rnd_output0.c:702:21
	lui	a0, %hi(g_589)
	lw	a0, %lo(g_589)(a0)
	srai	a1, a0, 31
	.loc	2 702 37 is_stmt 0              # rnd_output0.c:702:37
	lw	a3, -36(s0)
	.loc	2 702 5                         # rnd_output0.c:702:5
	lui	a2, %hi(.L.str.43)
	addi	a2, a2, %lo(.L.str.43)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 703 21 is_stmt 1              # rnd_output0.c:703:21
	lui	a0, %hi(g_642)
	lhu	a0, %lo(g_642)(a0)
	.loc	2 703 37 is_stmt 0              # rnd_output0.c:703:37
	lw	a3, -36(s0)
	.loc	2 703 5                         # rnd_output0.c:703:5
	lui	a2, %hi(.L.str.44)
	addi	a2, a2, %lo(.L.str.44)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 704 27 is_stmt 1              # rnd_output0.c:704:27
	lui	a0, %hi(g_645)
	lw	a0, %lo(g_645)(a0)
	.loc	2 704 43 is_stmt 0              # rnd_output0.c:704:43
	lw	a3, -36(s0)
	.loc	2 704 5                         # rnd_output0.c:704:5
	lui	a2, %hi(.L.str.45)
	addi	a2, a2, %lo(.L.str.45)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 705 27 is_stmt 1              # rnd_output0.c:705:27
	lui	a0, %hi(g_733)
	lw	a0, %lo(g_733)(a0)
	.loc	2 705 43 is_stmt 0              # rnd_output0.c:705:43
	lw	a3, -36(s0)
	.loc	2 705 5                         # rnd_output0.c:705:5
	lui	a2, %hi(.L.str.46)
	addi	a2, a2, %lo(.L.str.46)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 706 27 is_stmt 1              # rnd_output0.c:706:27
	lui	a0, %hi(g_765)
	lw	a0, %lo(g_765)(a0)
	.loc	2 706 43 is_stmt 0              # rnd_output0.c:706:43
	lw	a3, -36(s0)
	.loc	2 706 5                         # rnd_output0.c:706:5
	lui	a2, %hi(.L.str.47)
	addi	a2, a2, %lo(.L.str.47)
	call	transparent_crc
	lw	a1, -56(s0)                     # 4-byte Folded Reload
	.loc	2 707 27 is_stmt 1              # rnd_output0.c:707:27
	lui	a0, %hi(g_813)
	lw	a0, %lo(g_813)(a0)
	.loc	2 707 43 is_stmt 0              # rnd_output0.c:707:43
	lw	a3, -36(s0)
	.loc	2 707 5                         # rnd_output0.c:707:5
	lui	a2, %hi(.L.str.48)
	addi	a2, a2, %lo(.L.str.48)
	call	transparent_crc
	lw	a0, -56(s0)                     # 4-byte Folded Reload
.Ltmp515:
	.loc	2 708 12 is_stmt 1              # rnd_output0.c:708:12
	sw	a0, -24(s0)
	.loc	2 708 10 is_stmt 0              # rnd_output0.c:708:10
	j	.LBB56_72
.LBB56_72:                              # =>This Inner Loop Header: Depth=1
.Ltmp516:
	.loc	2 708 17                        # rnd_output0.c:708:17
	lw	a1, -24(s0)
	li	a0, 0
.Ltmp517:
	.loc	2 708 5                         # rnd_output0.c:708:5
	blt	a0, a1, .LBB56_77
	j	.LBB56_73
.LBB56_73:                              #   in Loop: Header=BB56_72 Depth=1
.Ltmp518:
	.loc	2 710 31 is_stmt 1              # rnd_output0.c:710:31
	lw	a0, -24(s0)
	.loc	2 710 25 is_stmt 0              # rnd_output0.c:710:25
	slli	a1, a0, 2
	lui	a0, %hi(g_921)
	addi	a0, a0, %lo(g_921)
	add	a0, a0, a1
	.loc	2 710 34                        # rnd_output0.c:710:34
	lw	a0, 0(a0)
	.loc	2 710 53                        # rnd_output0.c:710:53
	lw	a3, -36(s0)
	.loc	2 710 9                         # rnd_output0.c:710:9
	lui	a1, %hi(.L.str.49)
	addi	a2, a1, %lo(.L.str.49)
	li	a1, 0
	call	transparent_crc
.Ltmp519:
	.loc	2 711 13 is_stmt 1              # rnd_output0.c:711:13
	lw	a0, -36(s0)
.Ltmp520:
	.loc	2 711 13 is_stmt 0              # rnd_output0.c:711:13
	beqz	a0, .LBB56_75
	j	.LBB56_74
.LBB56_74:                              #   in Loop: Header=BB56_72 Depth=1
.Ltmp521:
	.loc	2 711 56                        # rnd_output0.c:711:56
	lw	a1, -24(s0)
	.loc	2 711 31                        # rnd_output0.c:711:31
	lui	a0, %hi(.L.str.17)
	addi	a0, a0, %lo(.L.str.17)
	call	printf
	j	.LBB56_75
.Ltmp522:
.LBB56_75:                              #   in Loop: Header=BB56_72 Depth=1
	.loc	2 713 5 is_stmt 1               # rnd_output0.c:713:5
	j	.LBB56_76
.Ltmp523:
.LBB56_76:                              #   in Loop: Header=BB56_72 Depth=1
	.loc	2 708 25                        # rnd_output0.c:708:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 708 5 is_stmt 0               # rnd_output0.c:708:5
	j	.LBB56_72
.Ltmp524:
.LBB56_77:
	.loc	2 714 21 is_stmt 1              # rnd_output0.c:714:21
	lui	a0, %hi(g_932)
	lw	a0, %lo(g_932)(a0)
	.loc	2 714 37 is_stmt 0              # rnd_output0.c:714:37
	lw	a3, -36(s0)
	.loc	2 714 5                         # rnd_output0.c:714:5
	lui	a1, %hi(.L.str.50)
	addi	a2, a1, %lo(.L.str.50)
	li	a1, 0
	sw	a1, -64(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	.loc	2 715 30 is_stmt 1              # rnd_output0.c:715:30
	lui	a0, %hi(g_946)
	sw	a0, -68(s0)                     # 4-byte Folded Spill
	lw	a0, %lo(g_946)(a0)
	srai	a1, a0, 31
	.loc	2 715 49 is_stmt 0              # rnd_output0.c:715:49
	lw	a3, -36(s0)
	.loc	2 715 5                         # rnd_output0.c:715:5
	lui	a2, %hi(.L.str.51)
	addi	a2, a2, %lo(.L.str.51)
	call	transparent_crc
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	lw	a1, -64(s0)                     # 4-byte Folded Reload
	.loc	2 716 30 is_stmt 1              # rnd_output0.c:716:30
	lw	a0, %lo(g_946+4)(a0)
	.loc	2 716 49 is_stmt 0              # rnd_output0.c:716:49
	lw	a3, -36(s0)
	.loc	2 716 5                         # rnd_output0.c:716:5
	lui	a2, %hi(.L.str.52)
	addi	a2, a2, %lo(.L.str.52)
	call	transparent_crc
	lw	a0, -64(s0)                     # 4-byte Folded Reload
.Ltmp525:
	.loc	2 717 12 is_stmt 1              # rnd_output0.c:717:12
	sw	a0, -24(s0)
	.loc	2 717 10 is_stmt 0              # rnd_output0.c:717:10
	j	.LBB56_78
.LBB56_78:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_80 Depth 2
.Ltmp526:
	.loc	2 717 17                        # rnd_output0.c:717:17
	lw	a1, -24(s0)
	li	a0, 6
.Ltmp527:
	.loc	2 717 5                         # rnd_output0.c:717:5
	blt	a0, a1, .LBB56_87
	j	.LBB56_79
.LBB56_79:                              #   in Loop: Header=BB56_78 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp528:
	.loc	2 719 16 is_stmt 1              # rnd_output0.c:719:16
	sw	a0, -28(s0)
	.loc	2 719 14 is_stmt 0              # rnd_output0.c:719:14
	j	.LBB56_80
.LBB56_80:                              #   Parent Loop BB56_78 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp529:
	.loc	2 719 21                        # rnd_output0.c:719:21
	lw	a1, -28(s0)
	li	a0, 3
.Ltmp530:
	.loc	2 719 9                         # rnd_output0.c:719:9
	blt	a0, a1, .LBB56_85
	j	.LBB56_81
.LBB56_81:                              #   in Loop: Header=BB56_80 Depth=2
.Ltmp531:
	.loc	2 721 35 is_stmt 1              # rnd_output0.c:721:35
	lw	a0, -24(s0)
	.loc	2 721 29 is_stmt 0              # rnd_output0.c:721:29
	slli	a1, a0, 3
	lui	a0, %hi(g_947)
	addi	a0, a0, %lo(g_947)
	add	a0, a0, a1
	.loc	2 721 38                        # rnd_output0.c:721:38
	lw	a1, -28(s0)
	.loc	2 721 29                        # rnd_output0.c:721:29
	slli	a1, a1, 1
	add	a0, a0, a1
	lhu	a0, 0(a0)
	.loc	2 721 57                        # rnd_output0.c:721:57
	lw	a3, -36(s0)
	.loc	2 721 13                        # rnd_output0.c:721:13
	lui	a1, %hi(.L.str.53)
	addi	a2, a1, %lo(.L.str.53)
	li	a1, 0
	call	transparent_crc
.Ltmp532:
	.loc	2 722 17 is_stmt 1              # rnd_output0.c:722:17
	lw	a0, -36(s0)
.Ltmp533:
	.loc	2 722 17 is_stmt 0              # rnd_output0.c:722:17
	beqz	a0, .LBB56_83
	j	.LBB56_82
.LBB56_82:                              #   in Loop: Header=BB56_80 Depth=2
.Ltmp534:
	.loc	2 722 64                        # rnd_output0.c:722:64
	lw	a1, -24(s0)
	.loc	2 722 67                        # rnd_output0.c:722:67
	lw	a2, -28(s0)
	.loc	2 722 35                        # rnd_output0.c:722:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_83
.Ltmp535:
.LBB56_83:                              #   in Loop: Header=BB56_80 Depth=2
	.loc	2 724 9 is_stmt 1               # rnd_output0.c:724:9
	j	.LBB56_84
.Ltmp536:
.LBB56_84:                              #   in Loop: Header=BB56_80 Depth=2
	.loc	2 719 29                        # rnd_output0.c:719:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 719 9 is_stmt 0               # rnd_output0.c:719:9
	j	.LBB56_80
.Ltmp537:
.LBB56_85:                              #   in Loop: Header=BB56_78 Depth=1
	.loc	2 725 5 is_stmt 1               # rnd_output0.c:725:5
	j	.LBB56_86
.Ltmp538:
.LBB56_86:                              #   in Loop: Header=BB56_78 Depth=1
	.loc	2 717 25                        # rnd_output0.c:717:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 717 5 is_stmt 0               # rnd_output0.c:717:5
	j	.LBB56_78
.Ltmp539:
.LBB56_87:
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp540:
	.loc	2 726 12 is_stmt 1              # rnd_output0.c:726:12
	sw	a0, -24(s0)
	.loc	2 726 10 is_stmt 0              # rnd_output0.c:726:10
	j	.LBB56_88
.LBB56_88:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_90 Depth 2
                                        #       Child Loop BB56_92 Depth 3
.Ltmp541:
	.loc	2 726 17                        # rnd_output0.c:726:17
	lw	a1, -24(s0)
	li	a0, 6
.Ltmp542:
	.loc	2 726 5                         # rnd_output0.c:726:5
	blt	a0, a1, .LBB56_101
	j	.LBB56_89
.LBB56_89:                              #   in Loop: Header=BB56_88 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp543:
	.loc	2 728 16 is_stmt 1              # rnd_output0.c:728:16
	sw	a0, -28(s0)
	.loc	2 728 14 is_stmt 0              # rnd_output0.c:728:14
	j	.LBB56_90
.LBB56_90:                              #   Parent Loop BB56_88 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB56_92 Depth 3
.Ltmp544:
	.loc	2 728 21                        # rnd_output0.c:728:21
	lw	a1, -28(s0)
	li	a0, 0
.Ltmp545:
	.loc	2 728 9                         # rnd_output0.c:728:9
	blt	a0, a1, .LBB56_99
	j	.LBB56_91
.LBB56_91:                              #   in Loop: Header=BB56_90 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 0
.Ltmp546:
	.loc	2 730 20 is_stmt 1              # rnd_output0.c:730:20
	sw	a0, -32(s0)
	.loc	2 730 18 is_stmt 0              # rnd_output0.c:730:18
	j	.LBB56_92
.LBB56_92:                              #   Parent Loop BB56_88 Depth=1
                                        #     Parent Loop BB56_90 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp547:
	.loc	2 730 25                        # rnd_output0.c:730:25
	lw	a1, -32(s0)
	li	a0, 1
.Ltmp548:
	.loc	2 730 13                        # rnd_output0.c:730:13
	blt	a0, a1, .LBB56_97
	j	.LBB56_93
.LBB56_93:                              #   in Loop: Header=BB56_92 Depth=3
.Ltmp549:
	.loc	2 732 39 is_stmt 1              # rnd_output0.c:732:39
	lw	a0, -24(s0)
	.loc	2 732 33 is_stmt 0              # rnd_output0.c:732:33
	slli	a1, a0, 2
	lui	a0, %hi(g_955)
	addi	a0, a0, %lo(g_955)
	add	a0, a0, a1
	.loc	2 732 42                        # rnd_output0.c:732:42
	lw	a1, -28(s0)
	.loc	2 732 33                        # rnd_output0.c:732:33
	slli	a1, a1, 2
	add	a0, a0, a1
	.loc	2 732 45                        # rnd_output0.c:732:45
	lw	a1, -32(s0)
	.loc	2 732 33                        # rnd_output0.c:732:33
	slli	a1, a1, 1
	add	a0, a0, a1
	lh	a0, 0(a0)
	srai	a1, a0, 31
	.loc	2 732 67                        # rnd_output0.c:732:67
	lw	a3, -36(s0)
	.loc	2 732 17                        # rnd_output0.c:732:17
	lui	a2, %hi(.L.str.54)
	addi	a2, a2, %lo(.L.str.54)
	call	transparent_crc
.Ltmp550:
	.loc	2 733 21 is_stmt 1              # rnd_output0.c:733:21
	lw	a0, -36(s0)
.Ltmp551:
	.loc	2 733 21 is_stmt 0              # rnd_output0.c:733:21
	beqz	a0, .LBB56_95
	j	.LBB56_94
.LBB56_94:                              #   in Loop: Header=BB56_92 Depth=3
.Ltmp552:
	.loc	2 733 72                        # rnd_output0.c:733:72
	lw	a1, -24(s0)
	.loc	2 733 75                        # rnd_output0.c:733:75
	lw	a2, -28(s0)
	.loc	2 733 78                        # rnd_output0.c:733:78
	lw	a3, -32(s0)
	.loc	2 733 39                        # rnd_output0.c:733:39
	lui	a0, %hi(.L.str.9)
	addi	a0, a0, %lo(.L.str.9)
	call	printf
	j	.LBB56_95
.Ltmp553:
.LBB56_95:                              #   in Loop: Header=BB56_92 Depth=3
	.loc	2 735 13 is_stmt 1              # rnd_output0.c:735:13
	j	.LBB56_96
.Ltmp554:
.LBB56_96:                              #   in Loop: Header=BB56_92 Depth=3
	.loc	2 730 33                        # rnd_output0.c:730:33
	lw	a0, -32(s0)
	addi	a0, a0, 1
	sw	a0, -32(s0)
	.loc	2 730 13 is_stmt 0              # rnd_output0.c:730:13
	j	.LBB56_92
.Ltmp555:
.LBB56_97:                              #   in Loop: Header=BB56_90 Depth=2
	.loc	2 736 9 is_stmt 1               # rnd_output0.c:736:9
	j	.LBB56_98
.Ltmp556:
.LBB56_98:                              #   in Loop: Header=BB56_90 Depth=2
	.loc	2 728 29                        # rnd_output0.c:728:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 728 9 is_stmt 0               # rnd_output0.c:728:9
	j	.LBB56_90
.Ltmp557:
.LBB56_99:                              #   in Loop: Header=BB56_88 Depth=1
	.loc	2 737 5 is_stmt 1               # rnd_output0.c:737:5
	j	.LBB56_100
.Ltmp558:
.LBB56_100:                             #   in Loop: Header=BB56_88 Depth=1
	.loc	2 726 25                        # rnd_output0.c:726:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 726 5 is_stmt 0               # rnd_output0.c:726:5
	j	.LBB56_88
.Ltmp559:
.LBB56_101:
	.loc	2 738 21 is_stmt 1              # rnd_output0.c:738:21
	lui	a0, %hi(g_1000)
	lw	a0, %lo(g_1000)(a0)
	srai	a1, a0, 31
	.loc	2 738 39 is_stmt 0              # rnd_output0.c:738:39
	lw	a3, -36(s0)
	.loc	2 738 5                         # rnd_output0.c:738:5
	lui	a2, %hi(.L.str.55)
	addi	a2, a2, %lo(.L.str.55)
	call	transparent_crc
	.loc	2 739 28 is_stmt 1              # rnd_output0.c:739:28
	lui	a0, %hi(g_1113)
	lw	a0, %lo(g_1113)(a0)
	.loc	2 739 45 is_stmt 0              # rnd_output0.c:739:45
	lw	a3, -36(s0)
	.loc	2 739 5                         # rnd_output0.c:739:5
	lui	a1, %hi(.L.str.56)
	addi	a2, a1, %lo(.L.str.56)
	li	a1, 0
	sw	a1, -72(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	lw	a0, -72(s0)                     # 4-byte Folded Reload
.Ltmp560:
	.loc	2 740 12 is_stmt 1              # rnd_output0.c:740:12
	sw	a0, -24(s0)
	.loc	2 740 10 is_stmt 0              # rnd_output0.c:740:10
	j	.LBB56_102
.LBB56_102:                             # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_104 Depth 2
.Ltmp561:
	.loc	2 740 17                        # rnd_output0.c:740:17
	lw	a1, -24(s0)
	li	a0, 4
.Ltmp562:
	.loc	2 740 5                         # rnd_output0.c:740:5
	blt	a0, a1, .LBB56_111
	j	.LBB56_103
.LBB56_103:                             #   in Loop: Header=BB56_102 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp563:
	.loc	2 742 16 is_stmt 1              # rnd_output0.c:742:16
	sw	a0, -28(s0)
	.loc	2 742 14 is_stmt 0              # rnd_output0.c:742:14
	j	.LBB56_104
.LBB56_104:                             #   Parent Loop BB56_102 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp564:
	.loc	2 742 21                        # rnd_output0.c:742:21
	lw	a1, -28(s0)
	li	a0, 9
.Ltmp565:
	.loc	2 742 9                         # rnd_output0.c:742:9
	blt	a0, a1, .LBB56_109
	j	.LBB56_105
.LBB56_105:                             #   in Loop: Header=BB56_104 Depth=2
.Ltmp566:
	.loc	2 744 36 is_stmt 1              # rnd_output0.c:744:36
	lw	a0, -24(s0)
	li	a1, 40
	.loc	2 744 29 is_stmt 0              # rnd_output0.c:744:29
	mul	a1, a0, a1
	lui	a0, %hi(g_1259)
	addi	a0, a0, %lo(g_1259)
	add	a0, a0, a1
	.loc	2 744 39                        # rnd_output0.c:744:39
	lw	a1, -28(s0)
	.loc	2 744 29                        # rnd_output0.c:744:29
	slli	a1, a1, 2
	add	a0, a0, a1
	lw	a0, 0(a0)
	.loc	2 744 59                        # rnd_output0.c:744:59
	lw	a3, -36(s0)
	.loc	2 744 13                        # rnd_output0.c:744:13
	lui	a1, %hi(.L.str.57)
	addi	a2, a1, %lo(.L.str.57)
	li	a1, 0
	call	transparent_crc
.Ltmp567:
	.loc	2 745 17 is_stmt 1              # rnd_output0.c:745:17
	lw	a0, -36(s0)
.Ltmp568:
	.loc	2 745 17 is_stmt 0              # rnd_output0.c:745:17
	beqz	a0, .LBB56_107
	j	.LBB56_106
.LBB56_106:                             #   in Loop: Header=BB56_104 Depth=2
.Ltmp569:
	.loc	2 745 64                        # rnd_output0.c:745:64
	lw	a1, -24(s0)
	.loc	2 745 67                        # rnd_output0.c:745:67
	lw	a2, -28(s0)
	.loc	2 745 35                        # rnd_output0.c:745:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_107
.Ltmp570:
.LBB56_107:                             #   in Loop: Header=BB56_104 Depth=2
	.loc	2 747 9 is_stmt 1               # rnd_output0.c:747:9
	j	.LBB56_108
.Ltmp571:
.LBB56_108:                             #   in Loop: Header=BB56_104 Depth=2
	.loc	2 742 30                        # rnd_output0.c:742:30
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 742 9 is_stmt 0               # rnd_output0.c:742:9
	j	.LBB56_104
.Ltmp572:
.LBB56_109:                             #   in Loop: Header=BB56_102 Depth=1
	.loc	2 748 5 is_stmt 1               # rnd_output0.c:748:5
	j	.LBB56_110
.Ltmp573:
.LBB56_110:                             #   in Loop: Header=BB56_102 Depth=1
	.loc	2 740 25                        # rnd_output0.c:740:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 740 5 is_stmt 0               # rnd_output0.c:740:5
	j	.LBB56_102
.Ltmp574:
.LBB56_111:
	.loc	2 749 28 is_stmt 1              # rnd_output0.c:749:28
	lui	a0, %hi(g_1292)
	lw	a0, %lo(g_1292)(a0)
	.loc	2 749 45 is_stmt 0              # rnd_output0.c:749:45
	lw	a3, -36(s0)
	.loc	2 749 5                         # rnd_output0.c:749:5
	lui	a1, %hi(.L.str.58)
	addi	a2, a1, %lo(.L.str.58)
	li	a1, 0
	sw	a1, -76(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	lw	a0, -76(s0)                     # 4-byte Folded Reload
.Ltmp575:
	.loc	2 750 12 is_stmt 1              # rnd_output0.c:750:12
	sw	a0, -24(s0)
	.loc	2 750 10 is_stmt 0              # rnd_output0.c:750:10
	j	.LBB56_112
.LBB56_112:                             # =>This Inner Loop Header: Depth=1
.Ltmp576:
	.loc	2 750 17                        # rnd_output0.c:750:17
	lw	a1, -24(s0)
	li	a0, 8
.Ltmp577:
	.loc	2 750 5                         # rnd_output0.c:750:5
	blt	a0, a1, .LBB56_117
	j	.LBB56_113
.LBB56_113:                             #   in Loop: Header=BB56_112 Depth=1
.Ltmp578:
	.loc	2 752 32 is_stmt 1              # rnd_output0.c:752:32
	lw	a0, -24(s0)
	.loc	2 752 25 is_stmt 0              # rnd_output0.c:752:25
	slli	a1, a0, 1
	lui	a0, %hi(g_1375)
	addi	a0, a0, %lo(g_1375)
	add	a0, a0, a1
	lhu	a0, 0(a0)
	.loc	2 752 49                        # rnd_output0.c:752:49
	lw	a3, -36(s0)
	.loc	2 752 9                         # rnd_output0.c:752:9
	lui	a1, %hi(.L.str.59)
	addi	a2, a1, %lo(.L.str.59)
	li	a1, 0
	call	transparent_crc
.Ltmp579:
	.loc	2 753 13 is_stmt 1              # rnd_output0.c:753:13
	lw	a0, -36(s0)
.Ltmp580:
	.loc	2 753 13 is_stmt 0              # rnd_output0.c:753:13
	beqz	a0, .LBB56_115
	j	.LBB56_114
.LBB56_114:                             #   in Loop: Header=BB56_112 Depth=1
.Ltmp581:
	.loc	2 753 56                        # rnd_output0.c:753:56
	lw	a1, -24(s0)
	.loc	2 753 31                        # rnd_output0.c:753:31
	lui	a0, %hi(.L.str.17)
	addi	a0, a0, %lo(.L.str.17)
	call	printf
	j	.LBB56_115
.Ltmp582:
.LBB56_115:                             #   in Loop: Header=BB56_112 Depth=1
	.loc	2 755 5 is_stmt 1               # rnd_output0.c:755:5
	j	.LBB56_116
.Ltmp583:
.LBB56_116:                             #   in Loop: Header=BB56_112 Depth=1
	.loc	2 750 25                        # rnd_output0.c:750:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 750 5 is_stmt 0               # rnd_output0.c:750:5
	j	.LBB56_112
.Ltmp584:
.LBB56_117:
	.loc	2 756 28 is_stmt 1              # rnd_output0.c:756:28
	lui	a0, %hi(g_1548)
	lw	a0, %lo(g_1548)(a0)
	.loc	2 756 45 is_stmt 0              # rnd_output0.c:756:45
	lw	a3, -36(s0)
	.loc	2 756 5                         # rnd_output0.c:756:5
	lui	a1, %hi(.L.str.60)
	addi	a2, a1, %lo(.L.str.60)
	li	a1, 0
	sw	a1, -80(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	lw	a1, -80(s0)                     # 4-byte Folded Reload
	.loc	2 757 21 is_stmt 1              # rnd_output0.c:757:21
	lui	a0, %hi(g_1662)
	lw	a0, %lo(g_1662)(a0)
	.loc	2 757 39 is_stmt 0              # rnd_output0.c:757:39
	lw	a3, -36(s0)
	.loc	2 757 5                         # rnd_output0.c:757:5
	lui	a2, %hi(.L.str.61)
	addi	a2, a2, %lo(.L.str.61)
	call	transparent_crc
	lw	a0, -80(s0)                     # 4-byte Folded Reload
.Ltmp585:
	.loc	2 758 12 is_stmt 1              # rnd_output0.c:758:12
	sw	a0, -24(s0)
	.loc	2 758 10 is_stmt 0              # rnd_output0.c:758:10
	j	.LBB56_118
.LBB56_118:                             # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_120 Depth 2
                                        #       Child Loop BB56_122 Depth 3
.Ltmp586:
	.loc	2 758 17                        # rnd_output0.c:758:17
	lw	a1, -24(s0)
	li	a0, 7
.Ltmp587:
	.loc	2 758 5                         # rnd_output0.c:758:5
	blt	a0, a1, .LBB56_131
	j	.LBB56_119
.LBB56_119:                             #   in Loop: Header=BB56_118 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp588:
	.loc	2 760 16 is_stmt 1              # rnd_output0.c:760:16
	sw	a0, -28(s0)
	.loc	2 760 14 is_stmt 0              # rnd_output0.c:760:14
	j	.LBB56_120
.LBB56_120:                             #   Parent Loop BB56_118 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB56_122 Depth 3
.Ltmp589:
	.loc	2 760 21                        # rnd_output0.c:760:21
	lw	a1, -28(s0)
	li	a0, 4
.Ltmp590:
	.loc	2 760 9                         # rnd_output0.c:760:9
	blt	a0, a1, .LBB56_129
	j	.LBB56_121
.LBB56_121:                             #   in Loop: Header=BB56_120 Depth=2
	.loc	2 0 9                           # rnd_output0.c:0:9
	li	a0, 0
.Ltmp591:
	.loc	2 762 20 is_stmt 1              # rnd_output0.c:762:20
	sw	a0, -32(s0)
	.loc	2 762 18 is_stmt 0              # rnd_output0.c:762:18
	j	.LBB56_122
.LBB56_122:                             #   Parent Loop BB56_118 Depth=1
                                        #     Parent Loop BB56_120 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp592:
	.loc	2 762 25                        # rnd_output0.c:762:25
	lw	a1, -32(s0)
	li	a0, 1
.Ltmp593:
	.loc	2 762 13                        # rnd_output0.c:762:13
	blt	a0, a1, .LBB56_127
	j	.LBB56_123
.LBB56_123:                             #   in Loop: Header=BB56_122 Depth=3
.Ltmp594:
	.loc	2 764 40 is_stmt 1              # rnd_output0.c:764:40
	lw	a0, -24(s0)
	li	a1, 40
	.loc	2 764 33 is_stmt 0              # rnd_output0.c:764:33
	mul	a1, a0, a1
	lui	a0, %hi(g_1717)
	addi	a0, a0, %lo(g_1717)
	add	a0, a0, a1
	.loc	2 764 43                        # rnd_output0.c:764:43
	lw	a1, -28(s0)
	.loc	2 764 33                        # rnd_output0.c:764:33
	slli	a1, a1, 3
	add	a0, a0, a1
	.loc	2 764 46                        # rnd_output0.c:764:46
	lw	a1, -32(s0)
	.loc	2 764 33                        # rnd_output0.c:764:33
	slli	a1, a1, 2
	add	a0, a0, a1
	.loc	2 764 49                        # rnd_output0.c:764:49
	lw	a0, 0(a0)
	.loc	2 764 75                        # rnd_output0.c:764:75
	lw	a3, -36(s0)
	.loc	2 764 17                        # rnd_output0.c:764:17
	lui	a1, %hi(.L.str.62)
	addi	a2, a1, %lo(.L.str.62)
	li	a1, 0
	call	transparent_crc
.Ltmp595:
	.loc	2 765 21 is_stmt 1              # rnd_output0.c:765:21
	lw	a0, -36(s0)
.Ltmp596:
	.loc	2 765 21 is_stmt 0              # rnd_output0.c:765:21
	beqz	a0, .LBB56_125
	j	.LBB56_124
.LBB56_124:                             #   in Loop: Header=BB56_122 Depth=3
.Ltmp597:
	.loc	2 765 72                        # rnd_output0.c:765:72
	lw	a1, -24(s0)
	.loc	2 765 75                        # rnd_output0.c:765:75
	lw	a2, -28(s0)
	.loc	2 765 78                        # rnd_output0.c:765:78
	lw	a3, -32(s0)
	.loc	2 765 39                        # rnd_output0.c:765:39
	lui	a0, %hi(.L.str.9)
	addi	a0, a0, %lo(.L.str.9)
	call	printf
	j	.LBB56_125
.Ltmp598:
.LBB56_125:                             #   in Loop: Header=BB56_122 Depth=3
	.loc	2 767 13 is_stmt 1              # rnd_output0.c:767:13
	j	.LBB56_126
.Ltmp599:
.LBB56_126:                             #   in Loop: Header=BB56_122 Depth=3
	.loc	2 762 33                        # rnd_output0.c:762:33
	lw	a0, -32(s0)
	addi	a0, a0, 1
	sw	a0, -32(s0)
	.loc	2 762 13 is_stmt 0              # rnd_output0.c:762:13
	j	.LBB56_122
.Ltmp600:
.LBB56_127:                             #   in Loop: Header=BB56_120 Depth=2
	.loc	2 768 9 is_stmt 1               # rnd_output0.c:768:9
	j	.LBB56_128
.Ltmp601:
.LBB56_128:                             #   in Loop: Header=BB56_120 Depth=2
	.loc	2 760 29                        # rnd_output0.c:760:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 760 9 is_stmt 0               # rnd_output0.c:760:9
	j	.LBB56_120
.Ltmp602:
.LBB56_129:                             #   in Loop: Header=BB56_118 Depth=1
	.loc	2 769 5 is_stmt 1               # rnd_output0.c:769:5
	j	.LBB56_130
.Ltmp603:
.LBB56_130:                             #   in Loop: Header=BB56_118 Depth=1
	.loc	2 758 25                        # rnd_output0.c:758:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 758 5 is_stmt 0               # rnd_output0.c:758:5
	j	.LBB56_118
.Ltmp604:
.LBB56_131:
	.loc	2 770 21 is_stmt 1              # rnd_output0.c:770:21
	lui	a0, %hi(g_1781)
	lw	a0, %lo(g_1781)(a0)
	.loc	2 770 39 is_stmt 0              # rnd_output0.c:770:39
	lw	a3, -36(s0)
	.loc	2 770 5                         # rnd_output0.c:770:5
	lui	a1, %hi(.L.str.63)
	addi	a2, a1, %lo(.L.str.63)
	li	a1, 0
	sw	a1, -84(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 771 28 is_stmt 1              # rnd_output0.c:771:28
	lui	a0, %hi(g_1812)
	lw	a0, %lo(g_1812)(a0)
	.loc	2 771 45 is_stmt 0              # rnd_output0.c:771:45
	lw	a3, -36(s0)
	.loc	2 771 5                         # rnd_output0.c:771:5
	lui	a2, %hi(.L.str.64)
	addi	a2, a2, %lo(.L.str.64)
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 772 28 is_stmt 1              # rnd_output0.c:772:28
	lui	a0, %hi(g_1813)
	lw	a0, %lo(g_1813)(a0)
	.loc	2 772 45 is_stmt 0              # rnd_output0.c:772:45
	lw	a3, -36(s0)
	.loc	2 772 5                         # rnd_output0.c:772:5
	lui	a2, %hi(.L.str.65)
	addi	a2, a2, %lo(.L.str.65)
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 773 28 is_stmt 1              # rnd_output0.c:773:28
	lui	a0, %hi(g_1814)
	lw	a0, %lo(g_1814)(a0)
	.loc	2 773 45 is_stmt 0              # rnd_output0.c:773:45
	lw	a3, -36(s0)
	.loc	2 773 5                         # rnd_output0.c:773:5
	lui	a2, %hi(.L.str.66)
	addi	a2, a2, %lo(.L.str.66)
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 774 28 is_stmt 1              # rnd_output0.c:774:28
	lui	a0, %hi(g_1815)
	lw	a0, %lo(g_1815)(a0)
	.loc	2 774 45 is_stmt 0              # rnd_output0.c:774:45
	lw	a3, -36(s0)
	.loc	2 774 5                         # rnd_output0.c:774:5
	lui	a2, %hi(.L.str.67)
	addi	a2, a2, %lo(.L.str.67)
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 775 28 is_stmt 1              # rnd_output0.c:775:28
	lui	a0, %hi(g_1816)
	lw	a0, %lo(g_1816)(a0)
	.loc	2 775 45 is_stmt 0              # rnd_output0.c:775:45
	lw	a3, -36(s0)
	.loc	2 775 5                         # rnd_output0.c:775:5
	lui	a2, %hi(.L.str.68)
	addi	a2, a2, %lo(.L.str.68)
	call	transparent_crc
	lw	a1, -84(s0)                     # 4-byte Folded Reload
	.loc	2 776 45 is_stmt 1              # rnd_output0.c:776:45
	lw	a3, -36(s0)
	.loc	2 776 5 is_stmt 0               # rnd_output0.c:776:5
	lui	a0, %hi(.L.str.69)
	addi	a2, a0, %lo(.L.str.69)
	lui	a0, 230351
	addi	a0, a0, 1897
	call	transparent_crc
	lw	a0, -84(s0)                     # 4-byte Folded Reload
.Ltmp605:
	.loc	2 777 12 is_stmt 1              # rnd_output0.c:777:12
	sw	a0, -24(s0)
	.loc	2 777 10 is_stmt 0              # rnd_output0.c:777:10
	j	.LBB56_132
.LBB56_132:                             # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_134 Depth 2
.Ltmp606:
	.loc	2 777 17                        # rnd_output0.c:777:17
	lw	a1, -24(s0)
	li	a0, 2
.Ltmp607:
	.loc	2 777 5                         # rnd_output0.c:777:5
	blt	a0, a1, .LBB56_141
	j	.LBB56_133
.LBB56_133:                             #   in Loop: Header=BB56_132 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp608:
	.loc	2 779 16 is_stmt 1              # rnd_output0.c:779:16
	sw	a0, -28(s0)
	.loc	2 779 14 is_stmt 0              # rnd_output0.c:779:14
	j	.LBB56_134
.LBB56_134:                             #   Parent Loop BB56_132 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp609:
	.loc	2 779 21                        # rnd_output0.c:779:21
	lw	a1, -28(s0)
	li	a0, 2
.Ltmp610:
	.loc	2 779 9                         # rnd_output0.c:779:9
	blt	a0, a1, .LBB56_139
	j	.LBB56_135
.LBB56_135:                             #   in Loop: Header=BB56_134 Depth=2
.Ltmp611:
	.loc	2 781 36 is_stmt 1              # rnd_output0.c:781:36
	lw	a0, -24(s0)
	li	a1, 12
	.loc	2 781 29 is_stmt 0              # rnd_output0.c:781:29
	mul	a1, a0, a1
	lui	a0, %hi(g_1818)
	addi	a0, a0, %lo(g_1818)
	add	a0, a0, a1
	.loc	2 781 39                        # rnd_output0.c:781:39
	lw	a1, -28(s0)
	.loc	2 781 29                        # rnd_output0.c:781:29
	slli	a1, a1, 2
	add	a0, a0, a1
	.loc	2 781 42                        # rnd_output0.c:781:42
	lw	a0, 0(a0)
	.loc	2 781 65                        # rnd_output0.c:781:65
	lw	a3, -36(s0)
	.loc	2 781 13                        # rnd_output0.c:781:13
	lui	a1, %hi(.L.str.70)
	addi	a2, a1, %lo(.L.str.70)
	li	a1, 0
	call	transparent_crc
.Ltmp612:
	.loc	2 782 17 is_stmt 1              # rnd_output0.c:782:17
	lw	a0, -36(s0)
.Ltmp613:
	.loc	2 782 17 is_stmt 0              # rnd_output0.c:782:17
	beqz	a0, .LBB56_137
	j	.LBB56_136
.LBB56_136:                             #   in Loop: Header=BB56_134 Depth=2
.Ltmp614:
	.loc	2 782 64                        # rnd_output0.c:782:64
	lw	a1, -24(s0)
	.loc	2 782 67                        # rnd_output0.c:782:67
	lw	a2, -28(s0)
	.loc	2 782 35                        # rnd_output0.c:782:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_137
.Ltmp615:
.LBB56_137:                             #   in Loop: Header=BB56_134 Depth=2
	.loc	2 784 9 is_stmt 1               # rnd_output0.c:784:9
	j	.LBB56_138
.Ltmp616:
.LBB56_138:                             #   in Loop: Header=BB56_134 Depth=2
	.loc	2 779 29                        # rnd_output0.c:779:29
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 779 9 is_stmt 0               # rnd_output0.c:779:9
	j	.LBB56_134
.Ltmp617:
.LBB56_139:                             #   in Loop: Header=BB56_132 Depth=1
	.loc	2 785 5 is_stmt 1               # rnd_output0.c:785:5
	j	.LBB56_140
.Ltmp618:
.LBB56_140:                             #   in Loop: Header=BB56_132 Depth=1
	.loc	2 777 25                        # rnd_output0.c:777:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 777 5 is_stmt 0               # rnd_output0.c:777:5
	j	.LBB56_132
.Ltmp619:
.LBB56_141:
	.loc	2 786 28 is_stmt 1              # rnd_output0.c:786:28
	lui	a0, %hi(g_1852)
	lw	a0, %lo(g_1852)(a0)
	.loc	2 786 45 is_stmt 0              # rnd_output0.c:786:45
	lw	a3, -36(s0)
	.loc	2 786 5                         # rnd_output0.c:786:5
	lui	a1, %hi(.L.str.71)
	addi	a2, a1, %lo(.L.str.71)
	li	a1, 0
	sw	a1, -88(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	.loc	2 787 21 is_stmt 1              # rnd_output0.c:787:21
	lui	a0, %hi(g_2016)
	lb	a0, %lo(g_2016)(a0)
	srai	a1, a0, 31
	.loc	2 787 39 is_stmt 0              # rnd_output0.c:787:39
	lw	a3, -36(s0)
	.loc	2 787 5                         # rnd_output0.c:787:5
	lui	a2, %hi(.L.str.72)
	addi	a2, a2, %lo(.L.str.72)
	call	transparent_crc
	lw	a1, -88(s0)                     # 4-byte Folded Reload
	.loc	2 788 28 is_stmt 1              # rnd_output0.c:788:28
	lui	a0, %hi(g_2017)
	lw	a0, %lo(g_2017)(a0)
	.loc	2 788 45 is_stmt 0              # rnd_output0.c:788:45
	lw	a3, -36(s0)
	.loc	2 788 5                         # rnd_output0.c:788:5
	lui	a2, %hi(.L.str.73)
	addi	a2, a2, %lo(.L.str.73)
	call	transparent_crc
	.loc	2 789 21 is_stmt 1              # rnd_output0.c:789:21
	lui	a0, %hi(g_2070)
	lw	a0, %lo(g_2070)(a0)
	srai	a1, a0, 31
	.loc	2 789 39 is_stmt 0              # rnd_output0.c:789:39
	lw	a3, -36(s0)
	.loc	2 789 5                         # rnd_output0.c:789:5
	lui	a2, %hi(.L.str.74)
	addi	a2, a2, %lo(.L.str.74)
	call	transparent_crc
	lw	a1, -88(s0)                     # 4-byte Folded Reload
	.loc	2 790 28 is_stmt 1              # rnd_output0.c:790:28
	lui	a0, %hi(g_2128)
	lw	a0, %lo(g_2128)(a0)
	.loc	2 790 45 is_stmt 0              # rnd_output0.c:790:45
	lw	a3, -36(s0)
	.loc	2 790 5                         # rnd_output0.c:790:5
	lui	a2, %hi(.L.str.75)
	addi	a2, a2, %lo(.L.str.75)
	call	transparent_crc
	lw	a1, -88(s0)                     # 4-byte Folded Reload
	.loc	2 791 28 is_stmt 1              # rnd_output0.c:791:28
	lui	a0, %hi(g_2201)
	lw	a0, %lo(g_2201)(a0)
	.loc	2 791 45 is_stmt 0              # rnd_output0.c:791:45
	lw	a3, -36(s0)
	.loc	2 791 5                         # rnd_output0.c:791:5
	lui	a2, %hi(.L.str.76)
	addi	a2, a2, %lo(.L.str.76)
	call	transparent_crc
	lw	a0, -88(s0)                     # 4-byte Folded Reload
.Ltmp620:
	.loc	2 792 12 is_stmt 1              # rnd_output0.c:792:12
	sw	a0, -24(s0)
	.loc	2 792 10 is_stmt 0              # rnd_output0.c:792:10
	j	.LBB56_142
.LBB56_142:                             # =>This Loop Header: Depth=1
                                        #     Child Loop BB56_144 Depth 2
.Ltmp621:
	.loc	2 792 17                        # rnd_output0.c:792:17
	lw	a1, -24(s0)
	li	a0, 2
.Ltmp622:
	.loc	2 792 5                         # rnd_output0.c:792:5
	blt	a0, a1, .LBB56_151
	j	.LBB56_143
.LBB56_143:                             #   in Loop: Header=BB56_142 Depth=1
	.loc	2 0 5                           # rnd_output0.c:0:5
	li	a0, 0
.Ltmp623:
	.loc	2 794 16 is_stmt 1              # rnd_output0.c:794:16
	sw	a0, -28(s0)
	.loc	2 794 14 is_stmt 0              # rnd_output0.c:794:14
	j	.LBB56_144
.LBB56_144:                             #   Parent Loop BB56_142 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp624:
	.loc	2 794 21                        # rnd_output0.c:794:21
	lw	a1, -28(s0)
	li	a0, 9
.Ltmp625:
	.loc	2 794 9                         # rnd_output0.c:794:9
	blt	a0, a1, .LBB56_149
	j	.LBB56_145
.LBB56_145:                             #   in Loop: Header=BB56_144 Depth=2
.Ltmp626:
	.loc	2 796 36 is_stmt 1              # rnd_output0.c:796:36
	lw	a0, -24(s0)
	li	a1, 40
	.loc	2 796 29 is_stmt 0              # rnd_output0.c:796:29
	mul	a1, a0, a1
	lui	a0, %hi(g_2309)
	addi	a0, a0, %lo(g_2309)
	add	a0, a0, a1
	.loc	2 796 39                        # rnd_output0.c:796:39
	lw	a1, -28(s0)
	.loc	2 796 29                        # rnd_output0.c:796:29
	slli	a1, a1, 2
	add	a0, a0, a1
	.loc	2 796 42                        # rnd_output0.c:796:42
	lw	a0, 0(a0)
	.loc	2 796 65                        # rnd_output0.c:796:65
	lw	a3, -36(s0)
	.loc	2 796 13                        # rnd_output0.c:796:13
	lui	a1, %hi(.L.str.77)
	addi	a2, a1, %lo(.L.str.77)
	li	a1, 0
	call	transparent_crc
.Ltmp627:
	.loc	2 797 17 is_stmt 1              # rnd_output0.c:797:17
	lw	a0, -36(s0)
.Ltmp628:
	.loc	2 797 17 is_stmt 0              # rnd_output0.c:797:17
	beqz	a0, .LBB56_147
	j	.LBB56_146
.LBB56_146:                             #   in Loop: Header=BB56_144 Depth=2
.Ltmp629:
	.loc	2 797 64                        # rnd_output0.c:797:64
	lw	a1, -24(s0)
	.loc	2 797 67                        # rnd_output0.c:797:67
	lw	a2, -28(s0)
	.loc	2 797 35                        # rnd_output0.c:797:35
	lui	a0, %hi(.L.str.30)
	addi	a0, a0, %lo(.L.str.30)
	call	printf
	j	.LBB56_147
.Ltmp630:
.LBB56_147:                             #   in Loop: Header=BB56_144 Depth=2
	.loc	2 799 9 is_stmt 1               # rnd_output0.c:799:9
	j	.LBB56_148
.Ltmp631:
.LBB56_148:                             #   in Loop: Header=BB56_144 Depth=2
	.loc	2 794 30                        # rnd_output0.c:794:30
	lw	a0, -28(s0)
	addi	a0, a0, 1
	sw	a0, -28(s0)
	.loc	2 794 9 is_stmt 0               # rnd_output0.c:794:9
	j	.LBB56_144
.Ltmp632:
.LBB56_149:                             #   in Loop: Header=BB56_142 Depth=1
	.loc	2 800 5 is_stmt 1               # rnd_output0.c:800:5
	j	.LBB56_150
.Ltmp633:
.LBB56_150:                             #   in Loop: Header=BB56_142 Depth=1
	.loc	2 792 25                        # rnd_output0.c:792:25
	lw	a0, -24(s0)
	addi	a0, a0, 1
	sw	a0, -24(s0)
	.loc	2 792 5 is_stmt 0               # rnd_output0.c:792:5
	j	.LBB56_142
.Ltmp634:
.LBB56_151:
	.loc	2 801 28 is_stmt 1              # rnd_output0.c:801:28
	lui	a0, %hi(g_2448)
	lw	a0, %lo(g_2448)(a0)
	.loc	2 801 45 is_stmt 0              # rnd_output0.c:801:45
	lw	a3, -36(s0)
	.loc	2 801 5                         # rnd_output0.c:801:5
	lui	a1, %hi(.L.str.78)
	addi	a2, a1, %lo(.L.str.78)
	li	a1, 0
	sw	a1, -92(s0)                     # 4-byte Folded Spill
	call	transparent_crc
	.loc	2 802 23 is_stmt 1              # rnd_output0.c:802:23
	lui	a0, %hi(crc32_context)
	lw	a0, %lo(crc32_context)(a0)
	.loc	2 802 37 is_stmt 0              # rnd_output0.c:802:37
	not	a0, a0
	.loc	2 802 53                        # rnd_output0.c:802:53
	lw	a1, -36(s0)
	.loc	2 802 5                         # rnd_output0.c:802:5
	call	platform_main_end
	lw	a0, -92(s0)                     # 4-byte Folded Reload
	.loc	2 803 5 is_stmt 1               # rnd_output0.c:803:5
	lw	ra, 92(sp)                      # 4-byte Folded Reload
	lw	s0, 88(sp)                      # 4-byte Folded Reload
	.loc	2 803 5 epilogue_begin is_stmt 0 # rnd_output0.c:803:5
	addi	sp, sp, 96
	ret
.Ltmp635:
.Lfunc_end56:
	.size	main, .Lfunc_end56-main
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function platform_main_begin
	.type	platform_main_begin,@function
platform_main_begin:                    # @platform_main_begin
.Lfunc_begin57:
	.loc	5 44 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:44:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
.Ltmp636:
	.loc	5 46 1 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:46:1
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	5 46 1 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:46:1
	addi	sp, sp, 16
	ret
.Ltmp637:
.Lfunc_end57:
	.size	platform_main_begin, .Lfunc_end57-platform_main_begin
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function crc32_gentab
	.type	crc32_gentab,@function
crc32_gentab:                           # @crc32_gentab
.Lfunc_begin58:
	.loc	4 52 0 is_stmt 1                # ./csmith.h:52:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
	lui	a0, 973704
	addi	a0, a0, 800
.Ltmp638:
	.loc	4 54 17 prologue_end            # ./csmith.h:54:17
	sw	a0, -16(s0)
	li	a0, 0
.Ltmp639:
	.loc	4 57 9                          # ./csmith.h:57:9
	sw	a0, -20(s0)
	.loc	4 57 7 is_stmt 0                # ./csmith.h:57:7
	j	.LBB58_1
.LBB58_1:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB58_3 Depth 2
.Ltmp640:
	.loc	4 57 14                         # ./csmith.h:57:14
	lw	a1, -20(s0)
	li	a0, 255
.Ltmp641:
	.loc	4 57 2                          # ./csmith.h:57:2
	blt	a0, a1, .LBB58_11
	j	.LBB58_2
.LBB58_2:                               #   in Loop: Header=BB58_1 Depth=1
.Ltmp642:
	.loc	4 58 9 is_stmt 1                # ./csmith.h:58:9
	lw	a0, -20(s0)
	.loc	4 58 7 is_stmt 0                # ./csmith.h:58:7
	sw	a0, -12(s0)
	li	a0, 8
.Ltmp643:
	.loc	4 59 10 is_stmt 1               # ./csmith.h:59:10
	sw	a0, -24(s0)
	.loc	4 59 8 is_stmt 0                # ./csmith.h:59:8
	j	.LBB58_3
.LBB58_3:                               #   Parent Loop BB58_1 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp644:
	.loc	4 59 15                         # ./csmith.h:59:15
	lw	a1, -24(s0)
	li	a0, 0
.Ltmp645:
	.loc	4 59 3                          # ./csmith.h:59:3
	bge	a0, a1, .LBB58_9
	j	.LBB58_4
.LBB58_4:                               #   in Loop: Header=BB58_3 Depth=2
.Ltmp646:
	.loc	4 60 12 is_stmt 1               # ./csmith.h:60:12
	lbu	a0, -12(s0)
	andi	a0, a0, 1
.Ltmp647:
	.loc	4 60 8 is_stmt 0                # ./csmith.h:60:8
	beqz	a0, .LBB58_6
	j	.LBB58_5
.LBB58_5:                               #   in Loop: Header=BB58_3 Depth=2
.Ltmp648:
	.loc	4 61 12 is_stmt 1               # ./csmith.h:61:12
	lw	a0, -12(s0)
	.loc	4 61 16 is_stmt 0               # ./csmith.h:61:16
	srli	a0, a0, 1
	lui	a1, 973704
	addi	a1, a1, 800
	.loc	4 61 22                         # ./csmith.h:61:22
	xor	a0, a0, a1
	.loc	4 61 9                          # ./csmith.h:61:9
	sw	a0, -12(s0)
	.loc	4 62 4 is_stmt 1                # ./csmith.h:62:4
	j	.LBB58_7
.Ltmp649:
.LBB58_6:                               #   in Loop: Header=BB58_3 Depth=2
	.loc	4 63 9                          # ./csmith.h:63:9
	lw	a0, -12(s0)
	srli	a0, a0, 1
	sw	a0, -12(s0)
	j	.LBB58_7
.Ltmp650:
.LBB58_7:                               #   in Loop: Header=BB58_3 Depth=2
	.loc	4 65 3                          # ./csmith.h:65:3
	j	.LBB58_8
.Ltmp651:
.LBB58_8:                               #   in Loop: Header=BB58_3 Depth=2
	.loc	4 59 23                         # ./csmith.h:59:23
	lw	a0, -24(s0)
	addi	a0, a0, -1
	sw	a0, -24(s0)
	.loc	4 59 3 is_stmt 0                # ./csmith.h:59:3
	j	.LBB58_3
.Ltmp652:
.LBB58_9:                               #   in Loop: Header=BB58_1 Depth=1
	.loc	4 66 18 is_stmt 1               # ./csmith.h:66:18
	lw	a0, -12(s0)
	.loc	4 66 13 is_stmt 0               # ./csmith.h:66:13
	lw	a1, -20(s0)
	.loc	4 66 3                          # ./csmith.h:66:3
	slli	a2, a1, 2
	lui	a1, %hi(crc32_tab)
	addi	a1, a1, %lo(crc32_tab)
	add	a1, a1, a2
	.loc	4 66 16                         # ./csmith.h:66:16
	sw	a0, 0(a1)
	.loc	4 67 2 is_stmt 1                # ./csmith.h:67:2
	j	.LBB58_10
.Ltmp653:
.LBB58_10:                              #   in Loop: Header=BB58_1 Depth=1
	.loc	4 57 24                         # ./csmith.h:57:24
	lw	a0, -20(s0)
	addi	a0, a0, 1
	sw	a0, -20(s0)
	.loc	4 57 2 is_stmt 0                # ./csmith.h:57:2
	j	.LBB58_1
.Ltmp654:
.LBB58_11:
	.loc	4 68 1 is_stmt 1                # ./csmith.h:68:1
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 68 1 epilogue_begin is_stmt 0 # ./csmith.h:68:1
	addi	sp, sp, 32
	ret
.Ltmp655:
.Lfunc_end58:
	.size	crc32_gentab, .Lfunc_end58-crc32_gentab
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function transparent_crc
	.type	transparent_crc,@function
transparent_crc:                        # @transparent_crc
.Lfunc_begin59:
	.loc	4 111 0 is_stmt 1               # ./csmith.h:111:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -32
	.cfi_def_cfa_offset 32
	sw	ra, 28(sp)                      # 4-byte Folded Spill
	sw	s0, 24(sp)                      # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 32
	.cfi_def_cfa s0, 0
                                        # kill: def $x14 killed $x11
                                        # kill: def $x14 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
	sw	a2, -20(s0)
	sw	a3, -24(s0)
.Ltmp656:
	.loc	4 112 15 prologue_end           # ./csmith.h:112:15
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	.loc	4 112 2 is_stmt 0               # ./csmith.h:112:2
	call	crc32_8bytes
.Ltmp657:
	.loc	4 113 6 is_stmt 1               # ./csmith.h:113:6
	lw	a0, -24(s0)
.Ltmp658:
	.loc	4 113 6 is_stmt 0               # ./csmith.h:113:6
	beqz	a0, .LBB59_2
	j	.LBB59_1
.LBB59_1:
.Ltmp659:
	.loc	4 114 52 is_stmt 1              # ./csmith.h:114:52
	lw	a1, -20(s0)
	.loc	4 114 59 is_stmt 0              # ./csmith.h:114:59
	lui	a0, %hi(crc32_context)
	lw	a0, %lo(crc32_context)(a0)
	.loc	4 114 73                        # ./csmith.h:114:73
	not	a2, a0
	.loc	4 114 5                         # ./csmith.h:114:5
	lui	a0, %hi(.L.str.79)
	addi	a0, a0, %lo(.L.str.79)
	call	printf
	.loc	4 115 2 is_stmt 1               # ./csmith.h:115:2
	j	.LBB59_2
.Ltmp660:
.LBB59_2:
	.loc	4 116 1                         # ./csmith.h:116:1
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 116 1 epilogue_begin is_stmt 0 # ./csmith.h:116:1
	addi	sp, sp, 32
	ret
.Ltmp661:
.Lfunc_end59:
	.size	transparent_crc, .Lfunc_end59-transparent_crc
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function platform_main_end
	.type	platform_main_end,@function
platform_main_end:                      # @platform_main_end
.Lfunc_begin60:
	.loc	5 50 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:50:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
	sw	a0, -12(s0)
	sw	a1, -16(s0)
.Ltmp662:
	.loc	5 56 29 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:56:29
	lw	a1, -12(s0)
	.loc	5 56 2 is_stmt 0                # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:56:2
	lui	a0, %hi(.L.str.80)
	addi	a0, a0, %lo(.L.str.80)
	call	printf
	.loc	5 120 1 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:120:1
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	5 120 1 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/platform_generic.h:120:1
	addi	sp, sp, 16
	ret
.Ltmp663:
.Lfunc_end60:
	.size	platform_main_end, .Lfunc_end60-platform_main_end
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function crc32_8bytes
	.type	crc32_8bytes,@function
crc32_8bytes:                           # @crc32_8bytes
.Lfunc_begin61:
	.loc	4 98 0 is_stmt 1                # ./csmith.h:98:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x12 killed $x11
                                        # kill: def $x12 killed $x10
	sw	a1, -12(s0)
	sw	a0, -16(s0)
.Ltmp664:
	.loc	4 99 15 prologue_end            # ./csmith.h:99:15
	lbu	a0, -16(s0)
	.loc	4 99 2 is_stmt 0                # ./csmith.h:99:2
	call	crc32_byte
	.loc	4 100 15 is_stmt 1              # ./csmith.h:100:15
	lbu	a0, -15(s0)
	.loc	4 100 2 is_stmt 0               # ./csmith.h:100:2
	call	crc32_byte
	.loc	4 101 15 is_stmt 1              # ./csmith.h:101:15
	lbu	a0, -14(s0)
	.loc	4 101 2 is_stmt 0               # ./csmith.h:101:2
	call	crc32_byte
	.loc	4 102 15 is_stmt 1              # ./csmith.h:102:15
	lbu	a0, -13(s0)
	.loc	4 102 2 is_stmt 0               # ./csmith.h:102:2
	call	crc32_byte
	.loc	4 103 15 is_stmt 1              # ./csmith.h:103:15
	lbu	a0, -12(s0)
	.loc	4 103 2 is_stmt 0               # ./csmith.h:103:2
	call	crc32_byte
	.loc	4 104 15 is_stmt 1              # ./csmith.h:104:15
	lbu	a0, -11(s0)
	.loc	4 104 2 is_stmt 0               # ./csmith.h:104:2
	call	crc32_byte
	.loc	4 105 15 is_stmt 1              # ./csmith.h:105:15
	lbu	a0, -10(s0)
	.loc	4 105 2 is_stmt 0               # ./csmith.h:105:2
	call	crc32_byte
	.loc	4 106 15 is_stmt 1              # ./csmith.h:106:15
	lbu	a0, -9(s0)
	.loc	4 106 2 is_stmt 0               # ./csmith.h:106:2
	call	crc32_byte
	.loc	4 107 1 is_stmt 1               # ./csmith.h:107:1
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 107 1 epilogue_begin is_stmt 0 # ./csmith.h:107:1
	addi	sp, sp, 16
	ret
.Ltmp665:
.Lfunc_end61:
	.size	crc32_8bytes, .Lfunc_end61-crc32_8bytes
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function crc32_byte
	.type	crc32_byte,@function
crc32_byte:                             # @crc32_byte
.Lfunc_begin62:
	.loc	4 71 0 is_stmt 1                # ./csmith.h:71:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -16
	.cfi_def_cfa_offset 16
	sw	ra, 12(sp)                      # 4-byte Folded Spill
	sw	s0, 8(sp)                       # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 16
	.cfi_def_cfa s0, 0
                                        # kill: def $x11 killed $x10
	sb	a0, -9(s0)
.Ltmp666:
	.loc	4 73 5 prologue_end             # ./csmith.h:73:5
	lui	a1, %hi(crc32_context)
	lw	a2, %lo(crc32_context)(a1)
	.loc	4 73 19 is_stmt 0               # ./csmith.h:73:19
	srli	a0, a2, 8
	.loc	4 74 30 is_stmt 1               # ./csmith.h:74:30
	lbu	a3, -9(s0)
	.loc	4 74 28 is_stmt 0               # ./csmith.h:74:28
	xor	a2, a2, a3
	.loc	4 74 33                         # ./csmith.h:74:33
	andi	a2, a2, 255
	.loc	4 74 3                          # ./csmith.h:74:3
	slli	a3, a2, 2
	lui	a2, %hi(crc32_tab)
	addi	a2, a2, %lo(crc32_tab)
	add	a2, a2, a3
	lw	a2, 0(a2)
	.loc	4 73 39 is_stmt 1               # ./csmith.h:73:39
	xor	a0, a0, a2
	.loc	4 72 16                         # ./csmith.h:72:16
	sw	a0, %lo(crc32_context)(a1)
	.loc	4 75 1                          # ./csmith.h:75:1
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 75 1 epilogue_begin is_stmt 0 # ./csmith.h:75:1
	addi	sp, sp, 16
	ret
.Ltmp667:
.Lfunc_end62:
	.size	crc32_byte, .Lfunc_end62-crc32_byte
	.cfi_endproc
                                        # -- End function
	.type	g_3,@object                     # @g_3
	.section	.sdata,"aw",@progbits
	.globl	g_3
	.p2align	2
g_3:
	.word	503185553                       # 0x1dfe0091
	.size	g_3, 4

	.type	g_73,@object                    # @g_73
	.globl	g_73
	.p2align	2
g_73:
	.word	g_70+80
	.size	g_73, 4

	.type	g_97,@object                    # @g_97
	.globl	g_97
	.p2align	2
g_97:
	.word	g_8+272
	.size	g_97, 4

	.type	g_124,@object                   # @g_124
	.section	.rodata,"a",@progbits
	.globl	g_124
	.p2align	2, 0x0
g_124:
	.word	72975627                        # 0x459850b
	.size	g_124, 4

	.type	g_197,@object                   # @g_197
	.data
	.globl	g_197
g_197:
	.ascii	"\340\373j\001"
	.ascii	"#\373\373#"
	.ascii	"\373#\340\003"
	.ascii	"\373\340\373j"
	.ascii	"#\003jj"
	.ascii	"\340\340\001\003"
	.ascii	"\003#\001#"
	.ascii	"\340\373j\001"
	.ascii	"#\373\373#"
	.ascii	"\373#\340\003"
	.size	g_197, 40

	.type	g_200,@object                   # @g_200
	.section	.sdata,"aw",@progbits
	.globl	g_200
	.p2align	2
g_200:
	.word	g_69+32
	.size	g_200, 4

	.type	g_199,@object                   # @g_199
	.data
	.globl	g_199
	.p2align	2, 0x0
g_199:
	.word	g_200
	.word	0
	.word	0
	.word	g_200
	.word	g_200
	.word	g_200
	.word	0
	.word	0
	.word	g_200
	.word	g_200
	.size	g_199, 40

	.type	g_302,@object                   # @g_302
	.section	.sdata,"aw",@progbits
	.globl	g_302
	.p2align	2
g_302:
	.word	2                               # 0x2
	.size	g_302, 4

	.type	g_334,@object                   # @g_334
	.globl	g_334
	.p2align	2
g_334:
	.word	g_13
	.size	g_334, 4

	.type	g_467,@object                   # @g_467
	.data
	.globl	g_467
	.p2align	2, 0x0
g_467:
	.word	g_200
	.word	0
	.word	g_200
	.word	g_200
	.word	0
	.word	g_200
	.word	g_200
	.word	0
	.word	g_200
	.size	g_467, 36

	.type	g_500,@object                   # @g_500
	.section	.sdata,"aw",@progbits
	.globl	g_500
	.p2align	2
g_500:
	.word	g_477
	.size	g_500, 4

	.type	g_524,@object                   # @g_524
	.globl	g_524
	.p2align	2
g_524:
	.word	g_70+80
	.size	g_524, 4

	.type	g_556,@object                   # @g_556
	.data
	.globl	g_556
	.p2align	4, 0x0
g_556:
	.word	4294967295                      # 0xffffffff
	.word	1567011079                      # 0x5d66b107
	.zero	8
	.size	g_556, 16

	.type	g_555,@object                   # @g_555
	.globl	g_555
	.p2align	2, 0x0
g_555:
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	0
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_70+80
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	0
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_70+80
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	0
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_70+80
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	0
	.word	g_556
	.word	0
	.size	g_555, 576

	.type	g_672,@object                   # @g_672
	.globl	g_672
	.p2align	2, 0x0
g_672:
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.word	g_73
	.size	g_672, 576

	.type	g_901,@object                   # @g_901
	.globl	g_901
	.p2align	2, 0x0
g_901:
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.word	g_501
	.size	g_901, 36

	.type	g_932,@object                   # @g_932
	.section	.sdata,"aw",@progbits
	.globl	g_932
	.p2align	2
g_932:
	.word	2031194644                      # 0x79119214
	.size	g_932, 4

	.type	g_946,@object                   # @g_946
	.data
	.globl	g_946
	.p2align	4, 0x0
g_946:
	.word	1798423859                      # 0x6b31c533
	.word	85161018                        # 0x513743a
	.zero	8
	.size	g_946, 16

	.type	g_1000,@object                  # @g_1000
	.section	.sdata,"aw",@progbits
	.globl	g_1000
	.p2align	2
g_1000:
	.word	1725855004                      # 0x66de751c
	.size	g_1000, 4

	.type	g_1247,@object                  # @g_1247
	.section	.sbss,"aw",@nobits
	.globl	g_1247
	.p2align	2
g_1247:
	.word	0
	.size	g_1247, 4

	.type	g_1259,@object                  # @g_1259
	.data
	.globl	g_1259
	.p2align	2, 0x0
g_1259:
	.word	1152036948                      # 0x44aab054
	.word	8                               # 0x8
	.word	2736513609                      # 0xa31be249
	.word	4294967295                      # 0xffffffff
	.word	1152036948                      # 0x44aab054
	.word	240879750                       # 0xe5b8886
	.word	1636604803                      # 0x618c9b83
	.word	3672539937                      # 0xdae68321
	.word	1636604803                      # 0x618c9b83
	.word	240879750                       # 0xe5b8886
	.word	2066768880                      # 0x7b3063f0
	.word	101828961                       # 0x611c961
	.word	4294967295                      # 0xffffffff
	.word	101828961                       # 0x611c961
	.word	2066768880                      # 0x7b3063f0
	.word	877938942                       # 0x345448fe
	.word	1152036948                      # 0x44aab054
	.word	4294967295                      # 0xffffffff
	.word	9                               # 0x9
	.word	8                               # 0x8
	.word	2628511773                      # 0x9cabe81d
	.word	9                               # 0x9
	.word	2265683553                      # 0x870b9661
	.word	4224567368                      # 0xfbcdc848
	.word	4294967295                      # 0xffffffff
	.word	2736513609                      # 0xa31be249
	.word	877938942                       # 0x345448fe
	.word	1                               # 0x1
	.word	8                               # 0x8
	.word	8                               # 0x8
	.word	1152036948                      # 0x44aab054
	.word	4224567368                      # 0xfbcdc848
	.word	2628511773                      # 0x9cabe81d
	.word	2066768880                      # 0x7b3063f0
	.word	2066768880                      # 0x7b3063f0
	.word	2628511773                      # 0x9cabe81d
	.word	4224567368                      # 0xfbcdc848
	.word	1152036948                      # 0x44aab054
	.word	101828961                       # 0x611c961
	.word	240879750                       # 0xe5b8886
	.word	240879750                       # 0xe5b8886
	.word	2736513609                      # 0xa31be249
	.word	0                               # 0x0
	.word	2628511773                      # 0x9cabe81d
	.word	1152036948                      # 0x44aab054
	.word	1                               # 0x1
	.word	4                               # 0x4
	.word	4294967295                      # 0xffffffff
	.word	3672539937                      # 0xdae68321
	.word	2066768880                      # 0x7b3063f0
	.size	g_1259, 200

	.type	g_1374,@object                  # @g_1374
	.section	.sdata,"aw",@progbits
	.globl	g_1374
	.p2align	2
g_1374:
	.word	g_1375+8
	.size	g_1374, 4

	.type	g_1380,@object                  # @g_1380
	.data
	.globl	g_1380
	.p2align	2, 0x0
g_1380:
	.word	g_3
	.word	g_3
	.word	g_3
	.size	g_1380, 12

	.type	g_1571,@object                  # @g_1571
	.section	.sbss,"aw",@nobits
	.globl	g_1571
	.p2align	2
g_1571:
	.word	0
	.size	g_1571, 4

	.type	g_1717,@object                  # @g_1717
	.data
	.globl	g_1717
	.p2align	2, 0x0
g_1717:
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.word	4294967288                      # 0xfffffff8
	.word	3708320578                      # 0xdd087b42
	.word	3708320578                      # 0xdd087b42
	.word	4294967288                      # 0xfffffff8
	.word	670129472                       # 0x27f15d40
	.word	1                               # 0x1
	.word	670129472                       # 0x27f15d40
	.size	g_1717, 320

	.type	g_1781,@object                  # @g_1781
	.section	.sdata,"aw",@progbits
	.globl	g_1781
	.p2align	2
g_1781:
	.word	1523739916                      # 0x5ad26d0c
	.size	g_1781, 4

	.type	g_1816,@object                  # @g_1816
	.section	.sbss,"aw",@nobits
	.globl	g_1816
	.p2align	2
g_1816:
	.zero	4
	.size	g_1816, 4

	.type	g_1817,@object                  # @g_1817
	.section	.rodata,"a",@progbits
	.globl	g_1817
	.p2align	2, 0x0
g_1817:
	.word	943519593                       # 0x383cf769
	.size	g_1817, 4

	.type	g_1811,@object                  # @g_1811
	.data
	.globl	g_1811
	.p2align	2, 0x0
g_1811:
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	0
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	0
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	g_1813
	.word	g_1815
	.word	0
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	0
	.word	g_1812
	.word	g_1812
	.word	0
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.word	g_1813
	.word	g_1818+32
	.size	g_1811, 252

	.type	g_2016,@object                  # @g_2016
	.section	.sdata,"aw",@progbits
	.globl	g_2016
g_2016:
	.byte	202                             # 0xca
	.size	g_2016, 1

	.type	g_2014,@object                  # @g_2014
	.globl	g_2014
	.p2align	2
g_2014:
	.word	g_2015
	.size	g_2014, 4

	.type	g_2201,@object                  # @g_2201
	.globl	g_2201
	.p2align	2
g_2201:
	.word	4294967295                      # 0xffffffff
	.size	g_2201, 4

	.type	.L__const.func_40.l_529,@object # @__const.func_40.l_529
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_529:
	.word	3706738540                      # 0xdcf0576c
	.word	1                               # 0x1
	.zero	8
	.size	.L__const.func_40.l_529, 16

	.type	.L__const.func_40.l_551,@object # @__const.func_40.l_551
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_40.l_551:
	.word	g_136+56
	.word	g_136+72
	.word	g_136+28
	.word	g_136+52
	.word	g_136+28
	.word	0
	.word	g_136+28
	.word	0
	.word	0
	.word	g_136+44
	.word	g_136+68
	.word	g_136+28
	.word	g_136+108
	.word	g_136+48
	.word	g_136+28
	.word	g_136+112
	.word	g_136+108
	.word	g_136
	.word	g_136+52
	.word	g_136+28
	.word	g_136+72
	.word	g_136+36
	.word	g_136+108
	.word	g_136+32
	.word	g_136+44
	.word	g_136+48
	.word	g_136+16
	.word	g_136+28
	.word	g_136+68
	.word	g_136+28
	.word	g_136+28
	.word	0
	.word	g_136+36
	.word	g_136+28
	.word	g_136+28
	.word	g_136+44
	.word	g_136+28
	.word	g_136+72
	.word	g_136+108
	.word	g_136+44
	.word	g_136+116
	.word	g_136+28
	.word	g_136+36
	.word	g_136+44
	.word	g_136+28
	.word	g_136+52
	.word	g_136+44
	.word	g_136+28
	.word	g_136+112
	.word	g_136+28
	.word	g_136+108
	.word	g_136+108
	.word	g_136+32
	.word	g_136+44
	.size	.L__const.func_40.l_551, 216

	.type	.L__const.func_40.l_552,@object # @__const.func_40.l_552
	.p2align	4, 0x0
.L__const.func_40.l_552:
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1935831131                      # 0x7362705b
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1935831131                      # 0x7362705b
	.zero	8
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	3114109369                      # 0xb99d89b9
	.word	4294967287                      # 0xfffffff7
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1935831131                      # 0x7362705b
	.zero	8
	.word	3842284155                      # 0xe5049a7b
	.word	541735336                       # 0x204a39a8
	.zero	8
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	0                               # 0x0
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1935831131                      # 0x7362705b
	.zero	8
	.word	3114109369                      # 0xb99d89b9
	.word	4294967287                      # 0xfffffff7
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	3114109369                      # 0xb99d89b9
	.word	4294967287                      # 0xfffffff7
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	3842284155                      # 0xe5049a7b
	.word	541735336                       # 0x204a39a8
	.zero	8
	.word	3842284155                      # 0xe5049a7b
	.word	541735336                       # 0x204a39a8
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.word	0                               # 0x0
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1935831131                      # 0x7362705b
	.zero	8
	.word	3842284155                      # 0xe5049a7b
	.word	541735336                       # 0x204a39a8
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.word	3114109369                      # 0xb99d89b9
	.word	4294967287                      # 0xfffffff7
	.zero	8
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	3114109369                      # 0xb99d89b9
	.word	4294967287                      # 0xfffffff7
	.zero	8
	.word	3842284155                      # 0xe5049a7b
	.word	541735336                       # 0x204a39a8
	.zero	8
	.word	2635547234                      # 0x9d174262
	.word	718955026                       # 0x2ada6212
	.zero	8
	.word	0                               # 0x0
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	0                               # 0x0
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	1                               # 0x1
	.word	229562935                       # 0xdaeda37
	.zero	8
	.size	.L__const.func_40.l_552, 576

	.type	.L__const.func_40.l_775,@object # @__const.func_40.l_775
	.p2align	2, 0x0
.L__const.func_40.l_775:
	.word	4294967295                      # 0xffffffff
	.word	1066920729                      # 0x3f97eb19
	.word	1684796561                      # 0x646bf491
	.word	3336263570                      # 0xc6db5792
	.word	9                               # 0x9
	.word	3896334085                      # 0xe83d5705
	.word	2                               # 0x2
	.word	1066920729                      # 0x3f97eb19
	.word	4294967295                      # 0xffffffff
	.word	2287599325                      # 0x8859fedd
	.word	4294967287                      # 0xfffffff7
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.word	3112876679                      # 0xb98aba87
	.word	0                               # 0x0
	.word	9                               # 0x9
	.word	3715007813                      # 0xdd6e8545
	.word	0                               # 0x0
	.word	9                               # 0x9
	.word	9                               # 0x9
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	3896334085                      # 0xe83d5705
	.word	1066920729                      # 0x3f97eb19
	.word	2287599325                      # 0x8859fedd
	.word	3020488997                      # 0xb4090125
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	3336263570                      # 0xc6db5792
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	9                               # 0x9
	.word	1066920729                      # 0x3f97eb19
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	2287599325                      # 0x8859fedd
	.word	2287599325                      # 0x8859fedd
	.word	77325658                        # 0x49be55a
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	77325658                        # 0x49be55a
	.word	0                               # 0x0
	.word	3561848503                      # 0xd44d7eb7
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.word	2                               # 0x2
	.word	9                               # 0x9
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	2287599325                      # 0x8859fedd
	.word	3896334085                      # 0xe83d5705
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	1684796561                      # 0x646bf491
	.word	1                               # 0x1
	.word	3020488997                      # 0xb4090125
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	3896334085                      # 0xe83d5705
	.word	466281900                       # 0x1bcae5ac
	.word	3561848503                      # 0xd44d7eb7
	.word	9                               # 0x9
	.word	3715007813                      # 0xdd6e8545
	.zero	12
	.word	2                               # 0x2
	.word	3561848503                      # 0xd44d7eb7
	.word	3020488997                      # 0xb4090125
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	1684796561                      # 0x646bf491
	.word	3896334085                      # 0xe83d5705
	.word	1                               # 0x1
	.word	3112876679                      # 0xb98aba87
	.word	1066920729                      # 0x3f97eb19
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	466281900                       # 0x1bcae5ac
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	2                               # 0x2
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	3561848503                      # 0xd44d7eb7
	.word	1684796561                      # 0x646bf491
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	77325658                        # 0x49be55a
	.word	2287599325                      # 0x8859fedd
	.word	2287599325                      # 0x8859fedd
	.word	2                               # 0x2
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	4294967295                      # 0xffffffff
	.word	4294967287                      # 0xfffffff7
	.word	466281900                       # 0x1bcae5ac
	.word	3336263570                      # 0xc6db5792
	.word	1684796561                      # 0x646bf491
	.word	1066920729                      # 0x3f97eb19
	.word	2                               # 0x2
	.word	4294967287                      # 0xfffffff7
	.word	3896334085                      # 0xe83d5705
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	2                               # 0x2
	.word	9                               # 0x9
	.word	77325658                        # 0x49be55a
	.word	1684796561                      # 0x646bf491
	.word	9                               # 0x9
	.word	1684796561                      # 0x646bf491
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	3715007813                      # 0xdd6e8545
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	3336263570                      # 0xc6db5792
	.word	3112876679                      # 0xb98aba87
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	1684796561                      # 0x646bf491
	.word	3715007813                      # 0xdd6e8545
	.word	1                               # 0x1
	.word	3020488997                      # 0xb4090125
	.word	4294967295                      # 0xffffffff
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	1684796561                      # 0x646bf491
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	3561848503                      # 0xd44d7eb7
	.word	3020488997                      # 0xb4090125
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	1684796561                      # 0x646bf491
	.word	3896334085                      # 0xe83d5705
	.word	1                               # 0x1
	.word	3112876679                      # 0xb98aba87
	.word	1066920729                      # 0x3f97eb19
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	466281900                       # 0x1bcae5ac
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	2                               # 0x2
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	3561848503                      # 0xd44d7eb7
	.word	1684796561                      # 0x646bf491
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	77325658                        # 0x49be55a
	.word	2287599325                      # 0x8859fedd
	.word	2287599325                      # 0x8859fedd
	.word	2                               # 0x2
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	4294967295                      # 0xffffffff
	.word	4294967287                      # 0xfffffff7
	.word	466281900                       # 0x1bcae5ac
	.word	3336263570                      # 0xc6db5792
	.word	1684796561                      # 0x646bf491
	.word	1066920729                      # 0x3f97eb19
	.word	2                               # 0x2
	.word	4294967287                      # 0xfffffff7
	.word	3896334085                      # 0xe83d5705
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	2                               # 0x2
	.word	9                               # 0x9
	.word	77325658                        # 0x49be55a
	.word	1684796561                      # 0x646bf491
	.word	9                               # 0x9
	.word	1684796561                      # 0x646bf491
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	3715007813                      # 0xdd6e8545
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	3336263570                      # 0xc6db5792
	.word	3112876679                      # 0xb98aba87
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	1684796561                      # 0x646bf491
	.word	3715007813                      # 0xdd6e8545
	.word	1                               # 0x1
	.word	3020488997                      # 0xb4090125
	.word	4294967295                      # 0xffffffff
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	1684796561                      # 0x646bf491
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	3561848503                      # 0xd44d7eb7
	.word	3020488997                      # 0xb4090125
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	1684796561                      # 0x646bf491
	.word	3896334085                      # 0xe83d5705
	.word	1                               # 0x1
	.word	3112876679                      # 0xb98aba87
	.word	1066920729                      # 0x3f97eb19
	.word	2287599325                      # 0x8859fedd
	.word	1                               # 0x1
	.word	466281900                       # 0x1bcae5ac
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	2                               # 0x2
	.word	2                               # 0x2
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	3561848503                      # 0xd44d7eb7
	.word	1684796561                      # 0x646bf491
	.word	2287599325                      # 0x8859fedd
	.word	0                               # 0x0
	.word	77325658                        # 0x49be55a
	.size	.L__const.func_40.l_775, 972

	.type	.L__const.func_40.l_792,@object # @__const.func_40.l_792
	.p2align	2, 0x0
.L__const.func_40.l_792:
	.word	4294967288                      # 0xfffffff8
	.word	1530003658                      # 0x5b3200ca
	.word	2310942536                      # 0x89be2f48
	.word	1530003658                      # 0x5b3200ca
	.word	3571588864                      # 0xd4e21f00
	.word	3054973357                      # 0xb61731ad
	.word	7590468                         # 0x73d244
	.word	2310942536                      # 0x89be2f48
	.word	1530003658                      # 0x5b3200ca
	.word	3054973357                      # 0xb61731ad
	.word	3054973357                      # 0xb61731ad
	.word	1530003658                      # 0x5b3200ca
	.word	3054973357                      # 0xb61731ad
	.word	1530003658                      # 0x5b3200ca
	.word	3571588864                      # 0xd4e21f00
	.word	7590468                         # 0x73d244
	.word	4294967288                      # 0xfffffff8
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	2310942536                      # 0x89be2f48
	.word	3054973357                      # 0xb61731ad
	.word	7590468                         # 0x73d244
	.word	2310942536                      # 0x89be2f48
	.word	2310942536                      # 0x89be2f48
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	3571588864                      # 0xd4e21f00
	.word	7590468                         # 0x73d244
	.word	7590468                         # 0x73d244
	.word	3054973357                      # 0xb61731ad
	.word	3571588864                      # 0xd4e21f00
	.word	3054973357                      # 0xb61731ad
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	2310942536                      # 0x89be2f48
	.word	3571588864                      # 0xd4e21f00
	.word	3054973357                      # 0xb61731ad
	.word	4294967288                      # 0xfffffff8
	.word	4294967288                      # 0xfffffff8
	.word	3054973357                      # 0xb61731ad
	.word	4294967288                      # 0xfffffff8
	.word	3054973357                      # 0xb61731ad
	.word	1                               # 0x1
	.word	7590468                         # 0x73d244
	.word	4294967288                      # 0xfffffff8
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	2310942536                      # 0x89be2f48
	.word	3054973357                      # 0xb61731ad
	.word	7590468                         # 0x73d244
	.word	2310942536                      # 0x89be2f48
	.word	2310942536                      # 0x89be2f48
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	3571588864                      # 0xd4e21f00
	.word	7590468                         # 0x73d244
	.word	7590468                         # 0x73d244
	.word	3054973357                      # 0xb61731ad
	.word	3571588864                      # 0xd4e21f00
	.word	3054973357                      # 0xb61731ad
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	2310942536                      # 0x89be2f48
	.word	3571588864                      # 0xd4e21f00
	.word	3054973357                      # 0xb61731ad
	.word	4294967288                      # 0xfffffff8
	.word	4294967288                      # 0xfffffff8
	.word	3054973357                      # 0xb61731ad
	.word	4294967288                      # 0xfffffff8
	.word	3054973357                      # 0xb61731ad
	.word	1                               # 0x1
	.word	7590468                         # 0x73d244
	.word	4294967288                      # 0xfffffff8
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	2310942536                      # 0x89be2f48
	.word	3054973357                      # 0xb61731ad
	.word	7590468                         # 0x73d244
	.word	2310942536                      # 0x89be2f48
	.word	2310942536                      # 0x89be2f48
	.size	.L__const.func_40.l_792, 320

	.type	.L__const.func_40.l_969,@object # @__const.func_40.l_969
	.p2align	2, 0x0
.L__const.func_40.l_969:
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.word	921616339                       # 0x36eebfd3
	.word	921616339                       # 0x36eebfd3
	.word	3322918256                      # 0xc60fb570
	.word	2951356590                      # 0xafea20ae
	.word	3322918256                      # 0xc60fb570
	.size	.L__const.func_40.l_969, 360

	.type	.L__const.func_40.l_1123,@object # @__const.func_40.l_1123
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1123:
	.word	3662609770                      # 0xda4efd6a
	.word	895476313                       # 0x355fe259
	.zero	8
	.size	.L__const.func_40.l_1123, 16

	.type	.L__const.func_40.l_490,@object # @__const.func_40.l_490
	.p2align	4, 0x0
.L__const.func_40.l_490:
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.zero	8
	.size	.L__const.func_40.l_490, 16

	.type	.L__const.func_40.l_646,@object # @__const.func_40.l_646
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_40.l_646:
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.word	g_556
	.size	.L__const.func_40.l_646, 288

	.type	.L__const.func_40.l_764,@object # @__const.func_40.l_764
	.p2align	4, 0x0
.L__const.func_40.l_764:
	.word	1                               # 0x1
	.word	1874486008                      # 0x6fba62f8
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	1356884453                      # 0x50e069e5
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	823927431                       # 0x311c2287
	.word	1157643431                      # 0x45003ca7
	.zero	8
	.word	1356884453                      # 0x50e069e5
	.word	0                               # 0x0
	.zero	8
	.word	1356884453                      # 0x50e069e5
	.word	0                               # 0x0
	.zero	8
	.word	1                               # 0x1
	.word	1874486008                      # 0x6fba62f8
	.zero	8
	.word	1                               # 0x1
	.word	1874486008                      # 0x6fba62f8
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	1356884453                      # 0x50e069e5
	.word	0                               # 0x0
	.zero	8
	.word	1                               # 0x1
	.word	790986234                       # 0x2f257dfa
	.zero	8
	.word	823927431                       # 0x311c2287
	.word	1157643431                      # 0x45003ca7
	.zero	8
	.word	1                               # 0x1
	.word	790986234                       # 0x2f257dfa
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	1                               # 0x1
	.word	790986234                       # 0x2f257dfa
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	1                               # 0x1
	.word	790986234                       # 0x2f257dfa
	.zero	8
	.word	1                               # 0x1
	.word	1874486008                      # 0x6fba62f8
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.word	1356884453                      # 0x50e069e5
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	3320325844                      # 0xc5e826d4
	.zero	8
	.size	.L__const.func_40.l_764, 384

	.type	.L__const.func_40.l_966,@object # @__const.func_40.l_966
.L__const.func_40.l_966:
	.ascii	"W\001WW\001W"
	.size	.L__const.func_40.l_966, 6

	.type	.L__const.func_40.l_1053,@object # @__const.func_40.l_1053
	.p2align	2, 0x0
.L__const.func_40.l_1053:
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.word	2739797080                      # 0xa34dfc58
	.size	.L__const.func_40.l_1053, 64

	.type	.L__const.func_40.l_1066,@object # @__const.func_40.l_1066
	.p2align	2, 0x0
.L__const.func_40.l_1066:
	.word	197189478                       # 0xbc0df66
	.word	197189478                       # 0xbc0df66
	.word	197189478                       # 0xbc0df66
	.word	197189478                       # 0xbc0df66
	.word	197189478                       # 0xbc0df66
	.word	197189478                       # 0xbc0df66
	.size	.L__const.func_40.l_1066, 24

	.type	.L__const.func_40.l_1060,@object # @__const.func_40.l_1060
	.p2align	2, 0x0
.L__const.func_40.l_1060:
	.word	4176454387                      # 0xf8efa2f3
	.word	2                               # 0x2
	.word	4176454387                      # 0xf8efa2f3
	.word	2                               # 0x2
	.word	4176454387                      # 0xf8efa2f3
	.word	2                               # 0x2
	.word	4176454387                      # 0xf8efa2f3
	.word	2                               # 0x2
	.word	4176454387                      # 0xf8efa2f3
	.size	.L__const.func_40.l_1060, 36

	.type	.L__const.func_40.l_1092,@object # @__const.func_40.l_1092
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1092:
	.word	1910991659                      # 0x71e76b2b
	.word	4294967295                      # 0xffffffff
	.zero	8
	.size	.L__const.func_40.l_1092, 16

	.type	.L__const.func_40.l_1304,@object # @__const.func_40.l_1304
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_40.l_1304:
	.word	g_136+32
	.word	g_645
	.word	g_1113
	.word	g_1292
	.word	g_645
	.word	g_1292
	.word	g_1113
	.word	g_136+32
	.word	g_1113
	.word	g_1113
	.word	g_1292
	.word	g_136+8
	.word	0
	.word	g_1113
	.word	g_1292
	.word	g_136+28
	.word	g_1292
	.word	g_1292
	.word	g_136+28
	.word	g_1292
	.word	g_1292
	.word	g_136+28
	.word	g_1292
	.word	g_1113
	.word	0
	.word	g_136+8
	.word	g_1292
	.word	g_1113
	.word	g_1113
	.word	g_136+32
	.size	.L__const.func_40.l_1304, 120

	.type	.L__const.func_40.l_1323,@object # @__const.func_40.l_1323
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1323:
	.word	3827920013                      # 0xe4296c8d
	.word	2864074095                      # 0xaab64d6f
	.zero	8
	.size	.L__const.func_40.l_1323, 16

	.type	.L__const.func_40.l_1411,@object # @__const.func_40.l_1411
	.section	.rodata,"a",@progbits
	.p2align	3, 0x0
.L__const.func_40.l_1411:
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8,255
	.quad	-7                              # 0xfffffffffffffff9
	.quad	-7                              # 0xfffffffffffffff9
	.zero	8,255
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8
	.quad	5                               # 0x5
	.quad	2                               # 0x2
	.quad	5                               # 0x5
	.zero	8
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8,255
	.quad	-7                              # 0xfffffffffffffff9
	.quad	-7                              # 0xfffffffffffffff9
	.zero	8,255
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8
	.quad	5                               # 0x5
	.quad	2                               # 0x2
	.quad	5                               # 0x5
	.zero	8
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8,255
	.quad	-7                              # 0xfffffffffffffff9
	.quad	-7                              # 0xfffffffffffffff9
	.zero	8,255
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8
	.quad	5                               # 0x5
	.quad	2                               # 0x2
	.quad	5                               # 0x5
	.zero	8
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8,255
	.quad	-7                              # 0xfffffffffffffff9
	.quad	-7                              # 0xfffffffffffffff9
	.zero	8,255
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8
	.quad	5                               # 0x5
	.quad	2                               # 0x2
	.quad	5                               # 0x5
	.zero	8
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8,255
	.quad	-7                              # 0xfffffffffffffff9
	.quad	-7                              # 0xfffffffffffffff9
	.zero	8,255
	.quad	1494246027021022811             # 0x14bca0d83fa0765b
	.zero	8
	.quad	5                               # 0x5
	.quad	2                               # 0x2
	.quad	5                               # 0x5
	.size	.L__const.func_40.l_1411, 432

	.type	.L__const.func_40.l_1153,@object # @__const.func_40.l_1153
	.p2align	4, 0x0
.L__const.func_40.l_1153:
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	1153996112                      # 0x44c89550
	.word	1172187130                      # 0x45de27fa
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	1153996112                      # 0x44c89550
	.word	1172187130                      # 0x45de27fa
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	1153996112                      # 0x44c89550
	.word	1172187130                      # 0x45de27fa
	.zero	8
	.size	.L__const.func_40.l_1153, 128

	.type	.L__const.func_40.tmp,@object   # @__const.func_40.tmp
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.tmp:
	.word	459640643                       # 0x1b658f43
	.word	274355123                       # 0x105a53b3
	.zero	8
	.size	.L__const.func_40.tmp, 16

	.type	.L__const.func_40.l_1246,@object # @__const.func_40.l_1246
	.section	.rodata,"a",@progbits
.L__const.func_40.l_1246:
	.asciz	"i\204\001\0013\001"
	.ascii	"\001C\373\001\001\373C"
	.ascii	"i\001\204|\370\373\001"
	.ascii	"\001\221\235\001\372\001\372"
	.ascii	"|\372\372|y\001\001"
	.size	.L__const.func_40.l_1246, 35

	.type	.L__const.func_40.l_1230,@object # @__const.func_40.l_1230
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1230:
	.word	76453353                        # 0x48e95e9
	.word	1241231519                      # 0x49fbb09f
	.zero	8
	.size	.L__const.func_40.l_1230, 16

	.type	.L__const.func_40.l_1281,@object # @__const.func_40.l_1281
	.p2align	4, 0x0
.L__const.func_40.l_1281:
	.word	4294967287                      # 0xfffffff7
	.word	4294967295                      # 0xffffffff
	.zero	8
	.size	.L__const.func_40.l_1281, 16

	.type	.L__const.func_40.l_1322,@object # @__const.func_40.l_1322
	.p2align	4, 0x0
.L__const.func_40.l_1322:
	.word	1                               # 0x1
	.word	2622343141                      # 0x9c4dc7e5
	.zero	8
	.size	.L__const.func_40.l_1322, 16

	.type	.L__const.func_40.l_1433,@object # @__const.func_40.l_1433
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_40.l_1433:
	.word	7                               # 0x7
	.word	2096674780                      # 0x7cf8b7dc
	.word	2096674780                      # 0x7cf8b7dc
	.word	7                               # 0x7
	.word	9                               # 0x9
	.word	1420271912                      # 0x54a7a128
	.word	3568607090                      # 0xd4b49f72
	.word	2929714597                      # 0xae9fe5a5
	.word	809649000                       # 0x30424368
	.word	2452584537                      # 0x922f7859
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.word	998247671                       # 0x3b800cf7
	.word	998247671                       # 0x3b800cf7
	.word	0                               # 0x0
	.word	4294967295                      # 0xffffffff
	.word	2452584537                      # 0x922f7859
	.word	2964065482                      # 0xb0ac0cca
	.word	4294967295                      # 0xffffffff
	.word	1834063390                      # 0x6d51961e
	.word	809649000                       # 0x30424368
	.word	5                               # 0x5
	.word	9                               # 0x9
	.word	2929714597                      # 0xae9fe5a5
	.word	2929714597                      # 0xae9fe5a5
	.word	9                               # 0x9
	.word	5                               # 0x5
	.word	1817054067                      # 0x6c4e0b73
	.word	4294967295                      # 0xffffffff
	.word	1817054067                      # 0x6c4e0b73
	.word	2559720821                      # 0x98923d75
	.word	608272450                       # 0x24418042
	.word	0                               # 0x0
	.word	1817054067                      # 0x6c4e0b73
	.word	752282159                       # 0x2cd6ea2f
	.word	752282159                       # 0x2cd6ea2f
	.word	7                               # 0x7
	.word	5                               # 0x5
	.word	3568607090                      # 0xd4b49f72
	.word	9                               # 0x9
	.word	3568607090                      # 0xd4b49f72
	.word	5                               # 0x5
	.word	7                               # 0x7
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.word	1817054067                      # 0x6c4e0b73
	.word	0                               # 0x0
	.word	608272450                       # 0x24418042
	.word	4294967286                      # 0xfffffff6
	.word	998247671                       # 0x3b800cf7
	.word	2452584537                      # 0x922f7859
	.word	998247671                       # 0x3b800cf7
	.word	4294967286                      # 0xfffffff6
	.word	608272450                       # 0x24418042
	.size	.L__const.func_40.l_1433, 216

	.type	.L__const.func_40.l_1437,@object # @__const.func_40.l_1437
	.p2align	2, 0x0
.L__const.func_40.l_1437:
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.word	g_71
	.size	.L__const.func_40.l_1437, 120

	.type	.L__const.func_40.l_1516,@object # @__const.func_40.l_1516
	.p2align	2, 0x0
.L__const.func_40.l_1516:
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.zero	4
	.word	g_152
	.zero	4
	.zero	4
	.size	.L__const.func_40.l_1516, 128

	.type	.Lconstinit,@object             # @constinit
	.p2align	2, 0x0
.Lconstinit:
	.word	g_467+12
	.word	0
	.word	0
	.word	g_467+12
	.word	g_467+20
	.word	g_467+24
	.size	.Lconstinit, 24

	.type	.Lconstinit.1,@object           # @constinit.1
	.p2align	2, 0x0
.Lconstinit.1:
	.word	g_467+20
	.word	g_71
	.word	g_71
	.word	g_467+4
	.word	g_467+12
	.word	g_467+8
	.size	.Lconstinit.1, 24

	.type	.Lconstinit.2,@object           # @constinit.2
	.p2align	2, 0x0
.Lconstinit.2:
	.word	g_467+24
	.word	g_467+4
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.size	.Lconstinit.2, 24

	.type	.Lconstinit.3,@object           # @constinit.3
	.p2align	2, 0x0
.Lconstinit.3:
	.word	g_71
	.word	g_71
	.word	g_467+24
	.word	g_71
	.word	g_467+24
	.word	g_467+12
	.size	.Lconstinit.3, 24

	.type	.Lconstinit.4,@object           # @constinit.4
	.p2align	2, 0x0
.Lconstinit.4:
	.word	g_467+12
	.word	0
	.word	0
	.word	g_467+12
	.word	g_467+20
	.word	g_467+24
	.size	.Lconstinit.4, 24

	.type	.Lconstinit.5,@object           # @constinit.5
	.p2align	2, 0x0
.Lconstinit.5:
	.word	g_467+20
	.word	g_71
	.word	g_71
	.word	g_467+4
	.word	g_467+12
	.word	g_467+8
	.size	.Lconstinit.5, 24

	.type	.Lconstinit.6,@object           # @constinit.6
	.p2align	2, 0x0
.Lconstinit.6:
	.word	g_467+24
	.word	g_467+4
	.word	g_71
	.word	g_467+12
	.word	g_71
	.word	g_467+12
	.size	.Lconstinit.6, 24

	.type	.Lconstinit.7,@object           # @constinit.7
	.p2align	2, 0x0
.Lconstinit.7:
	.word	g_71
	.word	g_71
	.word	g_467+24
	.word	g_71
	.word	g_467+24
	.word	g_467+12
	.size	.Lconstinit.7, 24

	.type	.L__const.func_40.l_1413,@object # @__const.func_40.l_1413
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1413:
	.word	9                               # 0x9
	.word	1563492333                      # 0x5d30ffed
	.zero	8
	.size	.L__const.func_40.l_1413, 16

	.type	.L__const.func_40.l_1431,@object # @__const.func_40.l_1431
	.section	.rodata,"a",@progbits
	.p2align	1, 0x0
.L__const.func_40.l_1431:
	.half	6016                            # 0x1780
	.half	1                               # 0x1
	.half	64644                           # 0xfc84
	.half	65535                           # 0xffff
	.half	2                               # 0x2
	.half	65535                           # 0xffff
	.half	16337                           # 0x3fd1
	.half	32970                           # 0x80ca
	.half	14744                           # 0x3998
	.half	28627                           # 0x6fd3
	.half	5580                            # 0x15cc
	.half	45719                           # 0xb297
	.half	1                               # 0x1
	.half	43136                           # 0xa880
	.half	65534                           # 0xfffe
	.half	55391                           # 0xd85f
	.half	65527                           # 0xfff7
	.half	65535                           # 0xffff
	.half	1                               # 0x1
	.half	4797                            # 0x12bd
	.half	6016                            # 0x1780
	.half	28627                           # 0x6fd3
	.half	3171                            # 0xc63
	.half	65530                           # 0xfffa
	.half	16337                           # 0x3fd1
	.half	6016                            # 0x1780
	.half	1                               # 0x1
	.half	65535                           # 0xffff
	.half	1                               # 0x1
	.half	35500                           # 0x8aac
	.half	6016                            # 0x1780
	.half	6016                            # 0x1780
	.half	51075                           # 0xc783
	.half	58337                           # 0xe3e1
	.half	3171                            # 0xc63
	.half	1                               # 0x1
	.half	43136                           # 0xa880
	.half	4797                            # 0x12bd
	.half	46785                           # 0xb6c1
	.half	65530                           # 0xfffa
	.half	65527                           # 0xfff7
	.half	0                               # 0x0
	.half	46785                           # 0xb6c1
	.half	43136                           # 0xa880
	.half	46785                           # 0xb6c1
	.half	1                               # 0x1
	.half	5580                            # 0x15cc
	.half	1                               # 0x1
	.half	65530                           # 0xfffa
	.half	32970                           # 0x80ca
	.half	51075                           # 0xc783
	.half	65535                           # 0xffff
	.half	2                               # 0x2
	.half	35500                           # 0x8aac
	.half	4                               # 0x4
	.half	1                               # 0x1
	.half	1                               # 0x1
	.half	65535                           # 0xffff
	.half	31434                           # 0x7aca
	.half	65530                           # 0xfffa
	.half	65530                           # 0xfffa
	.half	64644                           # 0xfc84
	.half	6016                            # 0x1780
	.half	1                               # 0x1
	.half	46630                           # 0xb626
	.half	65535                           # 0xffff
	.half	46785                           # 0xb6c1
	.half	51075                           # 0xc783
	.half	65534                           # 0xfffe
	.half	65530                           # 0xfffa
	.half	46630                           # 0xb626
	.half	45719                           # 0xb297
	.half	43136                           # 0xa880
	.half	64644                           # 0xfc84
	.half	14744                           # 0x3998
	.half	58337                           # 0xe3e1
	.half	31434                           # 0x7aca
	.half	65535                           # 0xffff
	.half	6016                            # 0x1780
	.half	1                               # 0x1
	.half	64644                           # 0xfc84
	.half	65535                           # 0xffff
	.half	2                               # 0x2
	.half	65535                           # 0xffff
	.half	16337                           # 0x3fd1
	.half	32970                           # 0x80ca
	.half	14744                           # 0x3998
	.half	28627                           # 0x6fd3
	.half	5580                            # 0x15cc
	.half	45719                           # 0xb297
	.half	1                               # 0x1
	.half	43136                           # 0xa880
	.half	65534                           # 0xfffe
	.half	55391                           # 0xd85f
	.half	65527                           # 0xfff7
	.half	65535                           # 0xffff
	.half	1                               # 0x1
	.half	4797                            # 0x12bd
	.half	6016                            # 0x1780
	.half	28627                           # 0x6fd3
	.half	3171                            # 0xc63
	.half	65530                           # 0xfffa
	.half	16337                           # 0x3fd1
	.half	6016                            # 0x1780
	.half	1                               # 0x1
	.half	65535                           # 0xffff
	.half	1                               # 0x1
	.half	35500                           # 0x8aac
	.half	6016                            # 0x1780
	.half	6016                            # 0x1780
	.half	51075                           # 0xc783
	.half	58337                           # 0xe3e1
	.half	3171                            # 0xc63
	.half	1                               # 0x1
	.half	43136                           # 0xa880
	.half	4797                            # 0x12bd
	.half	46785                           # 0xb6c1
	.half	65530                           # 0xfffa
	.half	65527                           # 0xfff7
	.half	0                               # 0x0
	.half	46785                           # 0xb6c1
	.half	43136                           # 0xa880
	.half	46785                           # 0xb6c1
	.half	1                               # 0x1
	.half	5580                            # 0x15cc
	.half	1                               # 0x1
	.half	65530                           # 0xfffa
	.half	32970                           # 0x80ca
	.half	43136                           # 0xa880
	.half	55391                           # 0xd85f
	.half	65527                           # 0xfff7
	.half	28627                           # 0x6fd3
	.half	6016                            # 0x1780
	.half	4                               # 0x4
	.half	4                               # 0x4
	.half	55391                           # 0xd85f
	.half	0                               # 0x0
	.half	45719                           # 0xb297
	.half	46785                           # 0xb6c1
	.half	1                               # 0x1
	.half	51075                           # 0xc783
	.half	4                               # 0x4
	.half	1                               # 0x1
	.half	55391                           # 0xd85f
	.half	64644                           # 0xfc84
	.half	43136                           # 0xa880
	.half	65530                           # 0xfffa
	.half	45719                           # 0xb297
	.half	1                               # 0x1
	.half	58337                           # 0xe3e1
	.half	16337                           # 0x3fd1
	.half	1                               # 0x1
	.half	65534                           # 0xfffe
	.half	1                               # 0x1
	.half	0                               # 0x0
	.half	0                               # 0x0
	.half	51075                           # 0xc783
	.half	4                               # 0x4
	.half	1                               # 0x1
	.half	0                               # 0x0
	.half	65527                           # 0xfff7
	.half	0                               # 0x0
	.half	32970                           # 0x80ca
	.half	4797                            # 0x12bd
	.half	65534                           # 0xfffe
	.half	65535                           # 0xffff
	.half	31434                           # 0x7aca
	.half	58337                           # 0xe3e1
	.half	4                               # 0x4
	.half	16337                           # 0x3fd1
	.half	65530                           # 0xfffa
	.half	65530                           # 0xfffa
	.half	9                               # 0x9
	.half	55391                           # 0xd85f
	.half	4                               # 0x4
	.half	14744                           # 0x3998
	.half	51075                           # 0xc783
	.half	65535                           # 0xffff
	.half	65527                           # 0xfff7
	.half	45719                           # 0xb297
	.half	32970                           # 0x80ca
	.half	51075                           # 0xc783
	.half	4                               # 0x4
	.half	0                               # 0x0
	.half	2                               # 0x2
	.half	28627                           # 0x6fd3
	.half	51075                           # 0xc783
	.half	51075                           # 0xc783
	.half	43136                           # 0xa880
	.half	1                               # 0x1
	.half	65527                           # 0xfff7
	.half	35500                           # 0x8aac
	.half	16337                           # 0x3fd1
	.half	14744                           # 0x3998
	.half	64644                           # 0xfc84
	.half	45719                           # 0xb297
	.half	9                               # 0x9
	.half	65535                           # 0xffff
	.half	64644                           # 0xfc84
	.half	16337                           # 0x3fd1
	.half	64644                           # 0xfc84
	.half	4                               # 0x4
	.half	31434                           # 0x7aca
	.half	35500                           # 0x8aac
	.half	46785                           # 0xb6c1
	.half	4797                            # 0x12bd
	.half	43136                           # 0xa880
	.half	55391                           # 0xd85f
	.half	65527                           # 0xfff7
	.half	28627                           # 0x6fd3
	.size	.L__const.func_40.l_1431, 420

	.type	.L__const.func_40.l_1532,@object # @__const.func_40.l_1532
	.p2align	2, 0x0
.L__const.func_40.l_1532:
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.size	.L__const.func_40.l_1532, 40

	.type	.L__const.func_40.l_1543,@object # @__const.func_40.l_1543
	.p2align	2, 0x0
.L__const.func_40.l_1543:
	.word	g_70+80
	.word	g_70+80
	.word	g_70+80
	.word	g_70+80
	.word	g_70+80
	.word	g_70+80
	.size	.L__const.func_40.l_1543, 24

	.type	.L__const.func_40.l_1661,@object # @__const.func_40.l_1661
	.p2align	1, 0x0
.L__const.func_40.l_1661:
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.half	65532                           # 0xfffc
	.size	.L__const.func_40.l_1661, 14

	.type	.L__const.func_40.l_1666,@object # @__const.func_40.l_1666
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1666:
	.word	2                               # 0x2
	.word	0                               # 0x0
	.zero	8
	.size	.L__const.func_40.l_1666, 16

	.type	.L__const.func_40.l_1581,@object # @__const.func_40.l_1581
	.p2align	4, 0x0
.L__const.func_40.l_1581:
	.word	164171603                       # 0x9c90f53
	.word	4294967294                      # 0xfffffffe
	.zero	8
	.size	.L__const.func_40.l_1581, 16

	.type	.L__const.func_40.l_1619,@object # @__const.func_40.l_1619
	.section	.rodata,"a",@progbits
	.p2align	4, 0x0
.L__const.func_40.l_1619:
	.word	4294967295                      # 0xffffffff
	.word	1150076594                      # 0x448cc6b2
	.zero	8
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3                               # 0x3
	.word	2241133223                      # 0x8594faa7
	.zero	8
	.word	3682291683                      # 0xdb7b4fe3
	.word	21831517                        # 0x14d1f5d
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	1746935832                      # 0x68202018
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1740630268                      # 0x67bfe8fc
	.zero	8
	.word	4294967294                      # 0xfffffffe
	.word	322771172                       # 0x133d18e4
	.zero	8
	.word	4149652845                      # 0xf756ad6d
	.word	1                               # 0x1
	.zero	8
	.word	9                               # 0x9
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3038322514                      # 0xb5191f52
	.word	1                               # 0x1
	.zero	8
	.word	3420179328                      # 0xcbdbcb80
	.word	0                               # 0x0
	.zero	8
	.word	9                               # 0x9
	.word	1                               # 0x1
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	1398153761                      # 0x53562221
	.word	115415039                       # 0x6e117ff
	.zero	8
	.word	7                               # 0x7
	.word	565817859                       # 0x21b9b203
	.zero	8
	.word	0                               # 0x0
	.word	2297970783                      # 0x88f8405f
	.zero	8
	.word	4149652845                      # 0xf756ad6d
	.word	1                               # 0x1
	.zero	8
	.word	4149652845                      # 0xf756ad6d
	.word	1                               # 0x1
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	1948857973                      # 0x74293675
	.word	4                               # 0x4
	.zero	8
	.word	4294967294                      # 0xfffffffe
	.word	3227264917                      # 0xc05c2795
	.zero	8
	.word	3                               # 0x3
	.word	2241133223                      # 0x8594faa7
	.zero	8
	.word	1942389900                      # 0x73c6848c
	.word	797800532                       # 0x2f8d7854
	.zero	8
	.word	3                               # 0x3
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3009056594                      # 0xb35a8f52
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1740630268                      # 0x67bfe8fc
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1150076594                      # 0x448cc6b2
	.zero	8
	.word	4240737434                      # 0xfcc4849a
	.word	92902032                        # 0x5899290
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	361776695                       # 0x15904637
	.zero	8
	.word	4294967294                      # 0xfffffffe
	.word	322771172                       # 0x133d18e4
	.zero	8
	.word	1398153761                      # 0x53562221
	.word	115415039                       # 0x6e117ff
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1275869666                      # 0x4c0c39e2
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967291                      # 0xfffffffb
	.word	4294967293                      # 0xfffffffd
	.zero	8
	.word	1759001645                      # 0x68d83c2d
	.word	2686568914                      # 0xa021c9d2
	.zero	8
	.word	4240737434                      # 0xfcc4849a
	.word	92902032                        # 0x5899290
	.zero	8
	.word	4294967288                      # 0xfffffff8
	.word	0                               # 0x0
	.zero	8
	.word	937603170                       # 0x37e2b062
	.word	215881815                       # 0xcde1857
	.zero	8
	.word	5                               # 0x5
	.word	3823553780                      # 0xe3e6ccf4
	.zero	8
	.word	259358768                       # 0xf758030
	.word	84205662                        # 0x504e05e
	.zero	8
	.word	2010761012                      # 0x77d9c734
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	4149652845                      # 0xf756ad6d
	.word	1                               # 0x1
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	1603222996                      # 0x5f8f3dd4
	.word	8                               # 0x8
	.zero	8
	.word	1719326387                      # 0x667ad6b3
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	0                               # 0x0
	.word	129225240                       # 0x7b3d218
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	1746935832                      # 0x68202018
	.zero	8
	.word	1603222996                      # 0x5f8f3dd4
	.word	8                               # 0x8
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1150076594                      # 0x448cc6b2
	.zero	8
	.word	1603222996                      # 0x5f8f3dd4
	.word	8                               # 0x8
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1                               # 0x1
	.zero	8
	.word	2087065929                      # 0x7c661949
	.word	4294967286                      # 0xfffffff6
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1740630268                      # 0x67bfe8fc
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	2297970783                      # 0x88f8405f
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.zero	8
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3009056594                      # 0xb35a8f52
	.word	4294967292                      # 0xfffffffc
	.zero	8
	.word	0                               # 0x0
	.word	129225240                       # 0x7b3d218
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1150076594                      # 0x448cc6b2
	.zero	8
	.word	1719326387                      # 0x667ad6b3
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	424132797                       # 0x1947c0bd
	.word	1038964280                      # 0x3ded5638
	.zero	8
	.word	259358768                       # 0xf758030
	.word	84205662                        # 0x504e05e
	.zero	8
	.word	4149652845                      # 0xf756ad6d
	.word	1                               # 0x1
	.zero	8
	.word	2913545827                      # 0xada92e63
	.word	4294967294                      # 0xfffffffe
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	1786897349                      # 0x6a81e3c5
	.zero	8
	.word	9                               # 0x9
	.word	1                               # 0x1
	.zero	8
	.word	3198295815                      # 0xbea21f07
	.word	1                               # 0x1
	.zero	8
	.word	4294967288                      # 0xfffffff8
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1775045887                      # 0x69cd0cff
	.zero	8
	.word	406070921                       # 0x18342689
	.word	8                               # 0x8
	.zero	8
	.word	4240737434                      # 0xfcc4849a
	.word	92902032                        # 0x5899290
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	0                               # 0x0
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	136517963                       # 0x823194b
	.word	3322400441                      # 0xc607ceb9
	.zero	8
	.word	1                               # 0x1
	.word	1                               # 0x1
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	361776695                       # 0x15904637
	.zero	8
	.word	0                               # 0x0
	.word	129225240                       # 0x7b3d218
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3906353489                      # 0xe8d63951
	.word	3421158376                      # 0xcbeabbe8
	.zero	8
	.word	3906353489                      # 0xe8d63951
	.word	3421158376                      # 0xcbeabbe8
	.zero	8
	.word	1181987630                      # 0x4673b32e
	.word	4294967286                      # 0xfffffff6
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	1181987630                      # 0x4673b32e
	.word	4294967286                      # 0xfffffff6
	.zero	8
	.word	1                               # 0x1
	.word	9                               # 0x9
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	3198295815                      # 0xbea21f07
	.word	1                               # 0x1
	.zero	8
	.word	1181987630                      # 0x4673b32e
	.word	4294967286                      # 0xfffffff6
	.zero	8
	.word	3038322514                      # 0xb5191f52
	.word	1                               # 0x1
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	7                               # 0x7
	.zero	8
	.word	0                               # 0x0
	.word	4274179984                      # 0xfec2cf90
	.zero	8
	.word	3906353489                      # 0xe8d63951
	.word	3421158376                      # 0xcbeabbe8
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	990630586                       # 0x3b0bd2ba
	.word	1559180992                      # 0x5cef36c0
	.zero	8
	.word	424132797                       # 0x1947c0bd
	.word	1038964280                      # 0x3ded5638
	.zero	8
	.word	2808026706                      # 0xa75f1652
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	1095836743                      # 0x41512447
	.word	3045161322                      # 0xb581796a
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	1746935832                      # 0x68202018
	.zero	8
	.word	3038322514                      # 0xb5191f52
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	4274179984                      # 0xfec2cf90
	.zero	8
	.word	4294967292                      # 0xfffffffc
	.word	4249188609                      # 0xfd457901
	.zero	8
	.word	7                               # 0x7
	.word	565817859                       # 0x21b9b203
	.zero	8
	.word	1                               # 0x1
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	1181987630                      # 0x4673b32e
	.word	4294967286                      # 0xfffffff6
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	4033198105                      # 0xf065b819
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	2735677933                      # 0xa30f21ed
	.word	1317661394                      # 0x4e89ead2
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	7                               # 0x7
	.word	565817859                       # 0x21b9b203
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	1746935832                      # 0x68202018
	.zero	8
	.word	1                               # 0x1
	.word	9                               # 0x9
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	1095836743                      # 0x41512447
	.word	3045161322                      # 0xb581796a
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	3663079138                      # 0xda5626e2
	.zero	8
	.word	4294967292                      # 0xfffffffc
	.word	4249188609                      # 0xfd457901
	.zero	8
	.word	0                               # 0x0
	.word	2297970783                      # 0x88f8405f
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	3663079138                      # 0xda5626e2
	.zero	8
	.word	1772241043                      # 0x69a24093
	.word	1525180005                      # 0x5ae86665
	.zero	8
	.word	3198295815                      # 0xbea21f07
	.word	1                               # 0x1
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	361776695                       # 0x15904637
	.zero	8
	.word	1759001645                      # 0x68d83c2d
	.word	2686568914                      # 0xa021c9d2
	.zero	8
	.word	4294967286                      # 0xfffffff6
	.word	0                               # 0x0
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	0                               # 0x0
	.word	1775045887                      # 0x69cd0cff
	.zero	8
	.word	1                               # 0x1
	.word	3681946393                      # 0xdb760b19
	.zero	8
	.word	2010761012                      # 0x77d9c734
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	3035692715                      # 0xb4f0feab
	.word	2712795099                      # 0xa1b1f7db
	.zero	8
	.word	1772241043                      # 0x69a24093
	.word	1525180005                      # 0x5ae86665
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	406070921                       # 0x18342689
	.word	8                               # 0x8
	.zero	8
	.word	1                               # 0x1
	.word	9                               # 0x9
	.zero	8
	.word	4294967292                      # 0xfffffffc
	.word	2                               # 0x2
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	3                               # 0x3
	.zero	8
	.word	3                               # 0x3
	.word	0                               # 0x0
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1275869666                      # 0x4c0c39e2
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	3                               # 0x3
	.zero	8
	.word	958345118                       # 0x391f2f9e
	.word	8                               # 0x8
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	9                               # 0x9
	.zero	8
	.word	1772241043                      # 0x69a24093
	.word	1525180005                      # 0x5ae86665
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	136517963                       # 0x823194b
	.word	3322400441                      # 0xc607ceb9
	.zero	8
	.word	4033198105                      # 0xf065b819
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	1                               # 0x1
	.word	0                               # 0x0
	.zero	8
	.word	4294967293                      # 0xfffffffd
	.word	4294967289                      # 0xfffffff9
	.zero	8
	.word	2658481718                      # 0x9e753636
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967292                      # 0xfffffffc
	.word	4249188609                      # 0xfd457901
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3198295815                      # 0xbea21f07
	.word	1                               # 0x1
	.zero	8
	.word	136517963                       # 0x823194b
	.word	3322400441                      # 0xc607ceb9
	.zero	8
	.word	1485724535                      # 0x588e5b77
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	129225240                       # 0x7b3d218
	.zero	8
	.word	937603170                       # 0x37e2b062
	.word	215881815                       # 0xcde1857
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	3663079138                      # 0xda5626e2
	.zero	8
	.word	4294967294                      # 0xfffffffe
	.word	322771172                       # 0x133d18e4
	.zero	8
	.word	2808026706                      # 0xa75f1652
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	0                               # 0x0
	.word	1                               # 0x1
	.zero	8
	.word	3430733399                      # 0xcc7cd657
	.word	1                               # 0x1
	.zero	8
	.word	7                               # 0x7
	.word	565817859                       # 0x21b9b203
	.zero	8
	.word	1772241043                      # 0x69a24093
	.word	1525180005                      # 0x5ae86665
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	287917248                       # 0x112944c0
	.word	1672585006                      # 0x63b19f2e
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	7                               # 0x7
	.zero	8
	.word	937603170                       # 0x37e2b062
	.word	215881815                       # 0xcde1857
	.zero	8
	.word	0                               # 0x0
	.word	4274179984                      # 0xfec2cf90
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	3363155678                      # 0xc875aede
	.word	1                               # 0x1
	.zero	8
	.word	3                               # 0x3
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	1                               # 0x1
	.word	1                               # 0x1
	.zero	8
	.word	424132797                       # 0x1947c0bd
	.word	1038964280                      # 0x3ded5638
	.zero	8
	.word	1095836743                      # 0x41512447
	.word	3045161322                      # 0xb581796a
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	361776695                       # 0x15904637
	.zero	8
	.word	136517963                       # 0x823194b
	.word	3322400441                      # 0xc607ceb9
	.zero	8
	.word	9                               # 0x9
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967289                      # 0xfffffff9
	.word	7                               # 0x7
	.zero	8
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.zero	8
	.word	424132797                       # 0x1947c0bd
	.word	1038964280                      # 0x3ded5638
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	9                               # 0x9
	.zero	8
	.word	1                               # 0x1
	.word	9                               # 0x9
	.zero	8
	.word	1156442717                      # 0x44edea5d
	.word	4294967295                      # 0xffffffff
	.zero	8
	.size	.L__const.func_40.l_1619, 3200

	.type	.L__const.func_40.l_1586,@object # @__const.func_40.l_1586
	.p2align	2, 0x0
.L__const.func_40.l_1586:
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.word	1420048621                      # 0x54a438ed
	.size	.L__const.func_40.l_1586, 36

	.type	.L__const.func_40.l_1665,@object # @__const.func_40.l_1665
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_40.l_1665:
	.word	2194631535                      # 0x82cf6b6f
	.word	0                               # 0x0
	.zero	8
	.size	.L__const.func_40.l_1665, 16

	.type	.L__const.func_40.l_1691,@object # @__const.func_40.l_1691
	.p2align	1, 0x0
.L__const.func_40.l_1691:
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.half	17951                           # 0x461f
	.size	.L__const.func_40.l_1691, 16

	.type	.L__const.func_40.l_1752,@object # @__const.func_40.l_1752
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_40.l_1752:
	.word	g_136+100
	.size	.L__const.func_40.l_1752, 4

	.type	.L__const.func_40.l_1708,@object # @__const.func_40.l_1708
.L__const.func_40.l_1708:
	.zero	7,201
	.zero	7,255
	.zero	7,201
	.zero	7,255
	.zero	7,201
	.zero	7,255
	.zero	7,201
	.zero	7,255
	.size	.L__const.func_40.l_1708, 56

	.type	.L__const.func_40.l_1775,@object # @__const.func_40.l_1775
	.p2align	4, 0x0
.L__const.func_40.l_1775:
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.word	7                               # 0x7
	.word	2734349549                      # 0xa2fadced
	.zero	8
	.size	.L__const.func_40.l_1775, 960

	.type	.L__const.func_40.l_1827,@object # @__const.func_40.l_1827
.L__const.func_40.l_1827:
	.ascii	"\004\000\000\377\267\371"
	.ascii	"\000\377\326G\326\377"
	.asciz	"G\326\377\000\005"
	.ascii	"\377\000\000\004x\346"
	.ascii	"x\000\271\000\005\377"
	.ascii	"\377\326\267\267\326\377"
	.asciz	"\000\377\004\377\267"
	.ascii	"\377\000\001\371\001\271"
	.ascii	"\377\271\371\377\000\001"
	.ascii	"\000\267x\267\000\001"
	.ascii	"\377\004\346\000R\005"
	.ascii	"x\001\004\004G\005"
	.ascii	"\377\371\346\000\001\001"
	.ascii	"GxxG\377\001"
	.ascii	"\000\346\371\377\377\271"
	.asciz	"\004\004\001x\377"
	.ascii	"\000\346\004\377\377\377"
	.ascii	"\267x\267\000\001\377"
	.ascii	"\004\346\000R\005\001"
	.ascii	"\346\326\377RG\371"
	.ascii	"\004\000x\371\371x"
	.ascii	"\005\005\004\267\377\346"
	.ascii	"\377\000\377\003\377\004"
	.ascii	"\000\377\377x\005\346"
	.ascii	"\271x\004\005\004x"
	.ascii	"\005\004x\271\001\371"
	.ascii	"x\377\377\000\003\001"
	.ascii	"\003\377\000\377\001\004"
	.ascii	"\267\004\005\005\004\267"
	.ascii	"\371x\000\004\005\271"
	.asciz	"R\377\326\346\377"
	.ascii	"R\000\346\004\377\377"
	.ascii	"\371\005\003\005\371\326"
	.asciz	"\267\000\001\377G"
	.asciz	"\003\326\377\000\005"
	.ascii	"x\346\001\271\326\326"
	.ascii	"\005\003\003\005x\377"
	.asciz	"\271\001\346x\004"
	.ascii	"\000\377\326\003\004\271"
	.ascii	"\377\001\000\267x\267"
	.size	.L__const.func_40.l_1827, 240

	.type	.L__const.func_57.l_74,@object  # @__const.func_57.l_74
	.p2align	2, 0x0
.L__const.func_57.l_74:
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	g_70+80
	.word	g_70
	.word	0
	.word	g_70
	.word	g_70+80
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.word	0
	.word	g_70+16
	.word	g_70+80
	.word	g_70+16
	.word	0
	.word	0
	.word	0
	.size	.L__const.func_57.l_74, 980

	.type	.L__const.func_57.l_207,@object # @__const.func_57.l_207
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_57.l_207:
	.word	3990563300                      # 0xeddb29e4
	.word	3154267261                      # 0xbc024c7d
	.zero	8
	.size	.L__const.func_57.l_207, 16

	.type	.L__const.func_57.l_219,@object # @__const.func_57.l_219
	.section	.rodata,"a",@progbits
	.p2align	3, 0x0
.L__const.func_57.l_219:
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.quad	1                               # 0x1
	.quad	-1                              # 0xffffffffffffffff
	.quad	1                               # 0x1
	.size	.L__const.func_57.l_219, 480

	.type	.L.str,@object                  # @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"1"
	.size	.L.str, 2

	.type	.L.str.8,@object                # @.str.8
.L.str.8:
	.asciz	"g_2[i][j][k]"
	.size	.L.str.8, 13

	.type	.L.str.9,@object                # @.str.9
.L.str.9:
	.asciz	"index = [%d][%d][%d]\n"
	.size	.L.str.9, 22

	.type	.L.str.10,@object               # @.str.10
.L.str.10:
	.asciz	"g_3"
	.size	.L.str.10, 4

	.type	.L.str.11,@object               # @.str.11
.L.str.11:
	.asciz	"g_6"
	.size	.L.str.11, 4

	.type	.L.str.12,@object               # @.str.12
.L.str.12:
	.asciz	"g_7"
	.size	.L.str.12, 4

	.type	.L.str.13,@object               # @.str.13
.L.str.13:
	.asciz	"g_8[i][j][k]"
	.size	.L.str.13, 13

	.type	.L.str.14,@object               # @.str.14
.L.str.14:
	.asciz	"g_13"
	.size	.L.str.14, 5

	.type	.L.str.15,@object               # @.str.15
.L.str.15:
	.asciz	"g_69[i].f0"
	.size	.L.str.15, 11

	.type	.L.str.16,@object               # @.str.16
.L.str.16:
	.asciz	"g_69[i].f1"
	.size	.L.str.16, 11

	.type	.L.str.17,@object               # @.str.17
.L.str.17:
	.asciz	"index = [%d]\n"
	.size	.L.str.17, 14

	.type	.L.str.18,@object               # @.str.18
.L.str.18:
	.asciz	"g_89"
	.size	.L.str.18, 5

	.type	.L.str.19,@object               # @.str.19
.L.str.19:
	.asciz	"g_93"
	.size	.L.str.19, 5

	.type	.L.str.20,@object               # @.str.20
.L.str.20:
	.asciz	"g_111"
	.size	.L.str.20, 6

	.type	.L.str.21,@object               # @.str.21
.L.str.21:
	.asciz	"g_116"
	.size	.L.str.21, 6

	.type	.L.str.22,@object               # @.str.22
.L.str.22:
	.asciz	"g_117"
	.size	.L.str.22, 6

	.type	.L.str.23,@object               # @.str.23
.L.str.23:
	.asciz	"g_123"
	.size	.L.str.23, 6

	.type	.L.str.24,@object               # @.str.24
.L.str.24:
	.asciz	"g_124.f0"
	.size	.L.str.24, 9

	.type	.L.str.25,@object               # @.str.25
.L.str.25:
	.asciz	"g_133[i][j][k]"
	.size	.L.str.25, 15

	.type	.L.str.26,@object               # @.str.26
.L.str.26:
	.asciz	"g_147.f0.f0"
	.size	.L.str.26, 12

	.type	.L.str.27,@object               # @.str.27
.L.str.27:
	.asciz	"g_147.f0.f1"
	.size	.L.str.27, 12

	.type	.L.str.28,@object               # @.str.28
.L.str.28:
	.asciz	"g_152"
	.size	.L.str.28, 6

	.type	.L.str.29,@object               # @.str.29
.L.str.29:
	.asciz	"g_197[i][j]"
	.size	.L.str.29, 12

	.type	.L.str.30,@object               # @.str.30
.L.str.30:
	.asciz	"index = [%d][%d]\n"
	.size	.L.str.30, 18

	.type	.L.str.31,@object               # @.str.31
.L.str.31:
	.asciz	"g_230"
	.size	.L.str.31, 6

	.type	.L.str.32,@object               # @.str.32
.L.str.32:
	.asciz	"g_252"
	.size	.L.str.32, 6

	.type	.L.str.33,@object               # @.str.33
.L.str.33:
	.asciz	"g_292[i][j].f0"
	.size	.L.str.33, 15

	.type	.L.str.34,@object               # @.str.34
.L.str.34:
	.asciz	"g_294.f0"
	.size	.L.str.34, 9

	.type	.L.str.35,@object               # @.str.35
.L.str.35:
	.asciz	"g_302"
	.size	.L.str.35, 6

	.type	.L.str.36,@object               # @.str.36
.L.str.36:
	.asciz	"g_325"
	.size	.L.str.36, 6

	.type	.L.str.37,@object               # @.str.37
.L.str.37:
	.asciz	"g_333"
	.size	.L.str.37, 6

	.type	.L.str.38,@object               # @.str.38
.L.str.38:
	.asciz	"g_388"
	.size	.L.str.38, 6

	.type	.L.str.39,@object               # @.str.39
.L.str.39:
	.asciz	"g_391"
	.size	.L.str.39, 6

	.type	.L.str.40,@object               # @.str.40
.L.str.40:
	.asciz	"g_556.f0"
	.size	.L.str.40, 9

	.type	.L.str.41,@object               # @.str.41
.L.str.41:
	.asciz	"g_556.f1"
	.size	.L.str.41, 9

	.type	.L.str.42,@object               # @.str.42
.L.str.42:
	.asciz	"g_588"
	.size	.L.str.42, 6

	.type	.L.str.43,@object               # @.str.43
.L.str.43:
	.asciz	"g_589"
	.size	.L.str.43, 6

	.type	.L.str.44,@object               # @.str.44
.L.str.44:
	.asciz	"g_642"
	.size	.L.str.44, 6

	.type	.L.str.45,@object               # @.str.45
.L.str.45:
	.asciz	"g_645.f0"
	.size	.L.str.45, 9

	.type	.L.str.46,@object               # @.str.46
.L.str.46:
	.asciz	"g_733.f0"
	.size	.L.str.46, 9

	.type	.L.str.47,@object               # @.str.47
.L.str.47:
	.asciz	"g_765.f0"
	.size	.L.str.47, 9

	.type	.L.str.48,@object               # @.str.48
.L.str.48:
	.asciz	"g_813.f0"
	.size	.L.str.48, 9

	.type	.L.str.49,@object               # @.str.49
.L.str.49:
	.asciz	"g_921[i].f0"
	.size	.L.str.49, 12

	.type	.L.str.50,@object               # @.str.50
.L.str.50:
	.asciz	"g_932"
	.size	.L.str.50, 6

	.type	.L.str.51,@object               # @.str.51
.L.str.51:
	.asciz	"g_946.f0.f0"
	.size	.L.str.51, 12

	.type	.L.str.52,@object               # @.str.52
.L.str.52:
	.asciz	"g_946.f0.f1"
	.size	.L.str.52, 12

	.type	.L.str.53,@object               # @.str.53
.L.str.53:
	.asciz	"g_947[i][j]"
	.size	.L.str.53, 12

	.type	.L.str.54,@object               # @.str.54
.L.str.54:
	.asciz	"g_955[i][j][k]"
	.size	.L.str.54, 15

	.type	.L.str.55,@object               # @.str.55
.L.str.55:
	.asciz	"g_1000"
	.size	.L.str.55, 7

	.type	.L.str.56,@object               # @.str.56
.L.str.56:
	.asciz	"g_1113.f0"
	.size	.L.str.56, 10

	.type	.L.str.57,@object               # @.str.57
.L.str.57:
	.asciz	"g_1259[i][j]"
	.size	.L.str.57, 13

	.type	.L.str.58,@object               # @.str.58
.L.str.58:
	.asciz	"g_1292.f0"
	.size	.L.str.58, 10

	.type	.L.str.59,@object               # @.str.59
.L.str.59:
	.asciz	"g_1375[i]"
	.size	.L.str.59, 10

	.type	.L.str.60,@object               # @.str.60
.L.str.60:
	.asciz	"g_1548.f0"
	.size	.L.str.60, 10

	.type	.L.str.61,@object               # @.str.61
.L.str.61:
	.asciz	"g_1662"
	.size	.L.str.61, 7

	.type	.L.str.62,@object               # @.str.62
.L.str.62:
	.asciz	"g_1717[i][j][k].f0"
	.size	.L.str.62, 19

	.type	.L.str.63,@object               # @.str.63
.L.str.63:
	.asciz	"g_1781"
	.size	.L.str.63, 7

	.type	.L.str.64,@object               # @.str.64
.L.str.64:
	.asciz	"g_1812.f0"
	.size	.L.str.64, 10

	.type	.L.str.65,@object               # @.str.65
.L.str.65:
	.asciz	"g_1813.f0"
	.size	.L.str.65, 10

	.type	.L.str.66,@object               # @.str.66
.L.str.66:
	.asciz	"g_1814.f0"
	.size	.L.str.66, 10

	.type	.L.str.67,@object               # @.str.67
.L.str.67:
	.asciz	"g_1815.f0"
	.size	.L.str.67, 10

	.type	.L.str.68,@object               # @.str.68
.L.str.68:
	.asciz	"g_1816.f0"
	.size	.L.str.68, 10

	.type	.L.str.69,@object               # @.str.69
.L.str.69:
	.asciz	"g_1817.f0"
	.size	.L.str.69, 10

	.type	.L.str.70,@object               # @.str.70
.L.str.70:
	.asciz	"g_1818[i][j].f0"
	.size	.L.str.70, 16

	.type	.L.str.71,@object               # @.str.71
.L.str.71:
	.asciz	"g_1852.f0"
	.size	.L.str.71, 10

	.type	.L.str.72,@object               # @.str.72
.L.str.72:
	.asciz	"g_2016"
	.size	.L.str.72, 7

	.type	.L.str.73,@object               # @.str.73
.L.str.73:
	.asciz	"g_2017.f0"
	.size	.L.str.73, 10

	.type	.L.str.74,@object               # @.str.74
.L.str.74:
	.asciz	"g_2070"
	.size	.L.str.74, 7

	.type	.L.str.75,@object               # @.str.75
.L.str.75:
	.asciz	"g_2128.f0"
	.size	.L.str.75, 10

	.type	.L.str.76,@object               # @.str.76
.L.str.76:
	.asciz	"g_2201.f0"
	.size	.L.str.76, 10

	.type	.L.str.77,@object               # @.str.77
.L.str.77:
	.asciz	"g_2309[i][j].f0"
	.size	.L.str.77, 16

	.type	.L.str.78,@object               # @.str.78
.L.str.78:
	.asciz	"g_2448.f0"
	.size	.L.str.78, 10

	.type	crc32_context,@object           # @crc32_context
	.section	.sdata,"aw",@progbits
	.p2align	2
crc32_context:
	.word	4294967295                      # 0xffffffff
	.size	crc32_context, 4

	.type	crc32_tab,@object               # @crc32_tab
	.local	crc32_tab
	.comm	crc32_tab,1024,4
	.type	.L.str.79,@object               # @.str.79
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str.79:
	.asciz	"...checksum after hashing %s : %lX\n"
	.size	.L.str.79, 36

	.type	.L.str.80,@object               # @.str.80
.L.str.80:
	.asciz	"checksum = %X\n"
	.size	.L.str.80, 15

	.section	.debug_abbrev,"",@progbits
	.byte	1                               # Abbreviation Code
	.byte	17                              # DW_TAG_compile_unit
	.byte	1                               # DW_CHILDREN_yes
	.byte	37                              # DW_AT_producer
	.byte	14                              # DW_FORM_strp
	.byte	19                              # DW_AT_language
	.byte	5                               # DW_FORM_data2
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	16                              # DW_AT_stmt_list
	.byte	23                              # DW_FORM_sec_offset
	.byte	27                              # DW_AT_comp_dir
	.byte	14                              # DW_FORM_strp
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	2                               # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	3                               # Abbreviation Code
	.byte	22                              # DW_TAG_typedef
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	4                               # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	5                               # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	6                               # Abbreviation Code
	.byte	23                              # DW_TAG_union_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	7                               # Abbreviation Code
	.byte	13                              # DW_TAG_member
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.ascii	"\210\001"                      # DW_AT_alignment
	.byte	15                              # DW_FORM_udata
	.byte	56                              # DW_AT_data_member_location
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	8                               # Abbreviation Code
	.byte	13                              # DW_TAG_member
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	56                              # DW_AT_data_member_location
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	9                               # Abbreviation Code
	.byte	19                              # DW_TAG_structure_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.ascii	"\210\001"                      # DW_AT_alignment
	.byte	15                              # DW_FORM_udata
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	10                              # Abbreviation Code
	.byte	38                              # DW_TAG_const_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	11                              # Abbreviation Code
	.byte	53                              # DW_TAG_volatile_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	12                              # Abbreviation Code
	.byte	23                              # DW_TAG_union_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.ascii	"\210\001"                      # DW_AT_alignment
	.byte	15                              # DW_FORM_udata
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	13                              # Abbreviation Code
	.byte	1                               # DW_TAG_array_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	14                              # Abbreviation Code
	.byte	33                              # DW_TAG_subrange_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	55                              # DW_AT_count
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	15                              # Abbreviation Code
	.byte	36                              # DW_TAG_base_type
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	11                              # DW_AT_byte_size
	.byte	11                              # DW_FORM_data1
	.byte	62                              # DW_AT_encoding
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	16                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	17                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	18                              # Abbreviation Code
	.byte	33                              # DW_TAG_subrange_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	55                              # DW_AT_count
	.byte	5                               # DW_FORM_data2
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	19                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	20                              # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	21                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	22                              # Abbreviation Code
	.byte	5                               # DW_TAG_formal_parameter
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	23                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	24                              # Abbreviation Code
	.byte	11                              # DW_TAG_lexical_block
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	25                              # Abbreviation Code
	.byte	52                              # DW_TAG_variable
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	26                              # Abbreviation Code
	.byte	10                              # DW_TAG_label
	.byte	0                               # DW_CHILDREN_no
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	27                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	28                              # Abbreviation Code
	.byte	5                               # DW_TAG_formal_parameter
	.byte	0                               # DW_CHILDREN_no
	.byte	2                               # DW_AT_location
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	29                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	30                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_FORM_data2
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	63                              # DW_AT_external
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	31                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	0                               # DW_CHILDREN_no
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	32                              # Abbreviation Code
	.byte	46                              # DW_TAG_subprogram
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
	.byte	64                              # DW_AT_frame_base
	.byte	24                              # DW_FORM_exprloc
	.byte	3                               # DW_AT_name
	.byte	14                              # DW_FORM_strp
	.byte	58                              # DW_AT_decl_file
	.byte	11                              # DW_FORM_data1
	.byte	59                              # DW_AT_decl_line
	.byte	11                              # DW_FORM_data1
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	0                               # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.word	.Ldebug_info_end0-.Ldebug_info_start0 # Length of Unit
.Ldebug_info_start0:
	.half	4                               # DWARF version number
	.word	.debug_abbrev                   # Offset Into Abbrev. Section
	.byte	4                               # Address Size (in bytes)
	.byte	1                               # Abbrev [1] 0xb:0x300d DW_TAG_compile_unit
	.word	.Linfo_string0                  # DW_AT_producer
	.half	29                              # DW_AT_language
	.word	.Linfo_string1                  # DW_AT_name
	.word	.Lline_table_start0             # DW_AT_stmt_list
	.word	.Linfo_string2                  # DW_AT_comp_dir
	.word	.Lfunc_begin0                   # DW_AT_low_pc
	.word	.Lfunc_end62-.Lfunc_begin0      # DW_AT_high_pc
	.byte	2                               # Abbrev [2] 0x26:0x11 DW_TAG_variable
	.word	.Linfo_string3                  # DW_AT_name
	.word	55                              # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_3
	.byte	3                               # Abbrev [3] 0x37:0xb DW_TAG_typedef
	.word	66                              # DW_AT_type
	.word	.Linfo_string5                  # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	105                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0x42:0x7 DW_TAG_base_type
	.word	.Linfo_string4                  # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x49:0x11 DW_TAG_variable
	.word	.Linfo_string6                  # DW_AT_name
	.word	90                              # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	29                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_73
	.byte	5                               # Abbrev [5] 0x5a:0x5 DW_TAG_pointer_type
	.word	95                              # DW_AT_type
	.byte	6                               # Abbrev [6] 0x5f:0x3a DW_TAG_union_type
	.word	.Linfo_string20                 # DW_AT_name
	.byte	16                              # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	14                              # DW_AT_decl_line
	.byte	7                               # Abbrev [7] 0x67:0xd DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	153                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	15                              # DW_AT_decl_line
	.byte	16                              # DW_AT_alignment
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x74:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	205                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	16                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x80:0xc DW_TAG_member
	.word	.Linfo_string14                 # DW_AT_name
	.word	223                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	17                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x8c:0xc DW_TAG_member
	.word	.Linfo_string17                 # DW_AT_name
	.word	241                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	18                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	9                               # Abbrev [9] 0x99:0x22 DW_TAG_structure_type
	.word	.Linfo_string11                 # DW_AT_name
	.byte	16                              # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	8                               # DW_AT_decl_line
	.byte	16                              # DW_AT_alignment
	.byte	8                               # Abbrev [8] 0xa2:0xc DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	55                              # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	9                               # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0xae:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	187                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	10                              # DW_AT_decl_line
	.byte	4                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	3                               # Abbrev [3] 0xbb:0xb DW_TAG_typedef
	.word	198                             # DW_AT_type
	.word	.Linfo_string10                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0xc6:0x7 DW_TAG_base_type
	.word	.Linfo_string9                  # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	3                               # Abbrev [3] 0xcd:0xb DW_TAG_typedef
	.word	216                             # DW_AT_type
	.word	.Linfo_string13                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	100                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0xd8:0x7 DW_TAG_base_type
	.word	.Linfo_string12                 # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	2                               # DW_AT_byte_size
	.byte	3                               # Abbrev [3] 0xdf:0xb DW_TAG_typedef
	.word	234                             # DW_AT_type
	.word	.Linfo_string16                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	120                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0xea:0x7 DW_TAG_base_type
	.word	.Linfo_string15                 # DW_AT_name
	.byte	8                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	3                               # Abbrev [3] 0xf1:0xb DW_TAG_typedef
	.word	252                             # DW_AT_type
	.word	.Linfo_string19                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	95                              # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0xfc:0x7 DW_TAG_base_type
	.word	.Linfo_string18                 # DW_AT_name
	.byte	6                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x103:0x11 DW_TAG_variable
	.word	.Linfo_string21                 # DW_AT_name
	.word	276                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	30                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_97
	.byte	5                               # Abbrev [5] 0x114:0x5 DW_TAG_pointer_type
	.word	281                             # DW_AT_type
	.byte	10                              # Abbrev [10] 0x119:0x5 DW_TAG_const_type
	.word	55                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x11e:0x11 DW_TAG_variable
	.word	.Linfo_string22                 # DW_AT_name
	.word	303                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	31                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_124
	.byte	10                              # Abbrev [10] 0x12f:0x5 DW_TAG_const_type
	.word	308                             # DW_AT_type
	.byte	11                              # Abbrev [11] 0x134:0x5 DW_TAG_volatile_type
	.word	313                             # DW_AT_type
	.byte	12                              # Abbrev [12] 0x139:0x3a DW_TAG_union_type
	.word	.Linfo_string25                 # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	21                              # DW_AT_decl_line
	.byte	4                               # DW_AT_alignment
	.byte	8                               # Abbrev [8] 0x142:0xc DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	187                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	22                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x14e:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	371                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	23                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x15a:0xc DW_TAG_member
	.word	.Linfo_string14                 # DW_AT_name
	.word	187                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	24                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	8                               # Abbrev [8] 0x166:0xc DW_TAG_member
	.word	.Linfo_string17                 # DW_AT_name
	.word	281                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	25                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x173:0x5 DW_TAG_const_type
	.word	376                             # DW_AT_type
	.byte	11                              # Abbrev [11] 0x178:0x5 DW_TAG_volatile_type
	.word	381                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x17d:0xb DW_TAG_typedef
	.word	392                             # DW_AT_type
	.word	.Linfo_string24                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	125                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0x188:0x7 DW_TAG_base_type
	.word	.Linfo_string23                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	2                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x18f:0x11 DW_TAG_variable
	.word	.Linfo_string26                 # DW_AT_name
	.word	416                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	32                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_197
	.byte	13                              # Abbrev [13] 0x1a0:0x12 DW_TAG_array_type
	.word	241                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x1a5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x1ab:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x1b2:0x7 DW_TAG_base_type
	.word	.Linfo_string27                 # DW_AT_name
	.byte	8                               # DW_AT_byte_size
	.byte	7                               # DW_AT_encoding
	.byte	2                               # Abbrev [2] 0x1b9:0x11 DW_TAG_variable
	.word	.Linfo_string28                 # DW_AT_name
	.word	458                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	33                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_200
	.byte	5                               # Abbrev [5] 0x1ca:0x5 DW_TAG_pointer_type
	.word	55                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x1cf:0x11 DW_TAG_variable
	.word	.Linfo_string29                 # DW_AT_name
	.word	480                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	34                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_199
	.byte	13                              # Abbrev [13] 0x1e0:0xc DW_TAG_array_type
	.word	492                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x1e5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	11                              # Abbrev [11] 0x1ec:0x5 DW_TAG_volatile_type
	.word	497                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x1f1:0x5 DW_TAG_pointer_type
	.word	458                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x1f6:0x11 DW_TAG_variable
	.word	.Linfo_string30                 # DW_AT_name
	.word	187                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	35                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_302
	.byte	2                               # Abbrev [2] 0x207:0x11 DW_TAG_variable
	.word	.Linfo_string31                 # DW_AT_name
	.word	536                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	36                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_334
	.byte	11                              # Abbrev [11] 0x218:0x5 DW_TAG_volatile_type
	.word	458                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x21d:0x11 DW_TAG_variable
	.word	.Linfo_string32                 # DW_AT_name
	.word	558                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	37                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_467
	.byte	13                              # Abbrev [13] 0x22e:0x12 DW_TAG_array_type
	.word	497                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x233:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x239:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	2                               # Abbrev [2] 0x240:0x11 DW_TAG_variable
	.word	.Linfo_string33                 # DW_AT_name
	.word	593                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	38                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_500
	.byte	5                               # Abbrev [5] 0x251:0x5 DW_TAG_pointer_type
	.word	598                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x256:0x5 DW_TAG_pointer_type
	.word	603                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x25b:0xb DW_TAG_typedef
	.word	614                             # DW_AT_type
	.word	.Linfo_string35                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	135                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0x266:0x7 DW_TAG_base_type
	.word	.Linfo_string34                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x26d:0x11 DW_TAG_variable
	.word	.Linfo_string36                 # DW_AT_name
	.word	638                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	39                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_524
	.byte	11                              # Abbrev [11] 0x27e:0x5 DW_TAG_volatile_type
	.word	643                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x283:0x5 DW_TAG_pointer_type
	.word	153                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x288:0x11 DW_TAG_variable
	.word	.Linfo_string37                 # DW_AT_name
	.word	153                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	40                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_556
	.byte	2                               # Abbrev [2] 0x299:0x11 DW_TAG_variable
	.word	.Linfo_string38                 # DW_AT_name
	.word	682                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	41                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_555
	.byte	13                              # Abbrev [13] 0x2aa:0x18 DW_TAG_array_type
	.word	638                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2af:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2bb:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	2                               # Abbrev [2] 0x2c2:0x11 DW_TAG_variable
	.word	.Linfo_string39                 # DW_AT_name
	.word	723                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_672
	.byte	13                              # Abbrev [13] 0x2d3:0x18 DW_TAG_array_type
	.word	747                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d8:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2de:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e4:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2eb:0x5 DW_TAG_pointer_type
	.word	90                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x2f0:0x11 DW_TAG_variable
	.word	.Linfo_string40                 # DW_AT_name
	.word	769                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	43                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_901
	.byte	13                              # Abbrev [13] 0x301:0xc DW_TAG_array_type
	.word	781                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x306:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	11                              # Abbrev [11] 0x30d:0x5 DW_TAG_volatile_type
	.word	786                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x312:0x5 DW_TAG_pointer_type
	.word	593                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x317:0x11 DW_TAG_variable
	.word	.Linfo_string41                 # DW_AT_name
	.word	808                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	44                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_932
	.byte	11                              # Abbrev [11] 0x328:0x5 DW_TAG_volatile_type
	.word	187                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x32d:0x11 DW_TAG_variable
	.word	.Linfo_string42                 # DW_AT_name
	.word	830                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	45                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_946
	.byte	11                              # Abbrev [11] 0x33e:0x5 DW_TAG_volatile_type
	.word	95                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x343:0x11 DW_TAG_variable
	.word	.Linfo_string43                 # DW_AT_name
	.word	55                              # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	46                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1000
	.byte	2                               # Abbrev [2] 0x354:0x11 DW_TAG_variable
	.word	.Linfo_string44                 # DW_AT_name
	.word	869                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	47                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1247
	.byte	5                               # Abbrev [5] 0x365:0x5 DW_TAG_pointer_type
	.word	313                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x36a:0x11 DW_TAG_variable
	.word	.Linfo_string45                 # DW_AT_name
	.word	891                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	48                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1259
	.byte	13                              # Abbrev [13] 0x37b:0x12 DW_TAG_array_type
	.word	808                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x380:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x386:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	2                               # Abbrev [2] 0x38d:0x11 DW_TAG_variable
	.word	.Linfo_string46                 # DW_AT_name
	.word	926                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	49                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1374
	.byte	5                               # Abbrev [5] 0x39e:0x5 DW_TAG_pointer_type
	.word	376                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x3a3:0x11 DW_TAG_variable
	.word	.Linfo_string47                 # DW_AT_name
	.word	948                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	50                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1380
	.byte	13                              # Abbrev [13] 0x3b4:0xc DW_TAG_array_type
	.word	276                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x3b9:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	2                               # Abbrev [2] 0x3c0:0x11 DW_TAG_variable
	.word	.Linfo_string48                 # DW_AT_name
	.word	977                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	51                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1571
	.byte	5                               # Abbrev [5] 0x3d1:0x5 DW_TAG_pointer_type
	.word	982                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x3d6:0xb DW_TAG_typedef
	.word	993                             # DW_AT_type
	.word	.Linfo_string50                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.byte	4                               # Abbrev [4] 0x3e1:0x7 DW_TAG_base_type
	.word	.Linfo_string49                 # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x3e8:0x11 DW_TAG_variable
	.word	.Linfo_string51                 # DW_AT_name
	.word	1017                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	52                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1717
	.byte	13                              # Abbrev [13] 0x3f9:0x18 DW_TAG_array_type
	.word	313                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x3fe:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x404:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x40a:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	2                               # Abbrev [2] 0x411:0x11 DW_TAG_variable
	.word	.Linfo_string52                 # DW_AT_name
	.word	808                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	53                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1781
	.byte	2                               # Abbrev [2] 0x422:0x11 DW_TAG_variable
	.word	.Linfo_string53                 # DW_AT_name
	.word	313                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	54                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1816
	.byte	2                               # Abbrev [2] 0x433:0x11 DW_TAG_variable
	.word	.Linfo_string54                 # DW_AT_name
	.word	1092                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	55                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1817
	.byte	10                              # Abbrev [10] 0x444:0x5 DW_TAG_const_type
	.word	313                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x449:0x11 DW_TAG_variable
	.word	.Linfo_string55                 # DW_AT_name
	.word	1114                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1811
	.byte	13                              # Abbrev [13] 0x45a:0x12 DW_TAG_array_type
	.word	1132                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x45f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x465:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x46c:0x5 DW_TAG_pointer_type
	.word	1092                            # DW_AT_type
	.byte	2                               # Abbrev [2] 0x471:0x11 DW_TAG_variable
	.word	.Linfo_string56                 # DW_AT_name
	.word	1154                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	57                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2016
	.byte	11                              # Abbrev [11] 0x482:0x5 DW_TAG_volatile_type
	.word	241                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x487:0x11 DW_TAG_variable
	.word	.Linfo_string57                 # DW_AT_name
	.word	1176                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	58                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2014
	.byte	5                               # Abbrev [5] 0x498:0x5 DW_TAG_pointer_type
	.word	1181                            # DW_AT_type
	.byte	5                               # Abbrev [5] 0x49d:0x5 DW_TAG_pointer_type
	.word	1154                            # DW_AT_type
	.byte	2                               # Abbrev [2] 0x4a2:0x11 DW_TAG_variable
	.word	.Linfo_string58                 # DW_AT_name
	.word	308                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	59                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2201
	.byte	16                              # Abbrev [16] 0x4b3:0xe DW_TAG_variable
	.word	1217                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	612                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str
	.byte	13                              # Abbrev [13] 0x4c1:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x4c6:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	4                               # Abbrev [4] 0x4cd:0x7 DW_TAG_base_type
	.word	.Linfo_string59                 # DW_AT_name
	.byte	8                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	16                              # Abbrev [16] 0x4d4:0xe DW_TAG_variable
	.word	1250                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	622                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.8
	.byte	13                              # Abbrev [13] 0x4e2:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x4e7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	13                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x4ee:0xe DW_TAG_variable
	.word	1276                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	623                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.9
	.byte	13                              # Abbrev [13] 0x4fc:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x501:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	22                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x508:0xe DW_TAG_variable
	.word	1302                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	628                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.10
	.byte	13                              # Abbrev [13] 0x516:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x51b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x522:0xe DW_TAG_variable
	.word	1302                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	629                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.11
	.byte	16                              # Abbrev [16] 0x530:0xe DW_TAG_variable
	.word	1302                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	630                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.12
	.byte	16                              # Abbrev [16] 0x53e:0xe DW_TAG_variable
	.word	1250                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	637                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.13
	.byte	16                              # Abbrev [16] 0x54c:0xe DW_TAG_variable
	.word	1370                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	643                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.14
	.byte	13                              # Abbrev [13] 0x55a:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x55f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x566:0xe DW_TAG_variable
	.word	1396                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	646                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.15
	.byte	13                              # Abbrev [13] 0x574:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x579:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	11                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x580:0xe DW_TAG_variable
	.word	1396                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	647                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.16
	.byte	16                              # Abbrev [16] 0x58e:0xe DW_TAG_variable
	.word	1436                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.17
	.byte	13                              # Abbrev [13] 0x59c:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x5a1:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	14                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x5a8:0xe DW_TAG_variable
	.word	1370                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	651                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.18
	.byte	16                              # Abbrev [16] 0x5b6:0xe DW_TAG_variable
	.word	1370                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	652                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.19
	.byte	16                              # Abbrev [16] 0x5c4:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	653                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.20
	.byte	13                              # Abbrev [13] 0x5d2:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x5d7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x5de:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	654                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.21
	.byte	16                              # Abbrev [16] 0x5ec:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	655                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.22
	.byte	16                              # Abbrev [16] 0x5fa:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	656                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.23
	.byte	16                              # Abbrev [16] 0x608:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	657                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.24
	.byte	13                              # Abbrev [13] 0x616:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x61b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x622:0xe DW_TAG_variable
	.word	1584                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	664                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.25
	.byte	13                              # Abbrev [13] 0x630:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x635:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	15                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x63c:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	670                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.26
	.byte	13                              # Abbrev [13] 0x64a:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x64f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	12                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x656:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	671                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.27
	.byte	16                              # Abbrev [16] 0x664:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	672                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.28
	.byte	16                              # Abbrev [16] 0x672:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	677                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.29
	.byte	16                              # Abbrev [16] 0x680:0xe DW_TAG_variable
	.word	1678                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	678                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.30
	.byte	13                              # Abbrev [13] 0x68e:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x693:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	18                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x69a:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	682                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.31
	.byte	16                              # Abbrev [16] 0x6a8:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	683                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.32
	.byte	16                              # Abbrev [16] 0x6b6:0xe DW_TAG_variable
	.word	1584                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	688                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.33
	.byte	16                              # Abbrev [16] 0x6c4:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	693                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.34
	.byte	16                              # Abbrev [16] 0x6d2:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	694                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.35
	.byte	16                              # Abbrev [16] 0x6e0:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	695                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.36
	.byte	16                              # Abbrev [16] 0x6ee:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	696                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.37
	.byte	16                              # Abbrev [16] 0x6fc:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	697                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.38
	.byte	16                              # Abbrev [16] 0x70a:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	698                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.39
	.byte	16                              # Abbrev [16] 0x718:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	699                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.40
	.byte	16                              # Abbrev [16] 0x726:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	700                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.41
	.byte	16                              # Abbrev [16] 0x734:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	701                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.42
	.byte	16                              # Abbrev [16] 0x742:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	702                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.43
	.byte	16                              # Abbrev [16] 0x750:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	703                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.44
	.byte	16                              # Abbrev [16] 0x75e:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	704                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.45
	.byte	16                              # Abbrev [16] 0x76c:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	705                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.46
	.byte	16                              # Abbrev [16] 0x77a:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	706                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.47
	.byte	16                              # Abbrev [16] 0x788:0xe DW_TAG_variable
	.word	1558                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	707                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.48
	.byte	16                              # Abbrev [16] 0x796:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	710                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.49
	.byte	16                              # Abbrev [16] 0x7a4:0xe DW_TAG_variable
	.word	1490                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	714                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.50
	.byte	16                              # Abbrev [16] 0x7b2:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	715                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.51
	.byte	16                              # Abbrev [16] 0x7c0:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	716                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.52
	.byte	16                              # Abbrev [16] 0x7ce:0xe DW_TAG_variable
	.word	1610                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	721                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.53
	.byte	16                              # Abbrev [16] 0x7dc:0xe DW_TAG_variable
	.word	1584                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	732                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.54
	.byte	16                              # Abbrev [16] 0x7ea:0xe DW_TAG_variable
	.word	2040                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	738                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.55
	.byte	13                              # Abbrev [13] 0x7f8:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x7fd:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x804:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	739                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.56
	.byte	13                              # Abbrev [13] 0x812:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x817:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x81e:0xe DW_TAG_variable
	.word	1250                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	744                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.57
	.byte	16                              # Abbrev [16] 0x82c:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	749                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.58
	.byte	16                              # Abbrev [16] 0x83a:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	752                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.59
	.byte	16                              # Abbrev [16] 0x848:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	756                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.60
	.byte	16                              # Abbrev [16] 0x856:0xe DW_TAG_variable
	.word	2040                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	757                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.61
	.byte	16                              # Abbrev [16] 0x864:0xe DW_TAG_variable
	.word	2162                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.62
	.byte	13                              # Abbrev [13] 0x872:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x877:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	19                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x87e:0xe DW_TAG_variable
	.word	2040                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	770                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.63
	.byte	16                              # Abbrev [16] 0x88c:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.64
	.byte	16                              # Abbrev [16] 0x89a:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	772                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.65
	.byte	16                              # Abbrev [16] 0x8a8:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	773                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.66
	.byte	16                              # Abbrev [16] 0x8b6:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	774                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.67
	.byte	16                              # Abbrev [16] 0x8c4:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	775                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.68
	.byte	16                              # Abbrev [16] 0x8d2:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	776                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.69
	.byte	16                              # Abbrev [16] 0x8e0:0xe DW_TAG_variable
	.word	2286                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	781                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.70
	.byte	13                              # Abbrev [13] 0x8ee:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x8f3:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	16                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x8fa:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	786                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.71
	.byte	16                              # Abbrev [16] 0x908:0xe DW_TAG_variable
	.word	2040                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	787                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.72
	.byte	16                              # Abbrev [16] 0x916:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	788                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.73
	.byte	16                              # Abbrev [16] 0x924:0xe DW_TAG_variable
	.word	2040                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	789                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.74
	.byte	16                              # Abbrev [16] 0x932:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	790                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.75
	.byte	16                              # Abbrev [16] 0x940:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	791                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.76
	.byte	16                              # Abbrev [16] 0x94e:0xe DW_TAG_variable
	.word	2286                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	796                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.77
	.byte	16                              # Abbrev [16] 0x95c:0xe DW_TAG_variable
	.word	2066                            # DW_AT_type
	.byte	2                               # DW_AT_decl_file
	.half	801                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.78
	.byte	17                              # Abbrev [17] 0x96a:0x11 DW_TAG_variable
	.word	.Linfo_string60                 # DW_AT_name
	.word	2427                            # DW_AT_type
	.byte	4                               # DW_AT_decl_file
	.byte	47                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	crc32_tab
	.byte	13                              # Abbrev [13] 0x97b:0xd DW_TAG_array_type
	.word	187                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x980:0x7 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.half	256                             # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	19                              # Abbrev [19] 0x988:0xd DW_TAG_variable
	.word	2453                            # DW_AT_type
	.byte	4                               # DW_AT_decl_file
	.byte	114                             # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.79
	.byte	13                              # Abbrev [13] 0x995:0xc DW_TAG_array_type
	.word	1229                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x99a:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	36                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	19                              # Abbrev [19] 0x9a1:0xd DW_TAG_variable
	.word	1584                            # DW_AT_type
	.byte	5                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	.L.str.80
	.byte	17                              # Abbrev [17] 0x9ae:0x11 DW_TAG_variable
	.word	.Linfo_string61                 # DW_AT_name
	.word	187                             # DW_AT_type
	.byte	4                               # DW_AT_decl_file
	.byte	48                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	crc32_context
	.byte	20                              # Abbrev [20] 0x9bf:0x1 DW_TAG_pointer_type
	.byte	21                              # Abbrev [21] 0x9c0:0x133b DW_TAG_subprogram
	.word	.Lfunc_begin0                   # DW_AT_low_pc
	.word	.Lfunc_end0-.Lfunc_begin0       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string62                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	276                             # DW_AT_type
                                        # DW_AT_external
	.byte	22                              # Abbrev [22] 0x9d5:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string125                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x9e3:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	96
	.word	.Linfo_string126                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x9f1:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	88
	.word	.Linfo_string127                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x9ff:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	84
	.word	.Linfo_string128                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0xa0d:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	80
	.word	.Linfo_string129                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa1b:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	76
	.word	.Linfo_string130                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	67                              # DW_AT_decl_line
	.word	11023                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa29:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	72
	.word	.Linfo_string131                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	68                              # DW_AT_decl_line
	.word	11023                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa37:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	68
	.word	.Linfo_string132                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	69                              # DW_AT_decl_line
	.word	11028                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa45:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	64
	.word	.Linfo_string133                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	70                              # DW_AT_decl_line
	.word	497                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa53:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360|"
	.word	.Linfo_string134                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	71                              # DW_AT_decl_line
	.word	11033                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa62:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354|"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	72                              # DW_AT_decl_line
	.word	598                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa71:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344|"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	73                              # DW_AT_decl_line
	.word	11057                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa80:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340|"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	74                              # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa8f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320|"
	.word	.Linfo_string138                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	75                              # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xa9e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370z"
	.word	.Linfo_string139                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	76                              # DW_AT_decl_line
	.word	11069                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xaad:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364z"
	.word	.Linfo_string140                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	77                              # DW_AT_decl_line
	.word	11093                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xabc:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260v"
	.word	.Linfo_string141                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	78                              # DW_AT_decl_line
	.word	11098                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xacb:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250v"
	.word	.Linfo_string142                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	79                              # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xada:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244v"
	.word	.Linfo_string143                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	80                              # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xae9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330n"
	.word	.Linfo_string144                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	81                              # DW_AT_decl_line
	.word	11116                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xaf8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230l"
	.word	.Linfo_string145                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
	.word	11140                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb07:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260i"
	.word	.Linfo_string146                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	83                              # DW_AT_decl_line
	.word	11164                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb16:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\257i"
	.word	.Linfo_string147                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	84                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb25:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250i"
	.word	.Linfo_string148                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	85                              # DW_AT_decl_line
	.word	11188                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb34:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\247i"
	.word	.Linfo_string149                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	86                              # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb43:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230i"
	.word	.Linfo_string150                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	87                              # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb52:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224i"
	.word	.Linfo_string151                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	88                              # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb61:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220i"
	.word	.Linfo_string152                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	89                              # DW_AT_decl_line
	.word	11198                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb70:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214i"
	.word	.Linfo_string153                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	90                              # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb7f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360h"
	.word	.Linfo_string154                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	91                              # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb8e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354h"
	.word	.Linfo_string155                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	92                              # DW_AT_decl_line
	.word	747                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xb9d:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230h"
	.word	.Linfo_string156                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	93                              # DW_AT_decl_line
	.word	11218                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbac:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\226h"
	.word	.Linfo_string157                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	94                              # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbbb:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220h"
	.word	.Linfo_string158                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	95                              # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbca:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214h"
	.word	.Linfo_string159                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	96                              # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbd9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300g"
	.word	.Linfo_string160                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	97                              # DW_AT_decl_line
	.word	11230                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbe8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\276g"
	.word	.Linfo_string161                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	98                              # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xbf7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270g"
	.word	.Linfo_string162                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	99                              # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc06:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264g"
	.word	.Linfo_string163                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	100                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc15:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260g"
	.word	.Linfo_string164                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	101                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc24:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\254g"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	102                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc33:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250g"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	102                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc42:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244g"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	102                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0xc51:0x19 DW_TAG_lexical_block
	.word	.Ltmp17                         # DW_AT_low_pc
	.word	.Ltmp23-.Ltmp17                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xc5a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240g"
	.word	.Linfo_string168                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	111                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0xc6a:0xcd DW_TAG_lexical_block
	.word	.Ltmp23                         # DW_AT_low_pc
	.word	.Ltmp34-.Ltmp23                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xc73:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234g"
	.word	.Linfo_string169                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	120                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc82:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200g"
	.word	.Linfo_string170                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	121                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xc91:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370f"
	.word	.Linfo_string171                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	122                             # DW_AT_decl_line
	.word	11247                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xca0:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364f"
	.word	.Linfo_string172                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	123                             # DW_AT_decl_line
	.word	11259                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xcaf:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360f"
	.word	.Linfo_string173                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	124                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xcbe:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320d"
	.word	.Linfo_string174                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	125                             # DW_AT_decl_line
	.word	11264                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xccd:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314d"
	.word	.Linfo_string175                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	126                             # DW_AT_decl_line
	.word	11093                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xcdc:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310d"
	.word	.Linfo_string176                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	127                             # DW_AT_decl_line
	.word	11288                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xceb:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\307d"
	.word	.Linfo_string177                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	128                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xcfa:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300d"
	.word	.Linfo_string178                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	129                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd09:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274d"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd18:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270d"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd27:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264d"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0xd37:0x127 DW_TAG_lexical_block
	.word	.Ltmp37                         # DW_AT_low_pc
	.word	.Ltmp53-.Ltmp37                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xd40:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260a"
	.word	.Linfo_string179                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	139                             # DW_AT_decl_line
	.word	11300                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd4f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\254a"
	.word	.Linfo_string180                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	140                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd5e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230a"
	.word	.Linfo_string181                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	141                             # DW_AT_decl_line
	.word	11318                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd6d:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230^"
	.word	.Linfo_string182                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	142                             # DW_AT_decl_line
	.word	11330                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd7c:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370]"
	.word	.Linfo_string183                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	143                             # DW_AT_decl_line
	.word	11354                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd8b:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350]"
	.word	.Linfo_string184                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	144                             # DW_AT_decl_line
	.word	11366                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xd9a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344]"
	.word	.Linfo_string185                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	145                             # DW_AT_decl_line
	.word	11259                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xda9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\342]"
	.word	.Linfo_string186                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	146                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xdb8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240V"
	.word	.Linfo_string187                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	147                             # DW_AT_decl_line
	.word	11378                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xdc7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330U"
	.word	.Linfo_string188                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	148                             # DW_AT_decl_line
	.word	11412                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xdd6:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324U"
	.word	.Linfo_string189                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	149                             # DW_AT_decl_line
	.word	11435                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xde5:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314U"
	.word	.Linfo_string190                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	150                             # DW_AT_decl_line
	.word	11440                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xdf4:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234U"
	.word	.Linfo_string191                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	151                             # DW_AT_decl_line
	.word	11452                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe03:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230U"
	.word	.Linfo_string192                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	152                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe12:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364T"
	.word	.Linfo_string193                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	153                             # DW_AT_decl_line
	.word	11476                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe21:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\363T"
	.word	.Linfo_string194                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	154                             # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe30:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354T"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	155                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe3f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350T"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	155                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe4e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344T"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	155                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0xe5e:0x258 DW_TAG_lexical_block
	.word	.Ltmp58                         # DW_AT_low_pc
	.word	.Ltmp116-.Ltmp58                # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xe67:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340T"
	.word	.Linfo_string195                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	165                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe76:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240T"
	.word	.Linfo_string196                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	166                             # DW_AT_decl_line
	.word	11488                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe85:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234T"
	.word	.Linfo_string197                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	167                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xe94:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\233T"
	.word	.Linfo_string198                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	168                             # DW_AT_decl_line
	.word	11506                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xea3:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220T"
	.word	.Linfo_string199                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	169                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xeb2:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360S"
	.word	.Linfo_string200                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	170                             # DW_AT_decl_line
	.word	11511                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xec1:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354S"
	.word	.Linfo_string201                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	171                             # DW_AT_decl_line
	.word	11198                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xed0:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350S"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xedf:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344S"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0xeee:0x172 DW_TAG_lexical_block
	.word	.Ltmp66                         # DW_AT_low_pc
	.word	.Ltmp109-.Ltmp66                # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xef7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\342S"
	.word	.Linfo_string202                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	177                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf06:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334S"
	.word	.Linfo_string203                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	178                             # DW_AT_decl_line
	.word	869                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf15:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330S"
	.word	.Linfo_string204                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	179                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf24:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324S"
	.word	.Linfo_string205                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	180                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf33:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274S"
	.word	.Linfo_string206                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	181                             # DW_AT_decl_line
	.word	11523                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf42:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270S"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	182                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0xf51:0x96 DW_TAG_lexical_block
	.word	.Ltmp69                         # DW_AT_low_pc
	.word	.Ltmp89-.Ltmp69                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xf5a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\266S"
	.word	.Linfo_string207                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	185                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf69:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260S"
	.word	.Linfo_string208                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0xf78:0x6e DW_TAG_lexical_block
	.word	.Ltmp73                         # DW_AT_low_pc
	.word	.Ltmp88-.Ltmp73                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xf81:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250S"
	.word	.Linfo_string209                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	189                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf90:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244S"
	.word	.Linfo_string210                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	190                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xf9f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240S"
	.word	.Linfo_string211                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	191                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0xfae:0x37 DW_TAG_lexical_block
	.word	.Ltmp77                         # DW_AT_low_pc
	.word	.Ltmp86-.Ltmp77                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xfb7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234S"
	.word	.Linfo_string212                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	194                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xfc6:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230S"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	195                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0xfd5:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224S"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	195                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0xfe7:0x78 DW_TAG_lexical_block
	.word	.Ltmp89                         # DW_AT_low_pc
	.word	.Ltmp103-.Ltmp89                # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0xff0:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220S"
	.word	.Linfo_string213                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	210                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0xfff:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214S"
	.word	.Linfo_string214                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	211                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0x100e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210S"
	.word	.Linfo_string215                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x101d:0x19 DW_TAG_lexical_block
	.word	.Ltmp92                         # DW_AT_low_pc
	.word	.Ltmp97-.Ltmp92                 # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0x1026:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204S"
	.word	.Linfo_string216                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	215                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1036:0x28 DW_TAG_lexical_block
	.word	.Ltmp97                         # DW_AT_low_pc
	.word	.Ltmp102-.Ltmp97                # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0x103f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340R"
	.word	.Linfo_string217                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	224                             # DW_AT_decl_line
	.word	11476                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0x104e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334R"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	225                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1060:0x55 DW_TAG_lexical_block
	.word	.Ltmp113                        # DW_AT_low_pc
	.word	.Ltmp114-.Ltmp113               # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0x1069:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330R"
	.word	.Linfo_string218                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	245                             # DW_AT_decl_line
	.word	11535                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0x1078:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324R"
	.word	.Linfo_string219                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	246                             # DW_AT_decl_line
	.word	11188                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0x1087:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320R"
	.word	.Linfo_string220                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	247                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0x1096:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300R"
	.word	.Linfo_string221                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	248                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0x10a5:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274R"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x10b6:0xb42 DW_TAG_lexical_block
	.word	.Ltmp119                        # DW_AT_low_pc
	.word	.Ltmp286-.Ltmp119               # DW_AT_high_pc
	.byte	23                              # Abbrev [23] 0x10bf:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374M"
	.word	.Linfo_string222                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	254                             # DW_AT_decl_line
	.word	11540                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0x10ce:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370M"
	.word	.Linfo_string223                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	255                             # DW_AT_decl_line
	.word	11569                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x10dd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364M"
	.word	.Linfo_string224                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	256                             # DW_AT_decl_line
	.word	11584                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x10ed:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360M"
	.word	.Linfo_string225                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	257                             # DW_AT_decl_line
	.word	11589                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x10fd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354M"
	.word	.Linfo_string226                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	258                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x110d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350M"
	.word	.Linfo_string227                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	259                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x111d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314M"
	.word	.Linfo_string228                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	11594                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x112d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324L"
	.word	.Linfo_string229                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	261                             # DW_AT_decl_line
	.word	11606                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x113d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300L"
	.word	.Linfo_string230                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	262                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x114d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274L"
	.word	.Linfo_string231                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	263                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x115d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270L"
	.word	.Linfo_string232                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	264                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x116d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264L"
	.word	.Linfo_string233                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	265                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x117d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200I"
	.word	.Linfo_string234                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	266                             # DW_AT_decl_line
	.word	11630                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x118d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374H"
	.word	.Linfo_string235                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	267                             # DW_AT_decl_line
	.word	11654                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x119d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370H"
	.word	.Linfo_string236                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	268                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11ad:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364H"
	.word	.Linfo_string237                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	269                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11bd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\362H"
	.word	.Linfo_string238                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	270                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11cd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354H"
	.word	.Linfo_string239                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	271                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11dd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350H"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	272                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11ed:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344H"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	272                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x11fd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340H"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	272                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	26                              # Abbrev [26] 0x120d:0xc DW_TAG_label
	.word	.Linfo_string364                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	323                             # DW_AT_decl_line
	.word	.Ltmp165                        # DW_AT_low_pc
	.byte	24                              # Abbrev [24] 0x1219:0x148 DW_TAG_lexical_block
	.word	.Ltmp123                        # DW_AT_low_pc
	.word	.Ltmp163-.Ltmp123               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1222:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340G"
	.word	.Linfo_string240                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	275                             # DW_AT_decl_line
	.word	11674                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1232:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334G"
	.word	.Linfo_string241                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	276                             # DW_AT_decl_line
	.word	11692                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1242:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324G"
	.word	.Linfo_string242                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	277                             # DW_AT_decl_line
	.word	11697                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1252:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314G"
	.word	.Linfo_string243                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	278                             # DW_AT_decl_line
	.word	11715                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1262:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310G"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	279                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1272:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304G"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	279                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1282:0xc4 DW_TAG_lexical_block
	.word	.Ltmp141                        # DW_AT_low_pc
	.word	.Ltmp156-.Ltmp141               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x128b:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300G"
	.word	.Linfo_string244                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	289                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x129b:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274G"
	.word	.Linfo_string245                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	290                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x12ab:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270G"
	.word	.Linfo_string246                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	291                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x12bb:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264G"
	.word	.Linfo_string247                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	292                             # DW_AT_decl_line
	.word	598                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x12cb:0x7a DW_TAG_lexical_block
	.word	.Ltmp145                        # DW_AT_low_pc
	.word	.Ltmp155-.Ltmp145               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x12d4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230G"
	.word	.Linfo_string248                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	295                             # DW_AT_decl_line
	.word	11727                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x12e4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224G"
	.word	.Linfo_string249                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	296                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x12f4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220G"
	.word	.Linfo_string250                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	297                             # DW_AT_decl_line
	.word	11259                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1304:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\216G"
	.word	.Linfo_string251                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	298                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1314:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210G"
	.word	.Linfo_string252                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	299                             # DW_AT_decl_line
	.word	11023                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1324:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204G"
	.word	.Linfo_string253                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	300                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1334:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200G"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	301                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1346:0x1a DW_TAG_lexical_block
	.word	.Ltmp160                        # DW_AT_low_pc
	.word	.Ltmp161-.Ltmp160               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x134f:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360F"
	.word	.Linfo_string254                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	318                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1361:0x1fa DW_TAG_lexical_block
	.word	.Ltmp168                        # DW_AT_low_pc
	.word	.Ltmp217-.Ltmp168               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x136a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354F"
	.word	.Linfo_string255                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	326                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x137a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350F"
	.word	.Linfo_string256                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	327                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x138a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344F"
	.word	.Linfo_string257                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	328                             # DW_AT_decl_line
	.word	598                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x139a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\301F"
	.word	.Linfo_string258                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	329                             # DW_AT_decl_line
	.word	11739                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x13aa:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274F"
	.word	.Linfo_string259                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	330                             # DW_AT_decl_line
	.word	869                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x13ba:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270F"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	331                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x13ca:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264F"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	331                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x13da:0x4e DW_TAG_lexical_block
	.word	.Ltmp171                        # DW_AT_low_pc
	.word	.Ltmp189-.Ltmp171               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x13e3:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260F"
	.word	.Linfo_string260                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	335                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x13f3:0x34 DW_TAG_lexical_block
	.word	.Ltmp182                        # DW_AT_low_pc
	.word	.Ltmp188-.Ltmp182               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x13fc:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\254F"
	.word	.Linfo_string261                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	346                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x140c:0x1a DW_TAG_lexical_block
	.word	.Ltmp186                        # DW_AT_low_pc
	.word	.Ltmp187-.Ltmp186               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1415:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250F"
	.word	.Linfo_string262                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	349                             # DW_AT_decl_line
	.word	276                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1428:0x132 DW_TAG_lexical_block
	.word	.Ltmp190                        # DW_AT_low_pc
	.word	.Ltmp212-.Ltmp190               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1431:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220F"
	.word	.Linfo_string263                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	358                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1441:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214F"
	.word	.Linfo_string264                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	359                             # DW_AT_decl_line
	.word	598                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1451:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210F"
	.word	.Linfo_string265                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	360                             # DW_AT_decl_line
	.word	11757                           # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1461:0xf8 DW_TAG_lexical_block
	.word	.Ltmp194                        # DW_AT_low_pc
	.word	.Ltmp210-.Ltmp194               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x146a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200F"
	.word	.Linfo_string266                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	363                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x147a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374E"
	.word	.Linfo_string267                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	364                             # DW_AT_decl_line
	.word	497                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x148a:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370E"
	.word	.Linfo_string268                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	365                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x149a:0x1a DW_TAG_lexical_block
	.word	.Ltmp197                        # DW_AT_low_pc
	.word	.Ltmp198-.Ltmp197               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x14a3:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364E"
	.word	.Linfo_string269                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	368                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x14b4:0x1a DW_TAG_lexical_block
	.word	.Ltmp198                        # DW_AT_low_pc
	.word	.Ltmp199-.Ltmp198               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x14bd:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360E"
	.word	.Linfo_string270                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	373                             # DW_AT_decl_line
	.word	497                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x14ce:0x8a DW_TAG_lexical_block
	.word	.Ltmp203                        # DW_AT_low_pc
	.word	.Ltmp208-.Ltmp203               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x14d7:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354E"
	.word	.Linfo_string271                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	380                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x14e7:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350E"
	.word	.Linfo_string272                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	381                             # DW_AT_decl_line
	.word	11535                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x14f7:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344E"
	.word	.Linfo_string273                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	382                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1507:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340E"
	.word	.Linfo_string274                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	383                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1517:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334E"
	.word	.Linfo_string275                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	384                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1527:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300E"
	.word	.Linfo_string276                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	385                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1537:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274E"
	.word	.Linfo_string277                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	386                             # DW_AT_decl_line
	.word	643                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1547:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270E"
	.word	.Linfo_string278                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	387                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x155b:0x2c7 DW_TAG_lexical_block
	.word	.Ltmp222                        # DW_AT_low_pc
	.word	.Ltmp240-.Ltmp222               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1564:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264E"
	.word	.Linfo_string279                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	403                             # DW_AT_decl_line
	.word	11762                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1574:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324D"
	.word	.Linfo_string280                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	404                             # DW_AT_decl_line
	.word	11774                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1584:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300D"
	.word	.Linfo_string281                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	405                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1594:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274D"
	.word	.Linfo_string282                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	406                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15a4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270D"
	.word	.Linfo_string283                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	407                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15b4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210@"
	.word	.Linfo_string284                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	408                             # DW_AT_decl_line
	.word	11808                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15c4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\206@"
	.word	.Linfo_string285                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	409                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15d4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\205@"
	.word	.Linfo_string286                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	410                             # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15e4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200@"
	.word	.Linfo_string287                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	411                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15f4:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\374\277\177"
	.word	.Linfo_string288                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	412                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1605:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\244\276\177"
	.word	.Linfo_string289                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	413                             # DW_AT_decl_line
	.word	11832                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1616:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\254\275\177"
	.word	.Linfo_string290                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	414                             # DW_AT_decl_line
	.word	11850                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1627:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\254\274\177"
	.word	.Linfo_string291                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	415                             # DW_AT_decl_line
	.word	11874                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1638:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\250\274\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	416                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1649:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\244\274\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	416                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x165a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\274\177"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	416                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x166b:0xd6 DW_TAG_lexical_block
	.word	.Ltmp233                        # DW_AT_low_pc
	.word	.Ltmp234-.Ltmp233               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1674:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\200\267\177"
	.word	.Linfo_string292                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	423                             # DW_AT_decl_line
	.word	11898                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1685:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\376\266\177"
	.word	.Linfo_string293                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	424                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1696:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\370\266\177"
	.word	.Linfo_string294                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	425                             # DW_AT_decl_line
	.word	11535                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16a7:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\340\266\177"
	.word	.Linfo_string295                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	426                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16b8:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\274\263\177"
	.word	.Linfo_string296                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	427                             # DW_AT_decl_line
	.word	11922                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16c9:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\272\263\177"
	.word	.Linfo_string297                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	428                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16da:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\270\263\177"
	.word	.Linfo_string298                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	429                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16eb:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\264\263\177"
	.word	.Linfo_string299                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	430                             # DW_AT_decl_line
	.word	747                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x16fc:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\260\263\177"
	.word	.Linfo_string300                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	431                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x170d:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\254\263\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	432                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x171e:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\250\263\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	432                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x172f:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\244\263\177"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	432                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1741:0x3d DW_TAG_lexical_block
	.word	.Ltmp237                        # DW_AT_low_pc
	.word	.Ltmp238-.Ltmp237               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x174a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\263\177"
	.word	.Linfo_string301                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	436                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x175b:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\234\263\177"
	.word	.Linfo_string302                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	437                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x176c:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\230\263\177"
	.word	.Linfo_string303                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	438                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x177e:0xa3 DW_TAG_lexical_block
	.word	.Ltmp238                        # DW_AT_low_pc
	.word	.Ltmp239-.Ltmp238               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1787:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\360\262\177"
	.word	.Linfo_string304                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	445                             # DW_AT_decl_line
	.word	11946                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1798:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\354\262\177"
	.word	.Linfo_string305                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	446                             # DW_AT_decl_line
	.word	11692                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17a9:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\324\262\177"
	.word	.Linfo_string306                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
	.word	11958                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17ba:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\320\262\177"
	.word	.Linfo_string307                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	448                             # DW_AT_decl_line
	.word	497                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17cb:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\314\262\177"
	.word	.Linfo_string308                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	449                             # DW_AT_decl_line
	.word	869                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17dc:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\310\262\177"
	.word	.Linfo_string309                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	450                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17ed:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\304\262\177"
	.word	.Linfo_string310                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	451                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x17fe:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\300\262\177"
	.word	.Linfo_string311                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	452                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x180f:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\274\262\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	453                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1822:0x3d5 DW_TAG_lexical_block
	.word	.Ltmp244                        # DW_AT_low_pc
	.word	.Ltmp284-.Ltmp244               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x182b:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\260\262\177"
	.word	.Linfo_string312                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	460                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x183c:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\254\262\177"
	.word	.Linfo_string313                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x184d:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\250\262\177"
	.word	.Linfo_string314                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	462                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x185e:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\244\262\177"
	.word	.Linfo_string315                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	463                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x186f:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\262\177"
	.word	.Linfo_string316                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	464                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1880:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\220\262\177"
	.word	.Linfo_string317                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	465                             # DW_AT_decl_line
	.word	11970                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1891:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\200\262\177"
	.word	.Linfo_string318                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	466                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x18a2:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\374\261\177"
	.word	.Linfo_string319                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	467                             # DW_AT_decl_line
	.word	11982                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x18b3:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\370\261\177"
	.word	.Linfo_string320                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	468                             # DW_AT_decl_line
	.word	11997                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x18c4:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\364\261\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	469                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x18d5:0x321 DW_TAG_lexical_block
	.word	.Ltmp248                        # DW_AT_low_pc
	.word	.Ltmp282-.Ltmp248               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x18de:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\340\261\177"
	.word	.Linfo_string321                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x18ef:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\334\261\177"
	.word	.Linfo_string322                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	474                             # DW_AT_decl_line
	.word	869                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1900:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\330\261\177"
	.word	.Linfo_string323                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	475                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1911:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\320\230\177"
	.word	.Linfo_string324                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	476                             # DW_AT_decl_line
	.word	12002                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1922:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\314\230\177"
	.word	.Linfo_string325                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	477                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1933:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\310\230\177"
	.word	.Linfo_string326                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	478                             # DW_AT_decl_line
	.word	12026                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1944:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\304\230\177"
	.word	.Linfo_string327                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	479                             # DW_AT_decl_line
	.word	12026                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1955:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\300\230\177"
	.word	.Linfo_string328                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	480                             # DW_AT_decl_line
	.word	12031                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1966:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\270\230\177"
	.word	.Linfo_string329                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	481                             # DW_AT_decl_line
	.word	12036                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1977:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\264\230\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	482                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1988:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\260\230\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	482                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1999:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\254\230\177"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	482                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x19aa:0x92 DW_TAG_lexical_block
	.word	.Ltmp257                        # DW_AT_low_pc
	.word	.Ltmp258-.Ltmp257               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x19b3:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\210\230\177"
	.word	.Linfo_string330                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	487                             # DW_AT_decl_line
	.word	12048                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x19c4:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\204\230\177"
	.word	.Linfo_string331                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	488                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x19d5:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\200\230\177"
	.word	.Linfo_string332                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	489                             # DW_AT_decl_line
	.word	11535                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x19e6:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\374\227\177"
	.word	.Linfo_string333                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	490                             # DW_AT_decl_line
	.word	11692                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x19f7:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\370\227\177"
	.word	.Linfo_string334                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	491                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a08:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\364\227\177"
	.word	.Linfo_string335                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	492                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a19:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\360\227\177"
	.word	.Linfo_string336                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	493                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a2a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\354\227\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	494                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1a3c:0x135 DW_TAG_lexical_block
	.word	.Ltmp265                        # DW_AT_low_pc
	.word	.Ltmp275-.Ltmp265               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1a45:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\300\227\177"
	.word	.Linfo_string337                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	503                             # DW_AT_decl_line
	.word	12060                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a56:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\274\227\177"
	.word	.Linfo_string338                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	504                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a67:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\270\227\177"
	.word	.Linfo_string339                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	505                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a78:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\264\227\177"
	.word	.Linfo_string340                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	506                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a89:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\227\177"
	.word	.Linfo_string341                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	507                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1a9a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\234\227\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	508                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1aab:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\230\227\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	508                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1abc:0xb4 DW_TAG_lexical_block
	.word	.Ltmp269                        # DW_AT_low_pc
	.word	.Ltmp270-.Ltmp269               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1ac5:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\224\227\177"
	.word	.Linfo_string342                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	512                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1ad6:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\244\225\177"
	.word	.Linfo_string343                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	513                             # DW_AT_decl_line
	.word	12078                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1ae7:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\225\177"
	.word	.Linfo_string344                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	514                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1af8:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\234\225\177"
	.word	.Linfo_string345                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	515                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b09:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\230\225\177"
	.word	.Linfo_string346                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	516                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b1a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\224\225\177"
	.word	.Linfo_string347                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	517                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b2b:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\220\225\177"
	.word	.Linfo_string348                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	518                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b3c:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\214\225\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	519                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b4d:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\210\225\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	519                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b5e:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\204\225\177"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	519                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1b71:0x84 DW_TAG_lexical_block
	.word	.Ltmp276                        # DW_AT_low_pc
	.word	.Ltmp281-.Ltmp276               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1b7a:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\364\224\177"
	.word	.Linfo_string349                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	528                             # DW_AT_decl_line
	.word	12102                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1b8b:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\360\224\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	529                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1b9c:0x3d DW_TAG_lexical_block
	.word	.Ltmp279                        # DW_AT_low_pc
	.word	.Ltmp280-.Ltmp279               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1ba5:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\354\224\177"
	.word	.Linfo_string350                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	533                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1bb6:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\350\224\177"
	.word	.Linfo_string351                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	534                             # DW_AT_decl_line
	.word	12026                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1bc7:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\344\224\177"
	.word	.Linfo_string352                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	535                             # DW_AT_decl_line
	.word	11692                           # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1bd9:0x1b DW_TAG_lexical_block
	.word	.Ltmp280                        # DW_AT_low_pc
	.word	.Ltmp281-.Ltmp280               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1be2:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\340\224\177"
	.word	.Linfo_string353                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	541                             # DW_AT_decl_line
	.word	869                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	24                              # Abbrev [24] 0x1bf8:0x102 DW_TAG_lexical_block
	.word	.Ltmp287                        # DW_AT_low_pc
	.word	.Ltmp293-.Ltmp287               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1c01:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\334\224\177"
	.word	.Linfo_string354                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	550                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c12:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\330\224\177"
	.word	.Linfo_string355                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	551                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c23:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\324\224\177"
	.word	.Linfo_string356                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	552                             # DW_AT_decl_line
	.word	12114                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c34:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\320\224\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1c45:0xb4 DW_TAG_lexical_block
	.word	.Ltmp291                        # DW_AT_low_pc
	.word	.Ltmp292-.Ltmp291               # DW_AT_high_pc
	.byte	25                              # Abbrev [25] 0x1c4e:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\230\224\177"
	.word	.Linfo_string357                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	556                             # DW_AT_decl_line
	.word	12131                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c5f:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\224\224\177"
	.word	.Linfo_string358                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	557                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c70:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\220\224\177"
	.word	.Linfo_string359                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	558                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c81:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\320\214\177"
	.word	.Linfo_string360                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	559                             # DW_AT_decl_line
	.word	12149                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1c92:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\240\210\177"
	.word	.Linfo_string361                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
	.word	12167                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1ca3:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\370\207\177"
	.word	.Linfo_string362                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	561                             # DW_AT_decl_line
	.word	12191                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1cb4:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\210\206\177"
	.word	.Linfo_string363                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	562                             # DW_AT_decl_line
	.word	12208                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1cc5:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\204\206\177"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	563                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1cd6:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\200\206\177"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	563                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x1ce7:0x11 DW_TAG_variable
	.byte	4                               # DW_AT_location
	.byte	145
	.ascii	"\374\205\177"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	563                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1cfb:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin1                   # DW_AT_low_pc
	.word	.Lfunc_end1-.Lfunc_begin1       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string63                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1d11:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1d20:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x1d30:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin2                   # DW_AT_low_pc
	.word	.Lfunc_end2-.Lfunc_begin2       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string64                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1d45:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1d53:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1d62:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin3                   # DW_AT_low_pc
	.word	.Lfunc_end3-.Lfunc_begin3       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string65                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	539                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1d78:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string367                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	539                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1d88:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin4                   # DW_AT_low_pc
	.word	.Lfunc_end4-.Lfunc_begin4       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string66                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	681                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1d9e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	681                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1dad:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	681                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1dbd:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin5                   # DW_AT_low_pc
	.word	.Lfunc_end5-.Lfunc_begin5       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string67                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1dd3:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1de2:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x1df2:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin6                   # DW_AT_low_pc
	.word	.Lfunc_end6-.Lfunc_begin6       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string68                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1e07:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1e15:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1e24:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin7                   # DW_AT_low_pc
	.word	.Lfunc_end7-.Lfunc_begin7       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string69                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1e3a:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1e49:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x1e59:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin8                   # DW_AT_low_pc
	.word	.Lfunc_end8-.Lfunc_begin8       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string70                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1e6e:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1e7c:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1e8b:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin9                   # DW_AT_low_pc
	.word	.Lfunc_end9-.Lfunc_begin9       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string71                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1ea1:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1eb0:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1ec0:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin10                  # DW_AT_low_pc
	.word	.Lfunc_end10-.Lfunc_begin10     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string72                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	342                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1ed6:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	342                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1ee5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	342                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1ef5:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin11                  # DW_AT_low_pc
	.word	.Lfunc_end11-.Lfunc_begin11     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string73                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	898                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1f0b:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	898                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1f1a:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	898                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1f2a:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin12                  # DW_AT_low_pc
	.word	.Lfunc_end12-.Lfunc_begin12     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string74                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	603                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1f40:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	603                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1f4f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	603                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x1f5f:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin13                  # DW_AT_low_pc
	.word	.Lfunc_end13-.Lfunc_begin13     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string75                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1f74:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1f82:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1f91:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin14                  # DW_AT_low_pc
	.word	.Lfunc_end14-.Lfunc_begin14     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string76                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1fa7:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x1fb6:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x1fc6:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin15                  # DW_AT_low_pc
	.word	.Lfunc_end15-.Lfunc_begin15     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string77                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	158                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1fdb:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	158                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1fe9:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	158                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x1ff8:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin16                  # DW_AT_low_pc
	.word	.Lfunc_end16-.Lfunc_begin16     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string78                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x200e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x201d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x202d:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin17                  # DW_AT_low_pc
	.word	.Lfunc_end17-.Lfunc_begin17     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string79                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	669                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2043:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	669                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2052:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	669                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x2062:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin18                  # DW_AT_low_pc
	.word	.Lfunc_end18-.Lfunc_begin18     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string80                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2077:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2085:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2094:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin19                  # DW_AT_low_pc
	.word	.Lfunc_end19-.Lfunc_begin19     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string81                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x20aa:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x20b9:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x20c9:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin20                  # DW_AT_low_pc
	.word	.Lfunc_end20-.Lfunc_begin20     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string82                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x20df:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x20ee:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x20fe:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin21                  # DW_AT_low_pc
	.word	.Lfunc_end21-.Lfunc_begin21     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string83                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	405                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2114:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string372                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	405                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2124:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin22                  # DW_AT_low_pc
	.word	.Lfunc_end22-.Lfunc_begin22     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string84                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x213a:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2149:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2159:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin23                  # DW_AT_low_pc
	.word	.Lfunc_end23-.Lfunc_begin23     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string85                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x216f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x217e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x218e:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin24                  # DW_AT_low_pc
	.word	.Lfunc_end24-.Lfunc_begin24     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string86                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x21a3:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x21b1:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x21c0:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin25                  # DW_AT_low_pc
	.word	.Lfunc_end25-.Lfunc_begin25     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string87                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x21d6:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x21e5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x21f5:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin26                  # DW_AT_low_pc
	.word	.Lfunc_end26-.Lfunc_begin26     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string88                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x220a:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2218:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2227:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin27                  # DW_AT_low_pc
	.word	.Lfunc_end27-.Lfunc_begin27     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string89                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x223d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x224c:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x225c:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin28                  # DW_AT_low_pc
	.word	.Lfunc_end28-.Lfunc_begin28     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string90                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2272:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2281:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2291:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin29                  # DW_AT_low_pc
	.word	.Lfunc_end29-.Lfunc_begin29     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string91                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x22a7:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x22b6:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x22c6:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin30                  # DW_AT_low_pc
	.word	.Lfunc_end30-.Lfunc_begin30     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string92                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x22dc:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x22eb:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x22fb:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin31                  # DW_AT_low_pc
	.word	.Lfunc_end31-.Lfunc_begin31     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string93                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2311:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2320:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2330:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin32                  # DW_AT_low_pc
	.word	.Lfunc_end32-.Lfunc_begin32     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string94                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2346:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2355:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2365:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin33                  # DW_AT_low_pc
	.word	.Lfunc_end33-.Lfunc_begin33     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string95                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	274                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x237b:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string372                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	274                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x238b:0x24 DW_TAG_subprogram
	.word	.Lfunc_begin34                  # DW_AT_low_pc
	.word	.Lfunc_end34-.Lfunc_begin34     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string96                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	14                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x23a0:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string372                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	14                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x23af:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin35                  # DW_AT_low_pc
	.word	.Lfunc_end35-.Lfunc_begin35     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string97                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	497                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x23c5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	497                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x23d4:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	497                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x23e4:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin36                  # DW_AT_low_pc
	.word	.Lfunc_end36-.Lfunc_begin36     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string98                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x23fa:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2409:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2419:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin37                  # DW_AT_low_pc
	.word	.Lfunc_end37-.Lfunc_begin37     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string99                 # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x242f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x243e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x244e:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin38                  # DW_AT_low_pc
	.word	.Lfunc_end38-.Lfunc_begin38     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string100                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2463:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2471:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2480:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin39                  # DW_AT_low_pc
	.word	.Lfunc_end39-.Lfunc_begin39     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string101                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2496:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x24a5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x24b5:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin40                  # DW_AT_low_pc
	.word	.Lfunc_end40-.Lfunc_begin40     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string102                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x24cb:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x24da:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x24ea:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin41                  # DW_AT_low_pc
	.word	.Lfunc_end41-.Lfunc_begin41     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string103                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	288                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2500:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	288                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x250f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	288                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x251f:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin42                  # DW_AT_low_pc
	.word	.Lfunc_end42-.Lfunc_begin42     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string104                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2534:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2542:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2551:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin43                  # DW_AT_low_pc
	.word	.Lfunc_end43-.Lfunc_begin43     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string105                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	579                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2567:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	579                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2576:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	579                             # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2586:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin44                  # DW_AT_low_pc
	.word	.Lfunc_end44-.Lfunc_begin44     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string106                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	705                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x259c:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	705                             # DW_AT_decl_line
	.word	381                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x25ab:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	705                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x25bb:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin45                  # DW_AT_low_pc
	.word	.Lfunc_end45-.Lfunc_begin45     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string107                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	743                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x25d1:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string367                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	743                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x25e1:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin46                  # DW_AT_low_pc
	.word	.Lfunc_end46-.Lfunc_begin46     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string108                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x25f7:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2606:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
	.word	198                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2616:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin47                  # DW_AT_low_pc
	.word	.Lfunc_end47-.Lfunc_begin47     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string109                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x262c:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x263b:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x264b:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin48                  # DW_AT_low_pc
	.word	.Lfunc_end48-.Lfunc_begin48     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string110                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2661:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2670:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2680:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin49                  # DW_AT_low_pc
	.word	.Lfunc_end49-.Lfunc_begin49     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string111                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	867                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2696:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string368                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	867                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x26a5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string369                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	867                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x26b5:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin50                  # DW_AT_low_pc
	.word	.Lfunc_end50-.Lfunc_begin50     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string112                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	200                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x26ca:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	200                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x26d8:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	200                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x26e7:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin51                  # DW_AT_low_pc
	.word	.Lfunc_end51-.Lfunc_begin51     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string113                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x26fc:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x270a:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x2719:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin52                  # DW_AT_low_pc
	.word	.Lfunc_end52-.Lfunc_begin52     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string114                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x272f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x273e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
	.word	982                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	27                              # Abbrev [27] 0x274e:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin53                  # DW_AT_low_pc
	.word	.Lfunc_end53-.Lfunc_begin53     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string115                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2764:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string370                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2773:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string371                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	29                              # Abbrev [29] 0x2783:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin54                  # DW_AT_low_pc
	.word	.Lfunc_end54-.Lfunc_begin54     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string116                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	70                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2798:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string365                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	70                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x27a6:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string366                # DW_AT_name
	.byte	6                               # DW_AT_decl_file
	.byte	70                              # DW_AT_decl_line
	.word	241                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	30                              # Abbrev [30] 0x27b5:0x1e4 DW_TAG_subprogram
	.word	.Lfunc_begin55                  # DW_AT_low_pc
	.word	.Lfunc_end55-.Lfunc_begin55     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string117                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	982                             # DW_AT_type
                                        # DW_AT_external
	.byte	28                              # Abbrev [28] 0x27cb:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string373                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x27da:0x10 DW_TAG_formal_parameter
	.byte	3                               # DW_AT_location
	.byte	145
	.byte	108
	.byte	6
	.word	.Linfo_string374                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
	.word	153                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x27ea:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string375                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	28                              # Abbrev [28] 0x27f9:0x10 DW_TAG_formal_parameter
	.byte	3                               # DW_AT_location
	.byte	145
	.byte	100
	.byte	6
	.word	.Linfo_string376                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
	.word	95                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x2809:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	96
	.word	.Linfo_string377                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	576                             # DW_AT_decl_line
	.word	497                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2818:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214x"
	.word	.Linfo_string378                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	578                             # DW_AT_decl_line
	.word	12232                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2828:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210x"
	.word	.Linfo_string379                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	579                             # DW_AT_decl_line
	.word	12256                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2838:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204x"
	.word	.Linfo_string380                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	580                             # DW_AT_decl_line
	.word	11692                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2848:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200x"
	.word	.Linfo_string381                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	581                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2858:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374w"
	.word	.Linfo_string382                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	582                             # DW_AT_decl_line
	.word	977                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2868:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370w"
	.word	.Linfo_string383                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	583                             # DW_AT_decl_line
	.word	11242                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2878:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364w"
	.word	.Linfo_string384                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	584                             # DW_AT_decl_line
	.word	458                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2888:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340w"
	.word	.Linfo_string385                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	585                             # DW_AT_decl_line
	.word	12266                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2898:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334w"
	.word	.Linfo_string386                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	586                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28a8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330w"
	.word	.Linfo_string387                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	587                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28b8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324w"
	.word	.Linfo_string388                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	588                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28c8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320w"
	.word	.Linfo_string389                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	589                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28d8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314w"
	.word	.Linfo_string390                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	590                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28e8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310w"
	.word	.Linfo_string391                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	591                             # DW_AT_decl_line
	.word	55                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x28f8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274w"
	.word	.Linfo_string392                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	592                             # DW_AT_decl_line
	.word	12271                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2908:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330s"
	.word	.Linfo_string393                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	593                             # DW_AT_decl_line
	.word	12283                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2918:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324s"
	.word	.Linfo_string394                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	594                             # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2928:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\322s"
	.word	.Linfo_string395                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	595                             # DW_AT_decl_line
	.word	205                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2938:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310s"
	.word	.Linfo_string396                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	596                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2948:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304s"
	.word	.Linfo_string397                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	597                             # DW_AT_decl_line
	.word	1132                            # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2958:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300s"
	.word	.Linfo_string398                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	598                             # DW_AT_decl_line
	.word	1132                            # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2968:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274s"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	599                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2978:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270s"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	599                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x2988:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264s"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	599                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	30                              # Abbrev [30] 0x2999:0x71 DW_TAG_subprogram
	.word	.Lfunc_begin56                  # DW_AT_low_pc
	.word	.Lfunc_end56-.Lfunc_begin56     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string118                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	608                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	66                              # DW_AT_type
                                        # DW_AT_external
	.byte	28                              # Abbrev [28] 0x29af:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string399                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	608                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	28                              # Abbrev [28] 0x29be:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string400                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	608                             # DW_AT_decl_line
	.word	12301                           # DW_AT_type
	.byte	25                              # Abbrev [25] 0x29cd:0xf DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	610                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x29dc:0xf DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	100
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	610                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x29eb:0xf DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	96
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	610                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	25                              # Abbrev [25] 0x29fa:0xf DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	92
	.word	.Linfo_string401                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	611                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	31                              # Abbrev [31] 0x2a0a:0x11 DW_TAG_subprogram
	.word	.Lfunc_begin57                  # DW_AT_low_pc
	.word	.Lfunc_end57-.Lfunc_begin57     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string119                # DW_AT_name
	.byte	5                               # DW_AT_decl_file
	.byte	43                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	32                              # Abbrev [32] 0x2a1b:0x4a DW_TAG_subprogram
	.word	.Lfunc_begin58                  # DW_AT_low_pc
	.word	.Lfunc_end58-.Lfunc_begin58     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string120                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	51                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	23                              # Abbrev [23] 0x2a2c:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string402                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	53                              # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	23                              # Abbrev [23] 0x2a3a:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string403                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	54                              # DW_AT_decl_line
	.word	11193                           # DW_AT_type
	.byte	23                              # Abbrev [23] 0x2a48:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string165                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	55                              # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	23                              # Abbrev [23] 0x2a56:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string166                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	55                              # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	32                              # Abbrev [32] 0x2a65:0x3c DW_TAG_subprogram
	.word	.Lfunc_begin59                  # DW_AT_low_pc
	.word	.Lfunc_end59-.Lfunc_begin59     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string121                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	22                              # Abbrev [22] 0x2a76:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string404                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2a84:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string405                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.word	12306                           # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2a92:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string406                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	32                              # Abbrev [32] 0x2aa1:0x2e DW_TAG_subprogram
	.word	.Lfunc_begin60                  # DW_AT_low_pc
	.word	.Lfunc_end60-.Lfunc_begin60     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string122                # DW_AT_name
	.byte	5                               # DW_AT_decl_file
	.byte	49                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	22                              # Abbrev [22] 0x2ab2:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string402                # DW_AT_name
	.byte	5                               # DW_AT_decl_file
	.byte	49                              # DW_AT_decl_line
	.word	187                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x2ac0:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string406                # DW_AT_name
	.byte	5                               # DW_AT_decl_file
	.byte	49                              # DW_AT_decl_line
	.word	66                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	32                              # Abbrev [32] 0x2acf:0x20 DW_TAG_subprogram
	.word	.Lfunc_begin61                  # DW_AT_low_pc
	.word	.Lfunc_end61-.Lfunc_begin61     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string123                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	97                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	22                              # Abbrev [22] 0x2ae0:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string404                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	97                              # DW_AT_decl_line
	.word	603                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	32                              # Abbrev [32] 0x2aef:0x20 DW_TAG_subprogram
	.word	.Lfunc_begin62                  # DW_AT_low_pc
	.word	.Lfunc_end62-.Lfunc_begin62     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string124                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	71                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.byte	22                              # Abbrev [22] 0x2b00:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string407                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	71                              # DW_AT_decl_line
	.word	223                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2b0f:0x5 DW_TAG_pointer_type
	.word	187                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2b14:0x5 DW_TAG_pointer_type
	.word	497                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2b19:0x18 DW_TAG_array_type
	.word	11028                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b1e:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b24:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b2a:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2b31:0xc DW_TAG_array_type
	.word	593                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b36:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2b3d:0x18 DW_TAG_array_type
	.word	869                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b42:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b48:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b4e:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2b55:0x5 DW_TAG_pointer_type
	.word	869                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2b5a:0x12 DW_TAG_array_type
	.word	153                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b5f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b65:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2b6c:0x18 DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b71:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b77:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b7d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2b84:0x18 DW_TAG_array_type
	.word	187                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2b89:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b8f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2b95:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2b9c:0x18 DW_TAG_array_type
	.word	187                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ba1:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2ba7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2bad:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2bb4:0x5 DW_TAG_pointer_type
	.word	11193                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2bb9:0x5 DW_TAG_const_type
	.word	187                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2bbe:0x5 DW_TAG_pointer_type
	.word	11203                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2bc3:0x5 DW_TAG_pointer_type
	.word	11208                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2bc8:0x5 DW_TAG_pointer_type
	.word	11213                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2bcd:0x5 DW_TAG_const_type
	.word	497                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2bd2:0xc DW_TAG_array_type
	.word	603                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2bd7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2bde:0xc DW_TAG_array_type
	.word	982                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2be3:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2bea:0x5 DW_TAG_pointer_type
	.word	241                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2bef:0xc DW_TAG_array_type
	.word	786                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2bf4:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2bfb:0x5 DW_TAG_pointer_type
	.word	205                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2c00:0x18 DW_TAG_array_type
	.word	458                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c05:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c0b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c11:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c18:0xc DW_TAG_array_type
	.word	747                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c1d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c24:0x12 DW_TAG_array_type
	.word	95                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c29:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c2f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c36:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c3b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c42:0x18 DW_TAG_array_type
	.word	458                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c47:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c4d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c53:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c5a:0xc DW_TAG_array_type
	.word	603                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c5f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c66:0xc DW_TAG_array_type
	.word	869                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c6b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2c72:0x18 DW_TAG_array_type
	.word	11402                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c77:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c7d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c83:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2c8a:0x5 DW_TAG_pointer_type
	.word	11407                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2c8f:0x5 DW_TAG_const_type
	.word	603                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2c94:0x12 DW_TAG_array_type
	.word	11430                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2c99:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2c9f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2ca6:0x5 DW_TAG_pointer_type
	.word	11402                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2cab:0x5 DW_TAG_pointer_type
	.word	11430                           # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2cb0:0xc DW_TAG_array_type
	.word	223                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2cb5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2cbc:0x18 DW_TAG_array_type
	.word	381                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2cc1:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2cc7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2ccd:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2cd4:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2cd9:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2ce0:0x12 DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ce5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2ceb:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x2cf2:0x5 DW_TAG_const_type
	.word	223                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2cf7:0xc DW_TAG_array_type
	.word	11203                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2cfc:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2d03:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d08:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2d0f:0x5 DW_TAG_pointer_type
	.word	223                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2d14:0x18 DW_TAG_array_type
	.word	11564                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d19:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d1f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d25:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2d2c:0x5 DW_TAG_pointer_type
	.word	11028                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2d31:0x5 DW_TAG_const_type
	.word	11574                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2d36:0x5 DW_TAG_pointer_type
	.word	11579                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2d3b:0x5 DW_TAG_const_type
	.word	598                             # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2d40:0x5 DW_TAG_pointer_type
	.word	11569                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2d45:0x5 DW_TAG_pointer_type
	.word	11584                           # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2d4a:0xc DW_TAG_array_type
	.word	90                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d4f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2d56:0x18 DW_TAG_array_type
	.word	869                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d5b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d61:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d67:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2d6e:0x18 DW_TAG_array_type
	.word	603                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d73:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d79:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2d7f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2d86:0x5 DW_TAG_pointer_type
	.word	11659                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2d8b:0x5 DW_TAG_const_type
	.word	11664                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2d90:0x5 DW_TAG_pointer_type
	.word	11669                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2d95:0x5 DW_TAG_const_type
	.word	458                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2d9a:0x12 DW_TAG_array_type
	.word	153                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2d9f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2da5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2dac:0x5 DW_TAG_pointer_type
	.word	381                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2db1:0x12 DW_TAG_array_type
	.word	458                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2db6:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2dbc:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2dc3:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2dc8:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2dcf:0xc DW_TAG_array_type
	.word	786                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2dd4:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2ddb:0x12 DW_TAG_array_type
	.word	241                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2de0:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2de6:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2ded:0x5 DW_TAG_pointer_type
	.word	747                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2df2:0xc DW_TAG_array_type
	.word	1132                            # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2df7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2dfe:0x18 DW_TAG_array_type
	.word	11798                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e03:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e09:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e0f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x2e16:0x5 DW_TAG_const_type
	.word	11803                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2e1b:0x5 DW_TAG_pointer_type
	.word	1132                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2e20:0x18 DW_TAG_array_type
	.word	276                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e25:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e2b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e31:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2e38:0x12 DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e3d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e43:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2e4a:0x18 DW_TAG_array_type
	.word	11028                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e4f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e55:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e5b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2e62:0x18 DW_TAG_array_type
	.word	977                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e67:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e6d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e73:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2e7a:0x18 DW_TAG_array_type
	.word	11028                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e7f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e85:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e8b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2e92:0x18 DW_TAG_array_type
	.word	205                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2e97:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2e9d:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2ea3:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2eaa:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2eaf:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2eb6:0xc DW_TAG_array_type
	.word	11535                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ebb:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2ec2:0xc DW_TAG_array_type
	.word	205                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ec7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2ece:0x5 DW_TAG_pointer_type
	.word	11987                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2ed3:0x5 DW_TAG_pointer_type
	.word	11992                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2ed8:0x5 DW_TAG_const_type
	.word	11028                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2edd:0x5 DW_TAG_pointer_type
	.word	11564                           # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2ee2:0x18 DW_TAG_array_type
	.word	153                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ee7:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2eed:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2ef3:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2efa:0x5 DW_TAG_pointer_type
	.word	11242                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x2eff:0x5 DW_TAG_pointer_type
	.word	12026                           # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2f04:0xc DW_TAG_array_type
	.word	11997                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f09:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f10:0xc DW_TAG_array_type
	.word	187                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f15:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f1c:0x12 DW_TAG_array_type
	.word	11407                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f21:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f27:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f2e:0x18 DW_TAG_array_type
	.word	11535                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f33:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f39:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f3f:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f46:0xc DW_TAG_array_type
	.word	381                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f4b:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f52:0xc DW_TAG_array_type
	.word	12126                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f57:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	10                              # Abbrev [10] 0x2f5e:0x5 DW_TAG_const_type
	.word	869                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2f63:0x12 DW_TAG_array_type
	.word	223                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f68:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f6e:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f75:0x12 DW_TAG_array_type
	.word	95                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f7a:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f80:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f87:0x18 DW_TAG_array_type
	.word	11023                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2f8c:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f92:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2f98:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2f9f:0xc DW_TAG_array_type
	.word	12203                           # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2fa4:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2fab:0x5 DW_TAG_pointer_type
	.word	11023                           # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2fb0:0x18 DW_TAG_array_type
	.word	223                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2fb5:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2fbb:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2fc1:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2fc8:0x18 DW_TAG_array_type
	.word	90                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2fcd:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2fd3:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x2fd9:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x2fe0:0x5 DW_TAG_pointer_type
	.word	12261                           # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2fe5:0x5 DW_TAG_const_type
	.word	95                              # DW_AT_type
	.byte	10                              # Abbrev [10] 0x2fea:0x5 DW_TAG_const_type
	.word	153                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2fef:0xc DW_TAG_array_type
	.word	55                              # DW_AT_type
	.byte	14                              # Abbrev [14] 0x2ff4:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x2ffb:0x12 DW_TAG_array_type
	.word	982                             # DW_AT_type
	.byte	14                              # Abbrev [14] 0x3000:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	14                              # Abbrev [14] 0x3006:0x6 DW_TAG_subrange_type
	.word	434                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	5                               # Abbrev [5] 0x300d:0x5 DW_TAG_pointer_type
	.word	12306                           # DW_AT_type
	.byte	5                               # Abbrev [5] 0x3012:0x5 DW_TAG_pointer_type
	.word	1229                            # DW_AT_type
	.byte	0                               # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 17.0.6 (https://gitee.com/openeuler/llvm-project.git 6e0bf6efd908a21c57cd62f3ffa72df9fe86de6a)" # string offset=0
.Linfo_string1:
	.asciz	"rnd_output0.c"                 # string offset=109
.Linfo_string2:
	.asciz	"/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" # string offset=123
.Linfo_string3:
	.asciz	"g_3"                           # string offset=191
.Linfo_string4:
	.asciz	"int"                           # string offset=195
.Linfo_string5:
	.asciz	"int32_t"                       # string offset=199
.Linfo_string6:
	.asciz	"g_73"                          # string offset=207
.Linfo_string7:
	.asciz	"f0"                            # string offset=212
.Linfo_string8:
	.asciz	"f1"                            # string offset=215
.Linfo_string9:
	.asciz	"unsigned int"                  # string offset=218
.Linfo_string10:
	.asciz	"uint32_t"                      # string offset=231
.Linfo_string11:
	.asciz	"S0"                            # string offset=240
.Linfo_string12:
	.asciz	"short"                         # string offset=243
.Linfo_string13:
	.asciz	"int16_t"                       # string offset=249
.Linfo_string14:
	.asciz	"f2"                            # string offset=257
.Linfo_string15:
	.asciz	"unsigned char"                 # string offset=260
.Linfo_string16:
	.asciz	"uint8_t"                       # string offset=274
.Linfo_string17:
	.asciz	"f3"                            # string offset=282
.Linfo_string18:
	.asciz	"signed char"                   # string offset=285
.Linfo_string19:
	.asciz	"int8_t"                        # string offset=297
.Linfo_string20:
	.asciz	"U1"                            # string offset=304
.Linfo_string21:
	.asciz	"g_97"                          # string offset=307
.Linfo_string22:
	.asciz	"g_124"                         # string offset=312
.Linfo_string23:
	.asciz	"unsigned short"                # string offset=318
.Linfo_string24:
	.asciz	"uint16_t"                      # string offset=333
.Linfo_string25:
	.asciz	"U2"                            # string offset=342
.Linfo_string26:
	.asciz	"g_197"                         # string offset=345
.Linfo_string27:
	.asciz	"__ARRAY_SIZE_TYPE__"           # string offset=351
.Linfo_string28:
	.asciz	"g_200"                         # string offset=371
.Linfo_string29:
	.asciz	"g_199"                         # string offset=377
.Linfo_string30:
	.asciz	"g_302"                         # string offset=383
.Linfo_string31:
	.asciz	"g_334"                         # string offset=389
.Linfo_string32:
	.asciz	"g_467"                         # string offset=395
.Linfo_string33:
	.asciz	"g_500"                         # string offset=401
.Linfo_string34:
	.asciz	"unsigned long long"            # string offset=407
.Linfo_string35:
	.asciz	"uint64_t"                      # string offset=426
.Linfo_string36:
	.asciz	"g_524"                         # string offset=435
.Linfo_string37:
	.asciz	"g_556"                         # string offset=441
.Linfo_string38:
	.asciz	"g_555"                         # string offset=447
.Linfo_string39:
	.asciz	"g_672"                         # string offset=453
.Linfo_string40:
	.asciz	"g_901"                         # string offset=459
.Linfo_string41:
	.asciz	"g_932"                         # string offset=465
.Linfo_string42:
	.asciz	"g_946"                         # string offset=471
.Linfo_string43:
	.asciz	"g_1000"                        # string offset=477
.Linfo_string44:
	.asciz	"g_1247"                        # string offset=484
.Linfo_string45:
	.asciz	"g_1259"                        # string offset=491
.Linfo_string46:
	.asciz	"g_1374"                        # string offset=498
.Linfo_string47:
	.asciz	"g_1380"                        # string offset=505
.Linfo_string48:
	.asciz	"g_1571"                        # string offset=512
.Linfo_string49:
	.asciz	"long long"                     # string offset=519
.Linfo_string50:
	.asciz	"int64_t"                       # string offset=529
.Linfo_string51:
	.asciz	"g_1717"                        # string offset=537
.Linfo_string52:
	.asciz	"g_1781"                        # string offset=544
.Linfo_string53:
	.asciz	"g_1816"                        # string offset=551
.Linfo_string54:
	.asciz	"g_1817"                        # string offset=558
.Linfo_string55:
	.asciz	"g_1811"                        # string offset=565
.Linfo_string56:
	.asciz	"g_2016"                        # string offset=572
.Linfo_string57:
	.asciz	"g_2014"                        # string offset=579
.Linfo_string58:
	.asciz	"g_2201"                        # string offset=586
.Linfo_string59:
	.asciz	"char"                          # string offset=593
.Linfo_string60:
	.asciz	"crc32_tab"                     # string offset=598
.Linfo_string61:
	.asciz	"crc32_context"                 # string offset=608
.Linfo_string62:
	.asciz	"func_40"                       # string offset=622
.Linfo_string63:
	.asciz	"safe_mul_func_int64_t_s_s"     # string offset=630
.Linfo_string64:
	.asciz	"safe_sub_func_int8_t_s_s"      # string offset=656
.Linfo_string65:
	.asciz	"safe_unary_minus_func_uint8_t_u" # string offset=681
.Linfo_string66:
	.asciz	"safe_div_func_uint16_t_u_u"    # string offset=713
.Linfo_string67:
	.asciz	"safe_mul_func_uint8_t_u_u"     # string offset=740
.Linfo_string68:
	.asciz	"safe_add_func_int8_t_s_s"      # string offset=766
.Linfo_string69:
	.asciz	"safe_add_func_uint16_t_u_u"    # string offset=791
.Linfo_string70:
	.asciz	"safe_mul_func_int8_t_s_s"      # string offset=818
.Linfo_string71:
	.asciz	"safe_rshift_func_uint8_t_u_s"  # string offset=843
.Linfo_string72:
	.asciz	"safe_div_func_int32_t_s_s"     # string offset=872
.Linfo_string73:
	.asciz	"safe_lshift_func_uint64_t_u_s" # string offset=898
.Linfo_string74:
	.asciz	"safe_lshift_func_uint8_t_u_u"  # string offset=928
.Linfo_string75:
	.asciz	"safe_rshift_func_int8_t_s_u"   # string offset=957
.Linfo_string76:
	.asciz	"safe_rshift_func_uint32_t_u_u" # string offset=985
.Linfo_string77:
	.asciz	"safe_add_func_int16_t_s_s"     # string offset=1015
.Linfo_string78:
	.asciz	"safe_sub_func_uint64_t_u_u"    # string offset=1041
.Linfo_string79:
	.asciz	"safe_mod_func_uint16_t_u_u"    # string offset=1068
.Linfo_string80:
	.asciz	"safe_mul_func_int16_t_s_s"     # string offset=1095
.Linfo_string81:
	.asciz	"safe_mul_func_int32_t_s_s"     # string offset=1121
.Linfo_string82:
	.asciz	"safe_add_func_int64_t_s_s"     # string offset=1147
.Linfo_string83:
	.asciz	"safe_unary_minus_func_int64_t_s" # string offset=1173
.Linfo_string84:
	.asciz	"safe_lshift_func_int32_t_s_u"  # string offset=1205
.Linfo_string85:
	.asciz	"safe_mul_func_uint32_t_u_u"    # string offset=1234
.Linfo_string86:
	.asciz	"safe_lshift_func_int8_t_s_u"   # string offset=1261
.Linfo_string87:
	.asciz	"safe_sub_func_int64_t_s_s"     # string offset=1289
.Linfo_string88:
	.asciz	"safe_div_func_int16_t_s_s"     # string offset=1315
.Linfo_string89:
	.asciz	"safe_div_func_uint64_t_u_u"    # string offset=1341
.Linfo_string90:
	.asciz	"safe_add_func_uint64_t_u_u"    # string offset=1368
.Linfo_string91:
	.asciz	"safe_mod_func_int64_t_s_s"     # string offset=1395
.Linfo_string92:
	.asciz	"safe_sub_func_uint8_t_u_u"     # string offset=1421
.Linfo_string93:
	.asciz	"safe_sub_func_int32_t_s_s"     # string offset=1447
.Linfo_string94:
	.asciz	"safe_mod_func_uint8_t_u_u"     # string offset=1473
.Linfo_string95:
	.asciz	"safe_unary_minus_func_int32_t_s" # string offset=1499
.Linfo_string96:
	.asciz	"safe_unary_minus_func_int8_t_s" # string offset=1531
.Linfo_string97:
	.asciz	"safe_lshift_func_int64_t_s_u"  # string offset=1562
.Linfo_string98:
	.asciz	"safe_rshift_func_int16_t_s_u"  # string offset=1591
.Linfo_string99:
	.asciz	"safe_div_func_uint32_t_u_u"    # string offset=1620
.Linfo_string100:
	.asciz	"safe_rshift_func_int8_t_s_s"   # string offset=1647
.Linfo_string101:
	.asciz	"safe_add_func_uint8_t_u_u"     # string offset=1675
.Linfo_string102:
	.asciz	"safe_rshift_func_uint64_t_u_u" # string offset=1701
.Linfo_string103:
	.asciz	"safe_add_func_int32_t_s_s"     # string offset=1731
.Linfo_string104:
	.asciz	"safe_div_func_int8_t_s_s"      # string offset=1757
.Linfo_string105:
	.asciz	"safe_div_func_uint8_t_u_u"     # string offset=1782
.Linfo_string106:
	.asciz	"safe_lshift_func_uint16_t_u_u" # string offset=1808
.Linfo_string107:
	.asciz	"safe_unary_minus_func_uint32_t_u" # string offset=1838
.Linfo_string108:
	.asciz	"safe_rshift_func_int32_t_s_u"  # string offset=1871
.Linfo_string109:
	.asciz	"safe_rshift_func_int32_t_s_s"  # string offset=1900
.Linfo_string110:
	.asciz	"safe_mod_func_uint32_t_u_u"    # string offset=1929
.Linfo_string111:
	.asciz	"safe_mul_func_uint64_t_u_u"    # string offset=1956
.Linfo_string112:
	.asciz	"safe_mod_func_int16_t_s_s"     # string offset=1983
.Linfo_string113:
	.asciz	"safe_sub_func_int16_t_s_s"     # string offset=2009
.Linfo_string114:
	.asciz	"safe_div_func_int64_t_s_s"     # string offset=2035
.Linfo_string115:
	.asciz	"safe_rshift_func_uint64_t_u_s" # string offset=2061
.Linfo_string116:
	.asciz	"safe_mod_func_int8_t_s_s"      # string offset=2091
.Linfo_string117:
	.asciz	"func_57"                       # string offset=2116
.Linfo_string118:
	.asciz	"main"                          # string offset=2124
.Linfo_string119:
	.asciz	"platform_main_begin"           # string offset=2129
.Linfo_string120:
	.asciz	"crc32_gentab"                  # string offset=2149
.Linfo_string121:
	.asciz	"transparent_crc"               # string offset=2162
.Linfo_string122:
	.asciz	"platform_main_end"             # string offset=2178
.Linfo_string123:
	.asciz	"crc32_8bytes"                  # string offset=2196
.Linfo_string124:
	.asciz	"crc32_byte"                    # string offset=2209
.Linfo_string125:
	.asciz	"p_41"                          # string offset=2220
.Linfo_string126:
	.asciz	"p_42"                          # string offset=2225
.Linfo_string127:
	.asciz	"p_43"                          # string offset=2230
.Linfo_string128:
	.asciz	"p_44"                          # string offset=2235
.Linfo_string129:
	.asciz	"p_45"                          # string offset=2240
.Linfo_string130:
	.asciz	"l_459"                         # string offset=2245
.Linfo_string131:
	.asciz	"l_460"                         # string offset=2251
.Linfo_string132:
	.asciz	"l_464"                         # string offset=2257
.Linfo_string133:
	.asciz	"l_466"                         # string offset=2263
.Linfo_string134:
	.asciz	"l_465"                         # string offset=2269
.Linfo_string135:
	.asciz	"l_476"                         # string offset=2275
.Linfo_string136:
	.asciz	"l_475"                         # string offset=2281
.Linfo_string137:
	.asciz	"l_481"                         # string offset=2287
.Linfo_string138:
	.asciz	"l_529"                         # string offset=2293
.Linfo_string139:
	.asciz	"l_551"                         # string offset=2299
.Linfo_string140:
	.asciz	"l_550"                         # string offset=2305
.Linfo_string141:
	.asciz	"l_552"                         # string offset=2311
.Linfo_string142:
	.asciz	"l_631"                         # string offset=2317
.Linfo_string143:
	.asciz	"l_762"                         # string offset=2323
.Linfo_string144:
	.asciz	"l_775"                         # string offset=2329
.Linfo_string145:
	.asciz	"l_792"                         # string offset=2335
.Linfo_string146:
	.asciz	"l_969"                         # string offset=2341
.Linfo_string147:
	.asciz	"l_970"                         # string offset=2347
.Linfo_string148:
	.asciz	"l_1015"                        # string offset=2353
.Linfo_string149:
	.asciz	"l_1036"                        # string offset=2360
.Linfo_string150:
	.asciz	"l_1057"                        # string offset=2367
.Linfo_string151:
	.asciz	"l_1062"                        # string offset=2374
.Linfo_string152:
	.asciz	"l_1100"                        # string offset=2381
.Linfo_string153:
	.asciz	"l_1117"                        # string offset=2388
.Linfo_string154:
	.asciz	"l_1123"                        # string offset=2395
.Linfo_string155:
	.asciz	"l_1206"                        # string offset=2402
.Linfo_string156:
	.asciz	"l_1221"                        # string offset=2409
.Linfo_string157:
	.asciz	"l_1294"                        # string offset=2416
.Linfo_string158:
	.asciz	"l_1419"                        # string offset=2423
.Linfo_string159:
	.asciz	"l_1519"                        # string offset=2430
.Linfo_string160:
	.asciz	"l_1563"                        # string offset=2437
.Linfo_string161:
	.asciz	"l_1679"                        # string offset=2444
.Linfo_string162:
	.asciz	"l_1719"                        # string offset=2451
.Linfo_string163:
	.asciz	"l_1754"                        # string offset=2458
.Linfo_string164:
	.asciz	"l_1842"                        # string offset=2465
.Linfo_string165:
	.asciz	"i"                             # string offset=2472
.Linfo_string166:
	.asciz	"j"                             # string offset=2474
.Linfo_string167:
	.asciz	"k"                             # string offset=2476
.Linfo_string168:
	.asciz	"l_480"                         # string offset=2478
.Linfo_string169:
	.asciz	"l_489"                         # string offset=2484
.Linfo_string170:
	.asciz	"l_490"                         # string offset=2490
.Linfo_string171:
	.asciz	"l_499"                         # string offset=2496
.Linfo_string172:
	.asciz	"l_502"                         # string offset=2502
.Linfo_string173:
	.asciz	"l_517"                         # string offset=2508
.Linfo_string174:
	.asciz	"l_646"                         # string offset=2514
.Linfo_string175:
	.asciz	"l_648"                         # string offset=2520
.Linfo_string176:
	.asciz	"l_670"                         # string offset=2526
.Linfo_string177:
	.asciz	"l_706"                         # string offset=2532
.Linfo_string178:
	.asciz	"l_763"                         # string offset=2538
.Linfo_string179:
	.asciz	"l_764"                         # string offset=2544
.Linfo_string180:
	.asciz	"l_777"                         # string offset=2550
.Linfo_string181:
	.asciz	"l_778"                         # string offset=2556
.Linfo_string182:
	.asciz	"l_796"                         # string offset=2562
.Linfo_string183:
	.asciz	"l_798"                         # string offset=2568
.Linfo_string184:
	.asciz	"l_825"                         # string offset=2574
.Linfo_string185:
	.asciz	"l_863"                         # string offset=2580
.Linfo_string186:
	.asciz	"l_889"                         # string offset=2586
.Linfo_string187:
	.asciz	"l_906"                         # string offset=2592
.Linfo_string188:
	.asciz	"l_905"                         # string offset=2598
.Linfo_string189:
	.asciz	"l_904"                         # string offset=2604
.Linfo_string190:
	.asciz	"l_966"                         # string offset=2610
.Linfo_string191:
	.asciz	"l_976"                         # string offset=2616
.Linfo_string192:
	.asciz	"l_1033"                        # string offset=2622
.Linfo_string193:
	.asciz	"l_1034"                        # string offset=2629
.Linfo_string194:
	.asciz	"l_1035"                        # string offset=2636
.Linfo_string195:
	.asciz	"l_1040"                        # string offset=2643
.Linfo_string196:
	.asciz	"l_1053"                        # string offset=2650
.Linfo_string197:
	.asciz	"l_1070"                        # string offset=2657
.Linfo_string198:
	.asciz	"l_1078"                        # string offset=2664
.Linfo_string199:
	.asciz	"l_1081"                        # string offset=2671
.Linfo_string200:
	.asciz	"l_1102"                        # string offset=2678
.Linfo_string201:
	.asciz	"l_1101"                        # string offset=2685
.Linfo_string202:
	.asciz	"l_1045"                        # string offset=2692
.Linfo_string203:
	.asciz	"l_1052"                        # string offset=2699
.Linfo_string204:
	.asciz	"l_1064"                        # string offset=2706
.Linfo_string205:
	.asciz	"l_1065"                        # string offset=2713
.Linfo_string206:
	.asciz	"l_1066"                        # string offset=2720
.Linfo_string207:
	.asciz	"l_1047"                        # string offset=2727
.Linfo_string208:
	.asciz	"l_1050"                        # string offset=2734
.Linfo_string209:
	.asciz	"l_1041"                        # string offset=2741
.Linfo_string210:
	.asciz	"l_1046"                        # string offset=2748
.Linfo_string211:
	.asciz	"l_1051"                        # string offset=2755
.Linfo_string212:
	.asciz	"l_1044"                        # string offset=2762
.Linfo_string213:
	.asciz	"l_1061"                        # string offset=2769
.Linfo_string214:
	.asciz	"l_1063"                        # string offset=2776
.Linfo_string215:
	.asciz	"l_1067"                        # string offset=2783
.Linfo_string216:
	.asciz	"l_1054"                        # string offset=2790
.Linfo_string217:
	.asciz	"l_1060"                        # string offset=2797
.Linfo_string218:
	.asciz	"l_1071"                        # string offset=2804
.Linfo_string219:
	.asciz	"l_1082"                        # string offset=2811
.Linfo_string220:
	.asciz	"l_1091"                        # string offset=2818
.Linfo_string221:
	.asciz	"l_1092"                        # string offset=2825
.Linfo_string222:
	.asciz	"l_1148"                        # string offset=2832
.Linfo_string223:
	.asciz	"l_1187"                        # string offset=2839
.Linfo_string224:
	.asciz	"l_1186"                        # string offset=2846
.Linfo_string225:
	.asciz	"l_1185"                        # string offset=2853
.Linfo_string226:
	.asciz	"l_1237"                        # string offset=2860
.Linfo_string227:
	.asciz	"l_1274"                        # string offset=2867
.Linfo_string228:
	.asciz	"l_1303"                        # string offset=2874
.Linfo_string229:
	.asciz	"l_1304"                        # string offset=2881
.Linfo_string230:
	.asciz	"l_1323"                        # string offset=2888
.Linfo_string231:
	.asciz	"l_1324"                        # string offset=2895
.Linfo_string232:
	.asciz	"l_1357"                        # string offset=2902
.Linfo_string233:
	.asciz	"l_1379"                        # string offset=2909
.Linfo_string234:
	.asciz	"l_1411"                        # string offset=2916
.Linfo_string235:
	.asciz	"l_1446"                        # string offset=2923
.Linfo_string236:
	.asciz	"l_1458"                        # string offset=2930
.Linfo_string237:
	.asciz	"l_1512"                        # string offset=2937
.Linfo_string238:
	.asciz	"l_1552"                        # string offset=2944
.Linfo_string239:
	.asciz	"l_1630"                        # string offset=2951
.Linfo_string240:
	.asciz	"l_1153"                        # string offset=2958
.Linfo_string241:
	.asciz	"l_1159"                        # string offset=2965
.Linfo_string242:
	.asciz	"l_1181"                        # string offset=2972
.Linfo_string243:
	.asciz	"l_1184"                        # string offset=2979
.Linfo_string244:
	.asciz	"l_1152"                        # string offset=2986
.Linfo_string245:
	.asciz	"l_1180"                        # string offset=2993
.Linfo_string246:
	.asciz	"l_1183"                        # string offset=3000
.Linfo_string247:
	.asciz	"l_1192"                        # string offset=3007
.Linfo_string248:
	.asciz	"l_1149"                        # string offset=3014
.Linfo_string249:
	.asciz	"l_1150"                        # string offset=3021
.Linfo_string250:
	.asciz	"l_1151"                        # string offset=3028
.Linfo_string251:
	.asciz	"l_1164"                        # string offset=3035
.Linfo_string252:
	.asciz	"l_1182"                        # string offset=3042
.Linfo_string253:
	.asciz	"l_1190"                        # string offset=3049
.Linfo_string254:
	.asciz	"tmp"                           # string offset=3056
.Linfo_string255:
	.asciz	"l_1226"                        # string offset=3060
.Linfo_string256:
	.asciz	"l_1238"                        # string offset=3067
.Linfo_string257:
	.asciz	"l_1245"                        # string offset=3074
.Linfo_string258:
	.asciz	"l_1246"                        # string offset=3081
.Linfo_string259:
	.asciz	"l_1291"                        # string offset=3088
.Linfo_string260:
	.asciz	"l_1217"                        # string offset=3095
.Linfo_string261:
	.asciz	"l_1224"                        # string offset=3102
.Linfo_string262:
	.asciz	"l_1225"                        # string offset=3109
.Linfo_string263:
	.asciz	"l_1230"                        # string offset=3116
.Linfo_string264:
	.asciz	"l_1242"                        # string offset=3123
.Linfo_string265:
	.asciz	"l_1288"                        # string offset=3130
.Linfo_string266:
	.asciz	"l_1229"                        # string offset=3137
.Linfo_string267:
	.asciz	"l_1243"                        # string offset=3144
.Linfo_string268:
	.asciz	"l_1295"                        # string offset=3151
.Linfo_string269:
	.asciz	"l_1239"                        # string offset=3158
.Linfo_string270:
	.asciz	"l_1244"                        # string offset=3165
.Linfo_string271:
	.asciz	"l_1256"                        # string offset=3172
.Linfo_string272:
	.asciz	"l_1257"                        # string offset=3179
.Linfo_string273:
	.asciz	"l_1269"                        # string offset=3186
.Linfo_string274:
	.asciz	"l_1272"                        # string offset=3193
.Linfo_string275:
	.asciz	"l_1273"                        # string offset=3200
.Linfo_string276:
	.asciz	"l_1281"                        # string offset=3207
.Linfo_string277:
	.asciz	"l_1282"                        # string offset=3214
.Linfo_string278:
	.asciz	"l_1293"                        # string offset=3221
.Linfo_string279:
	.asciz	"l_1317"                        # string offset=3228
.Linfo_string280:
	.asciz	"l_1316"                        # string offset=3235
.Linfo_string281:
	.asciz	"l_1322"                        # string offset=3242
.Linfo_string282:
	.asciz	"l_1368"                        # string offset=3249
.Linfo_string283:
	.asciz	"l_1369"                        # string offset=3256
.Linfo_string284:
	.asciz	"l_1377"                        # string offset=3263
.Linfo_string285:
	.asciz	"l_1412"                        # string offset=3270
.Linfo_string286:
	.asciz	"l_1423"                        # string offset=3277
.Linfo_string287:
	.asciz	"l_1429"                        # string offset=3284
.Linfo_string288:
	.asciz	"l_1430"                        # string offset=3291
.Linfo_string289:
	.asciz	"l_1433"                        # string offset=3298
.Linfo_string290:
	.asciz	"l_1437"                        # string offset=3305
.Linfo_string291:
	.asciz	"l_1516"                        # string offset=3312
.Linfo_string292:
	.asciz	"l_1338"                        # string offset=3319
.Linfo_string293:
	.asciz	"l_1365"                        # string offset=3326
.Linfo_string294:
	.asciz	"l_1410"                        # string offset=3333
.Linfo_string295:
	.asciz	"l_1413"                        # string offset=3340
.Linfo_string296:
	.asciz	"l_1431"                        # string offset=3347
.Linfo_string297:
	.asciz	"l_1434"                        # string offset=3354
.Linfo_string298:
	.asciz	"l_1451"                        # string offset=3361
.Linfo_string299:
	.asciz	"l_1467"                        # string offset=3368
.Linfo_string300:
	.asciz	"l_1500"                        # string offset=3375
.Linfo_string301:
	.asciz	"l_1513"                        # string offset=3382
.Linfo_string302:
	.asciz	"l_1517"                        # string offset=3389
.Linfo_string303:
	.asciz	"l_1518"                        # string offset=3396
.Linfo_string304:
	.asciz	"l_1532"                        # string offset=3403
.Linfo_string305:
	.asciz	"l_1535"                        # string offset=3410
.Linfo_string306:
	.asciz	"l_1543"                        # string offset=3417
.Linfo_string307:
	.asciz	"l_1546"                        # string offset=3424
.Linfo_string308:
	.asciz	"l_1547"                        # string offset=3431
.Linfo_string309:
	.asciz	"l_1549"                        # string offset=3438
.Linfo_string310:
	.asciz	"l_1550"                        # string offset=3445
.Linfo_string311:
	.asciz	"l_1551"                        # string offset=3452
.Linfo_string312:
	.asciz	"l_1555"                        # string offset=3459
.Linfo_string313:
	.asciz	"l_1556"                        # string offset=3466
.Linfo_string314:
	.asciz	"l_1566"                        # string offset=3473
.Linfo_string315:
	.asciz	"l_1625"                        # string offset=3480
.Linfo_string316:
	.asciz	"l_1660"                        # string offset=3487
.Linfo_string317:
	.asciz	"l_1661"                        # string offset=3494
.Linfo_string318:
	.asciz	"l_1666"                        # string offset=3501
.Linfo_string319:
	.asciz	"l_1698"                        # string offset=3508
.Linfo_string320:
	.asciz	"l_1699"                        # string offset=3515
.Linfo_string321:
	.asciz	"l_1581"                        # string offset=3522
.Linfo_string322:
	.asciz	"l_1594"                        # string offset=3529
.Linfo_string323:
	.asciz	"l_1596"                        # string offset=3536
.Linfo_string324:
	.asciz	"l_1619"                        # string offset=3543
.Linfo_string325:
	.asciz	"l_1632"                        # string offset=3550
.Linfo_string326:
	.asciz	"l_1631"                        # string offset=3557
.Linfo_string327:
	.asciz	"l_1634"                        # string offset=3564
.Linfo_string328:
	.asciz	"l_1633"                        # string offset=3571
.Linfo_string329:
	.asciz	"l_1700"                        # string offset=3578
.Linfo_string330:
	.asciz	"l_1586"                        # string offset=3585
.Linfo_string331:
	.asciz	"l_1587"                        # string offset=3592
.Linfo_string332:
	.asciz	"l_1595"                        # string offset=3599
.Linfo_string333:
	.asciz	"l_1613"                        # string offset=3606
.Linfo_string334:
	.asciz	"l_1622"                        # string offset=3613
.Linfo_string335:
	.asciz	"l_1623"                        # string offset=3620
.Linfo_string336:
	.asciz	"l_1624"                        # string offset=3627
.Linfo_string337:
	.asciz	"l_1656"                        # string offset=3634
.Linfo_string338:
	.asciz	"l_1657"                        # string offset=3641
.Linfo_string339:
	.asciz	"l_1658"                        # string offset=3648
.Linfo_string340:
	.asciz	"l_1659"                        # string offset=3655
.Linfo_string341:
	.asciz	"l_1665"                        # string offset=3662
.Linfo_string342:
	.asciz	"l_1667"                        # string offset=3669
.Linfo_string343:
	.asciz	"l_1678"                        # string offset=3676
.Linfo_string344:
	.asciz	"l_1680"                        # string offset=3683
.Linfo_string345:
	.asciz	"l_1681"                        # string offset=3690
.Linfo_string346:
	.asciz	"l_1682"                        # string offset=3697
.Linfo_string347:
	.asciz	"l_1683"                        # string offset=3704
.Linfo_string348:
	.asciz	"l_1684"                        # string offset=3711
.Linfo_string349:
	.asciz	"l_1691"                        # string offset=3718
.Linfo_string350:
	.asciz	"l_1695"                        # string offset=3725
.Linfo_string351:
	.asciz	"l_1694"                        # string offset=3732
.Linfo_string352:
	.asciz	"l_1702"                        # string offset=3739
.Linfo_string353:
	.asciz	"l_1703"                        # string offset=3746
.Linfo_string354:
	.asciz	"l_1709"                        # string offset=3753
.Linfo_string355:
	.asciz	"l_1724"                        # string offset=3760
.Linfo_string356:
	.asciz	"l_1752"                        # string offset=3767
.Linfo_string357:
	.asciz	"l_1708"                        # string offset=3774
.Linfo_string358:
	.asciz	"l_1718"                        # string offset=3781
.Linfo_string359:
	.asciz	"l_1774"                        # string offset=3788
.Linfo_string360:
	.asciz	"l_1775"                        # string offset=3795
.Linfo_string361:
	.asciz	"l_1795"                        # string offset=3802
.Linfo_string362:
	.asciz	"l_1794"                        # string offset=3809
.Linfo_string363:
	.asciz	"l_1827"                        # string offset=3816
.Linfo_string364:
	.asciz	"lbl_1307"                      # string offset=3823
.Linfo_string365:
	.asciz	"si1"                           # string offset=3832
.Linfo_string366:
	.asciz	"si2"                           # string offset=3836
.Linfo_string367:
	.asciz	"ui"                            # string offset=3840
.Linfo_string368:
	.asciz	"ui1"                           # string offset=3843
.Linfo_string369:
	.asciz	"ui2"                           # string offset=3847
.Linfo_string370:
	.asciz	"left"                          # string offset=3851
.Linfo_string371:
	.asciz	"right"                         # string offset=3856
.Linfo_string372:
	.asciz	"si"                            # string offset=3862
.Linfo_string373:
	.asciz	"p_58"                          # string offset=3865
.Linfo_string374:
	.asciz	"p_59"                          # string offset=3870
.Linfo_string375:
	.asciz	"p_60"                          # string offset=3875
.Linfo_string376:
	.asciz	"p_61"                          # string offset=3880
.Linfo_string377:
	.asciz	"p_62"                          # string offset=3885
.Linfo_string378:
	.asciz	"l_74"                          # string offset=3890
.Linfo_string379:
	.asciz	"l_75"                          # string offset=3895
.Linfo_string380:
	.asciz	"l_88"                          # string offset=3900
.Linfo_string381:
	.asciz	"l_94"                          # string offset=3905
.Linfo_string382:
	.asciz	"l_195"                         # string offset=3910
.Linfo_string383:
	.asciz	"l_196"                         # string offset=3916
.Linfo_string384:
	.asciz	"l_198"                         # string offset=3922
.Linfo_string385:
	.asciz	"l_207"                         # string offset=3928
.Linfo_string386:
	.asciz	"l_210"                         # string offset=3934
.Linfo_string387:
	.asciz	"l_212"                         # string offset=3940
.Linfo_string388:
	.asciz	"l_213"                         # string offset=3946
.Linfo_string389:
	.asciz	"l_214"                         # string offset=3952
.Linfo_string390:
	.asciz	"l_215"                         # string offset=3958
.Linfo_string391:
	.asciz	"l_216"                         # string offset=3964
.Linfo_string392:
	.asciz	"l_217"                         # string offset=3970
.Linfo_string393:
	.asciz	"l_219"                         # string offset=3976
.Linfo_string394:
	.asciz	"l_220"                         # string offset=3982
.Linfo_string395:
	.asciz	"l_241"                         # string offset=3988
.Linfo_string396:
	.asciz	"l_287"                         # string offset=3994
.Linfo_string397:
	.asciz	"l_289"                         # string offset=4000
.Linfo_string398:
	.asciz	"l_293"                         # string offset=4006
.Linfo_string399:
	.asciz	"argc"                          # string offset=4012
.Linfo_string400:
	.asciz	"argv"                          # string offset=4017
.Linfo_string401:
	.asciz	"print_hash_value"              # string offset=4022
.Linfo_string402:
	.asciz	"crc"                           # string offset=4039
.Linfo_string403:
	.asciz	"poly"                          # string offset=4043
.Linfo_string404:
	.asciz	"val"                           # string offset=4048
.Linfo_string405:
	.asciz	"vname"                         # string offset=4052
.Linfo_string406:
	.asciz	"flag"                          # string offset=4058
.Linfo_string407:
	.asciz	"b"                             # string offset=4063
	.ident	"clang version 17.0.6 (https://gitee.com/openeuler/llvm-project.git 6e0bf6efd908a21c57cd62f3ffa72df9fe86de6a)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym safe_mul_func_int64_t_s_s
	.addrsig_sym safe_sub_func_int8_t_s_s
	.addrsig_sym safe_unary_minus_func_uint8_t_u
	.addrsig_sym safe_div_func_uint16_t_u_u
	.addrsig_sym safe_mul_func_uint8_t_u_u
	.addrsig_sym safe_add_func_int8_t_s_s
	.addrsig_sym safe_add_func_uint16_t_u_u
	.addrsig_sym safe_mul_func_int8_t_s_s
	.addrsig_sym safe_rshift_func_uint8_t_u_s
	.addrsig_sym safe_div_func_int32_t_s_s
	.addrsig_sym safe_lshift_func_uint64_t_u_s
	.addrsig_sym safe_lshift_func_uint8_t_u_u
	.addrsig_sym safe_rshift_func_int8_t_s_u
	.addrsig_sym safe_rshift_func_uint32_t_u_u
	.addrsig_sym safe_add_func_int16_t_s_s
	.addrsig_sym safe_sub_func_uint64_t_u_u
	.addrsig_sym safe_mod_func_uint16_t_u_u
	.addrsig_sym safe_mul_func_int16_t_s_s
	.addrsig_sym safe_mul_func_int32_t_s_s
	.addrsig_sym safe_add_func_int64_t_s_s
	.addrsig_sym safe_unary_minus_func_int64_t_s
	.addrsig_sym safe_lshift_func_int32_t_s_u
	.addrsig_sym safe_mul_func_uint32_t_u_u
	.addrsig_sym safe_lshift_func_int8_t_s_u
	.addrsig_sym safe_sub_func_int64_t_s_s
	.addrsig_sym safe_div_func_int16_t_s_s
	.addrsig_sym safe_div_func_uint64_t_u_u
	.addrsig_sym safe_add_func_uint64_t_u_u
	.addrsig_sym safe_mod_func_int64_t_s_s
	.addrsig_sym safe_sub_func_uint8_t_u_u
	.addrsig_sym safe_sub_func_int32_t_s_s
	.addrsig_sym safe_mod_func_uint8_t_u_u
	.addrsig_sym safe_unary_minus_func_int32_t_s
	.addrsig_sym safe_unary_minus_func_int8_t_s
	.addrsig_sym safe_lshift_func_int64_t_s_u
	.addrsig_sym safe_rshift_func_int16_t_s_u
	.addrsig_sym safe_div_func_uint32_t_u_u
	.addrsig_sym safe_rshift_func_int8_t_s_s
	.addrsig_sym safe_add_func_uint8_t_u_u
	.addrsig_sym safe_rshift_func_uint64_t_u_u
	.addrsig_sym safe_add_func_int32_t_s_s
	.addrsig_sym safe_div_func_int8_t_s_s
	.addrsig_sym safe_div_func_uint8_t_u_u
	.addrsig_sym safe_lshift_func_uint16_t_u_u
	.addrsig_sym safe_unary_minus_func_uint32_t_u
	.addrsig_sym safe_rshift_func_int32_t_s_u
	.addrsig_sym safe_rshift_func_int32_t_s_s
	.addrsig_sym safe_mod_func_uint32_t_u_u
	.addrsig_sym safe_mul_func_uint64_t_u_u
	.addrsig_sym safe_mod_func_int16_t_s_s
	.addrsig_sym safe_sub_func_int16_t_s_s
	.addrsig_sym safe_div_func_int64_t_s_s
	.addrsig_sym safe_rshift_func_uint64_t_u_s
	.addrsig_sym safe_mod_func_int8_t_s_s
	.addrsig_sym strcmp
	.addrsig_sym platform_main_begin
	.addrsig_sym crc32_gentab
	.addrsig_sym func_1
	.addrsig_sym transparent_crc
	.addrsig_sym printf
	.addrsig_sym platform_main_end
	.addrsig_sym crc32_8bytes
	.addrsig_sym crc32_byte
	.addrsig_sym g_3
	.addrsig_sym g_70
	.addrsig_sym g_73
	.addrsig_sym g_8
	.addrsig_sym g_124
	.addrsig_sym g_197
	.addrsig_sym g_69
	.addrsig_sym g_200
	.addrsig_sym g_302
	.addrsig_sym g_13
	.addrsig_sym g_334
	.addrsig_sym g_467
	.addrsig_sym g_477
	.addrsig_sym g_556
	.addrsig_sym g_672
	.addrsig_sym g_501
	.addrsig_sym g_932
	.addrsig_sym g_946
	.addrsig_sym g_1000
	.addrsig_sym g_1247
	.addrsig_sym g_1259
	.addrsig_sym g_1375
	.addrsig_sym g_1374
	.addrsig_sym g_1571
	.addrsig_sym g_1717
	.addrsig_sym g_1781
	.addrsig_sym g_1816
	.addrsig_sym g_1815
	.addrsig_sym g_1813
	.addrsig_sym g_1812
	.addrsig_sym g_1818
	.addrsig_sym g_2016
	.addrsig_sym g_2015
	.addrsig_sym g_2201
	.addrsig_sym g_136
	.addrsig_sym g_71
	.addrsig_sym g_123
	.addrsig_sym g_147
	.addrsig_sym g_325
	.addrsig_sym g_116
	.addrsig_sym g_111
	.addrsig_sym g_333
	.addrsig_sym g_642
	.addrsig_sym g_589
	.addrsig_sym g_733
	.addrsig_sym g_947
	.addrsig_sym g_89
	.addrsig_sym g_588
	.addrsig_sym g_294
	.addrsig_sym g_1124
	.addrsig_sym g_117
	.addrsig_sym g_645
	.addrsig_sym g_1113
	.addrsig_sym g_1292
	.addrsig_sym g_955
	.addrsig_sym g_1125
	.addrsig_sym g_92
	.addrsig_sym g_391
	.addrsig_sym g_813
	.addrsig_sym g_292
	.addrsig_sym g_1126
	.addrsig_sym g_252
	.addrsig_sym g_152
	.addrsig_sym g_133
	.addrsig_sym g_1258
	.addrsig_sym g_388
	.addrsig_sym g_903
	.addrsig_sym .Lconstinit
	.addrsig_sym .Lconstinit.1
	.addrsig_sym .Lconstinit.2
	.addrsig_sym .Lconstinit.3
	.addrsig_sym .Lconstinit.4
	.addrsig_sym .Lconstinit.5
	.addrsig_sym .Lconstinit.6
	.addrsig_sym .Lconstinit.7
	.addrsig_sym g_1548
	.addrsig_sym g_532
	.addrsig_sym g_1662
	.addrsig_sym g_230
	.addrsig_sym g_2
	.addrsig_sym g_6
	.addrsig_sym g_7
	.addrsig_sym g_93
	.addrsig_sym g_765
	.addrsig_sym g_921
	.addrsig_sym g_1814
	.addrsig_sym g_1852
	.addrsig_sym g_2017
	.addrsig_sym g_2070
	.addrsig_sym g_2128
	.addrsig_sym g_2309
	.addrsig_sym g_2448
	.addrsig_sym crc32_context
	.addrsig_sym crc32_tab
	.section	.debug_line,"",@progbits
.Lline_table_start0:
