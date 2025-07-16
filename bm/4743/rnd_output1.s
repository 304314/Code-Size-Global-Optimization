	.text
	.attribute	4, 16
	.attribute	5, "rv32i2p1_m2p0_f2p2_d2p2_c2p0_zicsr2p0"
	.file	"rnd_output1.c"
	.file	1 "/home/shiyanchu/outline_test" "llvm-install/bin/../lib/clang-runtimes/riscv32/include/bits/alltypes.h"
	.file	2 "/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" "rnd_output1.c"
	.file	3 "/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" "./rnd_globals.h"
	.globl	func_36                         # -- Begin function func_36
	.p2align	1
	.type	func_36,@function
func_36:                                # @func_36
.Lfunc_begin0:
	.loc	2 53 0                          # rnd_output1.c:53:0
	.cfi_sections .debug_frame
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -2032
	.cfi_def_cfa_offset 2032
	sw	ra, 2028(sp)                    # 4-byte Folded Spill
	sw	s0, 2024(sp)                    # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 2032
	.cfi_def_cfa s0, 0
	lui	a3, 1
	addi	a3, a3, 64
	sub	sp, sp, a3
	lui	a3, 1
	addi	a3, a3, 1844
	sub	a3, s0, a3
	lui	a4, 1
	sub	a4, s0, a4
	sw	a3, -1856(a4)                   # 4-byte Folded Spill
	sw	a0, -24(s0)
	sw	a1, -28(s0)
	sw	a2, -32(s0)
.Ltmp0:
	.loc	2 54 12 prologue_end            # rnd_output1.c:54:12
	lui	a0, %hi(.L__const.func_36.l_1843)
	addi	a1, a0, %lo(.L__const.func_36.l_1843)
	addi	a0, s0, -122
	li	a2, 90
	call	memcpy@plt
	li	a0, 0
	.loc	2 55 13                         # rnd_output1.c:55:13
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1852(a1)                   # 4-byte Folded Spill
	sw	a0, -128(s0)
	.loc	2 56 15                         # rnd_output1.c:56:15
	lui	a0, %hi(g_1662)
	addi	a0, a0, %lo(g_1662)
	sw	a0, -132(s0)
	.loc	2 57 22                         # rnd_output1.c:57:22
	lui	a0, %hi(g_1811)
	addi	a0, a0, %lo(g_1811)
	addi	a0, a0, 188
	sw	a0, -136(s0)
	.loc	2 58 14                         # rnd_output1.c:58:14
	lui	a0, %hi(g_955)
	addi	a0, a0, %lo(g_955)
	addi	a0, a0, 20
	sw	a0, -140(s0)
	.loc	2 59 17                         # rnd_output1.c:59:17
	lui	a0, %hi(g_501)
	addi	a0, a0, %lo(g_501)
	sw	a0, -144(s0)
	addi	a0, s0, -144
	.loc	2 60 18                         # rnd_output1.c:60:18
	sw	a0, -148(s0)
	.loc	2 61 14                         # rnd_output1.c:61:14
	lui	a0, %hi(.L__const.func_36.l_2043)
	addi	a1, a0, %lo(.L__const.func_36.l_2043)
	li	a0, 15
	slli	a2, a0, 8
	addi	a0, s0, -2048
	addi	a0, a0, -1952
	call	memcpy@plt
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 3
	addi	a0, a0, -395
	.loc	2 62 14                         # rnd_output1.c:62:14
	sh	a0, 1938(a1)
	.loc	2 63 14                         # rnd_output1.c:63:14
	lui	a0, %hi(.L__const.func_36.l_2148)
	addi	a1, a0, %lo(.L__const.func_36.l_2148)
	lui	a0, 1
	addi	a0, a0, 28
	sub	a0, s0, a0
	li	a2, 120
	call	memcpy@plt
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 64 15                         # rnd_output1.c:64:15
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1852(a0)                   # 4-byte Folded Reload
	lui	a2, %hi(g_947)
	addi	a2, a2, %lo(g_947)
	addi	a2, a2, 54
	sw	a2, 1812(a1)
	lui	a2, 1
	addi	a2, a2, 32
	sub	a2, s0, a2
	.loc	2 65 16                         # rnd_output1.c:65:16
	sw	a2, 1808(a1)
	.loc	2 66 13                         # rnd_output1.c:66:13
	lui	a2, %hi(g_70)
	addi	a2, a2, %lo(g_70)
	addi	a2, a2, 80
	sw	a2, 1804(a1)
	.loc	2 67 22                         # rnd_output1.c:67:22
	sw	a0, 1800(a1)
	.loc	2 68 16                         # rnd_output1.c:68:16
	lui	a2, %hi(g_69)
	addi	a2, a2, %lo(g_69)
	addi	a2, a2, 32
	sw	a2, 1796(a1)
	lui	a2, 234696
	addi	a2, a2, -1664
	.loc	2 69 13                         # rnd_output1.c:69:13
	sw	a2, 1792(a1)
	lui	a2, 23142
	addi	a2, a2, -1790
	.loc	2 70 13                         # rnd_output1.c:70:13
	sw	a2, 1788(a1)
	.loc	2 71 13                         # rnd_output1.c:71:13
	sw	a0, 1784(a1)
	.loc	2 72 13                         # rnd_output1.c:72:13
	sw	a0, 1780(a1)
	lui	a2, 1004415
	addi	a2, a2, 640
	.loc	2 73 13                         # rnd_output1.c:73:13
	sw	a2, 1776(a1)
	lui	a2, 680841
	addi	a2, a2, -2031
	.loc	2 74 13                         # rnd_output1.c:74:13
	sw	a2, 1772(a1)
	li	a2, 4
	.loc	2 76 13                         # rnd_output1.c:76:13
	sh	a2, 1730(a1)
	.loc	2 77 13                         # rnd_output1.c:77:13
	sw	a0, 1720(a1)
	li	a2, 9
	sw	a2, 1716(a1)
.Ltmp1:
	.loc	2 79 12                         # rnd_output1.c:79:12
	sw	a0, 1712(a1)
	.loc	2 79 10 is_stmt 0               # rnd_output1.c:79:10
	j	.LBB0_1
.LBB0_1:                                # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_3 Depth 2
.Ltmp2:
	.loc	2 79 17                         # rnd_output1.c:79:17
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1712(a0)
	li	a0, 4
.Ltmp3:
	.loc	2 79 5                          # rnd_output1.c:79:5
	blt	a0, a1, .LBB0_8
	j	.LBB0_2
.LBB0_2:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	2 0 5                           # rnd_output1.c:0:5
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, 0
.Ltmp4:
	.loc	2 81 16 is_stmt 1               # rnd_output1.c:81:16
	sw	a0, 1708(a1)
	.loc	2 81 14 is_stmt 0               # rnd_output1.c:81:14
	j	.LBB0_3
.LBB0_3:                                #   Parent Loop BB0_1 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp5:
	.loc	2 81 21                         # rnd_output1.c:81:21
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1708(a0)
	li	a0, 1
.Ltmp6:
	.loc	2 81 9                          # rnd_output1.c:81:9
	blt	a0, a1, .LBB0_6
	j	.LBB0_4
.LBB0_4:                                #   in Loop: Header=BB0_3 Depth=2
.Ltmp7:
	.loc	2 82 20 is_stmt 1               # rnd_output1.c:82:20
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1712(a1)
	.loc	2 82 13 is_stmt 0               # rnd_output1.c:82:13
	slli	a2, a0, 3
	lui	a0, 1
	addi	a0, a0, 112
	sub	a0, s0, a0
	add	a0, a0, a2
	.loc	2 82 23                         # rnd_output1.c:82:23
	lw	a1, 1708(a1)
	.loc	2 82 13                         # rnd_output1.c:82:13
	slli	a1, a1, 2
	add	a1, a1, a0
	lui	a0, 704830
	addi	a0, a0, -469
	.loc	2 82 26                         # rnd_output1.c:82:26
	sw	a0, 0(a1)
	.loc	2 82 13                         # rnd_output1.c:82:13
	j	.LBB0_5
.LBB0_5:                                #   in Loop: Header=BB0_3 Depth=2
	.loc	2 81 29 is_stmt 1               # rnd_output1.c:81:29
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1708(a1)
	addi	a0, a0, 1
	sw	a0, 1708(a1)
	.loc	2 81 9 is_stmt 0                # rnd_output1.c:81:9
	j	.LBB0_3
.Ltmp8:
.LBB0_6:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	2 83 5 is_stmt 1                # rnd_output1.c:83:5
	j	.LBB0_7
.Ltmp9:
.LBB0_7:                                #   in Loop: Header=BB0_1 Depth=1
	.loc	2 79 25                         # rnd_output1.c:79:25
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1712(a1)
	addi	a0, a0, 1
	sw	a0, 1712(a1)
	.loc	2 79 5 is_stmt 0                # rnd_output1.c:79:5
	j	.LBB0_1
.Ltmp10:
.LBB0_8:
	.loc	2 84 9 is_stmt 1                # rnd_output1.c:84:9
	lbu	a0, -62(s0)
.Ltmp11:
	.loc	2 84 9 is_stmt 0                # rnd_output1.c:84:9
	beqz	a0, .LBB0_10
	j	.LBB0_9
.LBB0_9:
	.loc	2 0 9                           # rnd_output1.c:0:9
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	li	a1, 1
.Ltmp12:
	.loc	2 86 17 is_stmt 1               # rnd_output1.c:86:17
	sw	a1, 1700(a0)
	.loc	2 87 18                         # rnd_output1.c:87:18
	lw	a0, 1700(a0)
	.loc	2 87 16 is_stmt 0               # rnd_output1.c:87:16
	sw	a0, -128(s0)
	.loc	2 88 5 is_stmt 1                # rnd_output1.c:88:5
	j	.LBB0_15
.Ltmp13:
.LBB0_10:
	.loc	2 91 17                         # rnd_output1.c:91:17
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, %hi(g_197)
	addi	a0, a0, %lo(g_197)
	addi	a0, a0, 26
	sw	a0, 1696(a1)
	lui	a0, 696922
	addi	a0, a0, 213
	.loc	2 92 17                         # rnd_output1.c:92:17
	sw	a0, 1692(a1)
	li	a0, -6
	.loc	2 93 17                         # rnd_output1.c:93:17
	sw	a0, 1688(a1)
	li	a0, 0
	.loc	2 94 20                         # rnd_output1.c:94:20
	lui	a2, 1
	sub	a2, s0, a2
	sw	a0, -1860(a2)                   # 4-byte Folded Spill
	sw	a0, 1684(a1)
	sw	a0, 1680(a1)
	sw	a0, 1676(a1)
	sw	a0, 1672(a1)
	.loc	2 95 18                         # rnd_output1.c:95:18
	lui	a2, %hi(g_70)
	addi	a2, a2, %lo(g_70)
	addi	a2, a2, 80
	sw	a2, 1668(a1)
	lui	a2, 917862
	addi	a2, a2, 645
	.loc	2 96 17                         # rnd_output1.c:96:17
	sw	a2, 1664(a1)
	li	a2, 5
	.loc	2 97 17                         # rnd_output1.c:97:17
	sw	a2, 1660(a1)
	.loc	2 99 28                         # rnd_output1.c:99:28
	sw	a0, 1620(a1)
	.loc	2 100 25                        # rnd_output1.c:100:25
	lui	a2, %hi(g_325)
	addi	a2, a2, %lo(g_325)
	sw	a2, 1616(a1)
	lui	a2, 1
	addi	a2, a2, 228
	sub	a2, s0, a2
	.loc	2 101 26                        # rnd_output1.c:101:26
	sw	a2, 1612(a1)
	lui	a2, 1
	addi	a2, a2, 232
	sub	a2, s0, a2
	.loc	2 102 27                        # rnd_output1.c:102:27
	sw	a2, 1608(a1)
	lui	a2, 1
	addi	a2, a2, 236
	sub	a2, s0, a2
	.loc	2 103 28                        # rnd_output1.c:103:28
	sw	a2, 1604(a1)
	.loc	2 104 19                        # rnd_output1.c:104:19
	sw	a0, 1600(a1)
	sw	a0, 1596(a1)
	li	a2, 1
	sw	a2, 1592(a1)
	lui	a3, 221930
	addi	a3, a3, 486
	sw	a3, 1588(a1)
	.loc	2 105 21                        # rnd_output1.c:105:21
	sw	a0, 1584(a1)
	.loc	2 106 26                        # rnd_output1.c:106:26
	lui	a3, %hi(g_200)
	addi	a3, a3, %lo(g_200)
	sw	a3, 1580(a1)
	lui	a3, 1
	addi	a3, a3, 264
	sub	a3, s0, a3
	.loc	2 107 27                        # rnd_output1.c:107:27
	sw	a3, 1576(a1)
	lui	a3, 1
	addi	a3, a3, 268
	sub	a3, s0, a3
	.loc	2 108 28                        # rnd_output1.c:108:28
	sw	a3, 1572(a1)
	lui	a3, 1
	addi	a3, a3, 272
	sub	a3, s0, a3
	.loc	2 109 29                        # rnd_output1.c:109:29
	sw	a3, 1568(a1)
	.loc	2 110 26                        # rnd_output1.c:110:26
	sw	a0, 1564(a1)
	lui	a3, 1
	addi	a3, a3, 280
	sub	a3, s0, a3
	.loc	2 111 27                        # rnd_output1.c:111:27
	sw	a3, 1560(a1)
	.loc	2 112 17                        # rnd_output1.c:112:17
	sw	a2, 1556(a1)
	lui	a2, 352219
	addi	a2, a2, 252
	.loc	2 113 18                        # rnd_output1.c:113:18
	sw	a2, 1552(a1)
.Ltmp14:
	.loc	2 115 16                        # rnd_output1.c:115:16
	sw	a0, 1548(a1)
	.loc	2 115 14 is_stmt 0              # rnd_output1.c:115:14
	j	.LBB0_11
.LBB0_11:                               # =>This Inner Loop Header: Depth=1
.Ltmp15:
	.loc	2 115 21                        # rnd_output1.c:115:21
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1548(a0)
	li	a0, 8
.Ltmp16:
	.loc	2 115 9                         # rnd_output1.c:115:9
	blt	a0, a1, .LBB0_14
	j	.LBB0_12
.LBB0_12:                               #   in Loop: Header=BB0_11 Depth=1
.Ltmp17:
	.loc	2 116 20 is_stmt 1              # rnd_output1.c:116:20
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1548(a0)
	.loc	2 116 13 is_stmt 0              # rnd_output1.c:116:13
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 220
	sub	a0, s0, a0
	add	a1, a1, a0
	.loc	2 116 23                        # rnd_output1.c:116:23
	lui	a0, %hi(g_955)
	addi	a0, a0, %lo(g_955)
	addi	a0, a0, 26
	sw	a0, 0(a1)
	.loc	2 116 13                        # rnd_output1.c:116:13
	j	.LBB0_13
.LBB0_13:                               #   in Loop: Header=BB0_11 Depth=1
	.loc	2 115 29 is_stmt 1              # rnd_output1.c:115:29
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1548(a1)
	addi	a0, a0, 1
	sw	a0, 1548(a1)
	.loc	2 115 9 is_stmt 0               # rnd_output1.c:115:9
	j	.LBB0_11
.Ltmp18:
.LBB0_14:
	.loc	2 0 9                           # rnd_output1.c:0:9
	j	.LBB0_15
.LBB0_15:
.Ltmp19:
	.loc	2 118 20 is_stmt 1              # rnd_output1.c:118:20
	lui	a1, %hi(g_1816)
	li	a0, -13
	sw	a0, %lo(g_1816)(a1)
	.loc	2 118 10 is_stmt 0              # rnd_output1.c:118:10
	j	.LBB0_16
.LBB0_16:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_18 Depth 2
                                        #     Child Loop BB0_22 Depth 2
.Ltmp20:
	.loc	2 118 37                        # rnd_output1.c:118:37
	lui	a0, %hi(g_1816)
	lw	a0, %lo(g_1816)(a0)
	li	a1, 47
.Ltmp21:
	.loc	2 118 5                         # rnd_output1.c:118:5
	bltu	a0, a1, .LBB0_32
	j	.LBB0_17
.LBB0_17:                               #   in Loop: Header=BB0_16 Depth=1
.Ltmp22:
	.loc	2 120 19 is_stmt 1              # rnd_output1.c:120:19
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, %hi(g_947)
	addi	a0, a0, %lo(g_947)
	addi	a0, a0, 32
	sw	a0, 1544(a1)
	li	a0, -1
	.loc	2 121 17                        # rnd_output1.c:121:17
	sw	a0, 1540(a1)
	li	a0, 4
	.loc	2 122 17                        # rnd_output1.c:122:17
	sw	a0, 1536(a1)
	lui	a0, 1
	addi	a0, a0, 48
	sub	a0, s0, a0
	.loc	2 123 21                        # rnd_output1.c:123:21
	sw	a0, 1532(a1)
	.loc	2 124 20                        # rnd_output1.c:124:20
	lui	a0, %hi(g_467)
	addi	a0, a0, %lo(g_467)
	addi	a0, a0, 12
	sw	a0, 1528(a1)
	li	a0, 0
.Ltmp23:
	.loc	2 127 16                        # rnd_output1.c:127:16
	sw	a0, 1520(a1)
	.loc	2 127 14 is_stmt 0              # rnd_output1.c:127:14
	j	.LBB0_18
.LBB0_18:                               #   Parent Loop BB0_16 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp24:
	.loc	2 127 21                        # rnd_output1.c:127:21
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1520(a0)
	li	a0, 0
.Ltmp25:
	.loc	2 127 9                         # rnd_output1.c:127:9
	blt	a0, a1, .LBB0_21
	j	.LBB0_19
.LBB0_19:                               #   in Loop: Header=BB0_18 Depth=2
.Ltmp26:
	.loc	2 128 20 is_stmt 1              # rnd_output1.c:128:20
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1520(a0)
	.loc	2 128 13 is_stmt 0              # rnd_output1.c:128:13
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 320
	sub	a0, s0, a0
	add	a1, a1, a0
	.loc	2 128 23                        # rnd_output1.c:128:23
	lui	a0, %hi(g_1717)
	addi	a0, a0, %lo(g_1717)
	addi	a0, a0, 164
	sw	a0, 0(a1)
	.loc	2 128 13                        # rnd_output1.c:128:13
	j	.LBB0_20
.LBB0_20:                               #   in Loop: Header=BB0_18 Depth=2
	.loc	2 127 29 is_stmt 1              # rnd_output1.c:127:29
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1520(a1)
	addi	a0, a0, 1
	sw	a0, 1520(a1)
	.loc	2 127 9 is_stmt 0               # rnd_output1.c:127:9
	j	.LBB0_18
.Ltmp27:
.LBB0_21:                               #   in Loop: Header=BB0_16 Depth=1
	.loc	2 0 9                           # rnd_output1.c:0:9
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, 0
.Ltmp28:
	.loc	2 129 21 is_stmt 1              # rnd_output1.c:129:21
	sh	a0, 1730(a1)
	.loc	2 129 14 is_stmt 0              # rnd_output1.c:129:14
	j	.LBB0_22
.LBB0_22:                               #   Parent Loop BB0_16 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp29:
	.loc	2 129 27                        # rnd_output1.c:129:27
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lh	a0, 1730(a0)
	li	a1, -27
.Ltmp30:
	.loc	2 129 9                         # rnd_output1.c:129:9
	beq	a0, a1, .LBB0_30
	j	.LBB0_23
.LBB0_23:                               #   in Loop: Header=BB0_22 Depth=2
.Ltmp31:
	.loc	2 131 23 is_stmt 1              # rnd_output1.c:131:23
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, %hi(g_2017)
	addi	a1, a1, %lo(g_2017)
	sw	a1, 1516(a0)
	.loc	2 132 22                        # rnd_output1.c:132:22
	lui	a1, %hi(g_391)
	addi	a1, a1, %lo(g_391)
	sw	a1, 1512(a0)
	li	a1, 2
	.loc	2 133 21                        # rnd_output1.c:133:21
	sw	a1, 1508(a0)
	lui	a1, 1
	addi	a1, a1, 72
	sub	a1, s0, a1
	.loc	2 134 22                        # rnd_output1.c:134:22
	sw	a1, 1504(a0)
	.loc	2 135 24                        # rnd_output1.c:135:24
	lui	a1, %hi(g_71)
	addi	a1, a1, %lo(g_71)
	sw	a1, 1500(a0)
	li	a1, 0
	.loc	2 136 22                        # rnd_output1.c:136:22
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1872(a2)                   # 4-byte Folded Spill
	sw	a1, 1488(a0)
	sw	a1, 1484(a0)
	lui	a2, 1019706
	addi	a2, a2, 1183
	sw	a2, 1480(a0)
	li	a2, -1
	sw	a2, 1476(a0)
	.loc	2 137 44                        # rnd_output1.c:137:44
	lw	a2, 1544(a0)
	.loc	2 137 34 is_stmt 0              # rnd_output1.c:137:34
	lw	a3, 1808(a0)
	.loc	2 137 42                        # rnd_output1.c:137:42
	sw	a2, 0(a3)
	.loc	2 137 57                        # rnd_output1.c:137:57
	lui	a3, %hi(g_1373)
	lw	a3, %lo(g_1373)(a3)
	.loc	2 137 56                        # rnd_output1.c:137:56
	lw	a3, 0(a3)
	.loc	2 137 52                        # rnd_output1.c:137:52
	xor	a2, a2, a3
	snez	a2, a2
	.loc	2 137 92                        # rnd_output1.c:137:92
	lw	a4, 1540(a0)
	.loc	2 137 89                        # rnd_output1.c:137:89
	lw	a3, 1536(a0)
	xor	a3, a3, a4
	sw	a3, 1536(a0)
	.loc	2 137 71                        # rnd_output1.c:137:71
	lw	a4, 1516(a0)
	.loc	2 137 79                        # rnd_output1.c:137:79
	sw	a3, 0(a4)
	.loc	2 137 66                        # rnd_output1.c:137:66
	xor	a2, a2, a3
	.loc	2 137 105                       # rnd_output1.c:137:105
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1864(a3)                   # 4-byte Folded Spill
	lw	a2, -32(s0)
	.loc	2 137 187                       # rnd_output1.c:137:187
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1868(a3)                   # 4-byte Folded Spill
	lbu	a0, 1540(a0)
	.loc	2 137 161                       # rnd_output1.c:137:161
	call	safe_add_func_uint8_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a3, -1856(a1)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a2, -1872(a1)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1868(a1)                   # 4-byte Folded Reload
                                        # kill: def $x14 killed $x10
	.loc	2 137 245                       # rnd_output1.c:137:245
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1864(a0)                   # 4-byte Folded Reload
	lui	a4, %hi(g_2137)
	lw	a4, %lo(g_2137)(a4)
	.loc	2 137 148                       # rnd_output1.c:137:148
	lw	a3, 1512(a3)
	.loc	2 137 156                       # rnd_output1.c:137:156
	sw	a2, 4(a3)
	li	a2, 1
	sw	a2, 0(a3)
	.loc	2 137 110                       # rnd_output1.c:137:110
	slti	a1, a1, 0
	.loc	2 137 315                       # rnd_output1.c:137:315
	bne	a0, a1, .LBB0_25
	j	.LBB0_24
.LBB0_24:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 137 318                       # rnd_output1.c:137:318
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1508(a0)
	li	a1, 0
	.loc	2 137 326                       # rnd_output1.c:137:326
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1876(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_26
	j	.LBB0_25
.LBB0_25:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 137 331                       # rnd_output1.c:137:331
	lui	a0, %hi(g_92)
	lw	a0, %lo(g_92)(a0)
	.loc	2 137 330                       # rnd_output1.c:137:330
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 137 326                       # rnd_output1.c:137:326
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1876(a1)                   # 4-byte Folded Spill
	j	.LBB0_26
.LBB0_26:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1876(a1)                   # 4-byte Folded Reload
	.loc	2 137 326                       # rnd_output1.c:137:326
	andi	a3, a1, 1
	.loc	2 137 15                        # rnd_output1.c:137:15
	lw	a2, 1504(a0)
	.loc	2 137 23                        # rnd_output1.c:137:23
	lw	a1, 0(a2)
	xor	a1, a1, a3
	sw	a1, 0(a2)
	.loc	2 138 42 is_stmt 1              # rnd_output1.c:138:42
	lw	a1, 1504(a0)
	lui	a0, 475306
	addi	a0, a0, -1502
	.loc	2 138 50 is_stmt 0              # rnd_output1.c:138:50
	sw	a0, 0(a1)
	.loc	2 138 119                       # rnd_output1.c:138:119
	lw	a0, -28(s0)
	.loc	2 138 129                       # rnd_output1.c:138:129
	lw	a1, -24(s0)
	.loc	2 138 128                       # rnd_output1.c:138:128
	lw	a1, 0(a1)
	li	a2, 1
	.loc	2 138 136                       # rnd_output1.c:138:136
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1880(a3)                   # 4-byte Folded Spill
	bne	a0, a1, .LBB0_28
	j	.LBB0_27
.LBB0_27:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 138 139                       # rnd_output1.c:138:139
	lw	a0, -28(s0)
	.loc	2 138 136                       # rnd_output1.c:138:136
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1880(a1)                   # 4-byte Folded Spill
	j	.LBB0_28
.LBB0_28:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 0 136                         # rnd_output1.c:0:136
	lui	a0, 1
	sub	a0, s0, a0
	lw	a2, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1880(a0)                   # 4-byte Folded Reload
	.loc	2 138 196                       # rnd_output1.c:138:196
	lw	a0, 1528(a2)
	.loc	2 138 206                       # rnd_output1.c:138:206
	lw	a1, 1500(a2)
	.loc	2 138 203                       # rnd_output1.c:138:203
	xor	a0, a0, a1
	seqz	a1, a0
	.loc	2 138 178                       # rnd_output1.c:138:178
	lw	a0, 1488(a2)
	sw	a0, 1472(a2)
	lw	a0, 1484(a2)
	sw	a0, 1468(a2)
	lw	a0, 1480(a2)
	sw	a0, 1464(a2)
	lw	a0, 1476(a2)
	sw	a0, 1460(a2)
	lui	a0, 1
	addi	a0, a0, 52
	sub	a0, s0, a0
	li	a2, 0
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1884(a3)                   # 4-byte Folded Spill
	lui	a3, 1
	addi	a3, a3, 384
	sub	a3, s0, a3
	call	func_46
	mv	a1, a0
	.loc	2 138 176                       # rnd_output1.c:138:176
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	sw	a1, 1524(a0)
	.loc	2 138 162                       # rnd_output1.c:138:162
	lui	a0, %hi(g_1259)
	addi	a0, a0, %lo(g_1259)
	addi	a0, a0, 172
	xor	a0, a0, a1
	seqz	a0, a0
	li	a1, 6
	.loc	2 138 87                        # rnd_output1.c:138:87
	call	safe_rshift_func_uint8_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
                                        # kill: def $x12 killed $x10
	.loc	2 138 26                        # rnd_output1.c:138:26
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1884(a0)                   # 4-byte Folded Reload
	sw	a0, 1732(a1)
	.loc	2 139 9 is_stmt 1               # rnd_output1.c:139:9
	j	.LBB0_29
.Ltmp32:
.LBB0_29:                               #   in Loop: Header=BB0_22 Depth=2
	.loc	2 129 51                        # rnd_output1.c:129:51
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lh	a0, 1730(a1)
	addi	a0, a0, -1
	sh	a0, 1730(a1)
	.loc	2 129 9 is_stmt 0               # rnd_output1.c:129:9
	j	.LBB0_22
.Ltmp33:
.LBB0_30:                               #   in Loop: Header=BB0_16 Depth=1
	.loc	2 140 21 is_stmt 1              # rnd_output1.c:140:21
	lw	a0, -24(s0)
	.loc	2 140 11 is_stmt 0              # rnd_output1.c:140:11
	lui	a1, %hi(g_2277)
	lw	a1, %lo(g_2277)(a1)
	.loc	2 140 19                        # rnd_output1.c:140:19
	sw	a0, 0(a1)
	.loc	2 141 5 is_stmt 1               # rnd_output1.c:141:5
	j	.LBB0_31
.Ltmp34:
.LBB0_31:                               #   in Loop: Header=BB0_16 Depth=1
	.loc	2 118 94                        # rnd_output1.c:118:94
	lui	a0, %hi(g_1816)
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1888(a1)                   # 4-byte Folded Spill
	lhu	a0, %lo(g_1816)(a0)
	li	a1, 5
	.loc	2 118 60 is_stmt 0              # rnd_output1.c:118:60
	call	safe_add_func_uint16_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1888(a1)                   # 4-byte Folded Reload
	.loc	2 118 58                        # rnd_output1.c:118:58
	sw	a0, %lo(g_1816)(a1)
	.loc	2 118 5                         # rnd_output1.c:118:5
	j	.LBB0_16
.Ltmp35:
.LBB0_32:
	.loc	2 0 5                           # rnd_output1.c:0:5
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, 0
.Ltmp36:
	.loc	2 142 17 is_stmt 1              # rnd_output1.c:142:17
	sw	a0, 1784(a1)
	.loc	2 142 10 is_stmt 0              # rnd_output1.c:142:10
	j	.LBB0_33
.LBB0_33:                               # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_49 Depth 2
                                        #       Child Loop BB0_51 Depth 3
                                        #       Child Loop BB0_55 Depth 3
                                        #         Child Loop BB0_78 Depth 4
.Ltmp37:
	.loc	2 142 23                        # rnd_output1.c:142:23
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1784(a0)
	li	a0, -12
.Ltmp38:
	.loc	2 142 5                         # rnd_output1.c:142:5
	bge	a0, a1, .LBB0_34
	j	.LBB0_106
.LBB0_34:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 5                           # rnd_output1.c:0:5
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	li	a1, 53
.Ltmp39:
	.loc	2 144 16 is_stmt 1              # rnd_output1.c:144:16
	sb	a1, 1459(a0)
	.loc	2 145 18                        # rnd_output1.c:145:18
	lui	a1, %hi(g_391)
	addi	a1, a1, %lo(g_391)
	sw	a1, 1452(a0)
	.loc	2 146 17                        # rnd_output1.c:146:17
	lui	a1, %hi(g_70)
	addi	a1, a1, %lo(g_70)
	addi	a1, a1, 80
	sw	a1, 1448(a0)
	li	a1, -5
	.loc	2 147 18                        # rnd_output1.c:147:18
	sh	a1, 1446(a0)
	li	a1, 0
	.loc	2 148 26                        # rnd_output1.c:148:26
	sw	a1, 1440(a0)
	lui	a2, 1
	addi	a2, a2, 404
	sub	a2, s0, a2
	.loc	2 149 27                        # rnd_output1.c:149:27
	sw	a2, 1436(a0)
	lui	a2, 1
	addi	a2, a2, 408
	sub	a2, s0, a2
	.loc	2 150 28                        # rnd_output1.c:150:28
	sw	a2, 1432(a0)
	li	a2, 1
	.loc	2 151 17                        # rnd_output1.c:151:17
	sb	a2, 1431(a0)
	.loc	2 152 34                        # rnd_output1.c:152:34
	lui	a2, 1
	addi	a2, a2, 96
	sub	a2, s0, a2
	.loc	2 152 24 is_stmt 0              # rnd_output1.c:152:24
	sw	a2, 1424(a0)
	lui	a2, 279640
	addi	a2, a2, -1556
	.loc	2 153 17 is_stmt 1              # rnd_output1.c:153:17
	sw	a2, 1420(a0)
	.loc	2 154 19                        # rnd_output1.c:154:19
	lui	a2, %hi(g_2448)
	addi	a2, a2, %lo(g_2448)
	sw	a2, 1416(a0)
	.loc	2 155 18                        # rnd_output1.c:155:18
	sw	a1, 1408(a0)
	sw	a1, 1404(a0)
	li	a2, 8
	sw	a2, 1400(a0)
	lui	a2, 817846
	addi	a2, a2, -1185
	sw	a2, 1396(a0)
.Ltmp40:
	.loc	2 156 51                        # rnd_output1.c:156:51
	lb	a0, 1459(a0)
	.loc	2 156 59 is_stmt 0              # rnd_output1.c:156:59
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1892(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_47
	j	.LBB0_35
.LBB0_35:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 122                       # rnd_output1.c:156:122
	lw	a0, -28(s0)
	li	a1, 0
	.loc	2 156 127                       # rnd_output1.c:156:127
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1896(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_44
	j	.LBB0_36
.LBB0_36:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 127                         # rnd_output1.c:0:127
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	addi	a0, s0, -24
	.loc	2 156 303                       # rnd_output1.c:156:303
	seqz	a0, a0
	.loc	2 156 354                       # rnd_output1.c:156:354
	lui	a2, 1
	sub	a2, s0, a2
	sw	a0, -1908(a2)                   # 4-byte Folded Spill
	lui	a0, %hi(g_1414)
	lw	a0, %lo(g_1414)(a0)
	.loc	2 156 387                       # rnd_output1.c:156:387
	lw	a0, 1720(a1)
	lw	a2, 1716(a1)
	.loc	2 156 396                       # rnd_output1.c:156:396
	lb	a3, 1459(a1)
	srai	a1, a3, 31
	.loc	2 156 394                       # rnd_output1.c:156:394
	sltu	a2, a2, a3
	slt	a3, a0, a1
	lui	a4, 1
	sub	a4, s0, a4
	sw	a3, -1904(a4)                   # 4-byte Folded Spill
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1900(a3)                   # 4-byte Folded Spill
	beq	a0, a1, .LBB0_38
# %bb.37:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 394                         # rnd_output1.c:0:394
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1904(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1900(a1)                   # 4-byte Folded Spill
.LBB0_38:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 394                       # rnd_output1.c:156:394
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a2, -1900(a1)                   # 4-byte Folded Reload
	.loc	2 156 406                       # rnd_output1.c:156:406
	lw	a1, -28(s0)
	.loc	2 156 404                       # rnd_output1.c:156:404
	sltu	a1, a1, a2
	.loc	2 156 375                       # rnd_output1.c:156:375
	lw	a3, 1452(a0)
	li	a2, 0
	.loc	2 156 383                       # rnd_output1.c:156:383
	sw	a2, 4(a3)
	sw	a1, 0(a3)
	.loc	2 156 416                       # rnd_output1.c:156:416
	lb	a3, 1459(a0)
	srai	a0, a3, 31
	.loc	2 156 413                       # rnd_output1.c:156:413
	sltu	a1, a1, a3
	slt	a2, a2, a0
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1916(a3)                   # 4-byte Folded Spill
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1912(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_40
# %bb.39:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 413                         # rnd_output1.c:0:413
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1916(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1912(a1)                   # 4-byte Folded Spill
.LBB0_40:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 413                       # rnd_output1.c:156:413
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1912(a0)                   # 4-byte Folded Reload
	lui	a0, 8
	addi	a0, a0, -1858
	.loc	2 156 315                       # rnd_output1.c:156:315
	call	safe_mul_func_uint16_t_u_u
	mv	a1, a0
	.loc	2 156 266                       # rnd_output1.c:156:266
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1908(a0)                   # 4-byte Folded Reload
	call	safe_sub_func_uint16_t_u_u
	li	a0, 1
	.loc	2 156 479                       # rnd_output1.c:156:479
	bnez	a0, .LBB0_42
	j	.LBB0_41
.LBB0_41:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 482                       # rnd_output1.c:156:482
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lb	a0, 1459(a0)
	li	a1, 0
	.loc	2 156 490                       # rnd_output1.c:156:490
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1920(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_43
	j	.LBB0_42
.LBB0_42:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 493                       # rnd_output1.c:156:493
	lw	a0, -32(s0)
	.loc	2 156 490                       # rnd_output1.c:156:490
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1920(a1)                   # 4-byte Folded Spill
	j	.LBB0_43
.LBB0_43:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1920(a1)                   # 4-byte Folded Reload
	.loc	2 156 490                       # rnd_output1.c:156:490
	andi	a1, a1, 1
	.loc	2 156 502                       # rnd_output1.c:156:502
	lb	a0, 1459(a0)
	.loc	2 156 499                       # rnd_output1.c:156:499
	slt	a0, a0, a1
	xori	a1, a0, 1
	.loc	2 156 512                       # rnd_output1.c:156:512
	lui	a0, %hi(g_642)
	lhu	a0, %lo(g_642)(a0)
	.loc	2 156 510                       # rnd_output1.c:156:510
	slt	a0, a0, a1
	.loc	2 156 520                       # rnd_output1.c:156:520
	lw	a2, -32(s0)
	srai	a3, a2, 31
	li	a1, 0
	.loc	2 156 229                       # rnd_output1.c:156:229
	call	safe_div_func_int64_t_s_s
	.loc	2 156 530                       # rnd_output1.c:156:530
	lw	a1, -24(s0)
	.loc	2 156 529                       # rnd_output1.c:156:529
	lw	a1, 0(a1)
	.loc	2 156 201                       # rnd_output1.c:156:201
	call	safe_sub_func_uint32_t_u_u
	mv	a1, a0
	li	a0, -1
	.loc	2 156 159                       # rnd_output1.c:156:159
	call	safe_mod_func_uint32_t_u_u
	.loc	2 156 541                       # rnd_output1.c:156:541
	lhu	a1, -28(s0)
	.loc	2 156 131                       # rnd_output1.c:156:131
	slli	a0, a0, 16
	srli	a0, a0, 16
	call	safe_mul_func_uint16_t_u_u
	.loc	2 156 127                       # rnd_output1.c:156:127
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1896(a1)                   # 4-byte Folded Spill
	j	.LBB0_44
.LBB0_44:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1896(a0)                   # 4-byte Folded Reload
	.loc	2 156 551                       # rnd_output1.c:156:551
	lbu	a3, 1459(a1)
	.loc	2 156 117                       # rnd_output1.c:156:117
	lui	a0, %hi(g_197)
	addi	a2, a0, %lo(g_197)
	lbu	a0, 15(a2)
	and	a0, a0, a3
	sb	a0, 15(a2)
	.loc	2 156 94                        # rnd_output1.c:156:94
	lw	a1, 1448(a1)
	.loc	2 156 102                       # rnd_output1.c:156:102
	sb	a0, 0(a1)
	.loc	2 156 91                        # rnd_output1.c:156:91
	andi	a0, a0, 255
	li	a1, 0
	.loc	2 156 561                       # rnd_output1.c:156:561
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1924(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_46
	j	.LBB0_45
.LBB0_45:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 156 564                       # rnd_output1.c:156:564
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lhu	a0, 1446(a0)
	.loc	2 156 561                       # rnd_output1.c:156:561
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1924(a1)                   # 4-byte Folded Spill
	j	.LBB0_46
.LBB0_46:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1924(a0)                   # 4-byte Folded Reload
	.loc	2 156 90                        # rnd_output1.c:156:90
	andi	a0, a0, 1
	.loc	2 156 573                       # rnd_output1.c:156:573
	lw	a2, -28(s0)
	li	a3, 0
	.loc	2 156 63                        # rnd_output1.c:156:63
	mv	a1, a3
	call	safe_mod_func_uint64_t_u_u
	.loc	2 156 59                        # rnd_output1.c:156:59
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1892(a1)                   # 4-byte Folded Spill
	j	.LBB0_47
.LBB0_47:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1892(a0)                   # 4-byte Folded Reload
	.loc	2 156 59                        # rnd_output1.c:156:59
	andi	a0, a0, 1
	.loc	2 156 583                       # rnd_output1.c:156:583
	lw	a1, -28(s0)
	.loc	2 156 581                       # rnd_output1.c:156:581
	or	a1, a1, a0
	lui	a0, 14
	addi	a0, a0, -210
	.loc	2 156 589                       # rnd_output1.c:156:589
	sltu	a0, a0, a1
	lui	a1, 978617
	addi	a2, a1, -817
	lui	a1, 371301
	addi	a3, a1, -835
	li	a1, 0
	.loc	2 156 14                        # rnd_output1.c:156:14
	call	safe_div_func_int64_t_s_s
	or	a0, a0, a1
.Ltmp41:
	.loc	2 156 13                        # rnd_output1.c:156:13
	beqz	a0, .LBB0_99
	j	.LBB0_48
.LBB0_48:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 13                          # rnd_output1.c:0:13
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, -1
.Ltmp42:
	.loc	2 158 22 is_stmt 1              # rnd_output1.c:158:22
	sw	a0, 1392(a1)
	.loc	2 159 22                        # rnd_output1.c:159:22
	lui	a0, %hi(.L__const.func_36.l_2374)
	addi	a1, a0, %lo(.L__const.func_36.l_2374)
	lui	a0, 1
	addi	a0, a0, 1360
	sub	a0, s0, a0
	li	a2, 896
	call	memcpy@plt
	.loc	2 160 24                        # rnd_output1.c:160:24
	lui	a0, %hi(.L__const.func_36.l_2404)
	addi	a1, a0, %lo(.L__const.func_36.l_2404)
	lui	a0, 1
	addi	a0, a0, 1460
	sub	a0, s0, a0
	li	a2, 100
	call	memcpy@plt
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 515952
	addi	a0, a0, 1670
	.loc	2 161 21                        # rnd_output1.c:161:21
	sw	a0, 380(a1)
	lui	a2, 321232
	addi	a2, a2, -1701
	sw	a2, 376(a1)
	sw	a2, 372(a1)
	sw	a0, 368(a1)
	sw	a2, 364(a1)
	sw	a2, 360(a1)
	sw	a0, 356(a1)
	.loc	2 163 13                        # rnd_output1.c:163:13
	lw	a0, 1392(a1)
	addi	a0, a0, 1
	sw	a0, 1392(a1)
	li	a0, 0
.Ltmp43:
	.loc	2 164 25                        # rnd_output1.c:164:25
	sw	a0, 1772(a1)
	.loc	2 164 18 is_stmt 0              # rnd_output1.c:164:18
	j	.LBB0_49
.LBB0_49:                               #   Parent Loop BB0_33 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB0_51 Depth 3
                                        #       Child Loop BB0_55 Depth 3
                                        #         Child Loop BB0_78 Depth 4
.Ltmp44:
	.loc	2 164 31                        # rnd_output1.c:164:31
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1772(a0)
	li	a1, 28
.Ltmp45:
	.loc	2 164 13                        # rnd_output1.c:164:13
	beq	a0, a1, .LBB0_98
	j	.LBB0_50
.LBB0_50:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 13                          # rnd_output1.c:0:13
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, -1
.Ltmp46:
	.loc	2 166 26 is_stmt 1              # rnd_output1.c:166:26
	sw	a0, 340(a1)
	lui	a0, 824880
	addi	a0, a0, -522
	.loc	2 167 25                        # rnd_output1.c:167:25
	sw	a0, 336(a1)
	li	a0, 0
	.loc	2 168 26                        # rnd_output1.c:168:26
	sh	a0, 334(a1)
	lui	a2, 208795
	addi	a2, a2, -608
	.loc	2 169 25                        # rnd_output1.c:169:25
	sw	a2, 328(a1)
	lui	a2, 700787
	addi	a2, a2, 2019
	sw	a2, 324(a1)
	.loc	2 170 29                        # rnd_output1.c:170:29
	sw	a0, 320(a1)
	lui	a2, 1
	addi	a2, a2, 1524
	sub	a2, s0, a2
	.loc	2 171 30                        # rnd_output1.c:171:30
	sw	a2, 316(a1)
	.loc	2 172 33                        # rnd_output1.c:172:33
	lui	a2, %hi(g_1007)
	addi	a2, a2, %lo(g_1007)
	addi	a2, a2, 116
	sw	a2, 312(a1)
	.loc	2 173 25                        # rnd_output1.c:173:25
	lui	a2, %hi(g_252)
	addi	a2, a2, %lo(g_252)
	sw	a2, 308(a1)
	.loc	2 175 25                        # rnd_output1.c:175:25
	sb	a0, 275(a1)
.Ltmp47:
	.loc	2 177 24                        # rnd_output1.c:177:24
	sw	a0, 268(a1)
	.loc	2 177 22 is_stmt 0              # rnd_output1.c:177:22
	j	.LBB0_51
.LBB0_51:                               #   Parent Loop BB0_33 Depth=1
                                        #     Parent Loop BB0_49 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp48:
	.loc	2 177 29                        # rnd_output1.c:177:29
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 268(a0)
	li	a0, 7
.Ltmp49:
	.loc	2 177 17                        # rnd_output1.c:177:17
	blt	a0, a1, .LBB0_54
	j	.LBB0_52
.LBB0_52:                               #   in Loop: Header=BB0_51 Depth=3
.Ltmp50:
	.loc	2 178 28 is_stmt 1              # rnd_output1.c:178:28
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 268(a0)
	.loc	2 178 21 is_stmt 0              # rnd_output1.c:178:21
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 1568
	sub	a0, s0, a0
	add	a1, a1, a0
	.loc	2 178 31                        # rnd_output1.c:178:31
	lui	a0, %hi(g_733)
	addi	a0, a0, %lo(g_733)
	sw	a0, 0(a1)
	.loc	2 178 21                        # rnd_output1.c:178:21
	j	.LBB0_53
.LBB0_53:                               #   in Loop: Header=BB0_51 Depth=3
	.loc	2 177 37 is_stmt 1              # rnd_output1.c:177:37
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 268(a1)
	addi	a0, a0, 1
	sw	a0, 268(a1)
	.loc	2 177 17 is_stmt 0              # rnd_output1.c:177:17
	j	.LBB0_51
.Ltmp51:
.LBB0_54:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 179 28 is_stmt 1              # rnd_output1.c:179:28
	lui	a1, %hi(g_252)
	li	a0, 0
	sb	a0, %lo(g_252)(a1)
	.loc	2 179 22 is_stmt 0              # rnd_output1.c:179:22
	j	.LBB0_55
.LBB0_55:                               #   Parent Loop BB0_33 Depth=1
                                        #     Parent Loop BB0_49 Depth=2
                                        # =>    This Loop Header: Depth=3
                                        #         Child Loop BB0_78 Depth 4
.Ltmp52:
	.loc	2 179 34                        # rnd_output1.c:179:34
	lui	a0, %hi(g_252)
	lb	a0, %lo(g_252)(a0)
	li	a1, -13
.Ltmp53:
	.loc	2 179 17                        # rnd_output1.c:179:17
	blt	a0, a1, .LBB0_84
	j	.LBB0_56
.LBB0_56:                               #   in Loop: Header=BB0_55 Depth=3
.Ltmp54:
	.loc	2 181 30 is_stmt 1              # rnd_output1.c:181:30
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, %hi(g_588)
	addi	a1, a1, %lo(g_588)
	sw	a1, 264(a0)
	li	a1, 1
	.loc	2 182 35                        # rnd_output1.c:182:35
	sw	a1, 260(a0)
	sw	a1, 256(a0)
	li	a1, -1
	.loc	2 183 29                        # rnd_output1.c:183:29
	sw	a1, 252(a0)
	.loc	2 184 40                        # rnd_output1.c:184:40
	addi	a1, s0, -2048
	addi	a1, a1, -1552
	.loc	2 184 30 is_stmt 0              # rnd_output1.c:184:30
	sw	a1, 248(a0)
	addi	a1, s0, -24
	.loc	2 186 69 is_stmt 1              # rnd_output1.c:186:69
	seqz	a1, a1
	.loc	2 186 128 is_stmt 0             # rnd_output1.c:186:128
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1940(a2)                   # 4-byte Folded Spill
	lbu	a1, 1459(a0)
	.loc	2 186 119                       # rnd_output1.c:186:119
	seqz	a1, a1
	.loc	2 186 294                       # rnd_output1.c:186:294
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1936(a2)                   # 4-byte Folded Spill
	lh	a0, 256(a0)
	li	a1, 13
	.loc	2 186 265                       # rnd_output1.c:186:265
	call	safe_rshift_func_int16_t_s_u
	.loc	2 186 338                       # rnd_output1.c:186:338
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1932(a1)                   # 4-byte Folded Spill
	lui	a0, %hi(g_111)
	lh	a0, %lo(g_111)(a0)
	li	a1, 0
	.loc	2 186 344                       # rnd_output1.c:186:344
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1928(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_58
	j	.LBB0_57
.LBB0_57:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 344                         # rnd_output1.c:0:344
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 308819
	addi	a0, a0, 1333
	.loc	2 186 383                       # rnd_output1.c:186:383
	sw	a0, 336(a1)
	li	a1, -1
	.loc	2 186 348                       # rnd_output1.c:186:348
	call	safe_div_func_uint32_t_u_u
	.loc	2 186 344                       # rnd_output1.c:186:344
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1928(a1)                   # 4-byte Folded Spill
	j	.LBB0_58
.LBB0_58:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1928(a0)                   # 4-byte Folded Reload
	.loc	2 186 344                       # rnd_output1.c:186:344
	andi	a0, a0, 1
	.loc	2 186 409                       # rnd_output1.c:186:409
	lb	a1, 1446(a1)
	.loc	2 186 312                       # rnd_output1.c:186:312
	call	safe_sub_func_int8_t_s_s
	mv	a1, a0
	.loc	2 186 238                       # rnd_output1.c:186:238
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1932(a0)                   # 4-byte Folded Reload
	andi	a1, a1, 255
	andi	a0, a0, 255
	call	safe_mod_func_uint8_t_u_u
	li	a1, -6
	.loc	2 186 211                       # rnd_output1.c:186:211
	call	safe_mul_func_int32_t_s_s
	.loc	2 186 439                       # rnd_output1.c:186:439
	lw	a1, -32(s0)
	.loc	2 186 436                       # rnd_output1.c:186:436
	xor	a0, a0, a1
	snez	a0, a0
	lui	a1, 752699
	addi	a1, a1, 1899
	.loc	2 186 183                       # rnd_output1.c:186:183
	call	safe_mul_func_int32_t_s_s
                                        # kill: def $x11 killed $x10
	.loc	2 186 463                       # rnd_output1.c:186:463
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lb	a0, 1459(a0)
	li	a1, 0
	.loc	2 186 481                       # rnd_output1.c:186:481
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1944(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_60
	j	.LBB0_59
.LBB0_59:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 186 484                       # rnd_output1.c:186:484
	lw	a0, -32(s0)
	.loc	2 186 481                       # rnd_output1.c:186:481
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1944(a1)                   # 4-byte Folded Spill
	j	.LBB0_60
.LBB0_60:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1936(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a2, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1944(a0)                   # 4-byte Folded Reload
	.loc	2 186 481                       # rnd_output1.c:186:481
	andi	a0, a0, 1
	.loc	2 186 492                       # rnd_output1.c:186:492
	lw	a2, 1392(a2)
	.loc	2 186 490                       # rnd_output1.c:186:490
	sltu	a0, a0, a2
	.loc	2 186 137                       # rnd_output1.c:186:137
	xor	a0, a0, a1
	.loc	2 186 117                       # rnd_output1.c:186:117
	srai	a1, a1, 31
	.loc	2 186 502                       # rnd_output1.c:186:502
	lw	a2, -28(s0)
	.loc	2 186 87                        # rnd_output1.c:186:87
	call	safe_lshift_func_uint64_t_u_u
	mv	a3, a0
	.loc	2 186 512                       # rnd_output1.c:186:512
	lw	a2, -32(s0)
	srai	a0, a2, 31
	.loc	2 186 509                       # rnd_output1.c:186:509
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sltu	a3, a0, a1
	xori	a3, a3, 1
	lui	a4, 1
	sub	a4, s0, a4
	sw	a3, -1952(a4)                   # 4-byte Folded Spill
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1948(a3)                   # 4-byte Folded Spill
	beq	a1, a0, .LBB0_62
# %bb.61:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 509                         # rnd_output1.c:0:509
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1952(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1948(a1)                   # 4-byte Folded Spill
.LBB0_62:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 186 509                       # rnd_output1.c:186:509
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a2, -1940(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1948(a0)                   # 4-byte Folded Reload
	.loc	2 186 82                        # rnd_output1.c:186:82
	slt	a0, a0, a2
	xori	a2, a0, 1
	.loc	2 186 522                       # rnd_output1.c:186:522
	lui	a0, %hi(g_2070)
	lw	a0, %lo(g_2070)(a0)
	.loc	2 186 519                       # rnd_output1.c:186:519
	slt	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 186 41                        # rnd_output1.c:186:41
	sw	a0, 252(a1)
	.loc	2 186 23                        # rnd_output1.c:186:23
	lw	a1, 248(a1)
	.loc	2 186 31                        # rnd_output1.c:186:31
	sw	a0, 0(a1)
.Ltmp55:
	.loc	2 187 36 is_stmt 1              # rnd_output1.c:187:36
	lui	a1, %hi(g_2017)
	li	a0, 0
	sw	a0, %lo(g_2017)(a1)
	.loc	2 187 26 is_stmt 0              # rnd_output1.c:187:26
	j	.LBB0_63
.LBB0_63:                               #   in Loop: Header=BB0_55 Depth=3
.Ltmp56:
	.loc	2 187 49                        # rnd_output1.c:187:49
	lui	a0, %hi(g_2017)
	lw	a0, %lo(g_2017)(a0)
	li	a1, 22
.Ltmp57:
	.loc	2 187 21                        # rnd_output1.c:187:21
	bltu	a0, a1, .LBB0_69
	j	.LBB0_64
.LBB0_64:
	.loc	2 0 21                          # rnd_output1.c:0:21
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, 0
.Ltmp58:
	.loc	2 191 32 is_stmt 1              # rnd_output1.c:191:32
	sw	a0, 208(a1)
	.loc	2 191 30 is_stmt 0              # rnd_output1.c:191:30
	j	.LBB0_65
.LBB0_65:                               # =>This Inner Loop Header: Depth=1
.Ltmp59:
	.loc	2 191 37                        # rnd_output1.c:191:37
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 208(a0)
	li	a0, 7
.Ltmp60:
	.loc	2 191 25                        # rnd_output1.c:191:25
	blt	a0, a1, .LBB0_68
	j	.LBB0_66
.LBB0_66:                               #   in Loop: Header=BB0_65 Depth=1
.Ltmp61:
	.loc	2 192 36 is_stmt 1              # rnd_output1.c:192:36
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 208(a0)
	.loc	2 192 29 is_stmt 0              # rnd_output1.c:192:29
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 1632
	sub	a0, s0, a0
	add	a1, a1, a0
	li	a0, 0
	.loc	2 192 39                        # rnd_output1.c:192:39
	sw	a0, 0(a1)
	.loc	2 192 29                        # rnd_output1.c:192:29
	j	.LBB0_67
.LBB0_67:                               #   in Loop: Header=BB0_65 Depth=1
	.loc	2 191 45 is_stmt 1              # rnd_output1.c:191:45
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 208(a1)
	addi	a0, a0, 1
	sw	a0, 208(a1)
	.loc	2 191 25 is_stmt 0              # rnd_output1.c:191:25
	j	.LBB0_65
.Ltmp62:
.LBB0_68:
	.loc	2 193 38 is_stmt 1              # rnd_output1.c:193:38
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 336(a0)
	.loc	2 193 332 is_stmt 0             # rnd_output1.c:193:332
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1960(a1)                   # 4-byte Folded Spill
	lw	a1, -24(s0)
	.loc	2 193 329                       # rnd_output1.c:193:329
	lui	a0, %hi(g_117)
	addi	a0, a0, %lo(g_117)
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 193 339                       # rnd_output1.c:193:339
	lui	a1, %hi(g_2)
	addi	a1, a1, %lo(g_2)
	lw	a1, 20(a1)
	.loc	2 193 294                       # rnd_output1.c:193:294
	call	safe_mod_func_uint32_t_u_u
	mv	a1, a0
	.loc	2 193 413                       # rnd_output1.c:193:413
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1964(a2)                   # 4-byte Folded Spill
	lw	a1, 336(a0)
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1972(a2)                   # 4-byte Folded Spill
	srai	a1, a1, 31
	.loc	2 193 489                       # rnd_output1.c:193:489
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1968(a2)                   # 4-byte Folded Spill
	lhu	a1, 334(a0)
	.loc	2 193 540                       # rnd_output1.c:193:540
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1980(a2)                   # 4-byte Folded Spill
	lw	a0, 248(a0)
	.loc	2 193 539                       # rnd_output1.c:193:539
	lw	a0, 0(a0)
	.loc	2 193 536                       # rnd_output1.c:193:536
	andi	a0, a0, 1
	.loc	2 193 500                       # rnd_output1.c:193:500
	call	safe_unary_minus_func_uint8_t_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 193 496                       # rnd_output1.c:193:496
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1980(a0)                   # 4-byte Folded Reload
	slt	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 193 568                       # rnd_output1.c:193:568
	lui	a2, %hi(g_1818)
	addi	a2, a2, %lo(g_1818)
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -1956(a3)                   # 4-byte Folded Spill
	lw	a2, 32(a2)
	.loc	2 193 552                       # rnd_output1.c:193:552
	sltu	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 193 575                       # rnd_output1.c:193:575
	lw	a1, 1392(a1)
	.loc	2 193 572                       # rnd_output1.c:193:572
	xor	a0, a0, a1
	snez	a0, a0
	.loc	2 193 584                       # rnd_output1.c:193:584
	lw	a2, -32(s0)
	li	a1, 0
	.loc	2 193 456                       # rnd_output1.c:193:456
	lui	a3, 1
	sub	a3, s0, a3
	sw	a1, -1976(a3)                   # 4-byte Folded Spill
	call	safe_rshift_func_uint64_t_u_u
	lui	a2, 1
	sub	a2, s0, a2
	lw	a3, -1976(a2)                   # 4-byte Folded Reload
	lui	a2, 1
	sub	a2, s0, a2
	lw	a4, -1856(a2)                   # 4-byte Folded Reload
	mv	a2, a0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1972(a0)                   # 4-byte Folded Reload
	mv	a5, a1
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1968(a1)                   # 4-byte Folded Reload
	lui	a6, 937405
	addi	a6, a6, -1696
	.loc	2 193 591                       # rnd_output1.c:193:591
	xor	a5, a5, a6
	lui	a6, 851612
	addi	a6, a6, 1017
	xor	a2, a2, a6
	or	a2, a2, a5
	snez	a2, a2
	.loc	2 193 452                       # rnd_output1.c:193:452
	addi	a2, a2, 252
	.loc	2 193 428                       # rnd_output1.c:193:428
	lw	a4, 264(a4)
	.loc	2 193 436                       # rnd_output1.c:193:436
	sb	a2, 0(a4)
	.loc	2 193 620                       # rnd_output1.c:193:620
	lw	a4, -32(s0)
	.loc	2 193 618                       # rnd_output1.c:193:618
	or	a4, a4, a2
	lui	a2, 15
	addi	a2, a2, 341
	.loc	2 193 626                       # rnd_output1.c:193:626
	slt	a2, a2, a4
	.loc	2 193 386                       # rnd_output1.c:193:386
	call	safe_add_func_uint64_t_u_u
	li	a1, 27
	.loc	2 193 356                       # rnd_output1.c:193:356
	call	safe_rshift_func_int32_t_s_s
	mv	a1, a0
	.loc	2 193 267                       # rnd_output1.c:193:267
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1964(a0)                   # 4-byte Folded Reload
	slli	a1, a1, 16
	srai	a1, a1, 16
	slli	a0, a0, 16
	srai	a0, a0, 16
	call	safe_mul_func_int16_t_s_s
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	.loc	2 193 256                       # rnd_output1.c:193:256
	lw	a1, 1808(a1)
	.loc	2 193 255                       # rnd_output1.c:193:255
	lw	a1, 0(a1)
	.loc	2 193 264                       # rnd_output1.c:193:264
	sh	a0, 0(a1)
	.loc	2 193 239                       # rnd_output1.c:193:239
	slli	a0, a0, 16
	srli	a0, a0, 16
	.loc	2 193 651                       # rnd_output1.c:193:651
	slti	a0, a0, 458
	li	a1, 247
	.loc	2 193 212                       # rnd_output1.c:193:212
	call	safe_add_func_uint8_t_u_u
	.loc	2 193 684                       # rnd_output1.c:193:684
	lui	a0, %hi(g_1373)
	lw	a0, %lo(g_1373)(a0)
	.loc	2 193 683                       # rnd_output1.c:193:683
	lw	a0, 0(a0)
	.loc	2 193 682                       # rnd_output1.c:193:682
	lhu	a0, 0(a0)
	li	a1, 10
	.loc	2 193 179                       # rnd_output1.c:193:179
	call	safe_rshift_func_uint16_t_u_s
	lui	a1, 1
	sub	a1, s0, a1
	lw	a2, -1856(a1)                   # 4-byte Folded Reload
	.loc	2 193 703                       # rnd_output1.c:193:703
	lw	a1, -24(s0)
	.loc	2 193 702                       # rnd_output1.c:193:702
	lw	a1, 0(a1)
	.loc	2 193 699                       # rnd_output1.c:193:699
	xor	a0, a0, a1
	.loc	2 193 177                       # rnd_output1.c:193:177
	srai	a1, a1, 31
	.loc	2 193 713                       # rnd_output1.c:193:713
	lw	a2, 248(a2)
	.loc	2 193 712                       # rnd_output1.c:193:712
	lw	a2, 0(a2)
	srai	a3, a2, 31
	.loc	2 193 151                       # rnd_output1.c:193:151
	call	safe_mod_func_int64_t_s_s
	mv	a2, a0
                                        # kill: def $x10 killed $x11
	.loc	2 193 147                       # rnd_output1.c:193:147
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1792(a1)
	xor	a0, a0, a2
	sw	a0, 1792(a1)
	.loc	2 193 728                       # rnd_output1.c:193:728
	lw	a1, 248(a1)
	.loc	2 193 727                       # rnd_output1.c:193:727
	lw	a1, 0(a1)
	.loc	2 193 724                       # rnd_output1.c:193:724
	xor	a0, a0, a1
	.loc	2 193 737                       # rnd_output1.c:193:737
	sltiu	a0, a0, -1
	.loc	2 193 766                       # rnd_output1.c:193:766
	lui	a1, %hi(g_111)
	lh	a1, %lo(g_111)(a1)
	.loc	2 193 763                       # rnd_output1.c:193:763
	xor	a0, a0, a1
	seqz	a0, a0
	li	a1, 18
	.loc	2 193 106                       # rnd_output1.c:193:106
	call	safe_lshift_func_uint32_t_u_s
	.loc	2 193 789                       # rnd_output1.c:193:789
	lui	a1, %hi(g_69)
	addi	a1, a1, %lo(g_69)
	lbu	a1, 32(a1)
	.loc	2 193 106                       # rnd_output1.c:193:106
	and	a0, a0, a1
	.loc	2 193 794                       # rnd_output1.c:193:794
	lui	a1, %hi(g_2070)
	lbu	a1, %lo(g_2070)(a1)
	.loc	2 193 78                        # rnd_output1.c:193:78
	call	safe_add_func_uint8_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	.loc	2 193 804                       # rnd_output1.c:193:804
	lb	a1, 1459(a1)
	.loc	2 193 48                        # rnd_output1.c:193:48
	call	safe_rshift_func_int32_t_s_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1960(a1)                   # 4-byte Folded Reload
	lui	a2, 1
	sub	a2, s0, a2
	lw	a2, -1856(a2)                   # 4-byte Folded Reload
	mv	a3, a0
	.loc	2 193 45                        # rnd_output1.c:193:45
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1956(a0)                   # 4-byte Folded Reload
	xor	a1, a1, a3
	.loc	2 193 27                        # rnd_output1.c:193:27
	lw	a2, 248(a2)
	.loc	2 193 35                        # rnd_output1.c:193:35
	sw	a1, 0(a2)
	.loc	2 194 32 is_stmt 1              # rnd_output1.c:194:32
	lw	a0, 32(a0)
	sw	a0, -20(s0)
	.loc	2 194 25 is_stmt 0              # rnd_output1.c:194:25
	j	.LBB0_107
.Ltmp63:
.LBB0_69:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 196 45 is_stmt 1              # rnd_output1.c:196:45
	lw	a0, -28(s0)
	li	a1, 0
	.loc	2 196 50 is_stmt 0              # rnd_output1.c:196:50
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1984(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_71
	j	.LBB0_70
.LBB0_70:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 196 94                        # rnd_output1.c:196:94
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a4, 328(a1)
	lw	a5, 324(a1)
	.loc	2 196 83                        # rnd_output1.c:196:83
	lw	a2, 1452(a1)
	.loc	2 196 91                        # rnd_output1.c:196:91
	lw	a3, 4(a2)
	lw	a0, 0(a2)
	xor	a0, a0, a5
	lui	a5, 1
	sub	a5, s0, a5
	sw	a0, -1992(a5)                   # 4-byte Folded Spill
	xor	a3, a3, a4
	lui	a4, 1
	sub	a4, s0, a4
	sw	a3, -1988(a4)                   # 4-byte Folded Spill
	sw	a3, 4(a2)
	sw	a0, 0(a2)
	.loc	2 196 157                       # rnd_output1.c:196:157
	lw	a0, 336(a1)
	lui	a2, 1
	sub	a2, s0, a2
	sw	a0, -2008(a2)                   # 4-byte Folded Spill
	srai	a0, a0, 31
	.loc	2 196 196                       # rnd_output1.c:196:196
	lui	a2, 1
	sub	a2, s0, a2
	sw	a0, -2012(a2)                   # 4-byte Folded Spill
	lw	a0, 248(a1)
	.loc	2 196 195                       # rnd_output1.c:196:195
	lw	a0, 0(a0)
	.loc	2 196 207                       # rnd_output1.c:196:207
	lw	a1, 340(a1)
	.loc	2 196 204                       # rnd_output1.c:196:204
	xor	a0, a0, a1
	snez	a0, a0
	lui	a1, 16
	addi	a1, a1, -2
	.loc	2 196 166                       # rnd_output1.c:196:166
	call	safe_add_func_uint16_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2012(a1)                   # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 196 131                       # rnd_output1.c:196:131
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -2008(a0)                   # 4-byte Folded Reload
	li	a3, 0
	lui	a4, 1
	sub	a4, s0, a4
	sw	a3, -2004(a4)                   # 4-byte Folded Spill
	call	safe_div_func_int64_t_s_s
	mv	a2, a0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -2000(a3)                   # 4-byte Folded Spill
	.loc	2 196 232                       # rnd_output1.c:196:232
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -1996(a2)                   # 4-byte Folded Spill
	lui	a1, %hi(g_2079)
	lw	a1, %lo(g_2079)(a1)
	.loc	2 196 242                       # rnd_output1.c:196:242
	lw	a2, 960(a0)
	sw	a2, 12(a1)
	lw	a2, 956(a0)
	sw	a2, 8(a1)
	lw	a2, 952(a0)
	sw	a2, 4(a1)
	lw	a0, 948(a0)
	sw	a0, 0(a1)
	.loc	2 196 346                       # rnd_output1.c:196:346
	lbu	a1, -28(s0)
	li	a0, 8
	.loc	2 196 315                       # rnd_output1.c:196:315
	call	safe_sub_func_uint8_t_u_u
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	.loc	2 196 355                       # rnd_output1.c:196:355
	lb	a0, 336(a1)
	.loc	2 196 366                       # rnd_output1.c:196:366
	lw	a1, 248(a1)
	.loc	2 196 365                       # rnd_output1.c:196:365
	lb	a1, 0(a1)
	.loc	2 196 288                       # rnd_output1.c:196:288
	call	safe_div_func_int8_t_s_s
	lui	a1, 1
	sub	a1, s0, a1
	lw	a3, -2004(a1)                   # 4-byte Folded Reload
	.loc	2 196 287                       # rnd_output1.c:196:287
	srai	a1, a0, 31
	.loc	2 196 377                       # rnd_output1.c:196:377
	lw	a2, -28(s0)
	.loc	2 196 260                       # rnd_output1.c:196:260
	call	safe_div_func_uint64_t_u_u
	lui	a2, 1
	sub	a2, s0, a2
	lw	a4, -1856(a2)                   # 4-byte Folded Reload
	lui	a2, 1
	sub	a2, s0, a2
	lw	a3, -2004(a2)                   # 4-byte Folded Reload
	mv	a6, a0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -2000(a0)                   # 4-byte Folded Reload
	mv	a5, a1
	.loc	2 196 386                       # rnd_output1.c:196:386
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1996(a1)                   # 4-byte Folded Reload
	lhu	a2, 1446(a4)
	.loc	2 196 384                       # rnd_output1.c:196:384
	sltu	a2, a2, a6
	snez	a5, a5
	or	a2, a2, a5
	.loc	2 196 413                       # rnd_output1.c:196:413
	lw	a4, 952(a4)
	.loc	2 196 395                       # rnd_output1.c:196:395
	and	a2, a2, a4
	.loc	2 196 104                       # rnd_output1.c:196:104
	call	safe_sub_func_int64_t_s_s
	mv	a2, a0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1992(a0)                   # 4-byte Folded Reload
	mv	a3, a1
	.loc	2 196 54                        # rnd_output1.c:196:54
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1988(a1)                   # 4-byte Folded Reload
	call	safe_sub_func_int64_t_s_s
	.loc	2 196 50                        # rnd_output1.c:196:50
	or	a0, a0, a1
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -1984(a1)                   # 4-byte Folded Spill
	j	.LBB0_71
.LBB0_71:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1984(a1)                   # 4-byte Folded Reload
	.loc	2 196 434                       # rnd_output1.c:196:434
	lhu	a0, 334(a0)
	.loc	2 196 447                       # rnd_output1.c:196:447
	lui	a1, %hi(g_2198)
	lw	a1, %lo(g_2198)(a1)
	.loc	2 196 446                       # rnd_output1.c:196:446
	lw	a1, 0(a1)
	.loc	2 196 445                       # rnd_output1.c:196:445
	lw	a1, 0(a1)
.Ltmp64:
	.loc	2 196 25                        # rnd_output1.c:196:25
	beq	a0, a1, .LBB0_77
	j	.LBB0_72
.LBB0_72:                               #   in Loop: Header=BB0_55 Depth=3
.Ltmp65:
	.loc	2 198 41 is_stmt 1              # rnd_output1.c:198:41
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, %hi(g_97)
	addi	a0, a0, %lo(g_97)
	sw	a0, 204(a1)
	.loc	2 199 64                        # rnd_output1.c:199:64
	addi	a0, s0, -2048
	addi	a0, a0, -1548
	.loc	2 199 35 is_stmt 0              # rnd_output1.c:199:35
	sw	a0, 200(a1)
	.loc	2 200 39 is_stmt 1              # rnd_output1.c:200:39
	lui	a0, %hi(.L__const.func_36.l_2391)
	addi	a1, a0, %lo(.L__const.func_36.l_2391)
	lui	a0, 1
	addi	a0, a0, 1772
	sub	a0, s0, a0
	li	a2, 128
	call	memcpy@plt
                                        # kill: def $x11 killed $x10
.Ltmp66:
	.loc	2 203 29                        # rnd_output1.c:203:29
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1392(a0)
.Ltmp67:
	.loc	2 203 29 is_stmt 0              # rnd_output1.c:203:29
	beqz	a0, .LBB0_74
	j	.LBB0_73
.LBB0_73:                               #   in Loop: Header=BB0_49 Depth=2
.Ltmp68:
	.loc	2 204 29 is_stmt 1              # rnd_output1.c:204:29
	j	.LBB0_84
.Ltmp69:
.LBB0_74:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 205 27                        # rnd_output1.c:205:27
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a2, 204(a0)
	lui	a1, 1
	addi	a1, a1, 1588
	sub	a1, s0, a1
	.loc	2 205 35 is_stmt 0              # rnd_output1.c:205:35
	sw	a1, 0(a2)
	li	a1, 1
	.loc	2 206 132 is_stmt 1             # rnd_output1.c:206:132
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2020(a2)                   # 4-byte Folded Spill
	lw	a0, 248(a0)
	.loc	2 206 131 is_stmt 0             # rnd_output1.c:206:131
	lw	a2, 0(a0)
	srai	a1, a2, 31
	.loc	2 206 100                       # rnd_output1.c:206:100
	mv	a0, a2
	call	safe_rshift_func_uint64_t_u_s
	mv	a2, a0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -2032(a3)                   # 4-byte Folded Spill
	mv	a2, a1
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2032(a1)                   # 4-byte Folded Reload
	lui	a3, 1
	sub	a3, s0, a3
	sw	a2, -2028(a3)                   # 4-byte Folded Spill
	.loc	2 206 158                       # rnd_output1.c:206:158
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2024(a2)                   # 4-byte Folded Spill
	lw	a1, -32(s0)
	.loc	2 206 173                       # rnd_output1.c:206:173
	lui	a1, %hi(g_1970)
	lw	a2, %lo(g_1970)(a1)
	li	a1, 0
	.loc	2 206 181                       # rnd_output1.c:206:181
	sw	a1, 0(a2)
	.loc	2 206 196                       # rnd_output1.c:206:196
	lw	a0, 1432(a0)
	.loc	2 206 193                       # rnd_output1.c:206:193
	snez	a0, a0
	.loc	2 206 209                       # rnd_output1.c:206:209
	lui	a0, %hi(g_1374)
	lw	a0, %lo(g_1374)(a0)
	.loc	2 206 208                       # rnd_output1.c:206:208
	lhu	a0, 0(a0)
	.loc	2 206 254                       # rnd_output1.c:206:254
	lui	a0, %hi(g_1812)
	lbu	a0, %lo(g_1812)(a0)
	.loc	2 206 221                       # rnd_output1.c:206:221
	call	safe_mul_func_uint8_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2020(a1)                   # 4-byte Folded Reload
	.loc	2 206 263                       # rnd_output1.c:206:263
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2016(a2)                   # 4-byte Folded Spill
	bnez	a0, .LBB0_76
	j	.LBB0_75
.LBB0_75:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 206 273                       # rnd_output1.c:206:273
	lui	a0, %hi(g_2017)
	lw	a0, %lo(g_2017)(a0)
	.loc	2 206 263                       # rnd_output1.c:206:263
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -2016(a1)                   # 4-byte Folded Spill
	j	.LBB0_76
.LBB0_76:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 263                         # rnd_output1.c:0:263
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -2020(a0)                   # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2024(a1)                   # 4-byte Folded Reload
	lui	a2, 1
	sub	a2, s0, a2
	lw	a2, -2028(a2)                   # 4-byte Folded Reload
	lui	a3, 1
	sub	a3, s0, a3
	lw	a3, -2016(a3)                   # 4-byte Folded Reload
	.loc	2 206 153                       # rnd_output1.c:206:153
	or	a1, a1, a2
	seqz	a1, a1
	.loc	2 206 95                        # rnd_output1.c:206:95
	xor	a0, a0, a1
	snez	a0, a0
	.loc	2 206 315                       # rnd_output1.c:206:315
	lw	a2, -32(s0)
	srai	a3, a2, 31
	li	a1, 0
	.loc	2 206 52                        # rnd_output1.c:206:52
	call	safe_sub_func_uint64_t_u_u
	mv	a2, a1
	.loc	2 206 322                       # rnd_output1.c:206:322
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	not	a2, a2
	xori	a0, a0, -10
	or	a0, a0, a2
	snez	a0, a0
	.loc	2 206 339                       # rnd_output1.c:206:339
	lw	a2, 204(a1)
	.loc	2 206 338                       # rnd_output1.c:206:338
	lw	a2, 0(a2)
	.loc	2 206 337                       # rnd_output1.c:206:337
	lw	a2, 0(a2)
	.loc	2 206 333                       # rnd_output1.c:206:333
	slt	a0, a0, a2
	xori	a0, a0, 1
	.loc	2 206 350                       # rnd_output1.c:206:350
	lw	a2, -28(s0)
	.loc	2 206 348                       # rnd_output1.c:206:348
	or	a0, a0, a2
	.loc	2 206 358                       # rnd_output1.c:206:358
	lw	a2, -32(s0)
	.loc	2 206 356                       # rnd_output1.c:206:356
	and	a2, a2, a0
	.loc	2 206 44                        # rnd_output1.c:206:44
	lw	a0, 948(a1)
	or	a0, a0, a2
	sw	a0, 948(a1)
	.loc	2 207 21 is_stmt 1              # rnd_output1.c:207:21
	j	.LBB0_82
.Ltmp70:
.LBB0_77:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 0 21 is_stmt 0                # rnd_output1.c:0:21
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	li	a0, 0
.Ltmp71:
	.loc	2 211 37 is_stmt 1              # rnd_output1.c:211:37
	sw	a0, 44(a1)
	.loc	2 212 36                        # rnd_output1.c:212:36
	lui	a2, %hi(g_1247)
	addi	a2, a2, %lo(g_1247)
	sw	a2, 40(a1)
	lui	a2, 1
	addi	a2, a2, 1804
	sub	a2, s0, a2
	.loc	2 213 37                        # rnd_output1.c:213:37
	sw	a2, 36(a1)
.Ltmp72:
	.loc	2 215 32                        # rnd_output1.c:215:32
	sw	a0, 32(a1)
	.loc	2 215 30 is_stmt 0              # rnd_output1.c:215:30
	j	.LBB0_78
.LBB0_78:                               #   Parent Loop BB0_33 Depth=1
                                        #     Parent Loop BB0_49 Depth=2
                                        #       Parent Loop BB0_55 Depth=3
                                        # =>      This Inner Loop Header: Depth=4
.Ltmp73:
	.loc	2 215 37                        # rnd_output1.c:215:37
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 32(a0)
	li	a0, 2
.Ltmp74:
	.loc	2 215 25                        # rnd_output1.c:215:25
	blt	a0, a1, .LBB0_81
	j	.LBB0_79
.LBB0_79:                               #   in Loop: Header=BB0_78 Depth=4
.Ltmp75:
	.loc	2 216 36 is_stmt 1              # rnd_output1.c:216:36
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 32(a0)
	.loc	2 216 29 is_stmt 0              # rnd_output1.c:216:29
	slli	a1, a0, 2
	lui	a0, 1
	addi	a0, a0, 1796
	sub	a0, s0, a0
	add	a1, a1, a0
	li	a0, -1
	.loc	2 216 39                        # rnd_output1.c:216:39
	sw	a0, 0(a1)
	.loc	2 216 29                        # rnd_output1.c:216:29
	j	.LBB0_80
.LBB0_80:                               #   in Loop: Header=BB0_78 Depth=4
	.loc	2 215 45 is_stmt 1              # rnd_output1.c:215:45
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 32(a1)
	addi	a0, a0, 1
	sw	a0, 32(a1)
	.loc	2 215 25 is_stmt 0              # rnd_output1.c:215:25
	j	.LBB0_78
.Ltmp76:
.LBB0_81:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 217 27 is_stmt 1              # rnd_output1.c:217:27
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a2, 1796(a1)
	.loc	2 217 50 is_stmt 0              # rnd_output1.c:217:50
	lw	a0, 960(a1)
	sw	a0, 12(a2)
	lw	a0, 956(a1)
	sw	a0, 8(a2)
	lw	a0, 952(a1)
	sw	a0, 4(a2)
	lw	a0, 948(a1)
	sw	a0, 0(a2)
	.loc	2 218 37 is_stmt 1              # rnd_output1.c:218:37
	lw	a0, 48(a1)
	.loc	2 218 27 is_stmt 0              # rnd_output1.c:218:27
	lw	a2, 248(a1)
	.loc	2 218 35                        # rnd_output1.c:218:35
	sw	a0, 0(a2)
	.loc	2 219 68 is_stmt 1              # rnd_output1.c:219:68
	lw	a0, 416(a1)
	.loc	2 219 90 is_stmt 0              # rnd_output1.c:219:90
	lw	a2, 36(a1)
	.loc	2 219 98                        # rnd_output1.c:219:98
	lui	a1, %hi(g_1247)
	addi	a1, a1, %lo(g_1247)
	sw	a1, 0(a2)
	.loc	2 219 84                        # rnd_output1.c:219:84
	xor	a0, a0, a1
	snez	a0, a0
	li	a1, 1
	.loc	2 219 39                        # rnd_output1.c:219:39
	call	safe_lshift_func_int8_t_s_s
	mv	a2, a0
	.loc	2 219 27                        # rnd_output1.c:219:27
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 248(a0)
	.loc	2 219 35                        # rnd_output1.c:219:35
	lw	a0, 0(a1)
	and	a0, a0, a2
	sw	a0, 0(a1)
	j	.LBB0_82
.Ltmp77:
.LBB0_82:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 221 23 is_stmt 1              # rnd_output1.c:221:23
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a1, 1796(a0)
	.loc	2 221 35 is_stmt 0              # rnd_output1.c:221:35
	lui	a0, %hi(g_557)
	lw	a0, %lo(g_557)(a0)
	.loc	2 221 34                        # rnd_output1.c:221:34
	lw	a2, 12(a0)
	sw	a2, 12(a1)
	lw	a2, 8(a0)
	sw	a2, 8(a1)
	lw	a2, 4(a0)
	sw	a2, 4(a1)
	lw	a0, 0(a0)
	sw	a0, 0(a1)
	.loc	2 222 17 is_stmt 1              # rnd_output1.c:222:17
	j	.LBB0_83
.Ltmp78:
.LBB0_83:                               #   in Loop: Header=BB0_55 Depth=3
	.loc	2 179 84                        # rnd_output1.c:179:84
	lui	a0, %hi(g_252)
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -2036(a1)                   # 4-byte Folded Spill
	lb	a0, %lo(g_252)(a0)
	srai	a1, a0, 31
	li	a2, 9
	li	a3, 0
	.loc	2 179 58 is_stmt 0              # rnd_output1.c:179:58
	call	safe_sub_func_int64_t_s_s
                                        # kill: def $x12 killed $x11
	.loc	2 179 56                        # rnd_output1.c:179:56
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2036(a1)                   # 4-byte Folded Reload
	sb	a0, %lo(g_252)(a1)
	.loc	2 179 17                        # rnd_output1.c:179:17
	j	.LBB0_55
.Ltmp79:
.LBB0_84:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 17                          # rnd_output1.c:0:17
	lui	a0, 1
	addi	a0, a0, 1504
	sub	a1, s0, a0
	addi	a0, s0, -28
	.loc	2 223 82 is_stmt 1              # rnd_output1.c:223:82
	xor	a0, a0, a1
	snez	a1, a0
	.loc	2 223 100 is_stmt 0             # rnd_output1.c:223:100
	lui	a0, %hi(g_2014)
	lw	a0, %lo(g_2014)(a0)
	.loc	2 223 99                        # rnd_output1.c:223:99
	lw	a0, 0(a0)
	.loc	2 223 98                        # rnd_output1.c:223:98
	lb	a0, 0(a0)
	.loc	2 223 95                        # rnd_output1.c:223:95
	slt	a0, a0, a1
	.loc	2 223 116                       # rnd_output1.c:223:116
	lui	a1, %hi(g_556)
	lw	a1, %lo(g_556+4)(a1)
	.loc	2 223 31                        # rnd_output1.c:223:31
	call	safe_rshift_func_uint32_t_u_u
	.loc	2 223 138                       # rnd_output1.c:223:138
	lui	a0, %hi(g_1970)
	lw	a0, %lo(g_1970)(a0)
	.loc	2 223 137                       # rnd_output1.c:223:137
	lw	a0, 0(a0)
	li	a1, 0
	.loc	2 223 147                       # rnd_output1.c:223:147
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2040(a2)                   # 4-byte Folded Spill
	bnez	a0, .LBB0_86
	j	.LBB0_85
.LBB0_85:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 223 150                       # rnd_output1.c:223:150
	lw	a0, -28(s0)
	.loc	2 223 147                       # rnd_output1.c:223:147
	snez	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -2040(a1)                   # 4-byte Folded Spill
	j	.LBB0_86
.LBB0_86:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -2040(a0)                   # 4-byte Folded Reload
	.loc	2 223 147                       # rnd_output1.c:223:147
	andi	a2, a0, 1
	.loc	2 223 24                        # rnd_output1.c:223:24
	lw	a0, 1420(a1)
	or	a0, a0, a2
	sw	a0, 1420(a1)
	.loc	2 224 83 is_stmt 1              # rnd_output1.c:224:83
	lui	a0, %hi(g_2)
	addi	a0, a0, %lo(g_2)
	lw	a0, 20(a0)
	li	a1, 1
	.loc	2 224 96 is_stmt 0              # rnd_output1.c:224:96
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2044(a2)                   # 4-byte Folded Spill
	bnez	a0, .LBB0_88
	j	.LBB0_87
.LBB0_87:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 96                          # rnd_output1.c:0:96
	li	a0, 0
	.loc	2 224 96                        # rnd_output1.c:224:96
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -2044(a1)                   # 4-byte Folded Spill
	j	.LBB0_88
.LBB0_88:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 96                          # rnd_output1.c:0:96
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -2044(a0)                   # 4-byte Folded Reload
	.loc	2 224 96                        # rnd_output1.c:224:96
	andi	a0, a0, 1
	.loc	2 224 105                       # rnd_output1.c:224:105
	lui	a1, %hi(g_252)
	lb	a1, %lo(g_252)(a1)
	.loc	2 224 54                        # rnd_output1.c:224:54
	call	safe_rshift_func_int8_t_s_u
	mv	a1, a0
	.loc	2 224 53                        # rnd_output1.c:224:53
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	.loc	2 224 122                       # rnd_output1.c:224:122
	lui	a2, 2
	sub	a2, s0, a2
	sw	a1, 2040(a2)                    # 4-byte Folded Spill
	lw	a1, -24(s0)
	.loc	2 224 121                       # rnd_output1.c:224:121
	lw	a1, 0(a1)
	.loc	2 224 229                       # rnd_output1.c:224:229
	lw	a1, -32(s0)
	.loc	2 224 228                       # rnd_output1.c:224:228
	not	a1, a1
	.loc	2 224 253                       # rnd_output1.c:224:253
	lui	a2, 2
	sub	a2, s0, a2
	sw	a1, 2044(a2)                    # 4-byte Folded Spill
	lw	a0, 948(a0)
	li	a1, 0
	.loc	2 224 256                       # rnd_output1.c:224:256
	lui	a2, 1
	sub	a2, s0, a2
	sw	a1, -2048(a2)                   # 4-byte Folded Spill
	beqz	a0, .LBB0_90
	j	.LBB0_89
.LBB0_89:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 224 272                       # rnd_output1.c:224:272
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1416(a0)
	.loc	2 224 269                       # rnd_output1.c:224:269
	seqz	a0, a0
	lui	a1, 1
	sub	a1, s0, a1
	sw	a0, -2048(a1)                   # 4-byte Folded Spill
	j	.LBB0_90
.LBB0_90:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2044(a0)                    # 4-byte Folded Reload
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -2048(a1)                   # 4-byte Folded Reload
	.loc	2 224 256                       # rnd_output1.c:224:256
	andi	a1, a1, 1
	.loc	2 224 198                       # rnd_output1.c:224:198
	slli	a0, a0, 16
	srai	a0, a0, 16
	call	safe_lshift_func_int16_t_s_s
	mv	a2, a0
	.loc	2 224 197                       # rnd_output1.c:224:197
	srai	a3, a2, 31
	li	a0, -9
	li	a1, -1
	.loc	2 224 146                       # rnd_output1.c:224:146
	call	safe_add_func_uint64_t_u_u
                                        # kill: def $x12 killed $x11
	.loc	2 224 135                       # rnd_output1.c:224:135
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	lw	a1, 1448(a1)
	.loc	2 224 143                       # rnd_output1.c:224:143
	sb	a0, 0(a1)
	li	a0, 1
	mv	a1, a0
	.loc	2 224 316                       # rnd_output1.c:224:316
	lui	a2, 2
	sub	a2, s0, a2
	sw	a1, 2036(a2)                    # 4-byte Folded Spill
	bnez	a0, .LBB0_92
	j	.LBB0_91
.LBB0_91:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 316                         # rnd_output1.c:0:316
	li	a0, 1
	.loc	2 224 316                       # rnd_output1.c:224:316
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2036(a1)                    # 4-byte Folded Spill
	j	.LBB0_92
.LBB0_92:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 316                         # rnd_output1.c:0:316
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2040(a0)                    # 4-byte Folded Reload
	lui	a1, 2
	sub	a1, s0, a1
	lw	a1, 2036(a1)                    # 4-byte Folded Reload
	.loc	2 224 316                       # rnd_output1.c:224:316
	andi	a1, a1, 1
	li	a2, 0
	.loc	2 224 327                       # rnd_output1.c:224:327
	lui	a3, 2
	sub	a3, s0, a3
	sw	a2, 2032(a3)                    # 4-byte Folded Spill
	bne	a0, a1, .LBB0_94
	j	.LBB0_93
.LBB0_93:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 224 330                       # rnd_output1.c:224:330
	lw	a0, -32(s0)
	.loc	2 224 327                       # rnd_output1.c:224:327
	snez	a0, a0
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2032(a1)                    # 4-byte Folded Spill
	j	.LBB0_94
.LBB0_94:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2032(a0)                    # 4-byte Folded Reload
	.loc	2 224 338                       # rnd_output1.c:224:338
	lw	a3, -32(s0)
	srai	a0, a3, 31
	lui	a1, 568966
	addi	a1, a1, -707
	.loc	2 224 48                        # rnd_output1.c:224:48
	sltu	a2, a1, a0
	lui	a4, 2
	sub	a4, s0, a4
	sw	a2, 2024(a4)                    # 4-byte Folded Spill
	lui	a2, 661771
	addi	a2, a2, 87
	sltu	a2, a2, a3
	lui	a3, 2
	sub	a3, s0, a3
	sw	a2, 2028(a3)                    # 4-byte Folded Spill
	beq	a0, a1, .LBB0_96
# %bb.95:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 0 48                          # rnd_output1.c:0:48
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2024(a0)                    # 4-byte Folded Reload
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2028(a1)                    # 4-byte Folded Spill
.LBB0_96:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 224 48                        # rnd_output1.c:224:48
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2028(a0)                    # 4-byte Folded Reload
	.loc	2 224 24                        # rnd_output1.c:224:24
	sw	a0, 1420(a1)
	.loc	2 225 13 is_stmt 1              # rnd_output1.c:225:13
	j	.LBB0_97
.Ltmp80:
.LBB0_97:                               #   in Loop: Header=BB0_49 Depth=2
	.loc	2 164 46                        # rnd_output1.c:164:46
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1772(a1)
	addi	a0, a0, 1
	sw	a0, 1772(a1)
	.loc	2 164 13 is_stmt 0              # rnd_output1.c:164:13
	j	.LBB0_49
.Ltmp81:
.LBB0_98:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 226 9 is_stmt 1               # rnd_output1.c:226:9
	j	.LBB0_102
.Ltmp82:
.LBB0_99:                               #   in Loop: Header=BB0_33 Depth=1
	.loc	2 229 31                        # rnd_output1.c:229:31
	lui	a0, 1
	sub	a0, s0, a0
	lw	a2, -1856(a0)                   # 4-byte Folded Reload
	addi	a0, s0, -106
	.loc	2 229 21 is_stmt 0              # rnd_output1.c:229:21
	sw	a0, 28(a2)
	li	a0, 0
	.loc	2 230 22 is_stmt 1              # rnd_output1.c:230:22
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2016(a1)                    # 4-byte Folded Spill
	sw	a0, 24(a2)
	lui	a1, 1
	addi	a1, a1, 40
	sub	a1, s0, a1
	.loc	2 231 22                        # rnd_output1.c:231:22
	sw	a1, 20(a2)
	.loc	2 232 22                        # rnd_output1.c:232:22
	sw	a0, 16(a2)
	sw	a0, 12(a2)
	lui	a1, 2250
	addi	a1, a1, 845
	sw	a1, 8(a2)
	li	a1, -8
	sw	a1, 4(a2)
	.loc	2 233 21                        # rnd_output1.c:233:21
	sw	a0, 0(a2)
	li	a0, 1
	.loc	2 235 250                       # rnd_output1.c:235:250
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2012(a1)                    # 4-byte Folded Spill
	lw	a0, 28(a2)
	.loc	2 235 274 is_stmt 0             # rnd_output1.c:235:274
	addi	a1, s0, -87
	.loc	2 235 263                       # rnd_output1.c:235:263
	lw	a2, 20(a2)
	.loc	2 235 271                       # rnd_output1.c:235:271
	sw	a1, 0(a2)
	.loc	2 235 257                       # rnd_output1.c:235:257
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 235 299                       # rnd_output1.c:235:299
	lui	a1, %hi(g_765)
	lw	a1, %lo(g_765)(a1)
	.loc	2 235 220                       # rnd_output1.c:235:220
	call	safe_rshift_func_int16_t_s_s
	lui	a1, 2
	sub	a1, s0, a1
	lw	a1, 2016(a1)                    # 4-byte Folded Reload
	.loc	2 235 304                       # rnd_output1.c:235:304
	lui	a2, 2
	sub	a2, s0, a2
	sw	a1, 2020(a2)                    # 4-byte Folded Spill
	beqz	a0, .LBB0_101
	j	.LBB0_100
.LBB0_100:                              #   in Loop: Header=BB0_33 Depth=1
	.loc	2 235 312                       # rnd_output1.c:235:312
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a2, 1812(a0)
	.loc	2 235 308                       # rnd_output1.c:235:308
	lh	a0, 0(a2)
	addi	a1, a0, 1
	slli	a0, a1, 16
	srli	a0, a0, 16
	sh	a1, 0(a2)
	.loc	2 235 304                       # rnd_output1.c:235:304
	snez	a0, a0
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2020(a1)                    # 4-byte Folded Spill
	j	.LBB0_101
.LBB0_101:                              #   in Loop: Header=BB0_33 Depth=1
	.loc	2 0 0                           # rnd_output1.c:0:0
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2020(a0)                    # 4-byte Folded Reload
	.loc	2 235 304                       # rnd_output1.c:235:304
	andi	a2, a0, 1
	li	a0, 1
	li	a1, 0
	.loc	2 235 185                       # rnd_output1.c:235:185
	lui	a3, 2
	sub	a3, s0, a3
	sw	a1, 2008(a3)                    # 4-byte Folded Spill
	call	safe_rshift_func_int64_t_s_u
	.loc	2 235 154                       # rnd_output1.c:235:154
	slli	a0, a0, 16
	srli	a0, a0, 16
	li	a1, 12
	call	safe_rshift_func_uint16_t_u_s
	.loc	2 235 450                       # rnd_output1.c:235:450
	lw	a0, -32(s0)
	.loc	2 235 457                       # rnd_output1.c:235:457
	lui	a1, 2
	sub	a1, s0, a1
	sw	a0, 2004(a1)                    # 4-byte Folded Spill
	li	a1, 27
	call	safe_lshift_func_uint32_t_u_s
	mv	a1, a0
	.loc	2 235 424                       # rnd_output1.c:235:424
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2004(a0)                    # 4-byte Folded Reload
	slli	a1, a1, 16
	srai	a1, a1, 16
	slli	a0, a0, 16
	srai	a0, a0, 16
	call	safe_div_func_int16_t_s_s
	lui	a1, 2
	sub	a1, s0, a1
	lw	a1, 2008(a1)                    # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 235 423                       # rnd_output1.c:235:423
	srai	a3, a2, 31
	li	a0, 3
	.loc	2 235 393                       # rnd_output1.c:235:393
	call	safe_div_func_int64_t_s_s
	.loc	2 235 528                       # rnd_output1.c:235:528
	lw	a1, -28(s0)
	.loc	2 235 363                       # rnd_output1.c:235:363
	andi	a0, a0, 255
	call	safe_rshift_func_uint8_t_u_s
	.loc	2 235 536                       # rnd_output1.c:235:536
	lw	a1, -28(s0)
	.loc	2 235 333                       # rnd_output1.c:235:333
	call	safe_rshift_func_int16_t_s_s
	lui	a0, 1
	sub	a0, s0, a0
	lw	a1, -1856(a0)                   # 4-byte Folded Reload
	.loc	2 235 548                       # rnd_output1.c:235:548
	lw	a0, 1424(a1)
	.loc	2 235 547                       # rnd_output1.c:235:547
	lw	a3, 0(a0)
	.loc	2 235 140                       # rnd_output1.c:235:140
	lw	a2, 28(a1)
	.loc	2 235 148                       # rnd_output1.c:235:148
	lbu	a0, 0(a2)
	and	a0, a0, a3
	sb	a0, 0(a2)
	.loc	2 235 137                       # rnd_output1.c:235:137
	slli	a0, a0, 24
	srai	a2, a0, 24
	.loc	2 235 134                       # rnd_output1.c:235:134
	lw	a0, 0(a1)
	and	a0, a0, a2
	sw	a0, 0(a1)
	.loc	2 235 560                       # rnd_output1.c:235:560
	lw	a1, -28(s0)
	.loc	2 235 98                        # rnd_output1.c:235:98
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_rshift_func_int8_t_s_s
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	.loc	2 235 570                       # rnd_output1.c:235:570
	lw	a1, 1424(a1)
	.loc	2 235 569                       # rnd_output1.c:235:569
	lw	a1, 0(a1)
	.loc	2 235 68                        # rnd_output1.c:235:68
	call	safe_rshift_func_int32_t_s_s
	mv	a1, a0
	.loc	2 235 26                        # rnd_output1.c:235:26
	lui	a0, 2
	sub	a0, s0, a0
	lw	a0, 2012(a0)                    # 4-byte Folded Reload
	slli	a1, a1, 24
	srai	a1, a1, 24
	slli	a0, a0, 24
	srai	a0, a0, 24
	call	safe_add_func_int8_t_s_s
	.loc	2 235 15                        # rnd_output1.c:235:15
	lui	a1, %hi(g_2088)
	lw	a1, %lo(g_2088)(a1)
	.loc	2 235 23                        # rnd_output1.c:235:23
	sw	a0, 0(a1)
	j	.LBB0_102
.Ltmp83:
.LBB0_102:                              #   in Loop: Header=BB0_33 Depth=1
	.loc	2 237 13 is_stmt 1              # rnd_output1.c:237:13
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lw	a0, 1756(a0)
.Ltmp84:
	.loc	2 237 13 is_stmt 0              # rnd_output1.c:237:13
	beqz	a0, .LBB0_104
	j	.LBB0_103
.LBB0_103:
.Ltmp85:
	.loc	2 238 13 is_stmt 1              # rnd_output1.c:238:13
	j	.LBB0_106
.Ltmp86:
.LBB0_104:                              #   in Loop: Header=BB0_33 Depth=1
	.loc	2 239 5                         # rnd_output1.c:239:5
	j	.LBB0_105
.Ltmp87:
.LBB0_105:                              #   in Loop: Header=BB0_33 Depth=1
	.loc	2 142 77                        # rnd_output1.c:142:77
	lui	a0, 1
	sub	a0, s0, a0
	lw	a0, -1856(a0)                   # 4-byte Folded Reload
	lhu	a0, 1784(a0)
	li	a1, 4
	.loc	2 142 50 is_stmt 0              # rnd_output1.c:142:50
	call	safe_sub_func_uint16_t_u_u
	lui	a1, 1
	sub	a1, s0, a1
	lw	a1, -1856(a1)                   # 4-byte Folded Reload
	.loc	2 142 48                        # rnd_output1.c:142:48
	sw	a0, 1784(a1)
	.loc	2 142 5                         # rnd_output1.c:142:5
	j	.LBB0_33
.Ltmp88:
.LBB0_106:
	.loc	2 240 12 is_stmt 1              # rnd_output1.c:240:12
	lui	a0, %hi(g_1818)
	addi	a0, a0, %lo(g_1818)
	lw	a0, 32(a0)
	sw	a0, -20(s0)
	.loc	2 240 5 is_stmt 0               # rnd_output1.c:240:5
	j	.LBB0_107
.LBB0_107:
	.loc	2 241 1 is_stmt 1               # rnd_output1.c:241:1
	lw	a0, -20(s0)
	.loc	2 241 1 epilogue_begin is_stmt 0 # rnd_output1.c:241:1
	lui	a1, 1
	addi	a1, a1, 64
	add	sp, sp, a1
	lw	ra, 2028(sp)                    # 4-byte Folded Reload
	lw	s0, 2024(sp)                    # 4-byte Folded Reload
	addi	sp, sp, 2032
	ret
.Ltmp89:
.Lfunc_end0:
	.size	func_36, .Lfunc_end0-func_36
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint8_t_u_u
	.type	safe_add_func_uint8_t_u_u,@function
safe_add_func_uint8_t_u_u:              # @safe_add_func_uint8_t_u_u
.Lfunc_begin1:
	.file	4 "/home/shiyanchu/outline_test" "linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h"
	.loc	4 547 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:547:0
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
.Ltmp90:
	.loc	4 549 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:10
	lbu	a0, -9(s0)
	.loc	4 549 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:16
	lbu	a1, -10(s0)
	.loc	4 549 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:14
	add	a0, a0, a1
	.loc	4 549 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 549 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:549:3
	addi	sp, sp, 16
	ret
.Ltmp91:
.Lfunc_end1:
	.size	safe_add_func_uint8_t_u_u, .Lfunc_end1-safe_add_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint8_t_u_u
	.type	safe_rshift_func_uint8_t_u_u,@function
safe_rshift_func_uint8_t_u_u:           # @safe_rshift_func_uint8_t_u_u
.Lfunc_begin2:
	.loc	4 628 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:628:0
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
.Ltmp92:
	.loc	4 632 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:632:21
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 632 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:632:5
	bltu	a0, a1, .LBB2_2
	j	.LBB2_1
.LBB2_1:
	.loc	4 633 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:633:6
	lbu	a0, -9(s0)
	.loc	4 632 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:632:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB2_3
.LBB2_2:
	.loc	4 635 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:635:6
	lbu	a0, -9(s0)
	.loc	4 635 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:635:29
	lw	a1, -16(s0)
	.loc	4 635 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:635:11
	srl	a0, a0, a1
	.loc	4 632 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:632:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB2_3
.LBB2_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 630 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:630:3
	andi	a0, a0, 255
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 630 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:630:3
	addi	sp, sp, 32
	ret
.Ltmp93:
.Lfunc_end2:
	.size	safe_rshift_func_uint8_t_u_u, .Lfunc_end2-safe_rshift_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint16_t_u_u
	.type	safe_add_func_uint16_t_u_u,@function
safe_add_func_uint16_t_u_u:             # @safe_add_func_uint16_t_u_u
.Lfunc_begin3:
	.loc	4 649 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:649:0
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
.Ltmp94:
	.loc	4 651 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:10
	lh	a0, -10(s0)
	.loc	4 651 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:16
	lh	a1, -12(s0)
	.loc	4 651 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:14
	add	a0, a0, a1
	.loc	4 651 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 651 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:651:3
	addi	sp, sp, 16
	ret
.Ltmp95:
.Lfunc_end3:
	.size	safe_add_func_uint16_t_u_u, .Lfunc_end3-safe_add_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int64_t_s_s
	.type	safe_div_func_int64_t_s_s,@function
safe_div_func_int64_t_s_s:              # @safe_div_func_int64_t_s_s
.Lfunc_begin4:
	.loc	4 474 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:474:0
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
.Ltmp96:
	.loc	4 478 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:7
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 478 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:11
	or	a0, a0, a1
	.loc	4 478 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:17
	beqz	a0, .LBB4_3
	j	.LBB4_1
.LBB4_1:
	.loc	4 478 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:22
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	lui	a2, 524288
	.loc	4 478 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:26
	xor	a1, a1, a2
	or	a0, a0, a1
	.loc	4 478 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:40
	bnez	a0, .LBB4_4
	j	.LBB4_2
.LBB4_2:
	.loc	4 478 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:44
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 478 48                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:48
	and	a0, a0, a1
	li	a1, -1
	.loc	4 478 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	bne	a0, a1, .LBB4_4
	j	.LBB4_3
.LBB4_3:
	.loc	4 479 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:479:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 478 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB4_5
.LBB4_4:
	.loc	4 481 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	4 481 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	4 481 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:481:10
	call	__divdi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 478 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:478:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB4_5
.LBB4_5:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	4 476 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:476:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 476 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:476:3
	addi	sp, sp, 32
	ret
.Ltmp97:
.Lfunc_end4:
	.size	safe_div_func_int64_t_s_s, .Lfunc_end4-safe_div_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint64_t_u_u
	.type	safe_mod_func_uint64_t_u_u,@function
safe_mod_func_uint64_t_u_u:             # @safe_mod_func_uint64_t_u_u
.Lfunc_begin5:
	.loc	4 875 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:875:0
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
.Ltmp98:
	.loc	4 879 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:879:6
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 879 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:879:10
	or	a0, a0, a1
	.loc	4 879 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:879:5
	bnez	a0, .LBB5_2
	j	.LBB5_1
.LBB5_1:
	.loc	4 880 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:880:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 879 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:879:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB5_3
.LBB5_2:
	.loc	4 882 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:882:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	4 882 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:882:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	4 882 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:882:10
	call	__umoddi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 879 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:879:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB5_3
.LBB5_3:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	4 877 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:877:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 877 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:877:3
	addi	sp, sp, 32
	ret
.Ltmp99:
.Lfunc_end5:
	.size	safe_mod_func_uint64_t_u_u, .Lfunc_end5-safe_mod_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint16_t_u_u
	.type	safe_mul_func_uint16_t_u_u,@function
safe_mul_func_uint16_t_u_u:             # @safe_mul_func_uint16_t_u_u
.Lfunc_begin6:
	.loc	4 663 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:663:0
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
.Ltmp100:
	.loc	4 665 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:665:11
	lh	a0, -10(s0)
	.loc	4 665 33 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:665:33
	lh	a1, -12(s0)
	.loc	4 665 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:665:30
	mul	a0, a0, a1
	.loc	4 665 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:665:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 665 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:665:3
	addi	sp, sp, 16
	ret
.Ltmp101:
.Lfunc_end6:
	.size	safe_mul_func_uint16_t_u_u, .Lfunc_end6-safe_mul_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint32_t_u_u
	.type	safe_mod_func_uint32_t_u_u,@function
safe_mod_func_uint32_t_u_u:             # @safe_mod_func_uint32_t_u_u
.Lfunc_begin7:
	.loc	4 772 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:772:0
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
.Ltmp102:
	.loc	4 776 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:6
	lw	a0, -16(s0)
	.loc	4 776 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	bnez	a0, .LBB7_2
	j	.LBB7_1
.LBB7_1:
	.loc	4 777 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:777:6
	lw	a0, -12(s0)
	.loc	4 776 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB7_3
.LBB7_2:
	.loc	4 779 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:6
	lw	a0, -12(s0)
	.loc	4 779 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:12
	lw	a1, -16(s0)
	.loc	4 779 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:779:10
	remu	a0, a0, a1
	.loc	4 776 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:776:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB7_3
.LBB7_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 774 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:774:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 774 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:774:3
	addi	sp, sp, 32
	ret
.Ltmp103:
.Lfunc_end7:
	.size	safe_mod_func_uint32_t_u_u, .Lfunc_end7-safe_mod_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint32_t_u_u
	.type	safe_sub_func_uint32_t_u_u,@function
safe_sub_func_uint32_t_u_u:             # @safe_sub_func_uint32_t_u_u
.Lfunc_begin8:
	.loc	4 758 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:758:0
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
.Ltmp104:
	.loc	4 760 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:760:10
	lw	a0, -12(s0)
	.loc	4 760 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:760:16
	lw	a1, -16(s0)
	.loc	4 760 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:760:14
	sub	a0, a0, a1
	.loc	4 760 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:760:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 760 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:760:3
	addi	sp, sp, 16
	ret
.Ltmp105:
.Lfunc_end8:
	.size	safe_sub_func_uint32_t_u_u, .Lfunc_end8-safe_sub_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint16_t_u_u
	.type	safe_sub_func_uint16_t_u_u,@function
safe_sub_func_uint16_t_u_u:             # @safe_sub_func_uint16_t_u_u
.Lfunc_begin9:
	.loc	4 656 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:656:0
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
.Ltmp106:
	.loc	4 658 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:658:10
	lh	a0, -10(s0)
	.loc	4 658 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:658:16
	lh	a1, -12(s0)
	.loc	4 658 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:658:14
	sub	a0, a0, a1
	.loc	4 658 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:658:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 658 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:658:3
	addi	sp, sp, 16
	ret
.Ltmp107:
.Lfunc_end9:
	.size	safe_sub_func_uint16_t_u_u, .Lfunc_end9-safe_sub_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_uint64_t_u_u
	.type	safe_lshift_func_uint64_t_u_u,@function
safe_lshift_func_uint64_t_u_u:          # @safe_lshift_func_uint64_t_u_u
.Lfunc_begin10:
	.loc	4 911 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:911:0
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
.Ltmp108:
	.loc	4 915 22 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:22
	lw	a1, -20(s0)
	li	a0, 31
	.loc	4 915 36 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:36
	bltu	a0, a1, .LBB10_6
	j	.LBB10_1
.LBB10_1:
	.loc	4 915 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:40
	lw	a0, -12(s0)
	sw	a0, -40(s0)                     # 4-byte Folded Spill
	lw	a0, -16(s0)
	.loc	4 915 77                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:77
	sw	a0, -36(s0)                     # 4-byte Folded Spill
	lw	a0, -20(s0)
	li	a1, -1
	.loc	4 915 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:59
	srl	a1, a1, a0
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	not	a3, a0
	li	a2, -2
	sll	a2, a2, a3
	or	a1, a1, a2
	addi	a0, a0, -32
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	sw	a1, -24(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB10_3
# %bb.2:
	.loc	4 0 59                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:59
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -24(s0)                     # 4-byte Folded Spill
.LBB10_3:
	.loc	4 915 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:59
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	lw	a3, -36(s0)                     # 4-byte Folded Reload
	lw	a4, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	lw	a2, -24(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a4
	.loc	4 915 45                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:45
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sltu	a3, a1, a0
	xori	a3, a3, 1
	sw	a3, -48(s0)                     # 4-byte Folded Spill
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB10_5
# %bb.4:
	.loc	4 0 45                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:45
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB10_5:
	.loc	4 915 45                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:45
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	4 915 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:5
	bnez	a0, .LBB10_7
	j	.LBB10_6
.LBB10_6:
	.loc	4 916 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:916:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	4 915 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB10_10
.LBB10_7:
	.loc	4 918 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:918:6
	lw	a2, -16(s0)
	lw	a1, -12(s0)
	.loc	4 918 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:918:29
	lw	a0, -20(s0)
	.loc	4 918 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:918:11
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
	bltz	a0, .LBB10_9
# %bb.8:
	.loc	4 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	sw	a0, -60(s0)                     # 4-byte Folded Spill
.LBB10_9:
	.loc	4 918 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:918:11
	lw	a2, -68(s0)                     # 4-byte Folded Reload
	lw	a1, -64(s0)                     # 4-byte Folded Reload
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	srai	a1, a1, 31
	and	a1, a1, a2
	sw	a1, -56(s0)                     # 4-byte Folded Spill
	.loc	4 915 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:915:5
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	j	.LBB10_10
.LBB10_10:
	lw	a0, -56(s0)                     # 4-byte Folded Reload
	lw	a1, -52(s0)                     # 4-byte Folded Reload
	.loc	4 913 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:913:3
	lw	ra, 76(sp)                      # 4-byte Folded Reload
	lw	s0, 72(sp)                      # 4-byte Folded Reload
	.loc	4 913 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:913:3
	addi	sp, sp, 80
	ret
.Ltmp109:
.Lfunc_end10:
	.size	safe_lshift_func_uint64_t_u_u, .Lfunc_end10-safe_lshift_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int32_t_s_s
	.type	safe_mul_func_int32_t_s_s,@function
safe_mul_func_int32_t_s_s:              # @safe_mul_func_int32_t_s_s
.Lfunc_begin11:
	.loc	4 317 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:317:0
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
.Ltmp110:
	.loc	4 322 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:8
	lw	a1, -12(s0)
	li	a0, 0
	.loc	4 322 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:17
	bge	a0, a1, .LBB11_3
	j	.LBB11_1
.LBB11_1:
	.loc	4 322 21                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:21
	lw	a1, -16(s0)
	li	a0, 0
	.loc	4 322 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:30
	bge	a0, a1, .LBB11_3
	j	.LBB11_2
.LBB11_2:
	.loc	4 322 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:34
	lw	a1, -12(s0)
	.loc	4 322 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:53
	lw	a2, -16(s0)
	lui	a0, 524288
	addi	a0, a0, -1
	.loc	4 322 51                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:51
	div	a0, a0, a2
	.loc	4 322 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:60
	blt	a0, a1, .LBB11_13
	j	.LBB11_3
.LBB11_3:
	.loc	4 322 65                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:65
	lw	a1, -12(s0)
	li	a0, 0
	.loc	4 322 74                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:74
	bge	a0, a1, .LBB11_6
	j	.LBB11_4
.LBB11_4:
	.loc	4 322 78                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:78
	lw	a1, -16(s0)
	li	a0, 0
	.loc	4 322 88                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:88
	blt	a0, a1, .LBB11_6
	j	.LBB11_5
.LBB11_5:
	.loc	4 322 92                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:92
	lw	a0, -16(s0)
	.loc	4 322 111                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:111
	lw	a2, -12(s0)
	lui	a1, 524288
	.loc	4 322 109                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:109
	div	a1, a1, a2
	.loc	4 322 118                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:118
	blt	a0, a1, .LBB11_13
	j	.LBB11_6
.LBB11_6:
	.loc	4 322 123                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:123
	lw	a1, -12(s0)
	li	a0, 0
	.loc	4 322 133                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:133
	blt	a0, a1, .LBB11_9
	j	.LBB11_7
.LBB11_7:
	.loc	4 322 137                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:137
	lw	a1, -16(s0)
	li	a0, 0
	.loc	4 322 146                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:146
	bge	a0, a1, .LBB11_9
	j	.LBB11_8
.LBB11_8:
	.loc	4 322 150                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:150
	lw	a0, -12(s0)
	.loc	4 322 169                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:169
	lw	a2, -16(s0)
	lui	a1, 524288
	.loc	4 322 167                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:167
	div	a1, a1, a2
	.loc	4 322 176                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:176
	blt	a0, a1, .LBB11_13
	j	.LBB11_9
.LBB11_9:
	.loc	4 322 181                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:181
	lw	a1, -12(s0)
	li	a0, 0
	.loc	4 322 191                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:191
	blt	a0, a1, .LBB11_14
	j	.LBB11_10
.LBB11_10:
	.loc	4 322 195                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:195
	lw	a1, -16(s0)
	li	a0, 0
	.loc	4 322 205                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:205
	blt	a0, a1, .LBB11_14
	j	.LBB11_11
.LBB11_11:
	.loc	4 322 209                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:209
	lw	a0, -12(s0)
	.loc	4 322 219                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:219
	beqz	a0, .LBB11_14
	j	.LBB11_12
.LBB11_12:
	.loc	4 322 223                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:223
	lw	a0, -16(s0)
	.loc	4 322 242                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:242
	lw	a2, -12(s0)
	lui	a1, 524288
	addi	a1, a1, -1
	.loc	4 322 240                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:240
	div	a1, a1, a2
	.loc	4 322 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	bge	a0, a1, .LBB11_14
	j	.LBB11_13
.LBB11_13:
	.loc	4 323 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:323:6
	lw	a0, -12(s0)
	.loc	4 322 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB11_15
.LBB11_14:
	.loc	4 326 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:5
	lw	a0, -12(s0)
	.loc	4 326 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:11
	lw	a1, -16(s0)
	.loc	4 326 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:326:9
	mul	a0, a0, a1
	.loc	4 322 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:322:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB11_15
.LBB11_15:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 319 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:319:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 319 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:319:3
	addi	sp, sp, 32
	ret
.Ltmp111:
.Lfunc_end11:
	.size	safe_mul_func_int32_t_s_s, .Lfunc_end11-safe_mul_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_uint8_t_u_u
	.type	safe_mod_func_uint8_t_u_u,@function
safe_mod_func_uint8_t_u_u:              # @safe_mod_func_uint8_t_u_u
.Lfunc_begin12:
	.loc	4 568 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:568:0
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
.Ltmp112:
	.loc	4 572 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:6
	lbu	a0, -10(s0)
	.loc	4 572 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	bnez	a0, .LBB12_2
	j	.LBB12_1
.LBB12_1:
	.loc	4 573 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:573:6
	lbu	a0, -9(s0)
	.loc	4 572 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB12_3
.LBB12_2:
	.loc	4 575 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:6
	lbu	a0, -9(s0)
	.loc	4 575 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:12
	lbu	a1, -10(s0)
	.loc	4 575 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:575:10
	remu	a0, a0, a1
	.loc	4 572 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:572:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB12_3
.LBB12_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	4 570 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:570:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 570 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:570:3
	addi	sp, sp, 16
	ret
.Ltmp113:
.Lfunc_end12:
	.size	safe_mod_func_uint8_t_u_u, .Lfunc_end12-safe_mod_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int16_t_s_u
	.type	safe_rshift_func_int16_t_s_u,@function
safe_rshift_func_int16_t_s_u:           # @safe_rshift_func_int16_t_s_u
.Lfunc_begin13:
	.loc	4 261 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:261:0
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
.Ltmp114:
	.loc	4 265 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:7
	lh	a0, -10(s0)
	.loc	4 265 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:17
	bltz	a0, .LBB13_2
	j	.LBB13_1
.LBB13_1:
	.loc	4 265 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 265 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	bltu	a0, a1, .LBB13_3
	j	.LBB13_2
.LBB13_2:
	.loc	4 266 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:266:6
	lh	a0, -10(s0)
	.loc	4 265 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB13_4
.LBB13_3:
	.loc	4 268 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:6
	lh	a0, -10(s0)
	.loc	4 268 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:29
	lw	a1, -16(s0)
	.loc	4 268 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:268:11
	sra	a0, a0, a1
	.loc	4 265 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:265:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB13_4
.LBB13_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 263 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:263:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 263 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:263:3
	addi	sp, sp, 32
	ret
.Ltmp115:
.Lfunc_end13:
	.size	safe_rshift_func_int16_t_s_u, .Lfunc_end13-safe_rshift_func_int16_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int8_t_s_s
	.type	safe_sub_func_int8_t_s_s,@function
safe_sub_func_int8_t_s_s:               # @safe_sub_func_int8_t_s_s
.Lfunc_begin14:
	.loc	4 43 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:43:0
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
.Ltmp116:
	.loc	4 52 6 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:6
	lbu	a0, -9(s0)
	.loc	4 52 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:12
	lbu	a1, -10(s0)
	.loc	4 52 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:52:10
	sub	a0, a0, a1
	.loc	4 45 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:45:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 45 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:45:3
	addi	sp, sp, 16
	ret
.Ltmp117:
.Lfunc_end14:
	.size	safe_sub_func_int8_t_s_s, .Lfunc_end14-safe_sub_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint32_t_u_u
	.type	safe_div_func_uint32_t_u_u,@function
safe_div_func_uint32_t_u_u:             # @safe_div_func_uint32_t_u_u
.Lfunc_begin15:
	.loc	4 784 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:784:0
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
.Ltmp118:
	.loc	4 788 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:6
	lw	a0, -16(s0)
	.loc	4 788 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	bnez	a0, .LBB15_2
	j	.LBB15_1
.LBB15_1:
	.loc	4 789 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:789:6
	lw	a0, -12(s0)
	.loc	4 788 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB15_3
.LBB15_2:
	.loc	4 791 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:6
	lw	a0, -12(s0)
	.loc	4 791 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:12
	lw	a1, -16(s0)
	.loc	4 791 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:791:10
	divu	a0, a0, a1
	.loc	4 788 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:788:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB15_3
.LBB15_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 786 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:786:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 786 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:786:3
	addi	sp, sp, 32
	ret
.Ltmp119:
.Lfunc_end15:
	.size	safe_div_func_uint32_t_u_u, .Lfunc_end15-safe_div_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int32_t_s_u
	.type	safe_rshift_func_int32_t_s_u,@function
safe_rshift_func_int32_t_s_u:           # @safe_rshift_func_int32_t_s_u
.Lfunc_begin16:
	.loc	4 391 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:391:0
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
.Ltmp120:
	.loc	4 395 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:7
	lw	a0, -12(s0)
	.loc	4 395 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:17
	bltz	a0, .LBB16_2
	j	.LBB16_1
.LBB16_1:
	.loc	4 395 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 395 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	bltu	a0, a1, .LBB16_3
	j	.LBB16_2
.LBB16_2:
	.loc	4 396 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:396:6
	lw	a0, -12(s0)
	.loc	4 395 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB16_4
.LBB16_3:
	.loc	4 398 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:6
	lw	a0, -12(s0)
	.loc	4 398 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:29
	lw	a1, -16(s0)
	.loc	4 398 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:398:11
	sra	a0, a0, a1
	.loc	4 395 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:395:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB16_4
.LBB16_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 393 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:393:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 393 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:393:3
	addi	sp, sp, 32
	ret
.Ltmp121:
.Lfunc_end16:
	.size	safe_rshift_func_int32_t_s_u, .Lfunc_end16-safe_rshift_func_int32_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_uint32_t_u_s
	.type	safe_lshift_func_uint32_t_u_s,@function
safe_lshift_func_uint32_t_u_s:          # @safe_lshift_func_uint32_t_u_s
.Lfunc_begin17:
	.loc	4 796 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:796:0
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
.Ltmp122:
	.loc	4 800 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:13
	lw	a0, -16(s0)
	.loc	4 800 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:25
	bltz	a0, .LBB17_3
	j	.LBB17_1
.LBB17_1:
	.loc	4 800 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:35
	lw	a1, -16(s0)
	li	a0, 31
	.loc	4 800 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:49
	blt	a0, a1, .LBB17_3
	j	.LBB17_2
.LBB17_2:
	.loc	4 800 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:53
	lw	a1, -12(s0)
	.loc	4 800 81                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:81
	lw	a2, -16(s0)
	li	a0, -1
	.loc	4 800 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:72
	srl	a0, a0, a2
	.loc	4 800 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:5
	bgeu	a0, a1, .LBB17_4
	j	.LBB17_3
.LBB17_3:
	.loc	4 801 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:801:6
	lw	a0, -12(s0)
	.loc	4 800 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB17_5
.LBB17_4:
	.loc	4 803 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:803:6
	lw	a0, -12(s0)
	.loc	4 803 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:803:20
	lw	a1, -16(s0)
	.loc	4 803 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:803:11
	sll	a0, a0, a1
	.loc	4 800 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:800:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB17_5
.LBB17_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 798 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:798:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 798 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:798:3
	addi	sp, sp, 32
	ret
.Ltmp123:
.Lfunc_end17:
	.size	safe_lshift_func_uint32_t_u_s, .Lfunc_end17-safe_lshift_func_uint32_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mod_func_int64_t_s_s
	.type	safe_mod_func_int64_t_s_s,@function
safe_mod_func_int64_t_s_s:              # @safe_mod_func_int64_t_s_s
.Lfunc_begin18:
	.loc	4 462 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:462:0
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
.Ltmp124:
	.loc	4 466 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:7
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 466 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:11
	or	a0, a0, a1
	.loc	4 466 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:17
	beqz	a0, .LBB18_3
	j	.LBB18_1
.LBB18_1:
	.loc	4 466 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:22
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	lui	a2, 524288
	.loc	4 466 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:26
	xor	a1, a1, a2
	or	a0, a0, a1
	.loc	4 466 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:40
	bnez	a0, .LBB18_4
	j	.LBB18_2
.LBB18_2:
	.loc	4 466 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:44
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 466 48                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:48
	and	a0, a0, a1
	li	a1, -1
	.loc	4 466 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	bne	a0, a1, .LBB18_4
	j	.LBB18_3
.LBB18_3:
	.loc	4 467 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:467:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 466 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB18_5
.LBB18_4:
	.loc	4 469 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	4 469 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	4 469 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:469:10
	call	__moddi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 466 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:466:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB18_5
.LBB18_5:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	4 464 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:464:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 464 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:464:3
	addi	sp, sp, 32
	ret
.Ltmp125:
.Lfunc_end18:
	.size	safe_mod_func_int64_t_s_s, .Lfunc_end18-safe_mod_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint16_t_u_s
	.type	safe_rshift_func_uint16_t_u_s,@function
safe_rshift_func_uint16_t_u_s:          # @safe_rshift_func_uint16_t_u_s
.Lfunc_begin19:
	.loc	4 718 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:718:0
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
.Ltmp126:
	.loc	4 722 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:13
	lw	a0, -16(s0)
	.loc	4 722 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:25
	bltz	a0, .LBB19_2
	j	.LBB19_1
.LBB19_1:
	.loc	4 722 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:35
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 722 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:5
	blt	a0, a1, .LBB19_3
	j	.LBB19_2
.LBB19_2:
	.loc	4 723 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:723:6
	lhu	a0, -10(s0)
	.loc	4 722 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB19_4
.LBB19_3:
	.loc	4 725 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:725:6
	lhu	a0, -10(s0)
	.loc	4 725 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:725:20
	lw	a1, -16(s0)
	.loc	4 725 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:725:11
	srl	a0, a0, a1
	.loc	4 722 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:722:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB19_4
.LBB19_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 720 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:720:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 720 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:720:3
	addi	sp, sp, 32
	ret
.Ltmp127:
.Lfunc_end19:
	.size	safe_rshift_func_uint16_t_u_s, .Lfunc_end19-safe_rshift_func_uint16_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int16_t_s_s
	.type	safe_mul_func_int16_t_s_s,@function
safe_mul_func_int16_t_s_s:              # @safe_mul_func_int16_t_s_s
.Lfunc_begin20:
	.loc	4 187 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:187:0
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
.Ltmp128:
	.loc	4 196 5 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:5
	lh	a0, -10(s0)
	.loc	4 196 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:11
	lh	a1, -12(s0)
	.loc	4 196 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:196:9
	mul	a0, a0, a1
	.loc	4 189 3 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:189:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 189 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:189:3
	addi	sp, sp, 16
	ret
.Ltmp129:
.Lfunc_end20:
	.size	safe_mul_func_int16_t_s_s, .Lfunc_end20-safe_mul_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int32_t_s_s
	.type	safe_rshift_func_int32_t_s_s,@function
safe_rshift_func_int32_t_s_s:           # @safe_rshift_func_int32_t_s_s
.Lfunc_begin21:
	.loc	4 379 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:379:0
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
.Ltmp130:
	.loc	4 383 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:7
	lw	a0, -12(s0)
	.loc	4 383 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:17
	bltz	a0, .LBB21_3
	j	.LBB21_1
.LBB21_1:
	.loc	4 383 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:27
	lw	a0, -16(s0)
	.loc	4 383 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:39
	bltz	a0, .LBB21_3
	j	.LBB21_2
.LBB21_2:
	.loc	4 383 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:49
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 383 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	blt	a0, a1, .LBB21_4
	j	.LBB21_3
.LBB21_3:
	.loc	4 384 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:384:6
	lw	a0, -12(s0)
	.loc	4 383 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB21_5
.LBB21_4:
	.loc	4 386 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:6
	lw	a0, -12(s0)
	.loc	4 386 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:20
	lw	a1, -16(s0)
	.loc	4 386 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:386:11
	sra	a0, a0, a1
	.loc	4 383 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:383:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB21_5
.LBB21_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 381 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:381:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 381 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:381:3
	addi	sp, sp, 32
	ret
.Ltmp131:
.Lfunc_end21:
	.size	safe_rshift_func_int32_t_s_s, .Lfunc_end21-safe_rshift_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_uint64_t_u_u
	.type	safe_add_func_uint64_t_u_u,@function
safe_add_func_uint64_t_u_u:             # @safe_add_func_uint64_t_u_u
.Lfunc_begin22:
	.loc	4 854 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:854:0
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
.Ltmp132:
	.loc	4 856 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:10
	lw	a2, -16(s0)
	lw	a1, -12(s0)
	.loc	4 856 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:16
	lw	a0, -24(s0)
	lw	a3, -20(s0)
	.loc	4 856 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:14
	add	a1, a1, a3
	add	a0, a0, a2
	sltu	a2, a0, a2
	add	a1, a1, a2
	.loc	4 856 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 856 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:856:3
	addi	sp, sp, 32
	ret
.Ltmp133:
.Lfunc_end22:
	.size	safe_add_func_uint64_t_u_u, .Lfunc_end22-safe_add_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint64_t_u_u
	.type	safe_rshift_func_uint64_t_u_u,@function
safe_rshift_func_uint64_t_u_u:          # @safe_rshift_func_uint64_t_u_u
.Lfunc_begin23:
	.loc	4 935 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:935:0
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
.Ltmp134:
	.loc	4 939 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:21
	lw	a0, -20(s0)
	li	a1, 32
	.loc	4 939 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	bltu	a0, a1, .LBB23_2
	j	.LBB23_1
.LBB23_1:
	.loc	4 940 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:940:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 939 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB23_5
.LBB23_2:
	.loc	4 942 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:6
	lw	a2, -12(s0)
	lw	a1, -16(s0)
	.loc	4 942 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:29
	lw	a0, -20(s0)
	.loc	4 942 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:11
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
	bltz	a0, .LBB23_4
# %bb.3:
	.loc	4 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -32(s0)                     # 4-byte Folded Spill
.LBB23_4:
	.loc	4 942 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:942:11
	lw	a2, -40(s0)                     # 4-byte Folded Reload
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	lw	a1, -32(s0)                     # 4-byte Folded Reload
	srai	a0, a0, 31
	and	a0, a0, a2
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 939 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:939:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB23_5
.LBB23_5:
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	lw	a1, -24(s0)                     # 4-byte Folded Reload
	.loc	4 937 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:937:3
	lw	ra, 44(sp)                      # 4-byte Folded Reload
	lw	s0, 40(sp)                      # 4-byte Folded Reload
	.loc	4 937 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:937:3
	addi	sp, sp, 48
	ret
.Ltmp135:
.Lfunc_end23:
	.size	safe_rshift_func_uint64_t_u_u, .Lfunc_end23-safe_rshift_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_uint8_t_u
	.type	safe_unary_minus_func_uint8_t_u,@function
safe_unary_minus_func_uint8_t_u:        # @safe_unary_minus_func_uint8_t_u
.Lfunc_begin24:
	.loc	4 540 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:540:0
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
.Ltmp136:
	.loc	4 542 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:11
	lbu	a1, -9(s0)
	li	a0, 0
	.loc	4 542 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:10
	sub	a0, a0, a1
	.loc	4 542 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 542 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:542:3
	addi	sp, sp, 16
	ret
.Ltmp137:
.Lfunc_end24:
	.size	safe_unary_minus_func_uint8_t_u, .Lfunc_end24-safe_unary_minus_func_uint8_t_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int64_t_s_s
	.type	safe_add_func_int64_t_s_s,@function
safe_add_func_int64_t_s_s:              # @safe_add_func_int64_t_s_s
.Lfunc_begin25:
	.loc	4 420 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:420:0
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
.Ltmp138:
	.loc	4 425 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:8
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	4 425 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:11
	slti	a2, a0, 0
	sw	a2, -32(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB25_2
# %bb.1:
	.loc	4 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -28(s0)                     # 4-byte Folded Spill
.LBB25_2:
	.loc	4 425 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:11
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	.loc	4 425 15                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:15
	bnez	a0, .LBB25_9
	j	.LBB25_3
.LBB25_3:
	.loc	4 425 19                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:19
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	4 425 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:22
	slti	a2, a0, 0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -36(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB25_5
# %bb.4:
	.loc	4 0 22                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:22
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -36(s0)                     # 4-byte Folded Spill
.LBB25_5:
	.loc	4 425 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:22
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	.loc	4 425 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:26
	bnez	a0, .LBB25_9
	j	.LBB25_6
.LBB25_6:
	.loc	4 425 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:30
	lw	a0, -12(s0)
	lw	a3, -16(s0)
	.loc	4 425 47                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:47
	lw	a2, -24(s0)
	lw	a1, -20(s0)
	lui	a4, 524288
	addi	a4, a4, -1
	.loc	4 425 46                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:46
	xor	a1, a1, a4
	not	a2, a2
	.loc	4 425 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:34
	sltu	a2, a2, a3
	slt	a3, a1, a0
	sw	a3, -48(s0)                     # 4-byte Folded Spill
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB25_8
# %bb.7:
	.loc	4 0 34                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:34
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB25_8:
	.loc	4 425 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:34
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	4 425 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:54
	bnez	a0, .LBB25_14
	j	.LBB25_9
.LBB25_9:
	.loc	4 425 59                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:59
	lw	a0, -12(s0)
	.loc	4 425 66                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:66
	bgez	a0, .LBB25_15
	j	.LBB25_10
.LBB25_10:
	.loc	4 425 70                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:70
	lw	a0, -20(s0)
	.loc	4 425 77                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:77
	bgez	a0, .LBB25_15
	j	.LBB25_11
.LBB25_11:
	.loc	4 425 81                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:81
	lw	a0, -12(s0)
	lw	a2, -16(s0)
	.loc	4 425 98                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:98
	lw	a1, -20(s0)
	lw	a4, -24(s0)
	.loc	4 425 97                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:97
	snez	a3, a4
	add	a3, a3, a1
	lui	a1, 524288
	sub	a1, a1, a3
	li	a3, 0
	sub	a3, a3, a4
	.loc	4 425 85                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:85
	sltu	a2, a2, a3
	xori	a2, a2, 1
	slt	a3, a0, a1
	xori	a3, a3, 1
	sw	a3, -56(s0)                     # 4-byte Folded Spill
	sw	a2, -52(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB25_13
# %bb.12:
	.loc	4 0 85                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:85
	lw	a0, -56(s0)                     # 4-byte Folded Reload
	sw	a0, -52(s0)                     # 4-byte Folded Spill
.LBB25_13:
	.loc	4 425 85                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:85
	lw	a0, -52(s0)                     # 4-byte Folded Reload
	.loc	4 425 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	bnez	a0, .LBB25_15
	j	.LBB25_14
.LBB25_14:
	.loc	4 426 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:426:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -64(s0)                     # 4-byte Folded Spill
	.loc	4 425 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	sw	a0, -60(s0)                     # 4-byte Folded Spill
	j	.LBB25_16
.LBB25_15:
	.loc	4 429 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:6
	lw	a2, -16(s0)
	lw	a0, -12(s0)
	.loc	4 429 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:12
	lw	a1, -24(s0)
	lw	a3, -20(s0)
	.loc	4 429 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:429:10
	add	a0, a0, a3
	add	a1, a1, a2
	sltu	a2, a1, a2
	add	a0, a0, a2
	sw	a1, -64(s0)                     # 4-byte Folded Spill
	.loc	4 425 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:425:5
	sw	a0, -60(s0)                     # 4-byte Folded Spill
	j	.LBB25_16
.LBB25_16:
	lw	a0, -64(s0)                     # 4-byte Folded Reload
	lw	a1, -60(s0)                     # 4-byte Folded Reload
	.loc	4 422 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:422:3
	lw	ra, 60(sp)                      # 4-byte Folded Reload
	lw	s0, 56(sp)                      # 4-byte Folded Reload
	.loc	4 422 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:422:3
	addi	sp, sp, 64
	ret
.Ltmp139:
.Lfunc_end25:
	.size	safe_add_func_int64_t_s_s, .Lfunc_end25-safe_add_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int64_t_s_s
	.type	safe_sub_func_int64_t_s_s,@function
safe_sub_func_int64_t_s_s:              # @safe_sub_func_int64_t_s_s
.Lfunc_begin26:
	.loc	4 434 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:434:0
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
.Ltmp140:
	.loc	4 439 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:8
	lw	a3, -16(s0)
	lw	a1, -12(s0)
	.loc	4 439 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:12
	lw	a4, -24(s0)
	lw	a2, -20(s0)
	.loc	4 439 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:11
	xor	a0, a1, a2
	lui	a5, 524288
	.loc	4 439 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:39
	and	a5, a5, a0
	.loc	4 439 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:26
	xor	a1, a1, a5
	.loc	4 439 55                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:55
	sltu	a3, a3, a4
	sub	a1, a1, a2
	sub	a1, a1, a3
	.loc	4 439 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:60
	xor	a1, a1, a2
	.loc	4 439 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:17
	and	a0, a0, a1
	.loc	4 439 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	bgez	a0, .LBB26_2
	j	.LBB26_1
.LBB26_1:
	.loc	4 440 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:440:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	.loc	4 439 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	j	.LBB26_3
.LBB26_2:
	.loc	4 443 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	.loc	4 443 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:12
	lw	a4, -20(s0)
	lw	a2, -24(s0)
	.loc	4 443 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:443:10
	sltu	a3, a1, a2
	sub	a0, a0, a4
	sub	a0, a0, a3
	sub	a1, a1, a2
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	.loc	4 439 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:439:5
	sw	a0, -28(s0)                     # 4-byte Folded Spill
	j	.LBB26_3
.LBB26_3:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	4 436 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:436:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 436 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:436:3
	addi	sp, sp, 32
	ret
.Ltmp141:
.Lfunc_end26:
	.size	safe_sub_func_int64_t_s_s, .Lfunc_end26-safe_sub_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_uint64_t_u_u
	.type	safe_div_func_uint64_t_u_u,@function
safe_div_func_uint64_t_u_u:             # @safe_div_func_uint64_t_u_u
.Lfunc_begin27:
	.loc	4 887 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:887:0
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
.Ltmp142:
	.loc	4 891 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:6
	lw	a1, -20(s0)
	lw	a0, -24(s0)
	.loc	4 891 10 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:10
	or	a0, a0, a1
	.loc	4 891 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	bnez	a0, .LBB27_2
	j	.LBB27_1
.LBB27_1:
	.loc	4 892 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:892:6
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 891 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB27_3
.LBB27_2:
	.loc	4 894 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:6
	lw	a0, -16(s0)
	lw	a1, -12(s0)
	.loc	4 894 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:12
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	.loc	4 894 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:894:10
	call	__udivdi3@plt
	sw	a0, -32(s0)                     # 4-byte Folded Spill
	.loc	4 891 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:891:5
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	j	.LBB27_3
.LBB27_3:
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	lw	a1, -28(s0)                     # 4-byte Folded Reload
	.loc	4 889 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:889:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 889 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:889:3
	addi	sp, sp, 32
	ret
.Ltmp143:
.Lfunc_end27:
	.size	safe_div_func_uint64_t_u_u, .Lfunc_end27-safe_div_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int8_t_s_s
	.type	safe_div_func_int8_t_s_s,@function
safe_div_func_int8_t_s_s:               # @safe_div_func_int8_t_s_s
.Lfunc_begin28:
	.loc	4 83 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:83:0
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
.Ltmp144:
	.loc	4 87 7 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:7
	lb	a0, -10(s0)
	.loc	4 87 17 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:17
	beqz	a0, .LBB28_3
	j	.LBB28_1
.LBB28_1:
	.loc	4 87 22                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:22
	lb	a0, -9(s0)
	li	a1, -128
	.loc	4 87 39                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:39
	bne	a0, a1, .LBB28_4
	j	.LBB28_2
.LBB28_2:
	.loc	4 87 43                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:43
	lb	a0, -10(s0)
	li	a1, -1
	.loc	4 87 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	bne	a0, a1, .LBB28_4
	j	.LBB28_3
.LBB28_3:
	.loc	4 88 6 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:88:6
	lb	a0, -9(s0)
	.loc	4 87 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB28_5
.LBB28_4:
	.loc	4 90 6                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:6
	lb	a0, -9(s0)
	.loc	4 90 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:12
	lb	a1, -10(s0)
	.loc	4 90 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:90:10
	div	a0, a0, a1
	.loc	4 87 5 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:87:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB28_5
.LBB28_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	4 85 3                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:85:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 85 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:85:3
	addi	sp, sp, 16
	ret
.Ltmp145:
.Lfunc_end28:
	.size	safe_div_func_int8_t_s_s, .Lfunc_end28-safe_div_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint8_t_u_u
	.type	safe_sub_func_uint8_t_u_u,@function
safe_sub_func_uint8_t_u_u:              # @safe_sub_func_uint8_t_u_u
.Lfunc_begin29:
	.loc	4 554 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:554:0
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
.Ltmp146:
	.loc	4 556 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:10
	lbu	a0, -9(s0)
	.loc	4 556 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:16
	lbu	a1, -10(s0)
	.loc	4 556 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:14
	sub	a0, a0, a1
	.loc	4 556 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 556 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:556:3
	addi	sp, sp, 16
	ret
.Ltmp147:
.Lfunc_end29:
	.size	safe_sub_func_uint8_t_u_u, .Lfunc_end29-safe_sub_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_uint64_t_u_u
	.type	safe_sub_func_uint64_t_u_u,@function
safe_sub_func_uint64_t_u_u:             # @safe_sub_func_uint64_t_u_u
.Lfunc_begin30:
	.loc	4 861 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:861:0
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
.Ltmp148:
	.loc	4 863 10 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:10
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	.loc	4 863 16 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:16
	lw	a4, -20(s0)
	lw	a2, -24(s0)
	.loc	4 863 14                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:14
	sltu	a3, a0, a2
	sub	a1, a1, a4
	sub	a1, a1, a3
	sub	a0, a0, a2
	.loc	4 863 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 863 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:863:3
	addi	sp, sp, 32
	ret
.Ltmp149:
.Lfunc_end30:
	.size	safe_sub_func_uint64_t_u_u, .Lfunc_end30-safe_sub_func_uint64_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint64_t_u_s
	.type	safe_rshift_func_uint64_t_u_s,@function
safe_rshift_func_uint64_t_u_s:          # @safe_rshift_func_uint64_t_u_s
.Lfunc_begin31:
	.loc	4 923 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:923:0
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
.Ltmp150:
	.loc	4 927 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:13
	lw	a0, -20(s0)
	.loc	4 927 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:25
	bltz	a0, .LBB31_2
	j	.LBB31_1
.LBB31_1:
	.loc	4 927 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:35
	lw	a0, -20(s0)
	li	a1, 32
	.loc	4 927 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	blt	a0, a1, .LBB31_3
	j	.LBB31_2
.LBB31_2:
	.loc	4 928 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:928:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 927 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB31_6
.LBB31_3:
	.loc	4 930 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:6
	lw	a2, -12(s0)
	lw	a1, -16(s0)
	.loc	4 930 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:20
	lw	a0, -20(s0)
	.loc	4 930 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:11
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
	bltz	a0, .LBB31_5
# %bb.4:
	.loc	4 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -32(s0)                     # 4-byte Folded Spill
.LBB31_5:
	.loc	4 930 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:930:11
	lw	a2, -40(s0)                     # 4-byte Folded Reload
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	lw	a1, -32(s0)                     # 4-byte Folded Reload
	srai	a0, a0, 31
	and	a0, a0, a2
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 927 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:927:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB31_6
.LBB31_6:
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	lw	a1, -24(s0)                     # 4-byte Folded Reload
	.loc	4 925 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:925:3
	lw	ra, 44(sp)                      # 4-byte Folded Reload
	lw	s0, 40(sp)                      # 4-byte Folded Reload
	.loc	4 925 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:925:3
	addi	sp, sp, 48
	ret
.Ltmp151:
.Lfunc_end31:
	.size	safe_rshift_func_uint64_t_u_s, .Lfunc_end31-safe_rshift_func_uint64_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint8_t_u_u
	.type	safe_mul_func_uint8_t_u_u,@function
safe_mul_func_uint8_t_u_u:              # @safe_mul_func_uint8_t_u_u
.Lfunc_begin32:
	.loc	4 561 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:561:0
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
.Ltmp152:
	.loc	4 563 11 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:11
	lbu	a0, -9(s0)
	.loc	4 563 33 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:33
	lbu	a1, -10(s0)
	.loc	4 563 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:30
	mul	a0, a0, a1
	.loc	4 563 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:3
	andi	a0, a0, 255
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 563 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:563:3
	addi	sp, sp, 16
	ret
.Ltmp153:
.Lfunc_end32:
	.size	safe_mul_func_uint8_t_u_u, .Lfunc_end32-safe_mul_func_uint8_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int8_t_s_s
	.type	safe_lshift_func_int8_t_s_s,@function
safe_lshift_func_int8_t_s_s:            # @safe_lshift_func_int8_t_s_s
.Lfunc_begin33:
	.loc	4 95 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:95:0
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
.Ltmp154:
	.loc	4 99 7 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:7
	lb	a0, -9(s0)
	.loc	4 99 17 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:17
	bltz	a0, .LBB33_4
	j	.LBB33_1
.LBB33_1:
	.loc	4 99 27                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:27
	lw	a0, -16(s0)
	.loc	4 99 39                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:39
	bltz	a0, .LBB33_4
	j	.LBB33_2
.LBB33_2:
	.loc	4 99 49                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:49
	lw	a1, -16(s0)
	li	a0, 31
	.loc	4 99 63                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:63
	blt	a0, a1, .LBB33_4
	j	.LBB33_3
.LBB33_3:
	.loc	4 99 67                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:67
	lb	a1, -9(s0)
	.loc	4 99 93                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:93
	lw	a2, -16(s0)
	li	a0, 127
	.loc	4 99 84                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:84
	srl	a0, a0, a2
	.loc	4 99 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:5
	bge	a0, a1, .LBB33_5
	j	.LBB33_4
.LBB33_4:
	.loc	4 100 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:100:6
	lb	a0, -9(s0)
	.loc	4 99 5                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB33_6
.LBB33_5:
	.loc	4 102 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:102:6
	lb	a0, -9(s0)
	.loc	4 102 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:102:20
	lw	a1, -16(s0)
	.loc	4 102 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:102:11
	sll	a0, a0, a1
	.loc	4 99 5 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:99:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB33_6
.LBB33_6:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 97 3                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:97:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 97 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:97:3
	addi	sp, sp, 32
	ret
.Ltmp155:
.Lfunc_end33:
	.size	safe_lshift_func_int8_t_s_s, .Lfunc_end33-safe_lshift_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint32_t_u_u
	.type	safe_rshift_func_uint32_t_u_u,@function
safe_rshift_func_uint32_t_u_u:          # @safe_rshift_func_uint32_t_u_u
.Lfunc_begin34:
	.loc	4 832 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:832:0
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
.Ltmp156:
	.loc	4 836 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:21
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 836 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	bltu	a0, a1, .LBB34_2
	j	.LBB34_1
.LBB34_1:
	.loc	4 837 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:837:6
	lw	a0, -12(s0)
	.loc	4 836 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB34_3
.LBB34_2:
	.loc	4 839 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:6
	lw	a0, -12(s0)
	.loc	4 839 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:29
	lw	a1, -16(s0)
	.loc	4 839 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:839:11
	srl	a0, a0, a1
	.loc	4 836 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:836:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB34_3
.LBB34_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 834 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:834:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 834 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:834:3
	addi	sp, sp, 32
	ret
.Ltmp157:
.Lfunc_end34:
	.size	safe_rshift_func_uint32_t_u_u, .Lfunc_end34-safe_rshift_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int8_t_s_u
	.type	safe_rshift_func_int8_t_s_u,@function
safe_rshift_func_int8_t_s_u:            # @safe_rshift_func_int8_t_s_u
.Lfunc_begin35:
	.loc	4 131 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:131:0
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
.Ltmp158:
	.loc	4 135 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:7
	lb	a0, -9(s0)
	.loc	4 135 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:17
	bltz	a0, .LBB35_2
	j	.LBB35_1
.LBB35_1:
	.loc	4 135 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:36
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 135 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	bltu	a0, a1, .LBB35_3
	j	.LBB35_2
.LBB35_2:
	.loc	4 136 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:136:6
	lb	a0, -9(s0)
	.loc	4 135 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB35_4
.LBB35_3:
	.loc	4 138 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:6
	lb	a0, -9(s0)
	.loc	4 138 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:29
	lw	a1, -16(s0)
	.loc	4 138 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:138:11
	sra	a0, a0, a1
	.loc	4 135 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:135:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB35_4
.LBB35_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 133 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:133:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 133 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:133:3
	addi	sp, sp, 32
	ret
.Ltmp159:
.Lfunc_end35:
	.size	safe_rshift_func_int8_t_s_u, .Lfunc_end35-safe_rshift_func_int8_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int16_t_s_s
	.type	safe_lshift_func_int16_t_s_s,@function
safe_lshift_func_int16_t_s_s:           # @safe_lshift_func_int16_t_s_s
.Lfunc_begin36:
	.loc	4 225 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:225:0
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
.Ltmp160:
	.loc	4 229 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:7
	lh	a0, -10(s0)
	.loc	4 229 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:17
	bltz	a0, .LBB36_4
	j	.LBB36_1
.LBB36_1:
	.loc	4 229 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:27
	lw	a0, -16(s0)
	.loc	4 229 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:39
	bltz	a0, .LBB36_4
	j	.LBB36_2
.LBB36_2:
	.loc	4 229 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:49
	lw	a1, -16(s0)
	li	a0, 31
	.loc	4 229 63                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:63
	blt	a0, a1, .LBB36_4
	j	.LBB36_3
.LBB36_3:
	.loc	4 229 67                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:67
	lh	a1, -10(s0)
	.loc	4 229 94                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:94
	lw	a2, -16(s0)
	lui	a0, 8
	addi	a0, a0, -1
	.loc	4 229 85                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:85
	srl	a0, a0, a2
	.loc	4 229 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:5
	bge	a0, a1, .LBB36_5
	j	.LBB36_4
.LBB36_4:
	.loc	4 230 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:230:6
	lh	a0, -10(s0)
	.loc	4 229 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB36_6
.LBB36_5:
	.loc	4 232 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:232:6
	lh	a0, -10(s0)
	.loc	4 232 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:232:20
	lw	a1, -16(s0)
	.loc	4 232 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:232:11
	sll	a0, a0, a1
	.loc	4 229 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:229:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB36_6
.LBB36_6:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 227 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:227:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 227 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:227:3
	addi	sp, sp, 32
	ret
.Ltmp161:
.Lfunc_end36:
	.size	safe_lshift_func_int16_t_s_s, .Lfunc_end36-safe_lshift_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_add_func_int8_t_s_s
	.type	safe_add_func_int8_t_s_s,@function
safe_add_func_int8_t_s_s:               # @safe_add_func_int8_t_s_s
.Lfunc_begin37:
	.loc	4 29 0 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:29:0
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
.Ltmp162:
	.loc	4 38 6 prologue_end             # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:6
	lbu	a0, -9(s0)
	.loc	4 38 12 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:12
	lbu	a1, -10(s0)
	.loc	4 38 10                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:38:10
	add	a0, a0, a1
	.loc	4 31 3 is_stmt 1                # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:31:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 31 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:31:3
	addi	sp, sp, 16
	ret
.Ltmp163:
.Lfunc_end37:
	.size	safe_add_func_int8_t_s_s, .Lfunc_end37-safe_add_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int8_t_s_s
	.type	safe_rshift_func_int8_t_s_s,@function
safe_rshift_func_int8_t_s_s:            # @safe_rshift_func_int8_t_s_s
.Lfunc_begin38:
	.loc	4 119 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:119:0
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
.Ltmp164:
	.loc	4 123 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:7
	lb	a0, -9(s0)
	.loc	4 123 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:17
	bltz	a0, .LBB38_3
	j	.LBB38_1
.LBB38_1:
	.loc	4 123 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:27
	lw	a0, -16(s0)
	.loc	4 123 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:39
	bltz	a0, .LBB38_3
	j	.LBB38_2
.LBB38_2:
	.loc	4 123 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:49
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 123 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	blt	a0, a1, .LBB38_4
	j	.LBB38_3
.LBB38_3:
	.loc	4 124 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:124:6
	lb	a0, -9(s0)
	.loc	4 123 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB38_5
.LBB38_4:
	.loc	4 126 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:6
	lb	a0, -9(s0)
	.loc	4 126 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:20
	lw	a1, -16(s0)
	.loc	4 126 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:126:11
	sra	a0, a0, a1
	.loc	4 123 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:123:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB38_5
.LBB38_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 121 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:121:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 121 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:121:3
	addi	sp, sp, 32
	ret
.Ltmp165:
.Lfunc_end38:
	.size	safe_rshift_func_int8_t_s_s, .Lfunc_end38-safe_rshift_func_int8_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int64_t_s_u
	.type	safe_rshift_func_int64_t_s_u,@function
safe_rshift_func_int64_t_s_u:           # @safe_rshift_func_int64_t_s_u
.Lfunc_begin39:
	.loc	4 522 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:522:0
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
.Ltmp166:
	.loc	4 526 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:7
	lw	a0, -12(s0)
	.loc	4 526 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:17
	bltz	a0, .LBB39_2
	j	.LBB39_1
.LBB39_1:
	.loc	4 526 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:36
	lw	a0, -20(s0)
	li	a1, 32
	.loc	4 526 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:5
	bltu	a0, a1, .LBB39_3
	j	.LBB39_2
.LBB39_2:
	.loc	4 527 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:527:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 526 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB39_6
.LBB39_3:
	.loc	4 529 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:529:6
	lw	a3, -12(s0)
	lw	a1, -16(s0)
	.loc	4 529 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:529:29
	lw	a0, -20(s0)
	.loc	4 529 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:529:11
	srl	a1, a1, a0
	not	a4, a0
	slli	a2, a3, 1
	sll	a2, a2, a4
	or	a2, a2, a1
	sra	a1, a3, a0
	sw	a1, -44(s0)                     # 4-byte Folded Spill
	addi	a0, a0, -32
	srai	a3, a3, 31
	sw	a3, -40(s0)                     # 4-byte Folded Spill
	sw	a2, -36(s0)                     # 4-byte Folded Spill
	sw	a1, -32(s0)                     # 4-byte Folded Spill
	bltz	a0, .LBB39_5
# %bb.4:
	.loc	4 0 11                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:11
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	lw	a1, -44(s0)                     # 4-byte Folded Reload
	sw	a1, -36(s0)                     # 4-byte Folded Spill
	sw	a0, -32(s0)                     # 4-byte Folded Spill
.LBB39_5:
	.loc	4 529 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:529:11
	lw	a1, -36(s0)                     # 4-byte Folded Reload
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	.loc	4 526 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:526:5
	sw	a0, -24(s0)                     # 4-byte Folded Spill
	j	.LBB39_6
.LBB39_6:
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	lw	a1, -24(s0)                     # 4-byte Folded Reload
	.loc	4 524 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:524:3
	lw	ra, 44(sp)                      # 4-byte Folded Reload
	lw	s0, 40(sp)                      # 4-byte Folded Reload
	.loc	4 524 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:524:3
	addi	sp, sp, 48
	ret
.Ltmp167:
.Lfunc_end39:
	.size	safe_rshift_func_int64_t_s_u, .Lfunc_end39-safe_rshift_func_int64_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_int16_t_s_s
	.type	safe_rshift_func_int16_t_s_s,@function
safe_rshift_func_int16_t_s_s:           # @safe_rshift_func_int16_t_s_s
.Lfunc_begin40:
	.loc	4 249 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:249:0
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
.Ltmp168:
	.loc	4 253 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:7
	lh	a0, -10(s0)
	.loc	4 253 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:17
	bltz	a0, .LBB40_3
	j	.LBB40_1
.LBB40_1:
	.loc	4 253 27                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:27
	lw	a0, -16(s0)
	.loc	4 253 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:39
	bltz	a0, .LBB40_3
	j	.LBB40_2
.LBB40_2:
	.loc	4 253 49                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:49
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 253 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:5
	blt	a0, a1, .LBB40_4
	j	.LBB40_3
.LBB40_3:
	.loc	4 254 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:254:6
	lh	a0, -10(s0)
	.loc	4 253 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB40_5
.LBB40_4:
	.loc	4 256 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:256:6
	lh	a0, -10(s0)
	.loc	4 256 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:256:20
	lw	a1, -16(s0)
	.loc	4 256 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:256:11
	sra	a0, a0, a1
	.loc	4 253 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:253:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB40_5
.LBB40_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 251 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:251:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 251 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:251:3
	addi	sp, sp, 32
	ret
.Ltmp169:
.Lfunc_end40:
	.size	safe_rshift_func_int16_t_s_s, .Lfunc_end40-safe_rshift_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint8_t_u_s
	.type	safe_rshift_func_uint8_t_u_s,@function
safe_rshift_func_uint8_t_u_s:           # @safe_rshift_func_uint8_t_u_s
.Lfunc_begin41:
	.loc	4 616 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:616:0
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
.Ltmp170:
	.loc	4 620 13 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:13
	lw	a0, -16(s0)
	.loc	4 620 25 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:25
	bltz	a0, .LBB41_2
	j	.LBB41_1
.LBB41_1:
	.loc	4 620 35                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:35
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 620 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	blt	a0, a1, .LBB41_3
	j	.LBB41_2
.LBB41_2:
	.loc	4 621 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:621:6
	lbu	a0, -9(s0)
	.loc	4 620 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB41_4
.LBB41_3:
	.loc	4 623 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:6
	lbu	a0, -9(s0)
	.loc	4 623 20 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:20
	lw	a1, -16(s0)
	.loc	4 623 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:623:11
	srl	a0, a0, a1
	.loc	4 620 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:620:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB41_4
.LBB41_4:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 618 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:618:3
	andi	a0, a0, 255
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 618 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:618:3
	addi	sp, sp, 32
	ret
.Ltmp171:
.Lfunc_end41:
	.size	safe_rshift_func_uint8_t_u_s, .Lfunc_end41-safe_rshift_func_uint8_t_u_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_div_func_int16_t_s_s
	.type	safe_div_func_int16_t_s_s,@function
safe_div_func_int16_t_s_s:              # @safe_div_func_int16_t_s_s
.Lfunc_begin42:
	.loc	4 213 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:213:0
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
.Ltmp172:
	.loc	4 217 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:7
	lh	a0, -12(s0)
	.loc	4 217 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:17
	beqz	a0, .LBB42_3
	j	.LBB42_1
.LBB42_1:
	.loc	4 217 22                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:22
	lh	a0, -10(s0)
	lui	a1, 1048568
	.loc	4 217 40                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:40
	bne	a0, a1, .LBB42_4
	j	.LBB42_2
.LBB42_2:
	.loc	4 217 44                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:44
	lh	a0, -12(s0)
	li	a1, -1
	.loc	4 217 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	bne	a0, a1, .LBB42_4
	j	.LBB42_3
.LBB42_3:
	.loc	4 218 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:218:6
	lh	a0, -10(s0)
	.loc	4 217 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB42_5
.LBB42_4:
	.loc	4 220 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:6
	lh	a0, -10(s0)
	.loc	4 220 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:12
	lh	a1, -12(s0)
	.loc	4 220 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:220:10
	div	a0, a0, a1
	.loc	4 217 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:217:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB42_5
.LBB42_5:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	4 215 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:215:3
	slli	a0, a0, 16
	srai	a0, a0, 16
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 215 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:215:3
	addi	sp, sp, 16
	ret
.Ltmp173:
.Lfunc_end42:
	.size	safe_div_func_int16_t_s_s, .Lfunc_end42-safe_div_func_int16_t_s_s
	.cfi_endproc
                                        # -- End function
	.globl	func_80                         # -- Begin function func_80
	.p2align	1
	.type	func_80,@function
func_80:                                # @func_80
.Lfunc_begin43:
	.loc	2 250 0 is_stmt 1               # rnd_output1.c:250:0
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -1168
	.cfi_def_cfa_offset 1168
	sw	ra, 1164(sp)                    # 4-byte Folded Spill
	sw	s0, 1160(sp)                    # 4-byte Folded Spill
	.cfi_offset ra, -4
	.cfi_offset s0, -8
	addi	s0, sp, 1168
	.cfi_def_cfa s0, 0
                                        # kill: def $x15 killed $x14
                                        # kill: def $x15 killed $x10
	sb	a0, -14(s0)
	sw	a1, -20(s0)
	sw	a2, -24(s0)
	sw	a3, -28(s0)
	sh	a4, -30(s0)
.Ltmp174:
	.loc	2 251 20 prologue_end           # rnd_output1.c:251:20
	lui	a0, %hi(g_3)
	addi	a0, a0, %lo(g_3)
	sw	a0, -36(s0)
	li	a0, 0
	.loc	2 252 21                        # rnd_output1.c:252:21
	sw	a0, -1056(s0)                   # 4-byte Folded Spill
	sw	a0, -40(s0)
	.loc	2 253 14                        # rnd_output1.c:253:14
	lui	a1, %hi(g_111)
	addi	a1, a1, %lo(g_111)
	sw	a1, -44(s0)
	.loc	2 254 15                        # rnd_output1.c:254:15
	lui	a1, %hi(g_89)
	addi	a1, a1, %lo(g_89)
	sw	a1, -48(s0)
	lui	a1, 1
	addi	a1, a1, 1785
	.loc	2 255 13                        # rnd_output1.c:255:13
	sh	a1, -50(s0)
	.loc	2 256 14                        # rnd_output1.c:256:14
	sw	a0, -56(s0)
	.loc	2 257 14                        # rnd_output1.c:257:14
	lui	a0, %hi(.L__const.func_80.l_115)
	addi	a1, a0, %lo(.L__const.func_80.l_115)
	addi	a0, s0, -632
	li	a2, 576
	call	memcpy@plt
	lw	a1, -1056(s0)                   # 4-byte Folded Reload
	.loc	2 258 15                        # rnd_output1.c:258:15
	lui	a0, %hi(g_123)
	addi	a0, a0, %lo(g_123)
	sw	a0, -636(s0)
	.loc	2 259 22                        # rnd_output1.c:259:22
	sw	a1, -640(s0)
	.loc	2 261 15                        # rnd_output1.c:261:15
	lw	a0, -36(s0)
	.loc	2 261 7 is_stmt 0               # rnd_output1.c:261:7
	lui	a2, %hi(g_99)
	lw	a2, %lo(g_99)(a2)
	.loc	2 261 13                        # rnd_output1.c:261:13
	sw	a0, 0(a2)
	.loc	2 262 52 is_stmt 1              # rnd_output1.c:262:52
	lui	a0, %hi(g_69)
	addi	a0, a0, %lo(g_69)
	lw	a0, 32(a0)
	.loc	2 262 55 is_stmt 0              # rnd_output1.c:262:55
	sw	a1, -1052(s0)                   # 4-byte Folded Spill
	beqz	a0, .LBB43_2
	j	.LBB43_1
.LBB43_1:
	.loc	2 262 61                        # rnd_output1.c:262:61
	lw	a0, -36(s0)
	.loc	2 262 60                        # rnd_output1.c:262:60
	lw	a0, 0(a0)
	.loc	2 262 55                        # rnd_output1.c:262:55
	addi	a0, a0, -1
	snez	a0, a0
	sw	a0, -1052(s0)                   # 4-byte Folded Spill
	j	.LBB43_2
.LBB43_2:
	.loc	2 0 0                           # rnd_output1.c:0:0
	lw	a0, -1052(s0)                   # 4-byte Folded Reload
	.loc	2 262 55                        # rnd_output1.c:262:55
	andi	a0, a0, 1
	.loc	2 262 234                       # rnd_output1.c:262:234
	lw	a0, -36(s0)
	.loc	2 262 233                       # rnd_output1.c:262:233
	lhu	a0, 0(a0)
	.loc	2 262 267                       # rnd_output1.c:262:267
	lui	a1, %hi(g_89)
	lhu	a3, %lo(g_89)(a1)
	.loc	2 262 257                       # rnd_output1.c:262:257
	lw	a2, -44(s0)
	.loc	2 262 264                       # rnd_output1.c:262:264
	lh	a1, 0(a2)
	xor	a1, a1, a3
	sh	a1, 0(a2)
	.loc	2 262 254                       # rnd_output1.c:262:254
	slli	a1, a1, 16
	srai	a1, a1, 16
	.loc	2 262 275                       # rnd_output1.c:262:275
	lhu	a2, -30(s0)
	.loc	2 262 273                       # rnd_output1.c:262:273
	slt	a1, a1, a2
	.loc	2 262 244                       # rnd_output1.c:262:244
	lw	a2, -48(s0)
	.loc	2 262 251                       # rnd_output1.c:262:251
	sh	a1, 0(a2)
	.loc	2 262 202                       # rnd_output1.c:262:202
	call	safe_rshift_func_uint16_t_u_u
	mv	a1, a0
	.loc	2 262 289                       # rnd_output1.c:262:289
	lui	a0, %hi(g_97)
	lw	a0, %lo(g_97)(a0)
	.loc	2 262 288                       # rnd_output1.c:262:288
	lw	a0, 0(a0)
	li	a2, 1
	.loc	2 262 296                       # rnd_output1.c:262:296
	sw	a2, -1060(s0)                   # 4-byte Folded Spill
	bge	a0, a1, .LBB43_8
	j	.LBB43_3
.LBB43_3:
	.loc	2 262 302                       # rnd_output1.c:262:302
	lui	a0, %hi(g_3)
	lw	a0, %lo(g_3)(a0)
	li	a1, 1
	.loc	2 262 306                       # rnd_output1.c:262:306
	sw	a1, -1064(s0)                   # 4-byte Folded Spill
	bnez	a0, .LBB43_5
	j	.LBB43_4
.LBB43_4:
	.loc	2 0 306                         # rnd_output1.c:0:306
	li	a0, 1
	.loc	2 262 306                       # rnd_output1.c:262:306
	sw	a0, -1064(s0)                   # 4-byte Folded Spill
	j	.LBB43_5
.LBB43_5:
	.loc	2 0 306                         # rnd_output1.c:0:306
	lw	a0, -1064(s0)                   # 4-byte Folded Reload
	.loc	2 262 322                       # rnd_output1.c:262:322
	lw	a1, -36(s0)
	.loc	2 262 321                       # rnd_output1.c:262:321
	lw	a1, 0(a1)
	.loc	2 262 318                       # rnd_output1.c:262:318
	and	a0, a0, a1
	andi	a0, a0, 1
	li	a1, 1
	.loc	2 262 329                       # rnd_output1.c:262:329
	sw	a1, -1068(s0)                   # 4-byte Folded Spill
	bnez	a0, .LBB43_7
	j	.LBB43_6
.LBB43_6:
	.loc	2 0 329                         # rnd_output1.c:0:329
	li	a0, 1
	.loc	2 262 329                       # rnd_output1.c:262:329
	sw	a0, -1068(s0)                   # 4-byte Folded Spill
	j	.LBB43_7
.LBB43_7:
	.loc	2 0 329                         # rnd_output1.c:0:329
	lw	a0, -1068(s0)                   # 4-byte Folded Reload
	.loc	2 262 296                       # rnd_output1.c:262:296
	sw	a0, -1060(s0)                   # 4-byte Folded Spill
	j	.LBB43_8
.LBB43_8:
	.loc	2 0 296                         # rnd_output1.c:0:296
	lw	a0, -1060(s0)                   # 4-byte Folded Reload
	.loc	2 262 296                       # rnd_output1.c:262:296
	andi	a0, a0, 1
	.loc	2 262 341                       # rnd_output1.c:262:341
	lui	a1, %hi(g_2)
	addi	a1, a1, %lo(g_2)
	lw	a1, 116(a1)
	.loc	2 262 171                       # rnd_output1.c:262:171
	call	safe_lshift_func_int8_t_s_u
	.loc	2 262 359                       # rnd_output1.c:262:359
	lh	a1, -50(s0)
	.loc	2 262 356                       # rnd_output1.c:262:356
	xor	a0, a0, a1
	snez	a0, a0
	.loc	2 262 371                       # rnd_output1.c:262:371
	lw	a1, -36(s0)
	.loc	2 262 370                       # rnd_output1.c:262:370
	lw	a1, 0(a1)
	.loc	2 262 366                       # rnd_output1.c:262:366
	slt	a0, a0, a1
	xori	a0, a0, 1
	.loc	2 262 379                       # rnd_output1.c:262:379
	lbu	a1, -30(s0)
	.loc	2 262 142                       # rnd_output1.c:262:142
	call	safe_sub_func_uint8_t_u_u
	.loc	2 262 139                       # rnd_output1.c:262:139
	lui	a1, %hi(g_13)
	sw	a0, %lo(g_13)(a1)
	.loc	2 262 131                       # rnd_output1.c:262:131
	lui	a1, %hi(g_116)
	sw	a0, %lo(g_116)(a1)
	.loc	2 262 389                       # rnd_output1.c:262:389
	lui	a1, %hi(g_3)
	lw	a1, %lo(g_3)(a1)
	.loc	2 262 95                        # rnd_output1.c:262:95
	call	safe_rshift_func_int32_t_s_u
	.loc	2 262 400                       # rnd_output1.c:262:400
	lui	a0, %hi(g_92)
	lw	a0, %lo(g_92)(a0)
	.loc	2 262 399                       # rnd_output1.c:262:399
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 262 410                       # rnd_output1.c:262:410
	lw	a2, -36(s0)
	.loc	2 262 409                       # rnd_output1.c:262:409
	lw	a2, 0(a2)
	srai	a3, a2, 31
	.loc	2 262 15                        # rnd_output1.c:262:15
	call	safe_mul_func_int64_t_s_s
	mv	a2, a0
	.loc	2 262 11                        # rnd_output1.c:262:11
	lui	a1, %hi(g_117)
	lw	a0, %lo(g_117)(a1)
	or	a0, a0, a2
	sw	a0, %lo(g_117)(a1)
	lui	a0, 16
	addi	a1, a0, -1
	li	a0, 4
	.loc	2 263 21 is_stmt 1              # rnd_output1.c:263:21
	call	safe_mul_func_uint16_t_u_u
	.loc	2 263 126 is_stmt 0             # rnd_output1.c:263:126
	sw	a0, -1080(s0)                   # 4-byte Folded Spill
	lui	a1, %hi(g_93)
	lw	a0, %lo(g_93+4)(a1)
	lw	a2, %lo(g_93)(a1)
	.loc	2 263 133                       # rnd_output1.c:263:133
	lb	a3, -14(s0)
	srai	a1, a3, 31
	.loc	2 263 131                       # rnd_output1.c:263:131
	sltu	a2, a2, a3
	slt	a3, a0, a1
	sw	a3, -1076(s0)                   # 4-byte Folded Spill
	sw	a2, -1072(s0)                   # 4-byte Folded Spill
	beq	a0, a1, .LBB43_10
# %bb.9:
	.loc	2 0 131                         # rnd_output1.c:0:131
	lw	a0, -1076(s0)                   # 4-byte Folded Reload
	sw	a0, -1072(s0)                   # 4-byte Folded Spill
.LBB43_10:
	.loc	2 263 131                       # rnd_output1.c:263:131
	lw	a0, -1072(s0)                   # 4-byte Folded Reload
	.loc	2 263 153                       # rnd_output1.c:263:153
	lhu	a1, -30(s0)
	.loc	2 263 125                       # rnd_output1.c:263:125
	and	a0, a0, a1
	.loc	2 263 144                       # rnd_output1.c:263:144
	lw	a2, -636(s0)
	li	a3, 0
	.loc	2 263 151                       # rnd_output1.c:263:151
	sw	a3, -1084(s0)                   # 4-byte Folded Spill
	sw	a3, 4(a2)
	sw	a1, 0(a2)
	lui	a1, 5
	addi	a1, a1, 664
	.loc	2 263 97                        # rnd_output1.c:263:97
	call	safe_add_func_uint16_t_u_u
	lw	a1, -1084(s0)                   # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 263 94                        # rnd_output1.c:263:94
	lw	a0, -1080(s0)                   # 4-byte Folded Reload
	xori	a2, a2, 188
	.loc	2 263 85                        # rnd_output1.c:263:85
	lui	a3, %hi(g_111)
	sh	a2, %lo(g_111)(a3)
	.loc	2 263 78                        # rnd_output1.c:263:78
	slli	a2, a2, 16
	srai	a2, a2, 16
	.loc	2 263 177                       # rnd_output1.c:263:177
	lui	a3, %hi(g_8)
	addi	a3, a3, %lo(g_8)
	lhu	a3, 482(a3)
	.loc	2 263 190                       # rnd_output1.c:263:190
	seqz	a3, a3
	.loc	2 263 173                       # rnd_output1.c:263:173
	xor	a2, a2, a3
	snez	a2, a2
	lui	a3, 4
	addi	a3, a3, 662
	.loc	2 263 75                        # rnd_output1.c:263:75
	or	a2, a2, a3
	.loc	2 263 63                        # rnd_output1.c:263:63
	slt	a0, a0, a2
	xori	a3, a0, 1
	.loc	2 263 16                        # rnd_output1.c:263:16
	lui	a0, %hi(g_69)
	addi	a2, a0, %lo(g_69)
	lw	a0, 32(a2)
	and	a0, a0, a3
	sw	a0, 32(a2)
.Ltmp175:
	.loc	2 264 10 is_stmt 1              # rnd_output1.c:264:10
	lui	a0, %hi(g_124)
	lw	a0, %lo(g_124)(a0)
	sw	a0, -656(s0)
	.loc	2 264 61 is_stmt 0              # rnd_output1.c:264:61
	lw	a0, -640(s0)
	.loc	2 264 58                        # rnd_output1.c:264:58
	seqz	a0, a0
	li	a2, 56
	.loc	2 264 19                        # rnd_output1.c:264:19
	call	safe_rshift_func_int64_t_s_u
	.loc	2 264 16                        # rnd_output1.c:264:16
	or	a0, a0, a1
.Ltmp176:
	.loc	2 264 9                         # rnd_output1.c:264:9
	beqz	a0, .LBB43_62
	j	.LBB43_11
.LBB43_11:
	.loc	2 0 9                           # rnd_output1.c:0:9
	li	a0, 0
.Ltmp177:
	.loc	2 266 18 is_stmt 1              # rnd_output1.c:266:18
	sw	a0, -660(s0)
	sw	a0, -664(s0)
	lui	a0, 706106
	addi	a0, a0, 376
	sw	a0, -668(s0)
	lui	a0, 656166
	addi	a0, a0, -1043
	sw	a0, -672(s0)
	li	a0, 1
	.loc	2 267 17                        # rnd_output1.c:267:17
	sw	a0, -676(s0)
	addi	a0, s0, -40
	.loc	2 268 36                        # rnd_output1.c:268:36
	sw	a0, -680(s0)
	addi	a0, s0, -680
	.loc	2 269 37                        # rnd_output1.c:269:37
	sw	a0, -684(s0)
	.loc	2 269 9 is_stmt 0               # rnd_output1.c:269:9
	j	.LBB43_12
.LBB43_12:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB43_13 Depth 2
                                        #       Child Loop BB43_19 Depth 3
                                        #         Child Loop BB43_44 Depth 4
                                        #         Child Loop BB43_50 Depth 4
                                        #       Child Loop BB43_56 Depth 3
.Ltmp178:
	#DEBUG_LABEL: lbl_176
	.loc	2 271 20 is_stmt 1              # rnd_output1.c:271:20
	lui	a1, %hi(g_111)
	li	a0, 1
	sh	a0, %lo(g_111)(a1)
	.loc	2 271 14 is_stmt 0              # rnd_output1.c:271:14
	j	.LBB43_13
.LBB43_13:                              #   Parent Loop BB43_12 Depth=1
                                        # =>  This Loop Header: Depth=2
                                        #       Child Loop BB43_19 Depth 3
                                        #         Child Loop BB43_44 Depth 4
                                        #         Child Loop BB43_50 Depth 4
                                        #       Child Loop BB43_56 Depth 3
.Ltmp179:
	.loc	2 271 26                        # rnd_output1.c:271:26
	lui	a0, %hi(g_111)
	lh	a0, %lo(g_111)(a0)
.Ltmp180:
	.loc	2 271 9                         # rnd_output1.c:271:9
	bltz	a0, .LBB43_61
	j	.LBB43_14
.LBB43_14:                              #   in Loop: Header=BB43_13 Depth=2
.Ltmp181:
	.loc	2 273 22 is_stmt 1              # rnd_output1.c:273:22
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	addi	a0, a0, 288
	sw	a0, -688(s0)
	lui	a0, 533092
	addi	a0, a0, -1962
	.loc	2 274 21                        # rnd_output1.c:274:21
	sw	a0, -692(s0)
	.loc	2 275 29                        # rnd_output1.c:275:29
	lui	a0, %hi(.L__const.func_80.l_146)
	addi	a1, a0, %lo(.L__const.func_80.l_146)
	addi	a0, s0, -772
	li	a2, 80
	call	memcpy@plt
	.loc	2 276 22                        # rnd_output1.c:276:22
	lui	a0, %hi(.L__const.func_80.l_148)
	addi	a1, a0, %lo(.L__const.func_80.l_148)
	addi	a0, s0, -868
	li	a2, 96
	call	memcpy@plt
	lui	a0, 602420
	addi	a0, a0, -1141
	.loc	2 277 21                        # rnd_output1.c:277:21
	sw	a0, -872(s0)
	li	a0, 0
	.loc	2 278 22                        # rnd_output1.c:278:22
	sw	a0, -876(s0)
	.loc	2 279 22                        # rnd_output1.c:279:22
	lui	a0, %hi(g_152)
	addi	a0, a0, %lo(g_152)
	sw	a0, -880(s0)
	addi	a0, s0, -50
	.loc	2 280 22                        # rnd_output1.c:280:22
	sw	a0, -884(s0)
	.loc	2 282 85                        # rnd_output1.c:282:85
	lw	a1, -688(s0)
	.loc	2 282 92 is_stmt 0              # rnd_output1.c:282:92
	lw	a2, 4(a1)
	lw	a0, 0(a1)
	lui	a3, 665638
	addi	a3, a3, 921
	or	a0, a0, a3
	sw	a0, -1096(s0)                   # 4-byte Folded Spill
	lui	a3, 49920
	addi	a3, a3, 989
	or	a2, a2, a3
	sw	a2, -1092(s0)                   # 4-byte Folded Spill
	sw	a2, 4(a1)
	sw	a0, 0(a1)
	.loc	2 282 212                       # rnd_output1.c:282:212
	lw	a0, -692(s0)
	.loc	2 282 220                       # rnd_output1.c:282:220
	lui	a1, %hi(g_89)
	lhu	a1, %lo(g_89)(a1)
	.loc	2 282 218                       # rnd_output1.c:282:218
	and	a0, a0, a1
	.loc	2 282 179                       # rnd_output1.c:282:179
	call	safe_unary_minus_func_int32_t_s
	li	a0, 1
	mv	a1, a0
	.loc	2 282 243                       # rnd_output1.c:282:243
	sw	a1, -1088(s0)                   # 4-byte Folded Spill
	bnez	a0, .LBB43_16
	j	.LBB43_15
.LBB43_15:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 282 250                       # rnd_output1.c:282:250
	lw	a1, -636(s0)
	.loc	2 282 256                       # rnd_output1.c:282:256
	lw	a0, 4(a1)
	sw	a0, -1104(s0)                   # 4-byte Folded Spill
	lw	a2, 0(a1)
	sw	a2, -1100(s0)                   # 4-byte Folded Spill
	seqz	a3, a2
	sub	a0, a0, a3
	addi	a2, a2, -1
	sw	a2, 0(a1)
	sw	a0, 4(a1)
	.loc	2 282 315                       # rnd_output1.c:282:315
	lui	a0, %hi(g_89)
	lhu	a0, %lo(g_89)(a0)
	.loc	2 282 397                       # rnd_output1.c:282:397
	sw	a0, -1108(s0)                   # 4-byte Folded Spill
	lw	a0, -20(s0)
	.loc	2 282 396                       # rnd_output1.c:282:396
	lw	a1, 0(a0)
	.loc	2 282 393                       # rnd_output1.c:282:393
	sw	a1, -740(s0)
	addi	a0, s0, -672
	.loc	2 282 377                       # rnd_output1.c:282:377
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 282 357                       # rnd_output1.c:282:357
	sw	a0, -692(s0)
	.loc	2 282 407                       # rnd_output1.c:282:407
	lw	a1, -832(s0)
	.loc	2 282 324                       # rnd_output1.c:282:324
	call	safe_sub_func_int32_t_s_s
	mv	a1, a0
	.loc	2 282 421                       # rnd_output1.c:282:421
	lw	a0, -1108(s0)                   # 4-byte Folded Reload
	addi	a1, a1, -185
	snez	a1, a1
	.loc	2 282 320                       # rnd_output1.c:282:320
	and	a1, a1, a0
	.loc	2 282 311                       # rnd_output1.c:282:311
	lw	a0, -872(s0)
	xor	a0, a0, a1
	sw	a0, -872(s0)
	.loc	2 282 436                       # rnd_output1.c:282:436
	lw	a1, -800(s0)
	.loc	2 282 433                       # rnd_output1.c:282:433
	xor	a0, a0, a1
	seqz	a0, a0
	.loc	2 282 450                       # rnd_output1.c:282:450
	lhu	a1, -30(s0)
	.loc	2 282 276                       # rnd_output1.c:282:276
	call	safe_mul_func_uint32_t_u_u
	lw	a1, -1104(s0)                   # 4-byte Folded Reload
	mv	a2, a0
	.loc	2 282 266                       # rnd_output1.c:282:266
	lw	a0, -1100(s0)                   # 4-byte Folded Reload
	lw	a3, -880(s0)
	li	a4, 0
	.loc	2 282 273                       # rnd_output1.c:282:273
	sw	a4, 4(a3)
	sw	a2, 0(a3)
	.loc	2 282 260                       # rnd_output1.c:282:260
	xor	a0, a0, a2
	or	a0, a0, a1
	seqz	a0, a0
	.loc	2 282 243                       # rnd_output1.c:282:243
	sw	a0, -1088(s0)                   # 4-byte Folded Spill
	j	.LBB43_16
.LBB43_16:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 0 243                         # rnd_output1.c:0:243
	lw	a0, -1088(s0)                   # 4-byte Folded Reload
	.loc	2 282 465                       # rnd_output1.c:282:465
	lui	a0, %hi(g_92)
	lw	a0, %lo(g_92)(a0)
	.loc	2 282 464                       # rnd_output1.c:282:464
	lw	a1, 4(a0)
	lw	a0, 0(a0)
	.loc	2 282 473                       # rnd_output1.c:282:473
	lui	a2, %hi(g_8)
	addi	a2, a2, %lo(g_8)
	lw	a2, 404(a2)
	srai	a3, a2, 31
	.loc	2 282 134                       # rnd_output1.c:282:134
	call	safe_sub_func_int64_t_s_s
	lw	a3, -1096(s0)                   # 4-byte Folded Reload
	mv	a2, a0
	lw	a0, -1092(s0)                   # 4-byte Folded Reload
	sw	a2, -1120(s0)                   # 4-byte Folded Spill
                                        # kill: def $x12 killed $x11
	.loc	2 282 124                       # rnd_output1.c:282:124
	lw	a1, -1120(s0)                   # 4-byte Folded Reload
	lw	a2, -884(s0)
	.loc	2 282 131                       # rnd_output1.c:282:131
	sh	a1, 0(a2)
	.loc	2 282 121                       # rnd_output1.c:282:121
	slli	a1, a1, 16
	srai	a2, a1, 16
	lui	a4, 12
	addi	a4, a4, 215
	.loc	2 282 489                       # rnd_output1.c:282:489
	xor	a2, a2, a4
	.loc	2 282 120                       # rnd_output1.c:282:120
	srai	a1, a1, 31
	.loc	2 282 117                       # rnd_output1.c:282:117
	slt	a4, a1, a0
	xori	a4, a4, 1
	sw	a4, -1116(s0)                   # 4-byte Folded Spill
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sw	a2, -1112(s0)                   # 4-byte Folded Spill
	beq	a0, a1, .LBB43_18
# %bb.17:                               #   in Loop: Header=BB43_13 Depth=2
	.loc	2 0 117                         # rnd_output1.c:0:117
	lw	a0, -1116(s0)                   # 4-byte Folded Reload
	sw	a0, -1112(s0)                   # 4-byte Folded Spill
.LBB43_18:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 282 117                       # rnd_output1.c:282:117
	lw	a1, -1112(s0)                   # 4-byte Folded Reload
	.loc	2 282 504                       # rnd_output1.c:282:504
	lhu	a0, -30(s0)
	.loc	2 282 501                       # rnd_output1.c:282:501
	slt	a0, a0, a1
	xori	a0, a0, 1
	.loc	2 282 511                       # rnd_output1.c:282:511
	lw	a1, -832(s0)
	.loc	2 282 51                        # rnd_output1.c:282:51
	call	safe_lshift_func_int32_t_s_u
	mv	a1, a0
	.loc	2 282 527                       # rnd_output1.c:282:527
	lhu	a0, -30(s0)
	.loc	2 282 525                       # rnd_output1.c:282:525
	slt	a0, a0, a1
	.loc	2 282 542                       # rnd_output1.c:282:542
	lui	a1, %hi(g_69)
	addi	a1, a1, %lo(g_69)
	lw	a2, 36(a1)
	li	a3, 0
	.loc	2 282 23                        # rnd_output1.c:282:23
	sw	a3, -1124(s0)                   # 4-byte Folded Spill
	mv	a1, a3
	call	safe_mod_func_int64_t_s_s
                                        # kill: def $x12 killed $x10
	lw	a0, -1124(s0)                   # 4-byte Folded Reload
	.loc	2 282 18                        # rnd_output1.c:282:18
	lui	a1, %hi(g_13)
	sw	a0, %lo(g_13)(a1)
.Ltmp182:
	.loc	2 283 27 is_stmt 1              # rnd_output1.c:283:27
	sb	a0, -672(s0)
	.loc	2 283 18 is_stmt 0              # rnd_output1.c:283:18
	j	.LBB43_19
.LBB43_19:                              #   Parent Loop BB43_12 Depth=1
                                        #     Parent Loop BB43_13 Depth=2
                                        # =>    This Loop Header: Depth=3
                                        #         Child Loop BB43_44 Depth 4
                                        #         Child Loop BB43_50 Depth 4
.Ltmp183:
	.loc	2 283 39                        # rnd_output1.c:283:39
	lb	a1, -672(s0)
	li	a0, 1
.Ltmp184:
	.loc	2 283 13                        # rnd_output1.c:283:13
	blt	a0, a1, .LBB43_55
	j	.LBB43_20
.LBB43_20:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 13                          # rnd_output1.c:0:13
	li	a0, 117
.Ltmp185:
	.loc	2 285 25 is_stmt 1              # rnd_output1.c:285:25
	sb	a0, -893(s0)
	li	a0, 1
	.loc	2 286 25                        # rnd_output1.c:286:25
	sw	a0, -900(s0)
.Ltmp186:
	.loc	2 287 30                        # rnd_output1.c:287:30
	lbu	a0, -893(s0)
	.loc	2 287 28 is_stmt 0              # rnd_output1.c:287:28
	sw	a0, -676(s0)
.Ltmp187:
	.loc	2 287 21                        # rnd_output1.c:287:21
	beqz	a0, .LBB43_29
	j	.LBB43_21
.LBB43_21:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 21                          # rnd_output1.c:0:21
	li	a0, 7
.Ltmp188:
	.loc	2 289 31 is_stmt 1              # rnd_output1.c:289:31
	sb	a0, -14(s0)
	.loc	2 289 26 is_stmt 0              # rnd_output1.c:289:26
	j	.LBB43_22
.LBB43_22:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp189:
	.loc	2 289 37                        # rnd_output1.c:289:37
	lb	a1, -14(s0)
	li	a0, 0
.Ltmp190:
	.loc	2 289 21                        # rnd_output1.c:289:21
	bge	a0, a1, .LBB43_28
	j	.LBB43_23
.LBB43_23:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp191:
	.loc	2 292 29 is_stmt 1              # rnd_output1.c:292:29
	lhu	a0, -30(s0)
.Ltmp192:
	.loc	2 292 29 is_stmt 0              # rnd_output1.c:292:29
	beqz	a0, .LBB43_25
	j	.LBB43_24
.LBB43_24:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp193:
	.loc	2 293 29 is_stmt 1              # rnd_output1.c:293:29
	j	.LBB43_28
.Ltmp194:
.LBB43_25:
	.loc	2 294 67                        # rnd_output1.c:294:67
	lb	a0, -672(s0)
	sw	a0, -1136(s0)                   # 4-byte Folded Spill
	srai	a0, a0, 31
	.loc	2 294 83 is_stmt 0              # rnd_output1.c:294:83
	sw	a0, -1132(s0)                   # 4-byte Folded Spill
	lw	a1, -884(s0)
	.loc	2 294 80                        # rnd_output1.c:294:80
	lui	a0, %hi(g_111)
	addi	a0, a0, %lo(g_111)
	li	a2, 1
	.loc	2 294 90                        # rnd_output1.c:294:90
	sw	a2, -1128(s0)                   # 4-byte Folded Spill
	beq	a0, a1, .LBB43_27
	j	.LBB43_26
.LBB43_26:
	.loc	2 0 90                          # rnd_output1.c:0:90
	li	a0, 1
	.loc	2 294 90                        # rnd_output1.c:294:90
	sw	a0, -1128(s0)                   # 4-byte Folded Spill
	j	.LBB43_27
.LBB43_27:
	.loc	2 0 90                          # rnd_output1.c:0:90
	lw	a1, -1132(s0)                   # 4-byte Folded Reload
	lw	a0, -1136(s0)                   # 4-byte Folded Reload
	lw	a2, -1128(s0)                   # 4-byte Folded Reload
	.loc	2 294 71                        # rnd_output1.c:294:71
	andi	a2, a2, 1
	li	a3, 0
	.loc	2 294 34                        # rnd_output1.c:294:34
	call	safe_div_func_uint64_t_u_u
	.loc	2 294 31                        # rnd_output1.c:294:31
	sw	a0, -900(s0)
	.loc	2 295 32 is_stmt 1              # rnd_output1.c:295:32
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	lbu	a0, 288(a0)
	.loc	2 295 25 is_stmt 0              # rnd_output1.c:295:25
	sb	a0, -13(s0)
	j	.LBB43_72
.Ltmp195:
.LBB43_28:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 297 17 is_stmt 1              # rnd_output1.c:297:17
	j	.LBB43_43
.Ltmp196:
.LBB43_29:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 17 is_stmt 0                # rnd_output1.c:0:17
	li	a0, 1
.Ltmp197:
	.loc	2 300 35 is_stmt 1              # rnd_output1.c:300:35
	sb	a0, -913(s0)
.Ltmp198:
	.loc	2 301 32                        # rnd_output1.c:301:32
	sw	a0, -676(s0)
	.loc	2 301 26 is_stmt 0              # rnd_output1.c:301:26
	j	.LBB43_30
.LBB43_30:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp199:
	.loc	2 301 38                        # rnd_output1.c:301:38
	lw	a0, -676(s0)
.Ltmp200:
	.loc	2 301 21                        # rnd_output1.c:301:21
	bltz	a0, .LBB43_40
	j	.LBB43_31
.LBB43_31:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 21                          # rnd_output1.c:0:21
	li	a0, 50
.Ltmp201:
	.loc	2 303 32 is_stmt 1              # rnd_output1.c:303:32
	sb	a0, -914(s0)
.Ltmp202:
	.loc	2 305 29                        # rnd_output1.c:305:29
	lbu	a0, -14(s0)
.Ltmp203:
	.loc	2 305 29 is_stmt 0              # rnd_output1.c:305:29
	beqz	a0, .LBB43_33
	j	.LBB43_32
.LBB43_32:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp204:
	.loc	2 306 29 is_stmt 1              # rnd_output1.c:306:29
	j	.LBB43_40
.Ltmp205:
.LBB43_33:                              #   in Loop: Header=BB43_12 Depth=1
	.loc	2 307 29                        # rnd_output1.c:307:29
	lhu	a0, -30(s0)
.Ltmp206:
	.loc	2 307 29 is_stmt 0              # rnd_output1.c:307:29
	beqz	a0, .LBB43_35
	j	.LBB43_34
.LBB43_34:                              #   in Loop: Header=BB43_12 Depth=1
.Ltmp207:
	.loc	2 308 29 is_stmt 1              # rnd_output1.c:308:29
	j	.LBB43_12
.Ltmp208:
.LBB43_35:
	.loc	2 309 170                       # rnd_output1.c:309:170
	lui	a0, %hi(g_99)
	lw	a0, %lo(g_99)(a0)
	.loc	2 309 169 is_stmt 0             # rnd_output1.c:309:169
	lw	a0, 0(a0)
	.loc	2 309 168                       # rnd_output1.c:309:168
	lw	a0, 0(a0)
	.loc	2 309 218                       # rnd_output1.c:309:218
	sw	a0, -1144(s0)                   # 4-byte Folded Spill
	lw	a1, -28(s0)
	.loc	2 309 215                       # rnd_output1.c:309:215
	lui	a0, %hi(g_97)
	addi	a0, a0, %lo(g_97)
	li	a2, 0
	.loc	2 309 224                       # rnd_output1.c:309:224
	sw	a2, -1140(s0)                   # 4-byte Folded Spill
	bne	a0, a1, .LBB43_37
	j	.LBB43_36
.LBB43_36:
	.loc	2 309 228                       # rnd_output1.c:309:228
	lb	a0, -914(s0)
	lui	a1, 11
	addi	a1, a1, -1567
	.loc	2 309 234                       # rnd_output1.c:309:234
	slt	a0, a0, a1
	sw	a0, -1140(s0)                   # 4-byte Folded Spill
	j	.LBB43_37
.LBB43_37:
	.loc	2 0 0                           # rnd_output1.c:0:0
	lw	a0, -1140(s0)                   # 4-byte Folded Reload
	.loc	2 309 224                       # rnd_output1.c:309:224
	andi	a0, a0, 1
	li	a1, 1
	.loc	2 309 178                       # rnd_output1.c:309:178
	sw	a1, -1152(s0)                   # 4-byte Folded Spill
	call	safe_rshift_func_int16_t_s_u
	mv	a1, a0
	.loc	2 309 141                       # rnd_output1.c:309:141
	lw	a0, -1144(s0)                   # 4-byte Folded Reload
	call	safe_sub_func_int32_t_s_s
	lw	a1, -1152(s0)                   # 4-byte Folded Reload
	.loc	2 309 274                       # rnd_output1.c:309:274
	sw	a1, -1148(s0)                   # 4-byte Folded Spill
	bnez	a0, .LBB43_39
	j	.LBB43_38
.LBB43_38:
	.loc	2 309 277                       # rnd_output1.c:309:277
	lhu	a0, -30(s0)
	.loc	2 309 274                       # rnd_output1.c:309:274
	snez	a0, a0
	sw	a0, -1148(s0)                   # 4-byte Folded Spill
	j	.LBB43_39
.LBB43_39:
	.loc	2 0 274                         # rnd_output1.c:0:274
	lw	a0, -1148(s0)                   # 4-byte Folded Reload
	.loc	2 309 274                       # rnd_output1.c:309:274
	andi	a0, a0, 1
	li	a1, -1
	.loc	2 309 114                       # rnd_output1.c:309:114
	call	safe_sub_func_int8_t_s_s
	.loc	2 309 293                       # rnd_output1.c:309:293
	lb	a1, -14(s0)
	.loc	2 309 84                        # rnd_output1.c:309:84
	andi	a0, a0, 255
	call	safe_rshift_func_uint8_t_u_s
	.loc	2 309 310                       # rnd_output1.c:309:310
	lui	a0, %hi(g_69)
	addi	a0, a0, %lo(g_69)
	.loc	2 309 32                        # rnd_output1.c:309:32
	sw	a0, -1156(s0)                   # 4-byte Folded Spill
	lui	a0, %hi(g_93)
	addi	a1, a0, %lo(g_93)
	lui	a0, %hi(g_133)
	addi	a0, a0, %lo(g_133)
	addi	a0, a0, 288
	xor	a0, a0, a1
	seqz	a1, a0
	lui	a0, 16
	addi	a0, a0, -1
	call	safe_rshift_func_uint16_t_u_u
	mv	a1, a0
	.loc	2 309 29                        # rnd_output1.c:309:29
	lw	a0, -1156(s0)                   # 4-byte Folded Reload
	lui	a2, %hi(g_6)
	sw	a1, %lo(g_6)(a2)
	.loc	2 310 40 is_stmt 1              # rnd_output1.c:310:40
	lw	a0, 36(a0)
	.loc	2 310 25 is_stmt 0              # rnd_output1.c:310:25
	sb	a0, -13(s0)
	j	.LBB43_72
.Ltmp209:
.LBB43_40:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 312 31 is_stmt 1              # rnd_output1.c:312:31
	lbu	a0, -672(s0)
.Ltmp210:
	.loc	2 312 25 is_stmt 0              # rnd_output1.c:312:25
	beqz	a0, .LBB43_42
	j	.LBB43_41
.LBB43_41:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp211:
	.loc	2 313 25 is_stmt 1              # rnd_output1.c:313:25
	j	.LBB43_54
.Ltmp212:
.LBB43_42:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 25 is_stmt 0                # rnd_output1.c:0:25
	j	.LBB43_43
.LBB43_43:                              #   in Loop: Header=BB43_19 Depth=3
.Ltmp213:
	.loc	2 315 28 is_stmt 1              # rnd_output1.c:315:28
	lui	a1, %hi(g_123)
	li	a0, 0
	sw	a0, %lo(g_123+4)(a1)
	sw	a0, %lo(g_123)(a1)
	.loc	2 315 22 is_stmt 0              # rnd_output1.c:315:22
	j	.LBB43_44
.LBB43_44:                              #   Parent Loop BB43_12 Depth=1
                                        #     Parent Loop BB43_13 Depth=2
                                        #       Parent Loop BB43_19 Depth=3
                                        # =>      This Inner Loop Header: Depth=4
.Ltmp214:
	.loc	2 315 34                        # rnd_output1.c:315:34
	lui	a1, %hi(g_123)
	lw	a0, %lo(g_123+4)(a1)
	lw	a1, %lo(g_123)(a1)
	.loc	2 315 40                        # rnd_output1.c:315:40
	sltiu	a1, a1, 3
	seqz	a0, a0
	and	a0, a0, a1
.Ltmp215:
	.loc	2 315 17                        # rnd_output1.c:315:17
	beqz	a0, .LBB43_49
	j	.LBB43_45
.LBB43_45:                              #   in Loop: Header=BB43_44 Depth=4
.Ltmp216:
	.loc	2 318 30 is_stmt 1              # rnd_output1.c:318:30
	lw	a1, -900(s0)
	.loc	2 318 27 is_stmt 0              # rnd_output1.c:318:27
	lw	a0, -676(s0)
	or	a0, a0, a1
	sw	a0, -676(s0)
.Ltmp217:
	.loc	2 319 25 is_stmt 1              # rnd_output1.c:319:25
	lw	a0, -872(s0)
.Ltmp218:
	.loc	2 319 25 is_stmt 0              # rnd_output1.c:319:25
	beqz	a0, .LBB43_47
	j	.LBB43_46
.LBB43_46:                              #   in Loop: Header=BB43_44 Depth=4
.Ltmp219:
	.loc	2 320 25 is_stmt 1              # rnd_output1.c:320:25
	j	.LBB43_48
.Ltmp220:
.LBB43_47:                              #   in Loop: Header=BB43_44 Depth=4
	.loc	2 321 17                        # rnd_output1.c:321:17
	j	.LBB43_48
.Ltmp221:
.LBB43_48:                              #   in Loop: Header=BB43_44 Depth=4
	.loc	2 315 53                        # rnd_output1.c:315:53
	lui	a1, %hi(g_123)
	lw	a0, %lo(g_123+4)(a1)
	lw	a2, %lo(g_123)(a1)
	addi	a2, a2, 1
	seqz	a3, a2
	add	a0, a0, a3
	sw	a2, %lo(g_123)(a1)
	sw	a0, %lo(g_123+4)(a1)
	.loc	2 315 17 is_stmt 0              # rnd_output1.c:315:17
	j	.LBB43_44
.Ltmp222:
.LBB43_49:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 0 17                          # rnd_output1.c:0:17
	li	a0, 1
.Ltmp223:
	.loc	2 322 28 is_stmt 1              # rnd_output1.c:322:28
	sw	a0, -676(s0)
	.loc	2 322 22 is_stmt 0              # rnd_output1.c:322:22
	j	.LBB43_50
.LBB43_50:                              #   Parent Loop BB43_12 Depth=1
                                        #     Parent Loop BB43_13 Depth=2
                                        #       Parent Loop BB43_19 Depth=3
                                        # =>      This Inner Loop Header: Depth=4
.Ltmp224:
	.loc	2 322 34                        # rnd_output1.c:322:34
	lw	a0, -676(s0)
.Ltmp225:
	.loc	2 322 17                        # rnd_output1.c:322:17
	bltz	a0, .LBB43_53
	j	.LBB43_51
.LBB43_51:                              #   in Loop: Header=BB43_50 Depth=4
.Ltmp226:
	.loc	2 325 27 is_stmt 1              # rnd_output1.c:325:27
	lw	a0, -676(s0)
	li	a1, 288
	.loc	2 325 21 is_stmt 0              # rnd_output1.c:325:21
	mul	a1, a0, a1
	addi	a0, s0, -632
	add	a1, a1, a0
	.loc	2 325 40                        # rnd_output1.c:325:40
	lb	a0, -672(s0)
	.loc	2 325 21                        # rnd_output1.c:325:21
	slli	a2, a0, 5
	add	a1, a1, a2
	.loc	2 325 54                        # rnd_output1.c:325:54
	slli	a0, a0, 2
	.loc	2 325 21                        # rnd_output1.c:325:21
	add	a1, a1, a0
	addi	a0, s0, -676
	.loc	2 325 60                        # rnd_output1.c:325:60
	sw	a0, 16(a1)
	.loc	2 326 17 is_stmt 1              # rnd_output1.c:326:17
	j	.LBB43_52
.Ltmp227:
.LBB43_52:                              #   in Loop: Header=BB43_50 Depth=4
	.loc	2 322 53                        # rnd_output1.c:322:53
	lw	a0, -676(s0)
	addi	a0, a0, -1
	sw	a0, -676(s0)
	.loc	2 322 17 is_stmt 0              # rnd_output1.c:322:17
	j	.LBB43_50
.Ltmp228:
.LBB43_53:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 327 13 is_stmt 1              # rnd_output1.c:327:13
	j	.LBB43_54
.Ltmp229:
.LBB43_54:                              #   in Loop: Header=BB43_19 Depth=3
	.loc	2 283 58                        # rnd_output1.c:283:58
	lbu	a0, -672(s0)
	addi	a0, a0, 1
	sb	a0, -672(s0)
	.loc	2 283 13 is_stmt 0              # rnd_output1.c:283:13
	j	.LBB43_19
.Ltmp230:
.LBB43_55:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 0 13                          # rnd_output1.c:0:13
	li	a0, 8
.Ltmp231:
	.loc	2 328 30 is_stmt 1              # rnd_output1.c:328:30
	sw	a0, -668(s0)
	.loc	2 328 18 is_stmt 0              # rnd_output1.c:328:18
	j	.LBB43_56
.LBB43_56:                              #   Parent Loop BB43_12 Depth=1
                                        #     Parent Loop BB43_13 Depth=2
                                        # =>    This Inner Loop Header: Depth=3
.Ltmp232:
	.loc	2 328 45                        # rnd_output1.c:328:45
	lw	a0, -668(s0)
	li	a1, 10
.Ltmp233:
	.loc	2 328 13                        # rnd_output1.c:328:13
	bne	a0, a1, .LBB43_59
	j	.LBB43_57
.LBB43_57:                              #   in Loop: Header=BB43_56 Depth=3
	.loc	2 0 13                          # rnd_output1.c:0:13
	li	a0, 0
.Ltmp234:
	.loc	2 330 26 is_stmt 1              # rnd_output1.c:330:26
	sw	a0, -948(s0)
	addi	a0, s0, -948
	.loc	2 331 27                        # rnd_output1.c:331:27
	sw	a0, -952(s0)
	addi	a0, s0, -56
	.loc	2 332 27                        # rnd_output1.c:332:27
	sw	a0, -956(s0)
	.loc	2 333 40                        # rnd_output1.c:333:40
	lw	a0, -948(s0)
	.loc	2 333 31 is_stmt 0              # rnd_output1.c:333:31
	lw	a1, -952(s0)
	.loc	2 333 38                        # rnd_output1.c:333:38
	sw	a0, 0(a1)
	.loc	2 333 19                        # rnd_output1.c:333:19
	lw	a1, -956(s0)
	.loc	2 333 26                        # rnd_output1.c:333:26
	sw	a0, 0(a1)
	.loc	2 334 13 is_stmt 1              # rnd_output1.c:334:13
	j	.LBB43_58
.Ltmp235:
.LBB43_58:                              #   in Loop: Header=BB43_56 Depth=3
	.loc	2 328 105                       # rnd_output1.c:328:105
	lbu	a0, -668(s0)
	li	a1, 5
	.loc	2 328 70 is_stmt 0              # rnd_output1.c:328:70
	call	safe_add_func_uint8_t_u_u
	.loc	2 328 68                        # rnd_output1.c:328:68
	sw	a0, -668(s0)
	.loc	2 328 13                        # rnd_output1.c:328:13
	j	.LBB43_56
.Ltmp236:
.LBB43_59:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 335 9 is_stmt 1               # rnd_output1.c:335:9
	j	.LBB43_60
.Ltmp237:
.LBB43_60:                              #   in Loop: Header=BB43_13 Depth=2
	.loc	2 271 45                        # rnd_output1.c:271:45
	lui	a1, %hi(g_111)
	lh	a0, %lo(g_111)(a1)
	addi	a0, a0, -1
	sh	a0, %lo(g_111)(a1)
	.loc	2 271 9 is_stmt 0               # rnd_output1.c:271:9
	j	.LBB43_13
.Ltmp238:
.LBB43_61:
	.loc	2 336 11 is_stmt 1              # rnd_output1.c:336:11
	lw	a1, -684(s0)
	.loc	2 336 18 is_stmt 0              # rnd_output1.c:336:18
	lui	a0, %hi(g_96)
	addi	a0, a0, %lo(g_96)
	sw	a0, 0(a1)
	.loc	2 337 5 is_stmt 1               # rnd_output1.c:337:5
	j	.LBB43_71
.Ltmp239:
.LBB43_62:
	.loc	2 0 5 is_stmt 0                 # rnd_output1.c:0:5
	li	a1, -2
.Ltmp240:
	.loc	2 340 17 is_stmt 1              # rnd_output1.c:340:17
	sw	a1, -960(s0)
	lui	a0, 564343
	addi	a0, a0, 1159
	.loc	2 341 17                        # rnd_output1.c:341:17
	sw	a0, -964(s0)
	sw	a0, -968(s0)
	sw	a0, -972(s0)
	sw	a0, -976(s0)
	sw	a0, -980(s0)
	sw	a0, -984(s0)
	lui	a0, 1036371
	addi	a0, a0, 295
	.loc	2 342 17                        # rnd_output1.c:342:17
	sw	a0, -988(s0)
	li	a0, 0
	.loc	2 343 17                        # rnd_output1.c:343:17
	sw	a0, -992(s0)
	li	a2, 1
	.loc	2 344 17                        # rnd_output1.c:344:17
	sw	a2, -996(s0)
	lui	a3, 298992
	addi	a3, a3, 1958
	.loc	2 345 17                        # rnd_output1.c:345:17
	sw	a3, -1000(s0)
	.loc	2 346 17                        # rnd_output1.c:346:17
	sw	a1, -1004(s0)
	lui	a1, 746391
	addi	a1, a1, 948
	.loc	2 347 17                        # rnd_output1.c:347:17
	sw	a1, -1008(s0)
	sw	a1, -1012(s0)
	sw	a2, -1016(s0)
	sw	a1, -1020(s0)
	sw	a1, -1024(s0)
	sw	a2, -1028(s0)
	sw	a1, -1032(s0)
	sw	a1, -1036(s0)
	.loc	2 348 18                        # rnd_output1.c:348:18
	sh	a0, -1038(s0)
	.loc	2 350 9                         # rnd_output1.c:350:9
	lh	a1, -1038(s0)
	addi	a1, a1, -1
	sh	a1, -1038(s0)
.Ltmp241:
	.loc	2 351 19                        # rnd_output1.c:351:19
	lui	a1, %hi(g_89)
	sh	a0, %lo(g_89)(a1)
	.loc	2 351 14 is_stmt 0              # rnd_output1.c:351:14
	j	.LBB43_63
.LBB43_63:                              # =>This Loop Header: Depth=1
                                        #     Child Loop BB43_65 Depth 2
.Ltmp242:
	.loc	2 351 25                        # rnd_output1.c:351:25
	lui	a0, %hi(g_89)
	lhu	a0, %lo(g_89)(a0)
	li	a1, 48
.Ltmp243:
	.loc	2 351 9                         # rnd_output1.c:351:9
	beq	a0, a1, .LBB43_70
	j	.LBB43_64
.LBB43_64:                              #   in Loop: Header=BB43_63 Depth=1
	.loc	2 0 9                           # rnd_output1.c:0:9
	lui	a0, 388974
	addi	a0, a0, 1238
.Ltmp244:
	.loc	2 353 22 is_stmt 1              # rnd_output1.c:353:22
	sw	a0, -1048(s0)
	li	a0, 10
.Ltmp245:
	.loc	2 354 24                        # rnd_output1.c:354:24
	sw	a0, -992(s0)
	.loc	2 354 18 is_stmt 0              # rnd_output1.c:354:18
	j	.LBB43_65
.LBB43_65:                              #   Parent Loop BB43_63 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
.Ltmp246:
	.loc	2 354 31                        # rnd_output1.c:354:31
	lw	a0, -992(s0)
	li	a1, 4
.Ltmp247:
	.loc	2 354 13                        # rnd_output1.c:354:13
	beq	a0, a1, .LBB43_68
	j	.LBB43_66
.LBB43_66:                              #   in Loop: Header=BB43_65 Depth=2
.Ltmp248:
	.loc	2 356 33 is_stmt 1              # rnd_output1.c:356:33
	lw	a2, -1048(s0)
	.loc	2 356 30 is_stmt 0              # rnd_output1.c:356:30
	lui	a0, %hi(g_2)
	addi	a1, a0, %lo(g_2)
	lw	a0, 20(a1)
	and	a0, a0, a2
	sw	a0, 20(a1)
	.loc	2 357 22 is_stmt 1              # rnd_output1.c:357:22
	lui	a1, %hi(g_13)
	lw	a0, %lo(g_13)(a1)
	lui	a2, 30362
	addi	a2, a2, 300
	and	a0, a0, a2
	sw	a0, %lo(g_13)(a1)
	.loc	2 358 13                        # rnd_output1.c:358:13
	j	.LBB43_67
.Ltmp249:
.LBB43_67:                              #   in Loop: Header=BB43_65 Depth=2
	.loc	2 354 78                        # rnd_output1.c:354:78
	lw	a0, -992(s0)
	srai	a1, a0, 31
	li	a2, 6
	li	a3, 0
	.loc	2 354 52 is_stmt 0              # rnd_output1.c:354:52
	call	safe_sub_func_int64_t_s_s
	.loc	2 354 50                        # rnd_output1.c:354:50
	sw	a0, -992(s0)
	.loc	2 354 13                        # rnd_output1.c:354:13
	j	.LBB43_65
.Ltmp250:
.LBB43_68:                              #   in Loop: Header=BB43_63 Depth=1
	.loc	2 359 9 is_stmt 1               # rnd_output1.c:359:9
	j	.LBB43_69
.Ltmp251:
.LBB43_69:                              #   in Loop: Header=BB43_63 Depth=1
	.loc	2 351 72                        # rnd_output1.c:351:72
	lui	a0, %hi(g_89)
	sw	a0, -1160(s0)                   # 4-byte Folded Spill
	lhu	a0, %lo(g_89)(a0)
	li	a2, 4
	li	a3, 0
	.loc	2 351 45 is_stmt 0              # rnd_output1.c:351:45
	mv	a1, a3
	call	safe_add_func_uint64_t_u_u
                                        # kill: def $x12 killed $x11
	.loc	2 351 43                        # rnd_output1.c:351:43
	lw	a1, -1160(s0)                   # 4-byte Folded Reload
	sh	a0, %lo(g_89)(a1)
	.loc	2 351 9                         # rnd_output1.c:351:9
	j	.LBB43_63
.Ltmp252:
.LBB43_70:
	.loc	2 0 9                           # rnd_output1.c:0:9
	j	.LBB43_71
.LBB43_71:
	.loc	2 361 14 is_stmt 1              # rnd_output1.c:361:14
	lw	a0, -36(s0)
	.loc	2 361 13 is_stmt 0              # rnd_output1.c:361:13
	lw	a0, 0(a0)
	.loc	2 361 5                         # rnd_output1.c:361:5
	sb	a0, -13(s0)
	j	.LBB43_72
.LBB43_72:
	.loc	2 362 1 is_stmt 1               # rnd_output1.c:362:1
	lbu	a0, -13(s0)
	lw	ra, 1164(sp)                    # 4-byte Folded Reload
	lw	s0, 1160(sp)                    # 4-byte Folded Reload
	.loc	2 362 1 epilogue_begin is_stmt 0 # rnd_output1.c:362:1
	addi	sp, sp, 1168
	ret
.Ltmp253:
.Lfunc_end43:
	.size	func_80, .Lfunc_end43-func_80
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_int64_t_s_s
	.type	safe_mul_func_int64_t_s_s,@function
safe_mul_func_int64_t_s_s:              # @safe_mul_func_int64_t_s_s
.Lfunc_begin44:
	.loc	4 448 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:448:0
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
.Ltmp254:
	.loc	4 453 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:8
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	4 453 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:12
	slti	a2, a0, 0
	sw	a2, -32(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -28(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB44_2
# %bb.1:
	.loc	4 0 12                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:12
	lw	a0, -32(s0)                     # 4-byte Folded Reload
	sw	a0, -28(s0)                     # 4-byte Folded Spill
.LBB44_2:
	.loc	4 453 12                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:12
	lw	a0, -28(s0)                     # 4-byte Folded Reload
	.loc	4 453 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:17
	bnez	a0, .LBB44_9
	j	.LBB44_3
.LBB44_3:
	.loc	4 453 21                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:21
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	4 453 25                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:25
	slti	a2, a0, 0
	sw	a2, -40(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -36(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB44_5
# %bb.4:
	.loc	4 0 25                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:25
	lw	a0, -40(s0)                     # 4-byte Folded Reload
	sw	a0, -36(s0)                     # 4-byte Folded Spill
.LBB44_5:
	.loc	4 453 25                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:25
	lw	a0, -36(s0)                     # 4-byte Folded Reload
	.loc	4 453 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:30
	bnez	a0, .LBB44_9
	j	.LBB44_6
.LBB44_6:
	.loc	4 453 34                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:34
	lw	a0, -16(s0)
	sw	a0, -56(s0)                     # 4-byte Folded Spill
	lw	a0, -12(s0)
	.loc	4 453 53                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:53
	sw	a0, -52(s0)                     # 4-byte Folded Spill
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	lui	a0, 524288
	addi	a1, a0, -1
	li	a0, -1
	.loc	4 453 51                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:51
	call	__divdi3@plt
	lw	a3, -56(s0)                     # 4-byte Folded Reload
	mv	a2, a0
	lw	a0, -52(s0)                     # 4-byte Folded Reload
	.loc	4 453 38                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:38
	slt	a4, a1, a0
	sw	a4, -48(s0)                     # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -44(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB44_8
# %bb.7:
	.loc	4 0 38                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:38
	lw	a0, -48(s0)                     # 4-byte Folded Reload
	sw	a0, -44(s0)                     # 4-byte Folded Spill
.LBB44_8:
	.loc	4 453 38                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:38
	lw	a0, -44(s0)                     # 4-byte Folded Reload
	.loc	4 453 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:60
	bnez	a0, .LBB44_37
	j	.LBB44_9
.LBB44_9:
	.loc	4 453 65                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:65
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	.loc	4 453 69                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:69
	slti	a2, a0, 0
	sw	a2, -64(s0)                     # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -60(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB44_11
# %bb.10:
	.loc	4 0 69                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:69
	lw	a0, -64(s0)                     # 4-byte Folded Reload
	sw	a0, -60(s0)                     # 4-byte Folded Spill
.LBB44_11:
	.loc	4 453 69                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:69
	lw	a0, -60(s0)                     # 4-byte Folded Reload
	.loc	4 453 74                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:74
	bnez	a0, .LBB44_18
	j	.LBB44_12
.LBB44_12:
	.loc	4 453 78                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:78
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	li	a2, 0
	.loc	4 453 82                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:82
	slt	a2, a2, a0
	sw	a2, -72(s0)                     # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -68(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB44_14
# %bb.13:
	.loc	4 0 82                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:82
	lw	a0, -72(s0)                     # 4-byte Folded Reload
	sw	a0, -68(s0)                     # 4-byte Folded Spill
.LBB44_14:
	.loc	4 453 82                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:82
	lw	a0, -68(s0)                     # 4-byte Folded Reload
	.loc	4 453 88                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:88
	bnez	a0, .LBB44_18
	j	.LBB44_15
.LBB44_15:
	.loc	4 453 92                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:92
	lw	a0, -24(s0)
	sw	a0, -88(s0)                     # 4-byte Folded Spill
	lw	a0, -20(s0)
	.loc	4 453 111                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:111
	sw	a0, -84(s0)                     # 4-byte Folded Spill
	lw	a2, -16(s0)
	lw	a3, -12(s0)
	li	a0, 0
	lui	a1, 524288
	.loc	4 453 109                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:109
	call	__divdi3@plt
	lw	a2, -88(s0)                     # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -84(s0)                     # 4-byte Folded Reload
	.loc	4 453 96                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:96
	slt	a4, a0, a1
	sw	a4, -80(s0)                     # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -76(s0)                     # 4-byte Folded Spill
	beq	a0, a1, .LBB44_17
# %bb.16:
	.loc	4 0 96                          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:96
	lw	a0, -80(s0)                     # 4-byte Folded Reload
	sw	a0, -76(s0)                     # 4-byte Folded Spill
.LBB44_17:
	.loc	4 453 96                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:96
	lw	a0, -76(s0)                     # 4-byte Folded Reload
	.loc	4 453 118                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:118
	bnez	a0, .LBB44_37
	j	.LBB44_18
.LBB44_18:
	.loc	4 453 123                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:123
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	li	a2, 0
	.loc	4 453 127                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:127
	slt	a2, a2, a0
	sw	a2, -96(s0)                     # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -92(s0)                     # 4-byte Folded Spill
	beqz	a0, .LBB44_20
# %bb.19:
	.loc	4 0 127                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:127
	lw	a0, -96(s0)                     # 4-byte Folded Reload
	sw	a0, -92(s0)                     # 4-byte Folded Spill
.LBB44_20:
	.loc	4 453 127                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:127
	lw	a0, -92(s0)                     # 4-byte Folded Reload
	.loc	4 453 133                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:133
	bnez	a0, .LBB44_27
	j	.LBB44_21
.LBB44_21:
	.loc	4 453 137                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:137
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	.loc	4 453 141                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:141
	slti	a2, a0, 0
	sw	a2, -104(s0)                    # 4-byte Folded Spill
	seqz	a1, a1
	sw	a1, -100(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB44_23
# %bb.22:
	.loc	4 0 141                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:141
	lw	a0, -104(s0)                    # 4-byte Folded Reload
	sw	a0, -100(s0)                    # 4-byte Folded Spill
.LBB44_23:
	.loc	4 453 141                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:141
	lw	a0, -100(s0)                    # 4-byte Folded Reload
	.loc	4 453 146                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:146
	bnez	a0, .LBB44_27
	j	.LBB44_24
.LBB44_24:
	.loc	4 453 150                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:150
	lw	a0, -16(s0)
	sw	a0, -120(s0)                    # 4-byte Folded Spill
	lw	a0, -12(s0)
	.loc	4 453 169                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:169
	sw	a0, -116(s0)                    # 4-byte Folded Spill
	lw	a2, -24(s0)
	lw	a3, -20(s0)
	li	a0, 0
	lui	a1, 524288
	.loc	4 453 167                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:167
	call	__divdi3@plt
	lw	a2, -120(s0)                    # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -116(s0)                    # 4-byte Folded Reload
	.loc	4 453 154                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:154
	slt	a4, a0, a1
	sw	a4, -112(s0)                    # 4-byte Folded Spill
	sltu	a2, a2, a3
	sw	a2, -108(s0)                    # 4-byte Folded Spill
	beq	a0, a1, .LBB44_26
# %bb.25:
	.loc	4 0 154                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:154
	lw	a0, -112(s0)                    # 4-byte Folded Reload
	sw	a0, -108(s0)                    # 4-byte Folded Spill
.LBB44_26:
	.loc	4 453 154                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:154
	lw	a0, -108(s0)                    # 4-byte Folded Reload
	.loc	4 453 176                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:176
	bnez	a0, .LBB44_37
	j	.LBB44_27
.LBB44_27:
	.loc	4 453 181                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:181
	lw	a1, -16(s0)
	lw	a0, -12(s0)
	li	a2, 0
	.loc	4 453 185                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:185
	slt	a2, a2, a0
	sw	a2, -128(s0)                    # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -124(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB44_29
# %bb.28:
	.loc	4 0 185                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:185
	lw	a0, -128(s0)                    # 4-byte Folded Reload
	sw	a0, -124(s0)                    # 4-byte Folded Spill
.LBB44_29:
	.loc	4 453 185                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:185
	lw	a0, -124(s0)                    # 4-byte Folded Reload
	.loc	4 453 191                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:191
	bnez	a0, .LBB44_38
	j	.LBB44_30
.LBB44_30:
	.loc	4 453 195                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:195
	lw	a1, -24(s0)
	lw	a0, -20(s0)
	li	a2, 0
	.loc	4 453 199                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:199
	slt	a2, a2, a0
	sw	a2, -136(s0)                    # 4-byte Folded Spill
	snez	a1, a1
	sw	a1, -132(s0)                    # 4-byte Folded Spill
	beqz	a0, .LBB44_32
# %bb.31:
	.loc	4 0 199                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:199
	lw	a0, -136(s0)                    # 4-byte Folded Reload
	sw	a0, -132(s0)                    # 4-byte Folded Spill
.LBB44_32:
	.loc	4 453 199                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:199
	lw	a0, -132(s0)                    # 4-byte Folded Reload
	.loc	4 453 205                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:205
	bnez	a0, .LBB44_38
	j	.LBB44_33
.LBB44_33:
	.loc	4 453 209                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:209
	lw	a1, -12(s0)
	lw	a0, -16(s0)
	.loc	4 453 213                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:213
	or	a0, a0, a1
	.loc	4 453 219                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:219
	beqz	a0, .LBB44_38
	j	.LBB44_34
.LBB44_34:
	.loc	4 453 223                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:223
	lw	a0, -24(s0)
	sw	a0, -152(s0)                    # 4-byte Folded Spill
	lw	a0, -20(s0)
	.loc	4 453 242                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:242
	sw	a0, -148(s0)                    # 4-byte Folded Spill
	lw	a2, -16(s0)
	lw	a3, -12(s0)
	lui	a0, 524288
	addi	a1, a0, -1
	li	a0, -1
	.loc	4 453 240                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:240
	call	__divdi3@plt
	lw	a2, -152(s0)                    # 4-byte Folded Reload
	mv	a3, a0
	lw	a0, -148(s0)                    # 4-byte Folded Reload
	.loc	4 453 227                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:227
	slt	a4, a0, a1
	xori	a4, a4, 1
	sw	a4, -144(s0)                    # 4-byte Folded Spill
	sltu	a2, a2, a3
	xori	a2, a2, 1
	sw	a2, -140(s0)                    # 4-byte Folded Spill
	beq	a0, a1, .LBB44_36
# %bb.35:
	.loc	4 0 227                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:0:227
	lw	a0, -144(s0)                    # 4-byte Folded Reload
	sw	a0, -140(s0)                    # 4-byte Folded Spill
.LBB44_36:
	.loc	4 453 227                       # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:227
	lw	a0, -140(s0)                    # 4-byte Folded Reload
	.loc	4 453 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	bnez	a0, .LBB44_38
	j	.LBB44_37
.LBB44_37:
	.loc	4 454 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:454:6
	lw	a0, -12(s0)
	lw	a1, -16(s0)
	sw	a1, -160(s0)                    # 4-byte Folded Spill
	.loc	4 453 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	sw	a0, -156(s0)                    # 4-byte Folded Spill
	j	.LBB44_39
.LBB44_38:
	.loc	4 457 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:5
	lw	a3, -12(s0)
	lw	a1, -16(s0)
	.loc	4 457 11 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:11
	lw	a2, -24(s0)
	lw	a0, -20(s0)
	.loc	4 457 9                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:457:9
	mul	a4, a1, a0
	mulhu	a0, a1, a2
	add	a0, a0, a4
	mul	a3, a3, a2
	add	a0, a0, a3
	mul	a1, a1, a2
	sw	a1, -160(s0)                    # 4-byte Folded Spill
	.loc	4 453 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:453:5
	sw	a0, -156(s0)                    # 4-byte Folded Spill
	j	.LBB44_39
.LBB44_39:
	lw	a0, -160(s0)                    # 4-byte Folded Reload
	lw	a1, -156(s0)                    # 4-byte Folded Reload
	.loc	4 450 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:450:3
	lw	ra, 156(sp)                     # 4-byte Folded Reload
	lw	s0, 152(sp)                     # 4-byte Folded Reload
	.loc	4 450 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:450:3
	addi	sp, sp, 160
	ret
.Ltmp255:
.Lfunc_end44:
	.size	safe_mul_func_int64_t_s_s, .Lfunc_end44-safe_mul_func_int64_t_s_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int8_t_s_u
	.type	safe_lshift_func_int8_t_s_u,@function
safe_lshift_func_int8_t_s_u:            # @safe_lshift_func_int8_t_s_u
.Lfunc_begin45:
	.loc	4 107 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:107:0
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
.Ltmp256:
	.loc	4 111 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:7
	lb	a0, -9(s0)
	.loc	4 111 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:17
	bltz	a0, .LBB45_3
	j	.LBB45_1
.LBB45_1:
	.loc	4 111 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:36
	lw	a1, -16(s0)
	li	a0, 31
	.loc	4 111 50                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:50
	bltu	a0, a1, .LBB45_3
	j	.LBB45_2
.LBB45_2:
	.loc	4 111 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:54
	lb	a1, -9(s0)
	.loc	4 111 89                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:89
	lw	a2, -16(s0)
	li	a0, 127
	.loc	4 111 71                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:71
	srl	a0, a0, a2
	.loc	4 111 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	bge	a0, a1, .LBB45_4
	j	.LBB45_3
.LBB45_3:
	.loc	4 112 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:112:6
	lb	a0, -9(s0)
	.loc	4 111 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB45_5
.LBB45_4:
	.loc	4 114 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:6
	lb	a0, -9(s0)
	.loc	4 114 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:29
	lw	a1, -16(s0)
	.loc	4 114 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:114:11
	sll	a0, a0, a1
	.loc	4 111 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:111:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB45_5
.LBB45_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 109 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:109:3
	slli	a0, a0, 24
	srai	a0, a0, 24
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 109 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:109:3
	addi	sp, sp, 32
	ret
.Ltmp257:
.Lfunc_end45:
	.size	safe_lshift_func_int8_t_s_u, .Lfunc_end45-safe_lshift_func_int8_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_rshift_func_uint16_t_u_u
	.type	safe_rshift_func_uint16_t_u_u,@function
safe_rshift_func_uint16_t_u_u:          # @safe_rshift_func_uint16_t_u_u
.Lfunc_begin46:
	.loc	4 730 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:730:0
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
.Ltmp258:
	.loc	4 734 21 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:734:21
	lw	a0, -16(s0)
	li	a1, 32
	.loc	4 734 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:734:5
	bltu	a0, a1, .LBB46_2
	j	.LBB46_1
.LBB46_1:
	.loc	4 735 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:735:6
	lhu	a0, -10(s0)
	.loc	4 734 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:734:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB46_3
.LBB46_2:
	.loc	4 737 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:737:6
	lhu	a0, -10(s0)
	.loc	4 737 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:737:29
	lw	a1, -16(s0)
	.loc	4 737 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:737:11
	srl	a0, a0, a1
	.loc	4 734 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:734:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB46_3
.LBB46_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 732 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:732:3
	slli	a0, a0, 16
	srli	a0, a0, 16
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 732 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:732:3
	addi	sp, sp, 32
	ret
.Ltmp259:
.Lfunc_end46:
	.size	safe_rshift_func_uint16_t_u_u, .Lfunc_end46-safe_rshift_func_uint16_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_lshift_func_int32_t_s_u
	.type	safe_lshift_func_int32_t_s_u,@function
safe_lshift_func_int32_t_s_u:           # @safe_lshift_func_int32_t_s_u
.Lfunc_begin47:
	.loc	4 367 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:367:0
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
.Ltmp260:
	.loc	4 371 7 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:7
	lw	a0, -12(s0)
	.loc	4 371 17 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:17
	bltz	a0, .LBB47_3
	j	.LBB47_1
.LBB47_1:
	.loc	4 371 36                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:36
	lw	a1, -16(s0)
	li	a0, 31
	.loc	4 371 50                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:50
	bltu	a0, a1, .LBB47_3
	j	.LBB47_2
.LBB47_2:
	.loc	4 371 54                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:54
	lw	a1, -12(s0)
	.loc	4 371 90                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:90
	lw	a2, -16(s0)
	lui	a0, 524288
	addi	a0, a0, -1
	.loc	4 371 72                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:72
	srl	a0, a0, a2
	.loc	4 371 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	bge	a0, a1, .LBB47_4
	j	.LBB47_3
.LBB47_3:
	.loc	4 372 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:372:6
	lw	a0, -12(s0)
	.loc	4 371 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB47_5
.LBB47_4:
	.loc	4 374 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:6
	lw	a0, -12(s0)
	.loc	4 374 29 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:29
	lw	a1, -16(s0)
	.loc	4 374 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:374:11
	sll	a0, a0, a1
	.loc	4 371 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:371:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB47_5
.LBB47_5:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 369 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:369:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 369 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:369:3
	addi	sp, sp, 32
	ret
.Ltmp261:
.Lfunc_end47:
	.size	safe_lshift_func_int32_t_s_u, .Lfunc_end47-safe_lshift_func_int32_t_s_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_unary_minus_func_int32_t_s
	.type	safe_unary_minus_func_int32_t_s,@function
safe_unary_minus_func_int32_t_s:        # @safe_unary_minus_func_int32_t_s
.Lfunc_begin48:
	.loc	4 275 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:275:0
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
.Ltmp262:
	.loc	4 280 6 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:6
	lw	a0, -12(s0)
	lui	a1, 524288
	.loc	4 280 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	bne	a0, a1, .LBB48_2
	j	.LBB48_1
.LBB48_1:
	.loc	4 281 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:281:6
	lw	a0, -12(s0)
	.loc	4 280 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB48_3
.LBB48_2:
	.loc	4 284 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:284:6
	lw	a1, -12(s0)
	li	a0, 0
	.loc	4 284 5 is_stmt 0               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:284:5
	sub	a0, a0, a1
	.loc	4 280 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:280:5
	sw	a0, -16(s0)                     # 4-byte Folded Spill
	j	.LBB48_3
.LBB48_3:
	lw	a0, -16(s0)                     # 4-byte Folded Reload
	.loc	4 277 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:277:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 277 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:277:3
	addi	sp, sp, 16
	ret
.Ltmp263:
.Lfunc_end48:
	.size	safe_unary_minus_func_int32_t_s, .Lfunc_end48-safe_unary_minus_func_int32_t_s
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_mul_func_uint32_t_u_u
	.type	safe_mul_func_uint32_t_u_u,@function
safe_mul_func_uint32_t_u_u:             # @safe_mul_func_uint32_t_u_u
.Lfunc_begin49:
	.loc	4 765 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:765:0
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
.Ltmp264:
	.loc	4 767 25 prologue_end           # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:25
	lw	a0, -12(s0)
	.loc	4 767 47 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:47
	lw	a1, -16(s0)
	.loc	4 767 30                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:30
	mul	a0, a0, a1
	.loc	4 767 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:3
	lw	ra, 12(sp)                      # 4-byte Folded Reload
	lw	s0, 8(sp)                       # 4-byte Folded Reload
	.loc	4 767 3 epilogue_begin          # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:767:3
	addi	sp, sp, 16
	ret
.Ltmp265:
.Lfunc_end49:
	.size	safe_mul_func_uint32_t_u_u, .Lfunc_end49-safe_mul_func_uint32_t_u_u
	.cfi_endproc
                                        # -- End function
	.p2align	1                               # -- Begin function safe_sub_func_int32_t_s_s
	.type	safe_sub_func_int32_t_s_s,@function
safe_sub_func_int32_t_s_s:              # @safe_sub_func_int32_t_s_s
.Lfunc_begin50:
	.loc	4 303 0 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:303:0
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
.Ltmp266:
	.loc	4 308 8 prologue_end            # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:8
	lw	a1, -12(s0)
	.loc	4 308 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:12
	lw	a2, -16(s0)
	.loc	4 308 11                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:11
	xor	a0, a1, a2
	lui	a3, 524288
	.loc	4 308 39                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:39
	and	a3, a3, a0
	.loc	4 308 26                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:26
	xor	a1, a1, a3
	.loc	4 308 55                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:55
	sub	a1, a1, a2
	.loc	4 308 60                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:60
	xor	a1, a1, a2
	.loc	4 308 17                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:17
	and	a0, a0, a1
	.loc	4 308 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	bgez	a0, .LBB50_2
	j	.LBB50_1
.LBB50_1:
	.loc	4 309 6 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:309:6
	lw	a0, -12(s0)
	.loc	4 308 5                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB50_3
.LBB50_2:
	.loc	4 312 6                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:6
	lw	a0, -12(s0)
	.loc	4 312 12 is_stmt 0              # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:12
	lw	a1, -16(s0)
	.loc	4 312 10                        # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:312:10
	sub	a0, a0, a1
	.loc	4 308 5 is_stmt 1               # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:308:5
	sw	a0, -20(s0)                     # 4-byte Folded Spill
	j	.LBB50_3
.LBB50_3:
	lw	a0, -20(s0)                     # 4-byte Folded Reload
	.loc	4 305 3                         # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:305:3
	lw	ra, 28(sp)                      # 4-byte Folded Reload
	lw	s0, 24(sp)                      # 4-byte Folded Reload
	.loc	4 305 3 epilogue_begin is_stmt 0 # linx-mcu-test/Public/tools/csmith/runtime_x86/safe_math.h:305:3
	addi	sp, sp, 32
	ret
.Ltmp267:
.Lfunc_end50:
	.size	safe_sub_func_int32_t_s_s, .Lfunc_end50-safe_sub_func_int32_t_s_s
	.cfi_endproc
                                        # -- End function
	.type	g_6,@object                     # @g_6
	.section	.sdata,"aw",@progbits
	.globl	g_6
	.p2align	2
g_6:
	.word	4294967295                      # 0xffffffff
	.size	g_6, 4

	.type	g_70,@object                    # @g_70
	.data
	.globl	g_70
	.p2align	4, 0x0
g_70:
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.word	2615132094                      # 0x9bdfbfbe
	.word	4294967291                      # 0xfffffffb
	.zero	8
	.size	g_70, 112

	.type	g_71,@object                    # @g_71
	.section	.sbss,"aw",@nobits
	.globl	g_71
	.p2align	2
g_71:
	.word	0
	.size	g_71, 4

	.type	g_93,@object                    # @g_93
	.section	.sdata,"aw",@progbits
	.globl	g_93
	.p2align	3
g_93:
	.quad	2769636331364228521             # 0x266fb991b7fb1da9
	.size	g_93, 8

	.type	g_136,@object                   # @g_136
	.data
	.globl	g_136
	.p2align	2, 0x0
g_136:
	.zero	4
	.word	4294967290                      # 0xfffffffa
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.word	4294967295                      # 0xffffffff
	.word	2729982696                      # 0xa2b83ae8
	.zero	4
	.word	4294967295                      # 0xffffffff
	.zero	4
	.word	2                               # 0x2
	.word	4294967290                      # 0xfffffffa
	.word	2729982696                      # 0xa2b83ae8
	.word	2                               # 0x2
	.word	1217215205                      # 0x488d3ae5
	.word	4294967295                      # 0xffffffff
	.zero	4
	.word	4294967290                      # 0xfffffffa
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	2                               # 0x2
	.word	41623151                        # 0x27b1e6f
	.word	1047189441                      # 0x3e6ad7c1
	.word	2                               # 0x2
	.word	1047189441                      # 0x3e6ad7c1
	.word	2374753925                      # 0x8d8bde85
	.zero	4
	.word	41623151                        # 0x27b1e6f
	.word	2374753925                      # 0x8d8bde85
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.size	g_136, 120

	.type	g_152,@object                   # @g_152
	.section	.sdata,"aw",@progbits
	.globl	g_152
	.p2align	3
g_152:
	.quad	-6100123806707170864            # 0xab5801b7b750c1d0
	.size	g_152, 8

	.type	g_292,@object                   # @g_292
	.section	.rodata,"a",@progbits
	.globl	g_292
	.p2align	2, 0x0
g_292:
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.word	1261362410                      # 0x4b2edcea
	.size	g_292, 160

	.type	g_388,@object                   # @g_388
	.section	.sdata,"aw",@progbits
	.globl	g_388
	.p2align	1
g_388:
	.half	53820                           # 0xd23c
	.size	g_388, 2

	.type	g_391,@object                   # @g_391
	.globl	g_391
	.p2align	3
g_391:
	.quad	-8014284273513103161            # 0x90c78aea2c4080c7
	.size	g_391, 8

	.type	g_477,@object                   # @g_477
	.section	.sbss,"aw",@nobits
	.globl	g_477
	.p2align	2
g_477:
	.word	0
	.size	g_477, 4

	.type	g_501,@object                   # @g_501
	.section	.sdata,"aw",@progbits
	.globl	g_501
	.p2align	2
g_501:
	.word	g_477
	.size	g_501, 4

	.type	g_532,@object                   # @g_532
	.globl	g_532
	.p2align	2
g_532:
	.word	g_467+12
	.size	g_532, 4

	.type	g_557,@object                   # @g_557
	.globl	g_557
	.p2align	2
g_557:
	.word	g_556
	.size	g_557, 4

	.type	g_733,@object                   # @g_733
	.globl	g_733
	.p2align	2
g_733:
	.word	3895317700                      # 0xe82dd4c4
	.size	g_733, 4

	.type	g_1096,@object                  # @g_1096
	.section	.sbss,"aw",@nobits
	.globl	g_1096
	.p2align	2
g_1096:
	.word	0
	.size	g_1096, 4

	.type	g_1126,@object                  # @g_1126
	.section	.sdata,"aw",@progbits
	.globl	g_1126
	.p2align	2
g_1126:
	.word	g_1127
	.size	g_1126, 4

	.type	g_1548,@object                  # @g_1548
	.globl	g_1548
	.p2align	2
g_1548:
	.word	7                               # 0x7
	.size	g_1548, 4

	.type	g_1662,@object                  # @g_1662
	.globl	g_1662
	.p2align	2
g_1662:
	.word	2833916473                      # 0xa8ea2239
	.size	g_1662, 4

	.type	g_1812,@object                  # @g_1812
	.globl	g_1812
	.p2align	2
g_1812:
	.word	1                               # 0x1
	.size	g_1812, 4

	.type	g_1813,@object                  # @g_1813
	.globl	g_1813
	.p2align	2
g_1813:
	.word	4068559772                      # 0xf2814b9c
	.size	g_1813, 4

	.type	g_1815,@object                  # @g_1815
	.section	.rodata,"a",@progbits
	.globl	g_1815
	.p2align	2, 0x0
g_1815:
	.zero	4
	.size	g_1815, 4

	.type	g_1895,@object                  # @g_1895
	.globl	g_1895
	.p2align	2, 0x0
g_1895:
	.word	g_589
	.size	g_1895, 4

	.type	g_2040,@object                  # @g_2040
	.section	.sdata,"aw",@progbits
	.globl	g_2040
	.p2align	2
g_2040:
	.word	g_1810
	.size	g_2040, 4

	.type	g_2039,@object                  # @g_2039
	.data
	.globl	g_2039
	.p2align	2, 0x0
g_2039:
	.word	g_2040
	.word	g_2040
	.word	g_2040
	.size	g_2039, 12

	.type	g_2088,@object                  # @g_2088
	.section	.sdata,"aw",@progbits
	.globl	g_2088
	.p2align	2
g_2088:
	.word	g_70+80
	.size	g_2088, 4

	.type	g_2128,@object                  # @g_2128
	.globl	g_2128
	.p2align	2
g_2128:
	.word	8                               # 0x8
	.size	g_2128, 4

	.type	g_2136,@object                  # @g_2136
	.data
	.globl	g_2136
	.p2align	2, 0x0
g_2136:
	.word	0
	.word	g_1380
	.word	g_1380
	.word	0
	.word	g_1007+88
	.word	g_1380
	.word	0
	.word	g_1007+88
	.word	g_1380
	.word	g_1380
	.word	g_1380
	.word	g_1380
	.word	g_1007+116
	.word	g_1007+116
	.word	g_1380
	.word	g_97
	.word	g_1380
	.word	g_97
	.word	g_1380
	.word	g_1007+88
	.word	g_1007+32
	.word	g_97
	.word	g_1007+88
	.word	g_1380
	.word	g_1007+116
	.word	g_1380
	.word	g_1007+32
	.word	g_1380
	.word	g_1007+116
	.word	g_97
	.word	0
	.word	g_1380
	.word	g_1380
	.word	0
	.word	g_1007+88
	.word	g_1380
	.word	0
	.word	g_1007+88
	.word	g_1380
	.word	g_1380
	.word	g_1380
	.word	g_1380
	.word	g_1007+116
	.word	g_1007+116
	.word	g_1380
	.word	g_97
	.word	g_1380
	.word	g_97
	.word	g_1380
	.word	g_1007+88
	.word	g_1007+32
	.word	g_97
	.word	g_1007+88
	.word	g_1380
	.word	g_1007+116
	.word	g_1380
	.word	g_1007+32
	.word	g_1380
	.word	g_1007+116
	.word	g_97
	.size	g_2136, 240

	.type	g_2137,@object                  # @g_2137
	.section	.sdata,"aw",@progbits
	.globl	g_2137
	.p2align	2
g_2137:
	.word	g_1380+4
	.size	g_2137, 4

	.type	g_2198,@object                  # @g_2198
	.globl	g_2198
	.p2align	2
g_2198:
	.word	g_1380
	.size	g_2198, 4

	.type	g_2309,@object                  # @g_2309
	.data
	.globl	g_2309
	.p2align	2, 0x0
g_2309:
	.word	1314623712                      # 0x4e5b90e0
	.word	1314623712                      # 0x4e5b90e0
	.word	949733972                       # 0x389bca54
	.word	1314623712                      # 0x4e5b90e0
	.word	1314623712                      # 0x4e5b90e0
	.word	949733972                       # 0x389bca54
	.word	1314623712                      # 0x4e5b90e0
	.word	1314623712                      # 0x4e5b90e0
	.word	949733972                       # 0x389bca54
	.word	1314623712                      # 0x4e5b90e0
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.word	1314623712                      # 0x4e5b90e0
	.word	4248897854                      # 0xfd41093e
	.word	4248897854                      # 0xfd41093e
	.size	g_2309, 120

	.type	.L__const.func_36.l_1843,@object # @__const.func_36.l_1843
	.section	.rodata,"a",@progbits
.L__const.func_36.l_1843:
	.ascii	"\373\000\230\373\365\317\232\377\f"
	.ascii	"\b\232\001\b\264\n\366\365\230"
	.ascii	"\373\365\001\000\000\001\365\373b"
	.ascii	"\000\000\230\373\264\f\365\264V"
	.ascii	"\373\000\006\000\365\210\366&b"
	.ascii	"\232\000b\365&\377\232\366\230"
	.ascii	"\366\000\f\000\373\377\373j\264"
	.ascii	"\007\007\000\213\001\232\001\031\373"
	.ascii	"\007\003\232\377\003\264\213\000\365"
	.ascii	"\031j\000\001\003\b\001\375\377"
	.size	.L__const.func_36.l_1843, 90

	.type	.L__const.func_36.l_2043,@object # @__const.func_36.l_2043
	.p2align	4, 0x0
.L__const.func_36.l_2043:
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	2313659216                      # 0x89e7a350
	.word	1                               # 0x1
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.word	1196634878                      # 0x475332fe
	.word	0                               # 0x0
	.zero	8
	.word	0                               # 0x0
	.word	1722271817                      # 0x66a7c849
	.zero	8
	.size	.L__const.func_36.l_2043, 3840

	.type	.L__const.func_36.l_2148,@object # @__const.func_36.l_2148
	.p2align	2, 0x0
.L__const.func_36.l_2148:
	.word	3                               # 0x3
	.word	1                               # 0x1
	.word	307530320                       # 0x12548a50
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	1                               # 0x1
	.word	965667190                       # 0x398ee976
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	2987430185                      # 0xb2109129
	.word	0                               # 0x0
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	307530320                       # 0x12548a50
	.word	0                               # 0x0
	.word	0                               # 0x0
	.word	307530320                       # 0x12548a50
	.word	307530320                       # 0x12548a50
	.word	1832219400                      # 0x6d357308
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	4294967295                      # 0xffffffff
	.word	965667190                       # 0x398ee976
	.word	1832219400                      # 0x6d357308
	.word	1                               # 0x1
	.word	6                               # 0x6
	.word	4294967295                      # 0xffffffff
	.size	.L__const.func_36.l_2148, 120

	.type	.L__const.func_36.l_1945,@object # @__const.func_36.l_1945
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_36.l_1945:
	.word	909025766                       # 0x362ea1e6
	.word	1                               # 0x1
	.zero	8
	.size	.L__const.func_36.l_1945, 16

	.type	.L__const.func_36.l_2275,@object # @__const.func_36.l_2275
	.p2align	4, 0x0
.L__const.func_36.l_2275:
	.word	4294967295                      # 0xffffffff
	.word	4176716959                      # 0xf8f3a49f
	.zero	8
	.size	.L__const.func_36.l_2275, 16

	.type	.L__const.func_36.l_2476,@object # @__const.func_36.l_2476
	.p2align	4, 0x0
.L__const.func_36.l_2476:
	.word	3349896031                      # 0xc7ab5b5f
	.word	8                               # 0x8
	.zero	8
	.size	.L__const.func_36.l_2476, 16

	.type	.L__const.func_36.l_2374,@object # @__const.func_36.l_2374
	.section	.rodata,"a",@progbits
	.p2align	4, 0x0
.L__const.func_36.l_2374:
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	4294967295                      # 0xffffffff
	.word	1423428078                      # 0x54d7c9ee
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.word	7                               # 0x7
	.word	4294967290                      # 0xfffffffa
	.zero	8
	.size	.L__const.func_36.l_2374, 896

	.type	.L__const.func_36.l_2404,@object # @__const.func_36.l_2404
	.p2align	2, 0x0
.L__const.func_36.l_2404:
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	g_1247
	.word	0
	.size	.L__const.func_36.l_2404, 100

	.type	.L__const.func_36.l_2436,@object # @__const.func_36.l_2436
	.p2align	2, 0x0
.L__const.func_36.l_2436:
	.word	2113341062                      # 0x7df70686
	.word	1315764571                      # 0x4e6cf95b
	.word	1315764571                      # 0x4e6cf95b
	.word	2113341062                      # 0x7df70686
	.word	1315764571                      # 0x4e6cf95b
	.word	1315764571                      # 0x4e6cf95b
	.word	2113341062                      # 0x7df70686
	.size	.L__const.func_36.l_2436, 28

	.type	.L__const.func_36.l_2325,@object # @__const.func_36.l_2325
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	2, 0x0
.L__const.func_36.l_2325:
	.word	1                               # 0x1
	.word	1                               # 0x1
	.size	.L__const.func_36.l_2325, 8

	.type	.L__const.func_36.l_2391,@object # @__const.func_36.l_2391
	.section	.rodata,"a",@progbits
.L__const.func_36.l_2391:
	.ascii	"\307\217\376\371"
	.ascii	"\377\360\304\376"
	.ascii	"\371\360\200\371"
	.ascii	"\360\217\377\307"
	.ascii	"%o%\304"
	.ascii	"\371\307\267\367"
	.ascii	"o\377\376\307"
	.ascii	"\264\371\376\217"
	.ascii	"o\360\267\t"
	.ascii	"\371%%\371"
	.ascii	"%\371\377\264"
	.ascii	"\360o\200\367"
	.ascii	"\371\264\304\367"
	.ascii	"\377o\376\264"
	.ascii	"\307\371\000\371"
	.ascii	"o%\304\t"
	.ascii	"\217\360%\217"
	.ascii	"\360\371D\307"
	.ascii	"\360\377%\367"
	.ascii	"\217\307\304\304"
	.ascii	"oo\000\307"
	.ascii	"\307\217\376\371"
	.ascii	"\377\360\304\376"
	.ascii	"\371\360\200\371"
	.ascii	"\360\217\377\307"
	.ascii	"%o%\304"
	.ascii	"\371\307\267\367"
	.ascii	"o\377\376\307"
	.ascii	"\264\371\376\217"
	.ascii	"o\360\267\t"
	.ascii	"\371%%\371"
	.ascii	"%\371\377\264"
	.size	.L__const.func_36.l_2391, 128

	.type	.L__const.func_36.l_2477,@object # @__const.func_36.l_2477
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_36.l_2477:
	.word	4294967288                      # 0xfffffff8
	.word	9216845                         # 0x8ca34d
	.zero	8
	.size	.L__const.func_36.l_2477, 16

	.type	.L__const.func_80.l_115,@object # @__const.func_80.l_115
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_80.l_115:
	.word	0
	.word	g_3
	.word	g_8+568
	.word	0
	.word	g_8+480
	.word	g_13
	.word	0
	.word	g_70+80
	.word	0
	.word	0
	.word	g_69+32
	.word	g_3
	.word	0
	.word	g_13
	.word	g_3
	.word	0
	.word	0
	.word	g_13
	.word	g_3
	.word	0
	.word	0
	.word	g_8+884
	.word	g_70+80
	.word	g_8+884
	.word	0
	.word	g_69+32
	.word	g_70+80
	.word	g_69+32
	.word	0
	.word	g_3
	.word	0
	.word	g_8+392
	.word	g_70+80
	.word	g_3
	.word	0
	.word	g_70+80
	.word	g_69+32
	.word	0
	.word	g_8+480
	.word	g_69+32
	.word	0
	.word	g_8+480
	.word	0
	.word	g_70+80
	.word	g_8+884
	.word	0
	.word	0
	.word	g_3
	.word	g_13
	.word	g_69+32
	.word	0
	.word	0
	.word	g_8+480
	.word	g_3
	.word	g_70+80
	.word	0
	.word	g_70+80
	.word	g_13
	.word	g_3
	.word	g_13
	.word	g_3
	.word	0
	.word	0
	.word	0
	.word	g_69+32
	.word	g_8+392
	.word	0
	.word	g_70+80
	.word	0
	.word	g_70+80
	.word	g_70+80
	.word	0
	.word	0
	.word	g_69+32
	.word	g_69+32
	.word	0
	.word	g_70+80
	.word	g_69+32
	.word	g_70+80
	.word	g_13
	.word	g_8+480
	.word	g_13
	.word	g_13
	.word	g_70+80
	.word	0
	.word	g_70+80
	.word	g_3
	.word	g_70+80
	.word	0
	.word	g_13
	.word	g_3
	.word	0
	.word	g_13
	.word	g_69+32
	.word	0
	.word	g_13
	.word	0
	.word	g_69+32
	.word	g_8+480
	.word	g_69+32
	.word	0
	.word	g_70+80
	.word	g_3
	.word	0
	.word	g_8+492
	.word	g_8+392
	.word	0
	.word	g_70+80
	.word	g_13
	.word	0
	.word	0
	.word	g_8+568
	.word	g_69+32
	.word	g_13
	.word	0
	.word	0
	.word	g_3
	.word	g_3
	.word	g_3
	.word	0
	.word	0
	.word	g_69+32
	.word	0
	.word	0
	.word	g_8+568
	.word	g_8+884
	.word	g_13
	.word	g_70+80
	.word	g_3
	.word	g_69+32
	.word	g_69+32
	.word	g_3
	.word	0
	.word	g_8+492
	.word	g_8+568
	.word	g_8+480
	.word	g_3
	.word	0
	.word	g_8+884
	.word	g_69+32
	.word	g_8+568
	.word	g_69+32
	.word	g_3
	.word	0
	.size	.L__const.func_80.l_115, 576

	.type	.L__const.func_80.l_145,@object # @__const.func_80.l_145
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4, 0x0
.L__const.func_80.l_145:
	.word	2687654893                      # 0xa0325bed
	.word	2892210552                      # 0xac63a178
	.zero	8
	.size	.L__const.func_80.l_145, 16

	.type	.L__const.func_80.l_146,@object # @__const.func_80.l_146
	.section	.rodata,"a",@progbits
	.p2align	2, 0x0
.L__const.func_80.l_146:
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	0
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	0
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.word	g_147
	.size	.L__const.func_80.l_146, 80

	.type	.L__const.func_80.l_148,@object # @__const.func_80.l_148
	.p2align	2, 0x0
.L__const.func_80.l_148:
	.word	1307056399                      # 0x4de8190f
	.word	5                               # 0x5
	.word	4                               # 0x4
	.word	6                               # 0x6
	.word	1149239977                      # 0x448002a9
	.word	6                               # 0x6
	.word	4                               # 0x4
	.word	5                               # 0x5
	.word	0                               # 0x0
	.word	4                               # 0x4
	.word	1528045893                      # 0x5b142145
	.word	6                               # 0x6
	.word	1                               # 0x1
	.word	4294967288                      # 0xfffffff8
	.word	4294967288                      # 0xfffffff8
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	1                               # 0x1
	.word	0                               # 0x0
	.word	5                               # 0x5
	.word	4294967288                      # 0xfffffff8
	.word	1307056399                      # 0x4de8190f
	.size	.L__const.func_80.l_148, 96

	.type	.L__const.func_80.l_180,@object # @__const.func_80.l_180
	.p2align	2, 0x0
.L__const.func_80.l_180:
	.word	2311550087                      # 0x89c77487
	.word	2311550087                      # 0x89c77487
	.word	2311550087                      # 0x89c77487
	.word	2311550087                      # 0x89c77487
	.word	2311550087                      # 0x89c77487
	.word	2311550087                      # 0x89c77487
	.size	.L__const.func_80.l_180, 24

	.type	.L__const.func_80.l_186,@object # @__const.func_80.l_186
	.section	.rodata.cst32,"aM",@progbits,32
	.p2align	2, 0x0
.L__const.func_80.l_186:
	.word	3057218484                      # 0xb63973b4
	.word	3057218484                      # 0xb63973b4
	.word	1                               # 0x1
	.word	3057218484                      # 0xb63973b4
	.word	3057218484                      # 0xb63973b4
	.word	1                               # 0x1
	.word	3057218484                      # 0xb63973b4
	.word	3057218484                      # 0xb63973b4
	.size	.L__const.func_80.l_186, 32

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
	.byte	53                              # DW_TAG_volatile_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	4                               # Abbreviation Code
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
	.byte	5                               # Abbreviation Code
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
	.byte	6                               # Abbreviation Code
	.byte	1                               # DW_TAG_array_type
	.byte	1                               # DW_CHILDREN_yes
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	7                               # Abbreviation Code
	.byte	33                              # DW_TAG_subrange_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	55                              # DW_AT_count
	.byte	11                              # DW_FORM_data1
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	8                               # Abbreviation Code
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
	.byte	9                               # Abbreviation Code
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
	.byte	10                              # Abbreviation Code
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
	.byte	11                              # Abbreviation Code
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
	.byte	12                              # Abbreviation Code
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
	.byte	13                              # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	14                              # Abbreviation Code
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
	.byte	15                              # Abbreviation Code
	.byte	38                              # DW_TAG_const_type
	.byte	0                               # DW_CHILDREN_no
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	16                              # Abbreviation Code
	.byte	15                              # DW_TAG_pointer_type
	.byte	0                               # DW_CHILDREN_no
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	17                              # Abbreviation Code
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
	.byte	18                              # Abbreviation Code
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
	.byte	19                              # Abbreviation Code
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
	.byte	20                              # Abbreviation Code
	.byte	11                              # DW_TAG_lexical_block
	.byte	1                               # DW_CHILDREN_yes
	.byte	17                              # DW_AT_low_pc
	.byte	1                               # DW_FORM_addr
	.byte	18                              # DW_AT_high_pc
	.byte	6                               # DW_FORM_data4
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
	.byte	5                               # DW_FORM_data2
	.byte	39                              # DW_AT_prototyped
	.byte	25                              # DW_FORM_flag_present
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
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
	.byte	5                               # DW_FORM_data2
	.byte	73                              # DW_AT_type
	.byte	19                              # DW_FORM_ref4
	.byte	0                               # EOM(1)
	.byte	0                               # EOM(2)
	.byte	23                              # Abbreviation Code
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
	.byte	24                              # Abbreviation Code
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
	.byte	25                              # Abbreviation Code
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
	.byte	0                               # EOM(3)
	.section	.debug_info,"",@progbits
.Lcu_begin0:
	.word	.Ldebug_info_end0-.Ldebug_info_start0 # Length of Unit
.Ldebug_info_start0:
	.half	4                               # DWARF version number
	.word	.debug_abbrev                   # Offset Into Abbrev. Section
	.byte	4                               # Address Size (in bytes)
	.byte	1                               # Abbrev [1] 0xb:0x1c1b DW_TAG_compile_unit
	.word	.Linfo_string0                  # DW_AT_producer
	.half	29                              # DW_AT_language
	.word	.Linfo_string1                  # DW_AT_name
	.word	.Lline_table_start0             # DW_AT_stmt_list
	.word	.Linfo_string2                  # DW_AT_comp_dir
	.word	.Lfunc_begin0                   # DW_AT_low_pc
	.word	.Lfunc_end50-.Lfunc_begin0      # DW_AT_high_pc
	.byte	2                               # Abbrev [2] 0x26:0x11 DW_TAG_variable
	.word	.Linfo_string3                  # DW_AT_name
	.word	55                              # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	17                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_6
	.byte	3                               # Abbrev [3] 0x37:0x5 DW_TAG_volatile_type
	.word	60                              # DW_AT_type
	.byte	4                               # Abbrev [4] 0x3c:0xb DW_TAG_typedef
	.word	71                              # DW_AT_type
	.word	.Linfo_string5                  # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	105                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0x47:0x7 DW_TAG_base_type
	.word	.Linfo_string4                  # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x4e:0x11 DW_TAG_variable
	.word	.Linfo_string6                  # DW_AT_name
	.word	95                              # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	18                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_70
	.byte	6                               # Abbrev [6] 0x5f:0xc DW_TAG_array_type
	.word	107                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x64:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	8                               # Abbrev [8] 0x6b:0x3a DW_TAG_union_type
	.word	.Linfo_string20                 # DW_AT_name
	.byte	16                              # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	14                              # DW_AT_decl_line
	.byte	9                               # Abbrev [9] 0x73:0xd DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	165                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	15                              # DW_AT_decl_line
	.byte	16                              # DW_AT_alignment
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x80:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	217                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	16                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x8c:0xc DW_TAG_member
	.word	.Linfo_string14                 # DW_AT_name
	.word	235                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	17                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x98:0xc DW_TAG_member
	.word	.Linfo_string17                 # DW_AT_name
	.word	253                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	18                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	11                              # Abbrev [11] 0xa5:0x22 DW_TAG_structure_type
	.word	.Linfo_string11                 # DW_AT_name
	.byte	16                              # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	8                               # DW_AT_decl_line
	.byte	16                              # DW_AT_alignment
	.byte	10                              # Abbrev [10] 0xae:0xc DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	60                              # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	9                               # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0xba:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	199                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	10                              # DW_AT_decl_line
	.byte	4                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	4                               # Abbrev [4] 0xc7:0xb DW_TAG_typedef
	.word	210                             # DW_AT_type
	.word	.Linfo_string10                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0xd2:0x7 DW_TAG_base_type
	.word	.Linfo_string9                  # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	4                               # DW_AT_byte_size
	.byte	4                               # Abbrev [4] 0xd9:0xb DW_TAG_typedef
	.word	228                             # DW_AT_type
	.word	.Linfo_string13                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	100                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0xe4:0x7 DW_TAG_base_type
	.word	.Linfo_string12                 # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	2                               # DW_AT_byte_size
	.byte	4                               # Abbrev [4] 0xeb:0xb DW_TAG_typedef
	.word	246                             # DW_AT_type
	.word	.Linfo_string16                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	120                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0xf6:0x7 DW_TAG_base_type
	.word	.Linfo_string15                 # DW_AT_name
	.byte	8                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	4                               # Abbrev [4] 0xfd:0xb DW_TAG_typedef
	.word	264                             # DW_AT_type
	.word	.Linfo_string19                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	95                              # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0x108:0x7 DW_TAG_base_type
	.word	.Linfo_string18                 # DW_AT_name
	.byte	6                               # DW_AT_encoding
	.byte	1                               # DW_AT_byte_size
	.byte	12                              # Abbrev [12] 0x10f:0x7 DW_TAG_base_type
	.word	.Linfo_string21                 # DW_AT_name
	.byte	8                               # DW_AT_byte_size
	.byte	7                               # DW_AT_encoding
	.byte	2                               # Abbrev [2] 0x116:0x11 DW_TAG_variable
	.word	.Linfo_string22                 # DW_AT_name
	.word	295                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	19                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_71
	.byte	13                              # Abbrev [13] 0x127:0x5 DW_TAG_pointer_type
	.word	300                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x12c:0x5 DW_TAG_pointer_type
	.word	60                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x131:0x11 DW_TAG_variable
	.word	.Linfo_string23                 # DW_AT_name
	.word	322                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	20                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_93
	.byte	3                               # Abbrev [3] 0x142:0x5 DW_TAG_volatile_type
	.word	327                             # DW_AT_type
	.byte	4                               # Abbrev [4] 0x147:0xb DW_TAG_typedef
	.word	338                             # DW_AT_type
	.word	.Linfo_string25                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0x152:0x7 DW_TAG_base_type
	.word	.Linfo_string24                 # DW_AT_name
	.byte	5                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x159:0x11 DW_TAG_variable
	.word	.Linfo_string26                 # DW_AT_name
	.word	362                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	21                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_136
	.byte	6                               # Abbrev [6] 0x16a:0x12 DW_TAG_array_type
	.word	380                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x16f:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	7                               # Abbrev [7] 0x175:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	14                              # Abbrev [14] 0x17c:0x3a DW_TAG_union_type
	.word	.Linfo_string29                 # DW_AT_name
	.byte	4                               # DW_AT_byte_size
	.byte	3                               # DW_AT_decl_file
	.byte	21                              # DW_AT_decl_line
	.byte	4                               # DW_AT_alignment
	.byte	10                              # Abbrev [10] 0x185:0xc DW_TAG_member
	.word	.Linfo_string7                  # DW_AT_name
	.word	199                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	22                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x191:0xc DW_TAG_member
	.word	.Linfo_string8                  # DW_AT_name
	.word	438                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	23                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x19d:0xc DW_TAG_member
	.word	.Linfo_string14                 # DW_AT_name
	.word	199                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	24                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	10                              # Abbrev [10] 0x1a9:0xc DW_TAG_member
	.word	.Linfo_string17                 # DW_AT_name
	.word	466                             # DW_AT_type
	.byte	3                               # DW_AT_decl_file
	.byte	25                              # DW_AT_decl_line
	.byte	0                               # DW_AT_data_member_location
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x1b6:0x5 DW_TAG_const_type
	.word	443                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x1bb:0x5 DW_TAG_volatile_type
	.word	448                             # DW_AT_type
	.byte	4                               # Abbrev [4] 0x1c0:0xb DW_TAG_typedef
	.word	459                             # DW_AT_type
	.word	.Linfo_string28                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	125                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0x1cb:0x7 DW_TAG_base_type
	.word	.Linfo_string27                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	2                               # DW_AT_byte_size
	.byte	15                              # Abbrev [15] 0x1d2:0x5 DW_TAG_const_type
	.word	60                              # DW_AT_type
	.byte	2                               # Abbrev [2] 0x1d7:0x11 DW_TAG_variable
	.word	.Linfo_string30                 # DW_AT_name
	.word	327                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	22                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_152
	.byte	2                               # Abbrev [2] 0x1e8:0x11 DW_TAG_variable
	.word	.Linfo_string31                 # DW_AT_name
	.word	505                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	23                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_292
	.byte	6                               # Abbrev [6] 0x1f9:0x12 DW_TAG_array_type
	.word	523                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1fe:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x204:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x20b:0x5 DW_TAG_const_type
	.word	380                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x210:0x11 DW_TAG_variable
	.word	.Linfo_string32                 # DW_AT_name
	.word	448                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	24                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_388
	.byte	2                               # Abbrev [2] 0x221:0x11 DW_TAG_variable
	.word	.Linfo_string33                 # DW_AT_name
	.word	327                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	25                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_391
	.byte	2                               # Abbrev [2] 0x232:0x11 DW_TAG_variable
	.word	.Linfo_string34                 # DW_AT_name
	.word	579                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	26                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_477
	.byte	13                              # Abbrev [13] 0x243:0x5 DW_TAG_pointer_type
	.word	584                             # DW_AT_type
	.byte	4                               # Abbrev [4] 0x248:0xb DW_TAG_typedef
	.word	595                             # DW_AT_type
	.word	.Linfo_string36                 # DW_AT_name
	.byte	1                               # DW_AT_decl_file
	.byte	135                             # DW_AT_decl_line
	.byte	5                               # Abbrev [5] 0x253:0x7 DW_TAG_base_type
	.word	.Linfo_string35                 # DW_AT_name
	.byte	7                               # DW_AT_encoding
	.byte	8                               # DW_AT_byte_size
	.byte	2                               # Abbrev [2] 0x25a:0x11 DW_TAG_variable
	.word	.Linfo_string37                 # DW_AT_name
	.word	619                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	27                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_501
	.byte	13                              # Abbrev [13] 0x26b:0x5 DW_TAG_pointer_type
	.word	579                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x270:0x11 DW_TAG_variable
	.word	.Linfo_string38                 # DW_AT_name
	.word	641                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_532
	.byte	13                              # Abbrev [13] 0x281:0x5 DW_TAG_pointer_type
	.word	295                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x286:0x11 DW_TAG_variable
	.word	.Linfo_string39                 # DW_AT_name
	.word	663                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	29                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_557
	.byte	3                               # Abbrev [3] 0x297:0x5 DW_TAG_volatile_type
	.word	668                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x29c:0x5 DW_TAG_pointer_type
	.word	165                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x2a1:0x11 DW_TAG_variable
	.word	.Linfo_string40                 # DW_AT_name
	.word	380                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	30                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_733
	.byte	2                               # Abbrev [2] 0x2b2:0x11 DW_TAG_variable
	.word	.Linfo_string41                 # DW_AT_name
	.word	707                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	31                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1096
	.byte	13                              # Abbrev [13] 0x2c3:0x5 DW_TAG_pointer_type
	.word	199                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x2c8:0x11 DW_TAG_variable
	.word	.Linfo_string42                 # DW_AT_name
	.word	729                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	32                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1126
	.byte	13                              # Abbrev [13] 0x2d9:0x5 DW_TAG_pointer_type
	.word	734                             # DW_AT_type
	.byte	15                              # Abbrev [15] 0x2de:0x5 DW_TAG_const_type
	.word	739                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x2e3:0x5 DW_TAG_pointer_type
	.word	744                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x2e8:0x5 DW_TAG_volatile_type
	.word	300                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x2ed:0x11 DW_TAG_variable
	.word	.Linfo_string43                 # DW_AT_name
	.word	380                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	33                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1548
	.byte	2                               # Abbrev [2] 0x2fe:0x11 DW_TAG_variable
	.word	.Linfo_string44                 # DW_AT_name
	.word	199                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	34                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1662
	.byte	2                               # Abbrev [2] 0x30f:0x11 DW_TAG_variable
	.word	.Linfo_string45                 # DW_AT_name
	.word	380                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	35                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1812
	.byte	2                               # Abbrev [2] 0x320:0x11 DW_TAG_variable
	.word	.Linfo_string46                 # DW_AT_name
	.word	380                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	36                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1813
	.byte	2                               # Abbrev [2] 0x331:0x11 DW_TAG_variable
	.word	.Linfo_string47                 # DW_AT_name
	.word	523                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	37                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1815
	.byte	2                               # Abbrev [2] 0x342:0x11 DW_TAG_variable
	.word	.Linfo_string48                 # DW_AT_name
	.word	851                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	38                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_1895
	.byte	15                              # Abbrev [15] 0x353:0x5 DW_TAG_const_type
	.word	744                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x358:0x11 DW_TAG_variable
	.word	.Linfo_string49                 # DW_AT_name
	.word	873                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	39                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2040
	.byte	6                               # Abbrev [6] 0x369:0xc DW_TAG_array_type
	.word	885                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x36e:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	3                               # Abbrev [3] 0x375:0x5 DW_TAG_volatile_type
	.word	890                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x37a:0x5 DW_TAG_pointer_type
	.word	895                             # DW_AT_type
	.byte	3                               # Abbrev [3] 0x37f:0x5 DW_TAG_volatile_type
	.word	900                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x384:0x5 DW_TAG_pointer_type
	.word	905                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x389:0x5 DW_TAG_pointer_type
	.word	523                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x38e:0x11 DW_TAG_variable
	.word	.Linfo_string50                 # DW_AT_name
	.word	927                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	40                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2039
	.byte	6                               # Abbrev [6] 0x39f:0xc DW_TAG_array_type
	.word	939                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x3a4:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x3ab:0x5 DW_TAG_pointer_type
	.word	885                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x3b0:0x11 DW_TAG_variable
	.word	.Linfo_string51                 # DW_AT_name
	.word	744                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	41                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2088
	.byte	2                               # Abbrev [2] 0x3c1:0x11 DW_TAG_variable
	.word	.Linfo_string52                 # DW_AT_name
	.word	978                             # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2128
	.byte	3                               # Abbrev [3] 0x3d2:0x5 DW_TAG_volatile_type
	.word	380                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x3d7:0x11 DW_TAG_variable
	.word	.Linfo_string53                 # DW_AT_name
	.word	1000                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	43                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2136
	.byte	6                               # Abbrev [6] 0x3e8:0x12 DW_TAG_array_type
	.word	1018                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x3ed:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	7                               # Abbrev [7] 0x3f3:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	3                               # Abbrev [3] 0x3fa:0x5 DW_TAG_volatile_type
	.word	1023                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x3ff:0x5 DW_TAG_pointer_type
	.word	1028                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x404:0x5 DW_TAG_pointer_type
	.word	466                             # DW_AT_type
	.byte	2                               # Abbrev [2] 0x409:0x11 DW_TAG_variable
	.word	.Linfo_string54                 # DW_AT_name
	.word	1018                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	44                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2137
	.byte	2                               # Abbrev [2] 0x41a:0x11 DW_TAG_variable
	.word	.Linfo_string55                 # DW_AT_name
	.word	1018                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	45                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2198
	.byte	2                               # Abbrev [2] 0x42b:0x11 DW_TAG_variable
	.word	.Linfo_string56                 # DW_AT_name
	.word	1084                            # DW_AT_type
                                        # DW_AT_external
	.byte	2                               # DW_AT_decl_file
	.byte	46                              # DW_AT_decl_line
	.byte	5                               # DW_AT_location
	.byte	3
	.word	g_2309
	.byte	6                               # Abbrev [6] 0x43c:0x12 DW_TAG_array_type
	.word	380                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x441:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x447:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	16                              # Abbrev [16] 0x44e:0x1 DW_TAG_pointer_type
	.byte	17                              # Abbrev [17] 0x44f:0x7b1 DW_TAG_subprogram
	.word	.Lfunc_begin0                   # DW_AT_low_pc
	.word	.Lfunc_end0-.Lfunc_begin0       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string57                 # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	52                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	380                             # DW_AT_type
                                        # DW_AT_external
	.byte	18                              # Abbrev [18] 0x464:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string108                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	52                              # DW_AT_decl_line
	.word	1028                            # DW_AT_type
	.byte	18                              # Abbrev [18] 0x472:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	100
	.word	.Linfo_string109                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	52                              # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x480:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	96
	.word	.Linfo_string110                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	52                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x48e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\206\177"
	.word	.Linfo_string111                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	54                              # DW_AT_decl_line
	.word	6673                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x49d:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200\177"
	.word	.Linfo_string112                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	55                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4ac:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374~"
	.word	.Linfo_string113                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	56                              # DW_AT_decl_line
	.word	707                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4bb:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370~"
	.word	.Linfo_string114                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	57                              # DW_AT_decl_line
	.word	900                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4ca:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364~"
	.word	.Linfo_string115                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	58                              # DW_AT_decl_line
	.word	6697                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4d9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360~"
	.word	.Linfo_string116                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	59                              # DW_AT_decl_line
	.word	6702                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4e8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354~"
	.word	.Linfo_string117                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	60                              # DW_AT_decl_line
	.word	6707                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x4f7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340`"
	.word	.Linfo_string118                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	61                              # DW_AT_decl_line
	.word	6712                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x506:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\336`"
	.word	.Linfo_string119                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	62                              # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x515:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344_"
	.word	.Linfo_string120                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	63                              # DW_AT_decl_line
	.word	6736                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x524:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340_"
	.word	.Linfo_string121                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	64                              # DW_AT_decl_line
	.word	6754                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x533:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334_"
	.word	.Linfo_string122                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	65                              # DW_AT_decl_line
	.word	6759                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x542:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330_"
	.word	.Linfo_string123                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	66                              # DW_AT_decl_line
	.word	6764                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x551:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324_"
	.word	.Linfo_string124                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	67                              # DW_AT_decl_line
	.word	6769                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x560:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320_"
	.word	.Linfo_string125                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	68                              # DW_AT_decl_line
	.word	668                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x56f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314_"
	.word	.Linfo_string126                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	69                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x57e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310_"
	.word	.Linfo_string127                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	70                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x58d:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304_"
	.word	.Linfo_string128                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	71                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x59c:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300_"
	.word	.Linfo_string129                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	72                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5ab:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274_"
	.word	.Linfo_string130                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	73                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5ba:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270_"
	.word	.Linfo_string131                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	74                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5c9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220_"
	.word	.Linfo_string132                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	75                              # DW_AT_decl_line
	.word	6779                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5d8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\216_"
	.word	.Linfo_string133                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	76                              # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5e7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200_"
	.word	.Linfo_string134                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	77                              # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x5f6:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374^"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	78                              # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x605:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370^"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	78                              # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x614:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364^"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	78                              # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x623:0x19 DW_TAG_lexical_block
	.word	.Ltmp12                         # DW_AT_low_pc
	.word	.Ltmp13-.Ltmp12                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x62c:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360^"
	.word	.Linfo_string138                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	86                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x63c:0x172 DW_TAG_lexical_block
	.word	.Ltmp13                         # DW_AT_low_pc
	.word	.Ltmp18-.Ltmp13                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x645:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354^"
	.word	.Linfo_string139                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	91                              # DW_AT_decl_line
	.word	6764                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x654:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350^"
	.word	.Linfo_string140                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	92                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x663:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344^"
	.word	.Linfo_string141                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	93                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x672:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324^"
	.word	.Linfo_string142                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	94                              # DW_AT_decl_line
	.word	6797                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x681:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320^"
	.word	.Linfo_string143                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	95                              # DW_AT_decl_line
	.word	6814                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x690:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314^"
	.word	.Linfo_string144                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	96                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x69f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310^"
	.word	.Linfo_string145                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	97                              # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6ae:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244^"
	.word	.Linfo_string146                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	98                              # DW_AT_decl_line
	.word	6819                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6bd:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240^"
	.word	.Linfo_string147                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	99                              # DW_AT_decl_line
	.word	6831                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6cc:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234^"
	.word	.Linfo_string148                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	100                             # DW_AT_decl_line
	.word	6841                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6db:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230^"
	.word	.Linfo_string149                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	101                             # DW_AT_decl_line
	.word	6851                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6ea:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224^"
	.word	.Linfo_string150                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	102                             # DW_AT_decl_line
	.word	6856                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x6f9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220^"
	.word	.Linfo_string151                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	103                             # DW_AT_decl_line
	.word	6861                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x708:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200^"
	.word	.Linfo_string152                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	104                             # DW_AT_decl_line
	.word	165                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x717:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374]"
	.word	.Linfo_string153                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	105                             # DW_AT_decl_line
	.word	6866                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x726:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370]"
	.word	.Linfo_string154                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
	.word	6769                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x735:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364]"
	.word	.Linfo_string155                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	107                             # DW_AT_decl_line
	.word	6871                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x744:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360]"
	.word	.Linfo_string156                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	108                             # DW_AT_decl_line
	.word	6876                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x753:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354]"
	.word	.Linfo_string157                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	109                             # DW_AT_decl_line
	.word	6881                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x762:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350]"
	.word	.Linfo_string158                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	110                             # DW_AT_decl_line
	.word	6886                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x771:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344]"
	.word	.Linfo_string159                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	111                             # DW_AT_decl_line
	.word	6901                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x780:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340]"
	.word	.Linfo_string160                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	112                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x78f:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334]"
	.word	.Linfo_string161                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	113                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x79e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330]"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	114                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x7ae:0xd7 DW_TAG_lexical_block
	.word	.Ltmp22                         # DW_AT_low_pc
	.word	.Ltmp34-.Ltmp22                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x7b7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324]"
	.word	.Linfo_string162                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	120                             # DW_AT_decl_line
	.word	6754                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x7c6:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320]"
	.word	.Linfo_string163                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	121                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x7d5:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314]"
	.word	.Linfo_string164                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	122                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x7e4:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310]"
	.word	.Linfo_string165                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	123                             # DW_AT_decl_line
	.word	6836                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x7f3:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304]"
	.word	.Linfo_string166                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	124                             # DW_AT_decl_line
	.word	641                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x802:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300]"
	.word	.Linfo_string167                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	125                             # DW_AT_decl_line
	.word	6906                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x811:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274]"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	126                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x820:0x64 DW_TAG_lexical_block
	.word	.Ltmp31                         # DW_AT_low_pc
	.word	.Ltmp32-.Ltmp31                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x829:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\270]"
	.word	.Linfo_string168                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	131                             # DW_AT_decl_line
	.word	707                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x838:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\264]"
	.word	.Linfo_string169                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	132                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x847:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260]"
	.word	.Linfo_string170                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	133                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x856:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\254]"
	.word	.Linfo_string171                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	134                             # DW_AT_decl_line
	.word	300                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x865:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250]"
	.word	.Linfo_string172                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	135                             # DW_AT_decl_line
	.word	641                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x874:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220]"
	.word	.Linfo_string173                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	136                             # DW_AT_decl_line
	.word	107                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x885:0x37a DW_TAG_lexical_block
	.word	.Ltmp39                         # DW_AT_low_pc
	.word	.Ltmp87-.Ltmp39                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x88e:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\377\\"
	.word	.Linfo_string174                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	144                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x89d:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370\\"
	.word	.Linfo_string175                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	145                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8ac:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364\\"
	.word	.Linfo_string176                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	146                             # DW_AT_decl_line
	.word	6764                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8bb:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\362\\"
	.word	.Linfo_string177                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	147                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8ca:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354\\"
	.word	.Linfo_string178                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	148                             # DW_AT_decl_line
	.word	6851                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8d9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350\\"
	.word	.Linfo_string179                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	149                             # DW_AT_decl_line
	.word	6856                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8e8:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344\\"
	.word	.Linfo_string180                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	150                             # DW_AT_decl_line
	.word	6861                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x8f7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\343\\"
	.word	.Linfo_string181                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	151                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x906:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334\\"
	.word	.Linfo_string182                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	152                             # DW_AT_decl_line
	.word	1028                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x915:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330\\"
	.word	.Linfo_string183                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	153                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x924:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324\\"
	.word	.Linfo_string184                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	154                             # DW_AT_decl_line
	.word	6923                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x933:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300\\"
	.word	.Linfo_string185                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	155                             # DW_AT_decl_line
	.word	107                             # DW_AT_type
	.byte	20                              # Abbrev [20] 0x942:0x258 DW_TAG_lexical_block
	.word	.Ltmp42                         # DW_AT_low_pc
	.word	.Ltmp82-.Ltmp42                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x94b:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\274\\"
	.word	.Linfo_string186                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	158                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x95a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260U"
	.word	.Linfo_string187                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	159                             # DW_AT_decl_line
	.word	6928                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x969:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314T"
	.word	.Linfo_string188                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	160                             # DW_AT_decl_line
	.word	6946                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x978:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\260T"
	.word	.Linfo_string189                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	161                             # DW_AT_decl_line
	.word	6975                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x987:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\254T"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	162                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x996:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250T"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	162                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x9a5:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244T"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	162                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x9b4:0x1e5 DW_TAG_lexical_block
	.word	.Ltmp46                         # DW_AT_low_pc
	.word	.Ltmp80-.Ltmp46                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0x9bd:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240T"
	.word	.Linfo_string190                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	166                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x9cc:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234T"
	.word	.Linfo_string191                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	167                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0x9db:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\232T"
	.word	.Linfo_string192                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	168                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x9ea:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220T"
	.word	.Linfo_string193                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	169                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0x9f9:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214T"
	.word	.Linfo_string194                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	170                             # DW_AT_decl_line
	.word	6987                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa08:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210T"
	.word	.Linfo_string195                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	171                             # DW_AT_decl_line
	.word	6992                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa17:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204T"
	.word	.Linfo_string196                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	172                             # DW_AT_decl_line
	.word	1023                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa26:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200T"
	.word	.Linfo_string197                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	173                             # DW_AT_decl_line
	.word	6764                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa35:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340S"
	.word	.Linfo_string198                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	174                             # DW_AT_decl_line
	.word	6997                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa44:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\337S"
	.word	.Linfo_string199                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	175                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa53:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330S"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	176                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0xa62:0x136 DW_TAG_lexical_block
	.word	.Ltmp54                         # DW_AT_low_pc
	.word	.Ltmp78-.Ltmp54                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0xa6b:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324S"
	.word	.Linfo_string200                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	181                             # DW_AT_decl_line
	.word	6814                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa7a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314S"
	.word	.Linfo_string201                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	182                             # DW_AT_decl_line
	.word	7009                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa89:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310S"
	.word	.Linfo_string202                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	183                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0xa98:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304S"
	.word	.Linfo_string203                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	184                             # DW_AT_decl_line
	.word	300                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0xaa7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300S"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	185                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0xab6:0x28 DW_TAG_lexical_block
	.word	.Ltmp58                         # DW_AT_low_pc
	.word	.Ltmp63-.Ltmp58                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0xabf:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240S"
	.word	.Linfo_string204                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	189                             # DW_AT_decl_line
	.word	7021                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xace:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234S"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	190                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0xade:0x64 DW_TAG_lexical_block
	.word	.Ltmp65                         # DW_AT_low_pc
	.word	.Ltmp70-.Ltmp65                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0xae7:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230S"
	.word	.Linfo_string205                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	198                             # DW_AT_decl_line
	.word	1023                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xaf6:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224S"
	.word	.Linfo_string206                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	199                             # DW_AT_decl_line
	.word	707                             # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb05:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224R"
	.word	.Linfo_string207                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	200                             # DW_AT_decl_line
	.word	7033                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb14:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220R"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	201                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb23:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214R"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	201                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb32:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210R"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	201                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0xb42:0x55 DW_TAG_lexical_block
	.word	.Ltmp71                         # DW_AT_low_pc
	.word	.Ltmp77-.Ltmp71                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0xb4b:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374Q"
	.word	.Linfo_string208                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	210                             # DW_AT_decl_line
	.word	7062                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb5a:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370Q"
	.word	.Linfo_string209                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	211                             # DW_AT_decl_line
	.word	7074                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb69:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364Q"
	.word	.Linfo_string210                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	6970                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb78:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360Q"
	.word	.Linfo_string211                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	213                             # DW_AT_decl_line
	.word	7074                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xb87:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354Q"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	214                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0xb9a:0x64 DW_TAG_lexical_block
	.word	.Ltmp82                         # DW_AT_low_pc
	.word	.Ltmp83-.Ltmp82                 # DW_AT_high_pc
	.byte	19                              # Abbrev [19] 0xba3:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350Q"
	.word	.Linfo_string212                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	229                             # DW_AT_decl_line
	.word	6764                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xbb2:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344Q"
	.word	.Linfo_string213                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	230                             # DW_AT_decl_line
	.word	7079                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xbc1:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340Q"
	.word	.Linfo_string214                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	231                             # DW_AT_decl_line
	.word	7079                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xbd0:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320Q"
	.word	.Linfo_string215                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	232                             # DW_AT_decl_line
	.word	7084                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0xbdf:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314Q"
	.word	.Linfo_string216                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	233                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	19                              # Abbrev [19] 0xbee:0xf DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310Q"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	234                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xc00:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin1                   # DW_AT_low_pc
	.word	.Lfunc_end1-.Lfunc_begin1       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string58                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc16:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc25:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	546                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xc35:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin2                   # DW_AT_low_pc
	.word	.Lfunc_end2-.Lfunc_begin2       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string59                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	627                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc4b:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	627                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc5a:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	627                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xc6a:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin3                   # DW_AT_low_pc
	.word	.Lfunc_end3-.Lfunc_begin3       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string60                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc80:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xc8f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	648                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xc9f:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin4                   # DW_AT_low_pc
	.word	.Lfunc_end4-.Lfunc_begin4       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string61                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xcb5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xcc4:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	473                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xcd4:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin5                   # DW_AT_low_pc
	.word	.Lfunc_end5-.Lfunc_begin5       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string62                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	874                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xcea:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	874                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xcf9:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	874                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xd09:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin6                   # DW_AT_low_pc
	.word	.Lfunc_end6-.Lfunc_begin6       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string63                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	662                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd1f:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	662                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd2e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	662                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xd3e:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin7                   # DW_AT_low_pc
	.word	.Lfunc_end7-.Lfunc_begin7       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string64                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd54:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd63:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	771                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xd73:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin8                   # DW_AT_low_pc
	.word	.Lfunc_end8-.Lfunc_begin8       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string65                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	757                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd89:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	757                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xd98:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	757                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xda8:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin9                   # DW_AT_low_pc
	.word	.Lfunc_end9-.Lfunc_begin9       # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string66                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	655                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xdbe:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	655                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xdcd:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	655                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xddd:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin10                  # DW_AT_low_pc
	.word	.Lfunc_end10-.Lfunc_begin10     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string67                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	910                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xdf3:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	910                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe02:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	910                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xe12:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin11                  # DW_AT_low_pc
	.word	.Lfunc_end11-.Lfunc_begin11     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string68                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe28:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe37:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	316                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xe47:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin12                  # DW_AT_low_pc
	.word	.Lfunc_end12-.Lfunc_begin12     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string69                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe5d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe6c:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	567                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xe7c:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin13                  # DW_AT_low_pc
	.word	.Lfunc_end13-.Lfunc_begin13     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string70                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	217                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xe92:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xea1:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0xeb1:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin14                  # DW_AT_low_pc
	.word	.Lfunc_end14-.Lfunc_begin14     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string71                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0xec6:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0xed4:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	42                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xee3:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin15                  # DW_AT_low_pc
	.word	.Lfunc_end15-.Lfunc_begin15     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string72                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xef9:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf08:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	783                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xf18:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin16                  # DW_AT_low_pc
	.word	.Lfunc_end16-.Lfunc_begin16     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string73                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf2e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf3d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	390                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xf4d:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin17                  # DW_AT_low_pc
	.word	.Lfunc_end17-.Lfunc_begin17     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string74                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	795                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf63:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	795                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf72:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	795                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xf82:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin18                  # DW_AT_low_pc
	.word	.Lfunc_end18-.Lfunc_begin18     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string75                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xf98:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xfa7:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	461                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0xfb7:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin19                  # DW_AT_low_pc
	.word	.Lfunc_end19-.Lfunc_begin19     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string76                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	717                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xfcd:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	717                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0xfdc:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	717                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0xfec:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin20                  # DW_AT_low_pc
	.word	.Lfunc_end20-.Lfunc_begin20     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string77                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1001:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x100f:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	186                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x101e:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin21                  # DW_AT_low_pc
	.word	.Lfunc_end21-.Lfunc_begin21     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string78                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1034:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1043:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	378                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1053:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin22                  # DW_AT_low_pc
	.word	.Lfunc_end22-.Lfunc_begin22     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string79                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1069:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1078:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	853                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1088:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin23                  # DW_AT_low_pc
	.word	.Lfunc_end23-.Lfunc_begin23     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string80                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x109e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x10ad:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	934                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x10bd:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin24                  # DW_AT_low_pc
	.word	.Lfunc_end24-.Lfunc_begin24     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string81                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	539                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x10d3:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string223                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	539                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x10e3:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin25                  # DW_AT_low_pc
	.word	.Lfunc_end25-.Lfunc_begin25     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string82                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x10f9:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1108:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	419                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1118:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin26                  # DW_AT_low_pc
	.word	.Lfunc_end26-.Lfunc_begin26     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string83                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x112e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x113d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	433                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x114d:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin27                  # DW_AT_low_pc
	.word	.Lfunc_end27-.Lfunc_begin27     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string84                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1163:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1172:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	886                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1182:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin28                  # DW_AT_low_pc
	.word	.Lfunc_end28-.Lfunc_begin28     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string85                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1197:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x11a5:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	82                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x11b4:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin29                  # DW_AT_low_pc
	.word	.Lfunc_end29-.Lfunc_begin29     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string86                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x11ca:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x11d9:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	553                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x11e9:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin30                  # DW_AT_low_pc
	.word	.Lfunc_end30-.Lfunc_begin30     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string87                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x11ff:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x120e:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	860                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x121e:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin31                  # DW_AT_low_pc
	.word	.Lfunc_end31-.Lfunc_begin31     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string88                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1234:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
	.word	584                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1243:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	922                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1253:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin32                  # DW_AT_low_pc
	.word	.Lfunc_end32-.Lfunc_begin32     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string89                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1269:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1278:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	560                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1288:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin33                  # DW_AT_low_pc
	.word	.Lfunc_end33-.Lfunc_begin33     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string90                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	94                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x129d:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	94                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x12ab:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	94                              # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x12ba:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin34                  # DW_AT_low_pc
	.word	.Lfunc_end34-.Lfunc_begin34     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string91                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x12d0:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x12df:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	831                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x12ef:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin35                  # DW_AT_low_pc
	.word	.Lfunc_end35-.Lfunc_begin35     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string92                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1304:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1312:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	130                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1321:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin36                  # DW_AT_low_pc
	.word	.Lfunc_end36-.Lfunc_begin36     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string93                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	224                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1336:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	224                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1344:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	224                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1353:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin37                  # DW_AT_low_pc
	.word	.Lfunc_end37-.Lfunc_begin37     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string94                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1368:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1376:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	28                              # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1385:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin38                  # DW_AT_low_pc
	.word	.Lfunc_end38-.Lfunc_begin38     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string95                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x139a:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x13a8:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	118                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x13b7:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin39                  # DW_AT_low_pc
	.word	.Lfunc_end39-.Lfunc_begin39     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string96                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	521                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x13cd:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	521                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x13dc:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	521                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x13ec:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin40                  # DW_AT_low_pc
	.word	.Lfunc_end40-.Lfunc_begin40     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string97                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	248                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1401:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	248                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x140f:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	248                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x141e:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin41                  # DW_AT_low_pc
	.word	.Lfunc_end41-.Lfunc_begin41     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string98                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1434:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1443:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	615                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x1453:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin42                  # DW_AT_low_pc
	.word	.Lfunc_end42-.Lfunc_begin42     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string99                 # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1468:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1476:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	212                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	17                              # Abbrev [17] 0x1485:0x42b DW_TAG_subprogram
	.word	.Lfunc_begin43                  # DW_AT_low_pc
	.word	.Lfunc_end43-.Lfunc_begin43     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string100                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	235                             # DW_AT_type
                                        # DW_AT_external
	.byte	18                              # Abbrev [18] 0x149a:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	114
	.word	.Linfo_string224                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x14a8:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	108
	.word	.Linfo_string225                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	7096                            # DW_AT_type
	.byte	18                              # Abbrev [18] 0x14b6:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string226                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	18                              # Abbrev [18] 0x14c4:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	100
	.word	.Linfo_string227                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	295                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x14d2:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	98
	.word	.Linfo_string228                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	249                             # DW_AT_decl_line
	.word	7106                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x14e0:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	92
	.word	.Linfo_string229                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	251                             # DW_AT_decl_line
	.word	1028                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x14ee:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	88
	.word	.Linfo_string230                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	252                             # DW_AT_decl_line
	.word	1023                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x14fc:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	84
	.word	.Linfo_string231                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	253                             # DW_AT_decl_line
	.word	6697                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x150a:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	80
	.word	.Linfo_string232                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	254                             # DW_AT_decl_line
	.word	6754                            # DW_AT_type
	.byte	19                              # Abbrev [19] 0x1518:0xe DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	78
	.word	.Linfo_string233                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.byte	255                             # DW_AT_decl_line
	.word	217                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1526:0xf DW_TAG_variable
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	72
	.word	.Linfo_string234                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	256                             # DW_AT_decl_line
	.word	300                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1535:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210{"
	.word	.Linfo_string235                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	257                             # DW_AT_decl_line
	.word	7111                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1545:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204{"
	.word	.Linfo_string236                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	258                             # DW_AT_decl_line
	.word	579                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1555:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\200{"
	.word	.Linfo_string237                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	259                             # DW_AT_decl_line
	.word	6886                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1565:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374z"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1575:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370z"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1585:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364z"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	260                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1595:0x256 DW_TAG_lexical_block
	.word	.Ltmp177                        # DW_AT_low_pc
	.word	.Ltmp239-.Ltmp177               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x159e:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340z"
	.word	.Linfo_string238                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	266                             # DW_AT_decl_line
	.word	107                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x15ae:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334z"
	.word	.Linfo_string239                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	267                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x15be:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330z"
	.word	.Linfo_string240                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	268                             # DW_AT_decl_line
	.word	7135                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x15ce:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324z"
	.word	.Linfo_string241                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	269                             # DW_AT_decl_line
	.word	7140                            # DW_AT_type
	.byte	25                              # Abbrev [25] 0x15de:0xc DW_TAG_label
	.word	.Linfo_string267                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	270                             # DW_AT_decl_line
	.word	.Ltmp178                        # DW_AT_low_pc
	.byte	20                              # Abbrev [20] 0x15ea:0x200 DW_TAG_lexical_block
	.word	.Ltmp181                        # DW_AT_low_pc
	.word	.Ltmp237-.Ltmp181               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x15f3:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320z"
	.word	.Linfo_string242                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	273                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1603:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314z"
	.word	.Linfo_string243                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	274                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1613:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374y"
	.word	.Linfo_string244                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	275                             # DW_AT_decl_line
	.word	7145                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1623:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234y"
	.word	.Linfo_string245                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	276                             # DW_AT_decl_line
	.word	7163                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1633:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230y"
	.word	.Linfo_string246                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	277                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1643:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224y"
	.word	.Linfo_string247                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	278                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1653:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\220y"
	.word	.Linfo_string248                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	279                             # DW_AT_decl_line
	.word	6918                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1663:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\214y"
	.word	.Linfo_string249                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	280                             # DW_AT_decl_line
	.word	6697                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1673:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\210y"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	281                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1683:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\204y"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	281                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1693:0x11c DW_TAG_lexical_block
	.word	.Ltmp185                        # DW_AT_low_pc
	.word	.Ltmp229-.Ltmp185               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x169c:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\203y"
	.word	.Linfo_string250                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	285                             # DW_AT_decl_line
	.word	235                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x16ac:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\374x"
	.word	.Linfo_string251                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	286                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x16bc:0x3a DW_TAG_lexical_block
	.word	.Ltmp191                        # DW_AT_low_pc
	.word	.Ltmp195-.Ltmp191               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x16c5:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\370x"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	291                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x16d5:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364x"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	291                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x16e5:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\360x"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	291                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x16f6:0x64 DW_TAG_lexical_block
	.word	.Ltmp197                        # DW_AT_low_pc
	.word	.Ltmp212-.Ltmp197               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x16ff:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\357x"
	.word	.Linfo_string252                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	300                             # DW_AT_decl_line
	.word	7057                            # DW_AT_type
	.byte	20                              # Abbrev [20] 0x170f:0x4a DW_TAG_lexical_block
	.word	.Ltmp201                        # DW_AT_low_pc
	.word	.Ltmp209-.Ltmp201               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x1718:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\356x"
	.word	.Linfo_string253                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	303                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1728:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350x"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	304                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1738:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\344x"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	304                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1748:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\340x"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	304                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x175a:0x1a DW_TAG_lexical_block
	.word	.Ltmp216                        # DW_AT_low_pc
	.word	.Ltmp221-.Ltmp216               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x1763:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\334x"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	317                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x1774:0x3a DW_TAG_lexical_block
	.word	.Ltmp226                        # DW_AT_low_pc
	.word	.Ltmp227-.Ltmp226               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x177d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\330x"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	324                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x178d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\324x"
	.word	.Linfo_string136                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	324                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x179d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\320x"
	.word	.Linfo_string137                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	324                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x17af:0x3a DW_TAG_lexical_block
	.word	.Ltmp234                        # DW_AT_low_pc
	.word	.Ltmp235-.Ltmp234               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x17b8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\314x"
	.word	.Linfo_string254                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	330                             # DW_AT_decl_line
	.word	300                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x17c8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\310x"
	.word	.Linfo_string255                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	331                             # DW_AT_decl_line
	.word	295                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x17d8:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\304x"
	.word	.Linfo_string256                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	332                             # DW_AT_decl_line
	.word	295                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	20                              # Abbrev [20] 0x17eb:0xc4 DW_TAG_lexical_block
	.word	.Ltmp240                        # DW_AT_low_pc
	.word	.Ltmp252-.Ltmp240               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x17f4:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\300x"
	.word	.Linfo_string257                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	340                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1804:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\250x"
	.word	.Linfo_string258                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	341                             # DW_AT_decl_line
	.word	7181                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1814:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\244x"
	.word	.Linfo_string259                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	342                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1824:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\240x"
	.word	.Linfo_string260                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	343                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1834:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\234x"
	.word	.Linfo_string261                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	344                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1844:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\230x"
	.word	.Linfo_string262                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	345                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1854:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\224x"
	.word	.Linfo_string263                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	346                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1864:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\364w"
	.word	.Linfo_string264                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	347                             # DW_AT_decl_line
	.word	7193                            # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1874:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\362w"
	.word	.Linfo_string265                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	348                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	24                              # Abbrev [24] 0x1884:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\354w"
	.word	.Linfo_string135                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	349                             # DW_AT_decl_line
	.word	71                              # DW_AT_type
	.byte	20                              # Abbrev [20] 0x1894:0x1a DW_TAG_lexical_block
	.word	.Ltmp244                        # DW_AT_low_pc
	.word	.Ltmp251-.Ltmp244               # DW_AT_high_pc
	.byte	24                              # Abbrev [24] 0x189d:0x10 DW_TAG_variable
	.byte	3                               # DW_AT_location
	.byte	145
	.ascii	"\350w"
	.word	.Linfo_string266                # DW_AT_name
	.byte	2                               # DW_AT_decl_file
	.half	353                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x18b0:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin44                  # DW_AT_low_pc
	.word	.Lfunc_end44-.Lfunc_begin44     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string101                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x18c6:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x18d5:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	104
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	447                             # DW_AT_decl_line
	.word	327                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	23                              # Abbrev [23] 0x18e5:0x32 DW_TAG_subprogram
	.word	.Lfunc_begin45                  # DW_AT_low_pc
	.word	.Lfunc_end45-.Lfunc_begin45     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string102                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x18fa:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	119
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
	.word	253                             # DW_AT_type
	.byte	18                              # Abbrev [18] 0x1908:0xe DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.byte	106                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1917:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin46                  # DW_AT_low_pc
	.word	.Lfunc_end46-.Lfunc_begin46     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string103                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	729                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x192d:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	118
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	729                             # DW_AT_decl_line
	.word	448                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x193c:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	729                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x194c:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin47                  # DW_AT_low_pc
	.word	.Lfunc_end47-.Lfunc_begin47     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string104                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1962:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string219                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1971:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string220                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	366                             # DW_AT_decl_line
	.word	210                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x1981:0x26 DW_TAG_subprogram
	.word	.Lfunc_begin48                  # DW_AT_low_pc
	.word	.Lfunc_end48-.Lfunc_begin48     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string105                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	274                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1997:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string268                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	274                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x19a7:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin49                  # DW_AT_low_pc
	.word	.Lfunc_end49-.Lfunc_begin49     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string106                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x19bd:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string217                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	22                              # Abbrev [22] 0x19cc:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string218                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	764                             # DW_AT_decl_line
	.word	199                             # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	21                              # Abbrev [21] 0x19dc:0x35 DW_TAG_subprogram
	.word	.Lfunc_begin50                  # DW_AT_low_pc
	.word	.Lfunc_end50-.Lfunc_begin50     # DW_AT_high_pc
	.byte	1                               # DW_AT_frame_base
	.byte	88
	.word	.Linfo_string107                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
                                        # DW_AT_prototyped
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x19f2:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	116
	.word	.Linfo_string221                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	22                              # Abbrev [22] 0x1a01:0xf DW_TAG_formal_parameter
	.byte	2                               # DW_AT_location
	.byte	145
	.byte	112
	.word	.Linfo_string222                # DW_AT_name
	.byte	4                               # DW_AT_decl_file
	.half	302                             # DW_AT_decl_line
	.word	60                              # DW_AT_type
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1a11:0x18 DW_TAG_array_type
	.word	253                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1a16:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a1c:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a22:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1a29:0x5 DW_TAG_pointer_type
	.word	217                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a2e:0x5 DW_TAG_pointer_type
	.word	619                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a33:0x5 DW_TAG_pointer_type
	.word	6702                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1a38:0x18 DW_TAG_array_type
	.word	107                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1a3d:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a43:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a49:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1a50:0x12 DW_TAG_array_type
	.word	199                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1a55:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a5b:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1a62:0x5 DW_TAG_pointer_type
	.word	448                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a67:0x5 DW_TAG_pointer_type
	.word	6754                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a6c:0x5 DW_TAG_pointer_type
	.word	253                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a71:0x5 DW_TAG_pointer_type
	.word	6774                            # DW_AT_type
	.byte	15                              # Abbrev [15] 0x1a76:0x5 DW_TAG_const_type
	.word	300                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1a7b:0x12 DW_TAG_array_type
	.word	60                              # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1a80:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1a86:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1a8d:0xc DW_TAG_array_type
	.word	6809                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1a92:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1a99:0x5 DW_TAG_pointer_type
	.word	707                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1a9e:0x5 DW_TAG_pointer_type
	.word	235                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1aa3:0xc DW_TAG_array_type
	.word	6697                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1aa8:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x1aaf:0x5 DW_TAG_const_type
	.word	6836                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ab4:0x5 DW_TAG_pointer_type
	.word	668                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ab9:0x5 DW_TAG_pointer_type
	.word	6846                            # DW_AT_type
	.byte	15                              # Abbrev [15] 0x1abe:0x5 DW_TAG_const_type
	.word	584                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ac3:0x5 DW_TAG_pointer_type
	.word	6841                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ac8:0x5 DW_TAG_pointer_type
	.word	6851                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1acd:0x5 DW_TAG_pointer_type
	.word	6856                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ad2:0x5 DW_TAG_pointer_type
	.word	6759                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ad7:0x5 DW_TAG_pointer_type
	.word	6769                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1adc:0x5 DW_TAG_pointer_type
	.word	6871                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ae1:0x5 DW_TAG_pointer_type
	.word	6876                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ae6:0x5 DW_TAG_pointer_type
	.word	6891                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1aeb:0x5 DW_TAG_pointer_type
	.word	6896                            # DW_AT_type
	.byte	15                              # Abbrev [15] 0x1af0:0x5 DW_TAG_const_type
	.word	107                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1af5:0x5 DW_TAG_pointer_type
	.word	6886                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1afa:0xc DW_TAG_array_type
	.word	707                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1aff:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1b06:0x5 DW_TAG_pointer_type
	.word	327                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1b0b:0x5 DW_TAG_pointer_type
	.word	380                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1b10:0x12 DW_TAG_array_type
	.word	107                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b15:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1b1b:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1b22:0x18 DW_TAG_array_type
	.word	6970                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b27:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1b2d:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1b33:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	5                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1b3a:0x5 DW_TAG_pointer_type
	.word	6923                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1b3f:0xc DW_TAG_array_type
	.word	60                              # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b44:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	7                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1b4b:0x5 DW_TAG_pointer_type
	.word	641                             # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1b50:0x5 DW_TAG_pointer_type
	.word	6987                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1b55:0xc DW_TAG_array_type
	.word	707                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b5a:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1b61:0xc DW_TAG_array_type
	.word	466                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b66:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1b6d:0xc DW_TAG_array_type
	.word	300                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b72:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1b79:0x18 DW_TAG_array_type
	.word	7057                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b7e:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1b84:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1b8a:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	4                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	15                              # Abbrev [15] 0x1b91:0x5 DW_TAG_const_type
	.word	235                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1b96:0xc DW_TAG_array_type
	.word	60                              # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1b9b:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1ba2:0x5 DW_TAG_pointer_type
	.word	6970                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1ba7:0x5 DW_TAG_pointer_type
	.word	6764                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1bac:0xc DW_TAG_array_type
	.word	107                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1bb1:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	1                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1bb8:0x5 DW_TAG_pointer_type
	.word	7101                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1bbd:0x5 DW_TAG_pointer_type
	.word	107                             # DW_AT_type
	.byte	15                              # Abbrev [15] 0x1bc2:0x5 DW_TAG_const_type
	.word	448                             # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1bc7:0x18 DW_TAG_array_type
	.word	300                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1bcc:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1bd2:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	9                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1bd8:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	13                              # Abbrev [13] 0x1bdf:0x5 DW_TAG_pointer_type
	.word	1018                            # DW_AT_type
	.byte	13                              # Abbrev [13] 0x1be4:0x5 DW_TAG_pointer_type
	.word	7135                            # DW_AT_type
	.byte	6                               # Abbrev [6] 0x1be9:0x12 DW_TAG_array_type
	.word	6891                            # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1bee:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	10                              # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1bf4:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	2                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1bfb:0x12 DW_TAG_array_type
	.word	199                             # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1c00:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	3                               # DW_AT_count
	.byte	7                               # Abbrev [7] 0x1c06:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1c0d:0xc DW_TAG_array_type
	.word	60                              # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1c12:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	6                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	6                               # Abbrev [6] 0x1c19:0xc DW_TAG_array_type
	.word	60                              # DW_AT_type
	.byte	7                               # Abbrev [7] 0x1c1e:0x6 DW_TAG_subrange_type
	.word	271                             # DW_AT_type
	.byte	8                               # DW_AT_count
	.byte	0                               # End Of Children Mark
	.byte	0                               # End Of Children Mark
.Ldebug_info_end0:
	.section	.debug_str,"MS",@progbits,1
.Linfo_string0:
	.asciz	"clang version 17.0.6 (https://gitee.com/openeuler/llvm-project.git 6e0bf6efd908a21c57cd62f3ffa72df9fe86de6a)" # string offset=0
.Linfo_string1:
	.asciz	"rnd_output1.c"                 # string offset=109
.Linfo_string2:
	.asciz	"/home/shiyanchu/outline_test/outline_cases_4_withc/2024_0727_174743" # string offset=123
.Linfo_string3:
	.asciz	"g_6"                           # string offset=191
.Linfo_string4:
	.asciz	"int"                           # string offset=195
.Linfo_string5:
	.asciz	"int32_t"                       # string offset=199
.Linfo_string6:
	.asciz	"g_70"                          # string offset=207
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
	.asciz	"__ARRAY_SIZE_TYPE__"           # string offset=307
.Linfo_string22:
	.asciz	"g_71"                          # string offset=327
.Linfo_string23:
	.asciz	"g_93"                          # string offset=332
.Linfo_string24:
	.asciz	"long long"                     # string offset=337
.Linfo_string25:
	.asciz	"int64_t"                       # string offset=347
.Linfo_string26:
	.asciz	"g_136"                         # string offset=355
.Linfo_string27:
	.asciz	"unsigned short"                # string offset=361
.Linfo_string28:
	.asciz	"uint16_t"                      # string offset=376
.Linfo_string29:
	.asciz	"U2"                            # string offset=385
.Linfo_string30:
	.asciz	"g_152"                         # string offset=388
.Linfo_string31:
	.asciz	"g_292"                         # string offset=394
.Linfo_string32:
	.asciz	"g_388"                         # string offset=400
.Linfo_string33:
	.asciz	"g_391"                         # string offset=406
.Linfo_string34:
	.asciz	"g_477"                         # string offset=412
.Linfo_string35:
	.asciz	"unsigned long long"            # string offset=418
.Linfo_string36:
	.asciz	"uint64_t"                      # string offset=437
.Linfo_string37:
	.asciz	"g_501"                         # string offset=446
.Linfo_string38:
	.asciz	"g_532"                         # string offset=452
.Linfo_string39:
	.asciz	"g_557"                         # string offset=458
.Linfo_string40:
	.asciz	"g_733"                         # string offset=464
.Linfo_string41:
	.asciz	"g_1096"                        # string offset=470
.Linfo_string42:
	.asciz	"g_1126"                        # string offset=477
.Linfo_string43:
	.asciz	"g_1548"                        # string offset=484
.Linfo_string44:
	.asciz	"g_1662"                        # string offset=491
.Linfo_string45:
	.asciz	"g_1812"                        # string offset=498
.Linfo_string46:
	.asciz	"g_1813"                        # string offset=505
.Linfo_string47:
	.asciz	"g_1815"                        # string offset=512
.Linfo_string48:
	.asciz	"g_1895"                        # string offset=519
.Linfo_string49:
	.asciz	"g_2040"                        # string offset=526
.Linfo_string50:
	.asciz	"g_2039"                        # string offset=533
.Linfo_string51:
	.asciz	"g_2088"                        # string offset=540
.Linfo_string52:
	.asciz	"g_2128"                        # string offset=547
.Linfo_string53:
	.asciz	"g_2136"                        # string offset=554
.Linfo_string54:
	.asciz	"g_2137"                        # string offset=561
.Linfo_string55:
	.asciz	"g_2198"                        # string offset=568
.Linfo_string56:
	.asciz	"g_2309"                        # string offset=575
.Linfo_string57:
	.asciz	"func_36"                       # string offset=582
.Linfo_string58:
	.asciz	"safe_add_func_uint8_t_u_u"     # string offset=590
.Linfo_string59:
	.asciz	"safe_rshift_func_uint8_t_u_u"  # string offset=616
.Linfo_string60:
	.asciz	"safe_add_func_uint16_t_u_u"    # string offset=645
.Linfo_string61:
	.asciz	"safe_div_func_int64_t_s_s"     # string offset=672
.Linfo_string62:
	.asciz	"safe_mod_func_uint64_t_u_u"    # string offset=698
.Linfo_string63:
	.asciz	"safe_mul_func_uint16_t_u_u"    # string offset=725
.Linfo_string64:
	.asciz	"safe_mod_func_uint32_t_u_u"    # string offset=752
.Linfo_string65:
	.asciz	"safe_sub_func_uint32_t_u_u"    # string offset=779
.Linfo_string66:
	.asciz	"safe_sub_func_uint16_t_u_u"    # string offset=806
.Linfo_string67:
	.asciz	"safe_lshift_func_uint64_t_u_u" # string offset=833
.Linfo_string68:
	.asciz	"safe_mul_func_int32_t_s_s"     # string offset=863
.Linfo_string69:
	.asciz	"safe_mod_func_uint8_t_u_u"     # string offset=889
.Linfo_string70:
	.asciz	"safe_rshift_func_int16_t_s_u"  # string offset=915
.Linfo_string71:
	.asciz	"safe_sub_func_int8_t_s_s"      # string offset=944
.Linfo_string72:
	.asciz	"safe_div_func_uint32_t_u_u"    # string offset=969
.Linfo_string73:
	.asciz	"safe_rshift_func_int32_t_s_u"  # string offset=996
.Linfo_string74:
	.asciz	"safe_lshift_func_uint32_t_u_s" # string offset=1025
.Linfo_string75:
	.asciz	"safe_mod_func_int64_t_s_s"     # string offset=1055
.Linfo_string76:
	.asciz	"safe_rshift_func_uint16_t_u_s" # string offset=1081
.Linfo_string77:
	.asciz	"safe_mul_func_int16_t_s_s"     # string offset=1111
.Linfo_string78:
	.asciz	"safe_rshift_func_int32_t_s_s"  # string offset=1137
.Linfo_string79:
	.asciz	"safe_add_func_uint64_t_u_u"    # string offset=1166
.Linfo_string80:
	.asciz	"safe_rshift_func_uint64_t_u_u" # string offset=1193
.Linfo_string81:
	.asciz	"safe_unary_minus_func_uint8_t_u" # string offset=1223
.Linfo_string82:
	.asciz	"safe_add_func_int64_t_s_s"     # string offset=1255
.Linfo_string83:
	.asciz	"safe_sub_func_int64_t_s_s"     # string offset=1281
.Linfo_string84:
	.asciz	"safe_div_func_uint64_t_u_u"    # string offset=1307
.Linfo_string85:
	.asciz	"safe_div_func_int8_t_s_s"      # string offset=1334
.Linfo_string86:
	.asciz	"safe_sub_func_uint8_t_u_u"     # string offset=1359
.Linfo_string87:
	.asciz	"safe_sub_func_uint64_t_u_u"    # string offset=1385
.Linfo_string88:
	.asciz	"safe_rshift_func_uint64_t_u_s" # string offset=1412
.Linfo_string89:
	.asciz	"safe_mul_func_uint8_t_u_u"     # string offset=1442
.Linfo_string90:
	.asciz	"safe_lshift_func_int8_t_s_s"   # string offset=1468
.Linfo_string91:
	.asciz	"safe_rshift_func_uint32_t_u_u" # string offset=1496
.Linfo_string92:
	.asciz	"safe_rshift_func_int8_t_s_u"   # string offset=1526
.Linfo_string93:
	.asciz	"safe_lshift_func_int16_t_s_s"  # string offset=1554
.Linfo_string94:
	.asciz	"safe_add_func_int8_t_s_s"      # string offset=1583
.Linfo_string95:
	.asciz	"safe_rshift_func_int8_t_s_s"   # string offset=1608
.Linfo_string96:
	.asciz	"safe_rshift_func_int64_t_s_u"  # string offset=1636
.Linfo_string97:
	.asciz	"safe_rshift_func_int16_t_s_s"  # string offset=1665
.Linfo_string98:
	.asciz	"safe_rshift_func_uint8_t_u_s"  # string offset=1694
.Linfo_string99:
	.asciz	"safe_div_func_int16_t_s_s"     # string offset=1723
.Linfo_string100:
	.asciz	"func_80"                       # string offset=1749
.Linfo_string101:
	.asciz	"safe_mul_func_int64_t_s_s"     # string offset=1757
.Linfo_string102:
	.asciz	"safe_lshift_func_int8_t_s_u"   # string offset=1783
.Linfo_string103:
	.asciz	"safe_rshift_func_uint16_t_u_u" # string offset=1811
.Linfo_string104:
	.asciz	"safe_lshift_func_int32_t_s_u"  # string offset=1841
.Linfo_string105:
	.asciz	"safe_unary_minus_func_int32_t_s" # string offset=1870
.Linfo_string106:
	.asciz	"safe_mul_func_uint32_t_u_u"    # string offset=1902
.Linfo_string107:
	.asciz	"safe_sub_func_int32_t_s_s"     # string offset=1929
.Linfo_string108:
	.asciz	"p_37"                          # string offset=1955
.Linfo_string109:
	.asciz	"p_38"                          # string offset=1960
.Linfo_string110:
	.asciz	"p_39"                          # string offset=1965
.Linfo_string111:
	.asciz	"l_1843"                        # string offset=1970
.Linfo_string112:
	.asciz	"l_1845"                        # string offset=1977
.Linfo_string113:
	.asciz	"l_1870"                        # string offset=1984
.Linfo_string114:
	.asciz	"l_1892"                        # string offset=1991
.Linfo_string115:
	.asciz	"l_1898"                        # string offset=1998
.Linfo_string116:
	.asciz	"l_1928"                        # string offset=2005
.Linfo_string117:
	.asciz	"l_1927"                        # string offset=2012
.Linfo_string118:
	.asciz	"l_2043"                        # string offset=2019
.Linfo_string119:
	.asciz	"l_2101"                        # string offset=2026
.Linfo_string120:
	.asciz	"l_2148"                        # string offset=2033
.Linfo_string121:
	.asciz	"l_2161"                        # string offset=2040
.Linfo_string122:
	.asciz	"l_2160"                        # string offset=2047
.Linfo_string123:
	.asciz	"l_2174"                        # string offset=2054
.Linfo_string124:
	.asciz	"l_2211"                        # string offset=2061
.Linfo_string125:
	.asciz	"l_2219"                        # string offset=2068
.Linfo_string126:
	.asciz	"l_2232"                        # string offset=2075
.Linfo_string127:
	.asciz	"l_2234"                        # string offset=2082
.Linfo_string128:
	.asciz	"l_2235"                        # string offset=2089
.Linfo_string129:
	.asciz	"l_2236"                        # string offset=2096
.Linfo_string130:
	.asciz	"l_2237"                        # string offset=2103
.Linfo_string131:
	.asciz	"l_2238"                        # string offset=2110
.Linfo_string132:
	.asciz	"l_2240"                        # string offset=2117
.Linfo_string133:
	.asciz	"l_2241"                        # string offset=2124
.Linfo_string134:
	.asciz	"l_2298"                        # string offset=2131
.Linfo_string135:
	.asciz	"i"                             # string offset=2138
.Linfo_string136:
	.asciz	"j"                             # string offset=2140
.Linfo_string137:
	.asciz	"k"                             # string offset=2142
.Linfo_string138:
	.asciz	"l_1844"                        # string offset=2144
.Linfo_string139:
	.asciz	"l_1851"                        # string offset=2151
.Linfo_string140:
	.asciz	"l_1857"                        # string offset=2158
.Linfo_string141:
	.asciz	"l_1867"                        # string offset=2165
.Linfo_string142:
	.asciz	"l_1871"                        # string offset=2172
.Linfo_string143:
	.asciz	"l_1873"                        # string offset=2179
.Linfo_string144:
	.asciz	"l_1874"                        # string offset=2186
.Linfo_string145:
	.asciz	"l_1875"                        # string offset=2193
.Linfo_string146:
	.asciz	"l_1899"                        # string offset=2200
.Linfo_string147:
	.asciz	"l_1900"                        # string offset=2207
.Linfo_string148:
	.asciz	"l_1924"                        # string offset=2214
.Linfo_string149:
	.asciz	"l_1923"                        # string offset=2221
.Linfo_string150:
	.asciz	"l_1922"                        # string offset=2228
.Linfo_string151:
	.asciz	"l_1921"                        # string offset=2235
.Linfo_string152:
	.asciz	"l_1945"                        # string offset=2242
.Linfo_string153:
	.asciz	"l_1982"                        # string offset=2249
.Linfo_string154:
	.asciz	"l_2118"                        # string offset=2256
.Linfo_string155:
	.asciz	"l_2117"                        # string offset=2263
.Linfo_string156:
	.asciz	"l_2116"                        # string offset=2270
.Linfo_string157:
	.asciz	"l_2115"                        # string offset=2277
.Linfo_string158:
	.asciz	"l_2168"                        # string offset=2284
.Linfo_string159:
	.asciz	"l_2167"                        # string offset=2291
.Linfo_string160:
	.asciz	"l_2239"                        # string offset=2298
.Linfo_string161:
	.asciz	"l_2242"                        # string offset=2305
.Linfo_string162:
	.asciz	"l_2261"                        # string offset=2312
.Linfo_string163:
	.asciz	"l_2262"                        # string offset=2319
.Linfo_string164:
	.asciz	"l_2263"                        # string offset=2326
.Linfo_string165:
	.asciz	"l_2265"                        # string offset=2333
.Linfo_string166:
	.asciz	"l_2273"                        # string offset=2340
.Linfo_string167:
	.asciz	"l_2276"                        # string offset=2347
.Linfo_string168:
	.asciz	"l_2264"                        # string offset=2354
.Linfo_string169:
	.asciz	"l_2268"                        # string offset=2361
.Linfo_string170:
	.asciz	"l_2269"                        # string offset=2368
.Linfo_string171:
	.asciz	"l_2270"                        # string offset=2375
.Linfo_string172:
	.asciz	"l_2274"                        # string offset=2382
.Linfo_string173:
	.asciz	"l_2275"                        # string offset=2389
.Linfo_string174:
	.asciz	"l_2282"                        # string offset=2396
.Linfo_string175:
	.asciz	"l_2299"                        # string offset=2403
.Linfo_string176:
	.asciz	"l_2300"                        # string offset=2410
.Linfo_string177:
	.asciz	"l_2301"                        # string offset=2417
.Linfo_string178:
	.asciz	"l_2398"                        # string offset=2424
.Linfo_string179:
	.asciz	"l_2397"                        # string offset=2431
.Linfo_string180:
	.asciz	"l_2396"                        # string offset=2438
.Linfo_string181:
	.asciz	"l_2411"                        # string offset=2445
.Linfo_string182:
	.asciz	"l_2412"                        # string offset=2452
.Linfo_string183:
	.asciz	"l_2437"                        # string offset=2459
.Linfo_string184:
	.asciz	"l_2447"                        # string offset=2466
.Linfo_string185:
	.asciz	"l_2476"                        # string offset=2473
.Linfo_string186:
	.asciz	"l_2302"                        # string offset=2480
.Linfo_string187:
	.asciz	"l_2374"                        # string offset=2487
.Linfo_string188:
	.asciz	"l_2404"                        # string offset=2494
.Linfo_string189:
	.asciz	"l_2436"                        # string offset=2501
.Linfo_string190:
	.asciz	"l_2316"                        # string offset=2508
.Linfo_string191:
	.asciz	"l_2330"                        # string offset=2515
.Linfo_string192:
	.asciz	"l_2360"                        # string offset=2522
.Linfo_string193:
	.asciz	"l_2367"                        # string offset=2529
.Linfo_string194:
	.asciz	"l_2383"                        # string offset=2536
.Linfo_string195:
	.asciz	"l_2382"                        # string offset=2543
.Linfo_string196:
	.asciz	"l_2413"                        # string offset=2550
.Linfo_string197:
	.asciz	"l_2414"                        # string offset=2557
.Linfo_string198:
	.asciz	"l_2427"                        # string offset=2564
.Linfo_string199:
	.asciz	"l_2435"                        # string offset=2571
.Linfo_string200:
	.asciz	"l_2313"                        # string offset=2578
.Linfo_string201:
	.asciz	"l_2325"                        # string offset=2585
.Linfo_string202:
	.asciz	"l_2331"                        # string offset=2592
.Linfo_string203:
	.asciz	"l_2332"                        # string offset=2599
.Linfo_string204:
	.asciz	"l_2362"                        # string offset=2606
.Linfo_string205:
	.asciz	"l_2381"                        # string offset=2613
.Linfo_string206:
	.asciz	"l_2390"                        # string offset=2620
.Linfo_string207:
	.asciz	"l_2391"                        # string offset=2627
.Linfo_string208:
	.asciz	"l_2401"                        # string offset=2634
.Linfo_string209:
	.asciz	"l_2405"                        # string offset=2641
.Linfo_string210:
	.asciz	"l_2407"                        # string offset=2648
.Linfo_string211:
	.asciz	"l_2406"                        # string offset=2655
.Linfo_string212:
	.asciz	"l_2461"                        # string offset=2662
.Linfo_string213:
	.asciz	"l_2462"                        # string offset=2669
.Linfo_string214:
	.asciz	"l_2463"                        # string offset=2676
.Linfo_string215:
	.asciz	"l_2477"                        # string offset=2683
.Linfo_string216:
	.asciz	"l_2478"                        # string offset=2690
.Linfo_string217:
	.asciz	"ui1"                           # string offset=2697
.Linfo_string218:
	.asciz	"ui2"                           # string offset=2701
.Linfo_string219:
	.asciz	"left"                          # string offset=2705
.Linfo_string220:
	.asciz	"right"                         # string offset=2710
.Linfo_string221:
	.asciz	"si1"                           # string offset=2716
.Linfo_string222:
	.asciz	"si2"                           # string offset=2720
.Linfo_string223:
	.asciz	"ui"                            # string offset=2724
.Linfo_string224:
	.asciz	"p_81"                          # string offset=2727
.Linfo_string225:
	.asciz	"p_82"                          # string offset=2732
.Linfo_string226:
	.asciz	"p_83"                          # string offset=2737
.Linfo_string227:
	.asciz	"p_84"                          # string offset=2742
.Linfo_string228:
	.asciz	"p_85"                          # string offset=2747
.Linfo_string229:
	.asciz	"l_95"                          # string offset=2752
.Linfo_string230:
	.asciz	"l_98"                          # string offset=2757
.Linfo_string231:
	.asciz	"l_110"                         # string offset=2762
.Linfo_string232:
	.asciz	"l_112"                         # string offset=2768
.Linfo_string233:
	.asciz	"l_113"                         # string offset=2774
.Linfo_string234:
	.asciz	"l_114"                         # string offset=2780
.Linfo_string235:
	.asciz	"l_115"                         # string offset=2786
.Linfo_string236:
	.asciz	"l_122"                         # string offset=2792
.Linfo_string237:
	.asciz	"l_127"                         # string offset=2798
.Linfo_string238:
	.asciz	"l_145"                         # string offset=2804
.Linfo_string239:
	.asciz	"l_155"                         # string offset=2810
.Linfo_string240:
	.asciz	"l_178"                         # string offset=2816
.Linfo_string241:
	.asciz	"l_177"                         # string offset=2822
.Linfo_string242:
	.asciz	"l_132"                         # string offset=2828
.Linfo_string243:
	.asciz	"l_138"                         # string offset=2834
.Linfo_string244:
	.asciz	"l_146"                         # string offset=2840
.Linfo_string245:
	.asciz	"l_148"                         # string offset=2846
.Linfo_string246:
	.asciz	"l_149"                         # string offset=2852
.Linfo_string247:
	.asciz	"l_150"                         # string offset=2858
.Linfo_string248:
	.asciz	"l_151"                         # string offset=2864
.Linfo_string249:
	.asciz	"l_153"                         # string offset=2870
.Linfo_string250:
	.asciz	"l_154"                         # string offset=2876
.Linfo_string251:
	.asciz	"l_158"                         # string offset=2882
.Linfo_string252:
	.asciz	"l_170"                         # string offset=2888
.Linfo_string253:
	.asciz	"l_169"                         # string offset=2894
.Linfo_string254:
	.asciz	"l_173"                         # string offset=2900
.Linfo_string255:
	.asciz	"l_174"                         # string offset=2906
.Linfo_string256:
	.asciz	"l_175"                         # string offset=2912
.Linfo_string257:
	.asciz	"l_179"                         # string offset=2918
.Linfo_string258:
	.asciz	"l_180"                         # string offset=2924
.Linfo_string259:
	.asciz	"l_181"                         # string offset=2930
.Linfo_string260:
	.asciz	"l_182"                         # string offset=2936
.Linfo_string261:
	.asciz	"l_183"                         # string offset=2942
.Linfo_string262:
	.asciz	"l_184"                         # string offset=2948
.Linfo_string263:
	.asciz	"l_185"                         # string offset=2954
.Linfo_string264:
	.asciz	"l_186"                         # string offset=2960
.Linfo_string265:
	.asciz	"l_187"                         # string offset=2966
.Linfo_string266:
	.asciz	"l_194"                         # string offset=2972
.Linfo_string267:
	.asciz	"lbl_176"                       # string offset=2978
.Linfo_string268:
	.asciz	"si"                            # string offset=2986
	.ident	"clang version 17.0.6 (https://gitee.com/openeuler/llvm-project.git 6e0bf6efd908a21c57cd62f3ffa72df9fe86de6a)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
	.addrsig_sym safe_add_func_uint8_t_u_u
	.addrsig_sym safe_rshift_func_uint8_t_u_u
	.addrsig_sym func_46
	.addrsig_sym safe_add_func_uint16_t_u_u
	.addrsig_sym safe_div_func_int64_t_s_s
	.addrsig_sym safe_mod_func_uint64_t_u_u
	.addrsig_sym safe_mul_func_uint16_t_u_u
	.addrsig_sym safe_mod_func_uint32_t_u_u
	.addrsig_sym safe_sub_func_uint32_t_u_u
	.addrsig_sym safe_sub_func_uint16_t_u_u
	.addrsig_sym safe_lshift_func_uint64_t_u_u
	.addrsig_sym safe_mul_func_int32_t_s_s
	.addrsig_sym safe_mod_func_uint8_t_u_u
	.addrsig_sym safe_rshift_func_int16_t_s_u
	.addrsig_sym safe_sub_func_int8_t_s_s
	.addrsig_sym safe_div_func_uint32_t_u_u
	.addrsig_sym safe_rshift_func_int32_t_s_u
	.addrsig_sym safe_lshift_func_uint32_t_u_s
	.addrsig_sym safe_mod_func_int64_t_s_s
	.addrsig_sym safe_rshift_func_uint16_t_u_s
	.addrsig_sym safe_mul_func_int16_t_s_s
	.addrsig_sym safe_rshift_func_int32_t_s_s
	.addrsig_sym safe_add_func_uint64_t_u_u
	.addrsig_sym safe_rshift_func_uint64_t_u_u
	.addrsig_sym safe_unary_minus_func_uint8_t_u
	.addrsig_sym safe_sub_func_int64_t_s_s
	.addrsig_sym safe_div_func_uint64_t_u_u
	.addrsig_sym safe_div_func_int8_t_s_s
	.addrsig_sym safe_sub_func_uint8_t_u_u
	.addrsig_sym safe_sub_func_uint64_t_u_u
	.addrsig_sym safe_rshift_func_uint64_t_u_s
	.addrsig_sym safe_mul_func_uint8_t_u_u
	.addrsig_sym safe_lshift_func_int8_t_s_s
	.addrsig_sym safe_rshift_func_uint32_t_u_u
	.addrsig_sym safe_rshift_func_int8_t_s_u
	.addrsig_sym safe_lshift_func_int16_t_s_s
	.addrsig_sym safe_add_func_int8_t_s_s
	.addrsig_sym safe_rshift_func_int8_t_s_s
	.addrsig_sym safe_rshift_func_int64_t_s_u
	.addrsig_sym safe_rshift_func_int16_t_s_s
	.addrsig_sym safe_rshift_func_uint8_t_u_s
	.addrsig_sym safe_div_func_int16_t_s_s
	.addrsig_sym safe_mul_func_int64_t_s_s
	.addrsig_sym safe_lshift_func_int8_t_s_u
	.addrsig_sym safe_rshift_func_uint16_t_u_u
	.addrsig_sym safe_lshift_func_int32_t_s_u
	.addrsig_sym safe_unary_minus_func_int32_t_s
	.addrsig_sym safe_mul_func_uint32_t_u_u
	.addrsig_sym safe_sub_func_int32_t_s_s
	.addrsig_sym g_6
	.addrsig_sym g_70
	.addrsig_sym g_71
	.addrsig_sym g_93
	.addrsig_sym g_136
	.addrsig_sym g_152
	.addrsig_sym g_391
	.addrsig_sym g_477
	.addrsig_sym g_501
	.addrsig_sym g_467
	.addrsig_sym g_556
	.addrsig_sym g_557
	.addrsig_sym g_733
	.addrsig_sym g_1127
	.addrsig_sym g_1662
	.addrsig_sym g_1812
	.addrsig_sym g_589
	.addrsig_sym g_1810
	.addrsig_sym g_2040
	.addrsig_sym g_2088
	.addrsig_sym g_1380
	.addrsig_sym g_1007
	.addrsig_sym g_97
	.addrsig_sym g_2137
	.addrsig_sym g_2198
	.addrsig_sym g_2309
	.addrsig_sym g_1811
	.addrsig_sym g_955
	.addrsig_sym g_947
	.addrsig_sym g_69
	.addrsig_sym g_197
	.addrsig_sym g_325
	.addrsig_sym g_200
	.addrsig_sym g_1816
	.addrsig_sym g_1717
	.addrsig_sym g_2017
	.addrsig_sym g_1373
	.addrsig_sym g_555
	.addrsig_sym g_1971
	.addrsig_sym g_92
	.addrsig_sym g_1259
	.addrsig_sym g_2277
	.addrsig_sym g_2448
	.addrsig_sym g_1414
	.addrsig_sym g_642
	.addrsig_sym g_1247
	.addrsig_sym g_252
	.addrsig_sym g_588
	.addrsig_sym g_111
	.addrsig_sym g_2070
	.addrsig_sym g_117
	.addrsig_sym g_2
	.addrsig_sym g_1818
	.addrsig_sym g_2079
	.addrsig_sym g_1970
	.addrsig_sym g_1374
	.addrsig_sym g_2014
	.addrsig_sym g_765
	.addrsig_sym g_3
	.addrsig_sym g_89
	.addrsig_sym g_8
	.addrsig_sym g_13
	.addrsig_sym g_123
	.addrsig_sym g_99
	.addrsig_sym g_116
	.addrsig_sym g_124
	.addrsig_sym g_133
	.addrsig_sym g_147
	.addrsig_sym g_96
	.section	.debug_line,"",@progbits
.Lline_table_start0:
