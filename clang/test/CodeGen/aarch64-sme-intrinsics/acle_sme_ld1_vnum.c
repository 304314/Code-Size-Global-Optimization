// REQUIRES: aarch64-registered-target
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -emit-llvm -o - %s | FileCheck %s -check-prefixes=CHECK,CHECK-C
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -emit-llvm -o - -x c++ %s | FileCheck %s -check-prefixes=CHECK,CHECK-CXX
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -o /dev/null %s

#include <arm_sme.h>

// CHECK-C-LABEL:   @test_svld1_hor_vnum_za8(
// CHECK-CXX-LABEL: @_Z23test_svld1_hor_vnum_za8ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP0]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP1:%.*]] = getelementptr i8, [[PTRTY:ptr|i8\*]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1b.horiz(<vscale x 16 x i1> [[PG:%.*]], [[PTRTY]] [[TMP1]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 15
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1b.horiz(<vscale x 16 x i1> [[PG]], [[PTRTY]] [[TMP1]], i32 0, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_hor_vnum_za8(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_hor_vnum_za8(0, slice_base, pg, ptr, vnum);
  svld1_hor_vnum_za8(0, slice_base + 15, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_hor_vnum_za16(
// CHECK-CXX-LABEL: @_Z24test_svld1_hor_vnum_za16ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1h.horiz(<vscale x 8 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 7
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1h.horiz(<vscale x 8 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 1, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_hor_vnum_za16(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_hor_vnum_za16(0, slice_base, pg, ptr, vnum);
  svld1_hor_vnum_za16(1, slice_base + 7, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_hor_vnum_za32(
// CHECK-CXX-LABEL: @_Z24test_svld1_hor_vnum_za32ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1w.horiz(<vscale x 4 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 3
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1w.horiz(<vscale x 4 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 3, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_hor_vnum_za32(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_hor_vnum_za32(0, slice_base, pg, ptr, vnum);
  svld1_hor_vnum_za32(3, slice_base + 3, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_hor_vnum_za64(
// CHECK-CXX-LABEL: @_Z24test_svld1_hor_vnum_za64ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1d.horiz(<vscale x 2 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 1
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1d.horiz(<vscale x 2 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 7, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_hor_vnum_za64(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_hor_vnum_za64(0, slice_base, pg, ptr, vnum);
  svld1_hor_vnum_za64(7, slice_base + 1, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_hor_vnum_za128(
// CHECK-CXX-LABEL: @_Z25test_svld1_hor_vnum_za128ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 1 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv1i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1q.horiz(<vscale x 1 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1q.horiz(<vscale x 1 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 15, i32 [[SLICE_BASE]])
// CHECK-NEXT:        ret void
//
void test_svld1_hor_vnum_za128(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_hor_vnum_za128(0, slice_base, pg, ptr, vnum);
  svld1_hor_vnum_za128(15, slice_base, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_ver_hor_za8(
// CHECK-CXX-LABEL: @_Z22test_svld1_ver_hor_za8ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP0]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP1:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1b.vert(<vscale x 16 x i1> [[PG:%.*]], [[PTRTY]] [[TMP1]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 15
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1b.vert(<vscale x 16 x i1> [[PG]], [[PTRTY]] [[TMP1]], i32 0, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_ver_hor_za8(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_ver_vnum_za8(0, slice_base, pg, ptr, vnum);
  svld1_ver_vnum_za8(0, slice_base + 15, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_ver_vnum_za16(
// CHECK-CXX-LABEL: @_Z24test_svld1_ver_vnum_za16ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 8 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv8i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1h.vert(<vscale x 8 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 7
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1h.vert(<vscale x 8 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 1, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_ver_vnum_za16(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_ver_vnum_za16(0, slice_base, pg, ptr, vnum);
  svld1_ver_vnum_za16(1, slice_base + 7, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_ver_vnum_za32(
// CHECK-CXX-LABEL: @_Z24test_svld1_ver_vnum_za32ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 4 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv4i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1w.vert(<vscale x 4 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 3
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1w.vert(<vscale x 4 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 3, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_ver_vnum_za32(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_ver_vnum_za32(0, slice_base, pg, ptr, vnum);
  svld1_ver_vnum_za32(3, slice_base + 3, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_ver_vnum_za64(
// CHECK-CXX-LABEL: @_Z24test_svld1_ver_vnum_za64ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 2 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv2i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1d.vert(<vscale x 2 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        [[TILESLICE2:%.*]] = add i32 [[SLICE_BASE]], 1
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1d.vert(<vscale x 2 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 7, i32 [[TILESLICE2]])
// CHECK-NEXT:        ret void
//
void test_svld1_ver_vnum_za64(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_ver_vnum_za64(0, slice_base, pg, ptr, vnum);
  svld1_ver_vnum_za64(7, slice_base + 1, pg, ptr, vnum);
}

// CHECK-C-LABEL:   @test_svld1_ver_vnum_za128(
// CHECK-CXX-LABEL: @_Z25test_svld1_ver_vnum_za128ju10__SVBool_tPKvl(
// CHECK-NEXT:      entry:
// CHECK-NEXT:        [[TMP0:%.*]] = tail call <vscale x 1 x i1> @llvm.aarch64.sve.convert.from.svbool.nxv1i1(<vscale x 16 x i1> [[PG:%.*]])
// CHECK-NEXT:        [[TMP1:%.*]] = tail call i64 @llvm.aarch64.sme.cntsb()
// CHECK-NEXT:        [[MULVL:%.*]] = mul i64 [[TMP1]], [[VNUM:%.*]]
// CHECK-NEXT:        [[TMP2:%.*]] = getelementptr i8, [[PTRTY]] [[PTR:%.*]], i64 [[MULVL]]
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1q.vert(<vscale x 1 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 0, i32 [[SLICE_BASE:%.*]])
// CHECK-NEXT:        tail call void @llvm.aarch64.sme.ld1q.vert(<vscale x 1 x i1> [[TMP0]], [[PTRTY]] [[TMP2]], i32 15, i32 [[SLICE_BASE]])
// CHECK-NEXT:        ret void
//
void test_svld1_ver_vnum_za128(uint32_t slice_base, svbool_t pg, const void *ptr, int64_t vnum) __arm_streaming __arm_out("za") {
  svld1_ver_vnum_za128(0, slice_base, pg, ptr, vnum);
  svld1_ver_vnum_za128(15, slice_base, pg, ptr, vnum);
}
