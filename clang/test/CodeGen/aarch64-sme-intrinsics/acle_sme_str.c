// REQUIRES: aarch64-registered-target
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -emit-llvm -o - %s | FileCheck %s -check-prefixes=CHECK,CHECK-C
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -emit-llvm -o - -x c++ %s | FileCheck %s -check-prefixes=CHECK,CHECK-CXX
// RUN: %clang_cc1 -triple aarch64-none-linux-gnu -target-feature +sme -S -O1 -Werror -o /dev/null %s

#include <arm_sme.h>

// CHECK-C-LABEL: @test_svstr_vnum_za(
// CHECK-CXX-LABEL: @_Z18test_svstr_vnum_zajPv(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    tail call void @llvm.aarch64.sme.str(i32 [[SLICE_BASE:%.*]], ptr [[PTR:%.*]], i32 0)
// CHECK-NEXT:    ret void
//
void test_svstr_vnum_za(uint32_t slice_base, void *ptr) __arm_in("za") {
  svstr_vnum_za(slice_base, ptr, 0);
}

// CHECK-C-LABEL: @test_svstr_vnum_za_1(
// CHECK-CXX-LABEL: @_Z20test_svstr_vnum_za_1jPv(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    tail call void @llvm.aarch64.sme.str(i32 [[SLICE_BASE:%.*]], ptr [[PTR:%.*]], i32 15)
// CHECK-NEXT:    ret void
//
void test_svstr_vnum_za_1(uint32_t slice_base, void *ptr) __arm_in("za") {
  svstr_vnum_za(slice_base, ptr, 15);
}

// CHECK-C-LABEL: @test_svstr_za(
// CHECK-CXX-LABEL: @_Z13test_svstr_zajPv(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    tail call void @llvm.aarch64.sme.str(i32 [[SLICE_BASE:%.*]], ptr [[PTR:%.*]], i32 0)
// CHECK-NEXT:    ret void
//
void test_svstr_za(uint32_t slice_base, void *ptr) __arm_in("za") {
  svstr_za(slice_base, ptr);
}

// CHECK-C-LABEL: @test_svstr_vnum_za_var(
// CHECK-CXX-LABEL: @_Z22test_svstr_vnum_za_varjPvl(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    [[TMP0:%.*]] = trunc i64 [[VNUM:%.*]] to i32
// CHECK-NEXT:    tail call void @llvm.aarch64.sme.str(i32 [[SLICE_BASE:%.*]], ptr [[PTR:%.*]], i32 [[TMP0:%.*]])
// CHECK-NEXT:    ret void
//
void test_svstr_vnum_za_var(uint32_t slice_base, void *ptr, int64_t vnum) __arm_in("za") {
  svstr_vnum_za(slice_base, ptr, vnum);
}

// CHECK-C-LABEL: @test_svstr_vnum_za_2(
// CHECK-CXX-LABEL: @_Z20test_svstr_vnum_za_2jPv(
// CHECK-NEXT:  entry:
// CHECK-NEXT:    tail call void @llvm.aarch64.sme.str(i32 [[SLICE_BASE:%.*]], ptr [[PTR:%.*]], i32 16)
// CHECK-NEXT:    ret void
//
void test_svstr_vnum_za_2(uint32_t slice_base, void *ptr) __arm_in("za") {
  svstr_vnum_za(slice_base, ptr, 16);
}
