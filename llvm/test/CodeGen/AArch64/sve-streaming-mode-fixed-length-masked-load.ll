; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc -mattr=+sve -force-streaming-compatible-sve < %s | FileCheck %s


target triple = "aarch64-unknown-linux-gnu"

;
; Masked Load
;

define <4 x i8> @masked_load_v4i8(ptr %src, <4 x i1> %mask) {
; CHECK-LABEL: masked_load_v4i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    cmpne p0.h, p0/z, z0.h, #0
; CHECK-NEXT:    ld1b { z0.h }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %load = call <4 x i8> @llvm.masked.load.v4i8(ptr %src, i32 8, <4 x i1> %mask, <4 x i8> zeroinitializer)
  ret <4 x i8> %load
}

define <8 x i8> @masked_load_v8i8(ptr %src, <8 x i1> %mask) {
; CHECK-LABEL: masked_load_v8i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.b, vl8
; CHECK-NEXT:    lsl z0.b, z0.b, #7
; CHECK-NEXT:    asr z0.b, z0.b, #7
; CHECK-NEXT:    cmpne p0.b, p0/z, z0.b, #0
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %load = call <8 x i8> @llvm.masked.load.v8i8(ptr %src, i32 8, <8 x i1> %mask, <8 x i8> zeroinitializer)
  ret <8 x i8> %load
}

define <16 x i8> @masked_load_v16i8(ptr %src, <16 x i1> %mask) {
; CHECK-LABEL: masked_load_v16i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    ptrue p0.b, vl16
; CHECK-NEXT:    lsl z0.b, z0.b, #7
; CHECK-NEXT:    asr z0.b, z0.b, #7
; CHECK-NEXT:    cmpne p0.b, p0/z, z0.b, #0
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %load = call <16 x i8> @llvm.masked.load.v16i8(ptr %src, i32 8, <16 x i1> %mask, <16 x i8> zeroinitializer)
  ret <16 x i8> %load
}

define <32 x i8> @masked_load_v32i8(ptr %src, <32 x i1> %mask) {
; CHECK-LABEL: masked_load_v32i8:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #32
; CHECK-NEXT:    .cfi_def_cfa_offset 32
; CHECK-NEXT:    ldr w8, [sp, #224]
; CHECK-NEXT:    strb w7, [sp, #6]
; CHECK-NEXT:    ldr w9, [sp, #216]
; CHECK-NEXT:    strb w6, [sp, #5]
; CHECK-NEXT:    ldr w10, [sp, #208]
; CHECK-NEXT:    strb w5, [sp, #4]
; CHECK-NEXT:    strb w8, [sp, #31]
; CHECK-NEXT:    ldr w8, [sp, #200]
; CHECK-NEXT:    strb w9, [sp, #30]
; CHECK-NEXT:    ldr w9, [sp, #192]
; CHECK-NEXT:    strb w10, [sp, #29]
; CHECK-NEXT:    ldr w10, [sp, #184]
; CHECK-NEXT:    strb w8, [sp, #28]
; CHECK-NEXT:    ldr w8, [sp, #176]
; CHECK-NEXT:    strb w9, [sp, #27]
; CHECK-NEXT:    ldr w9, [sp, #168]
; CHECK-NEXT:    strb w10, [sp, #26]
; CHECK-NEXT:    ldr w10, [sp, #160]
; CHECK-NEXT:    strb w8, [sp, #25]
; CHECK-NEXT:    ldr w8, [sp, #152]
; CHECK-NEXT:    strb w9, [sp, #24]
; CHECK-NEXT:    ldr w9, [sp, #144]
; CHECK-NEXT:    strb w10, [sp, #23]
; CHECK-NEXT:    ldr w10, [sp, #136]
; CHECK-NEXT:    strb w8, [sp, #22]
; CHECK-NEXT:    ldr w8, [sp, #128]
; CHECK-NEXT:    strb w9, [sp, #21]
; CHECK-NEXT:    ldr w9, [sp, #120]
; CHECK-NEXT:    strb w10, [sp, #20]
; CHECK-NEXT:    ldr w10, [sp, #112]
; CHECK-NEXT:    strb w8, [sp, #19]
; CHECK-NEXT:    ldr w8, [sp, #104]
; CHECK-NEXT:    strb w9, [sp, #18]
; CHECK-NEXT:    ldr w9, [sp, #96]
; CHECK-NEXT:    strb w10, [sp, #17]
; CHECK-NEXT:    ldr w10, [sp, #88]
; CHECK-NEXT:    strb w8, [sp, #16]
; CHECK-NEXT:    ldr w8, [sp, #80]
; CHECK-NEXT:    strb w9, [sp, #15]
; CHECK-NEXT:    ldr w9, [sp, #72]
; CHECK-NEXT:    strb w10, [sp, #14]
; CHECK-NEXT:    ldr w10, [sp, #64]
; CHECK-NEXT:    strb w8, [sp, #13]
; CHECK-NEXT:    ldr w8, [sp, #56]
; CHECK-NEXT:    strb w9, [sp, #12]
; CHECK-NEXT:    ldr w9, [sp, #48]
; CHECK-NEXT:    strb w10, [sp, #11]
; CHECK-NEXT:    ldr w10, [sp, #40]
; CHECK-NEXT:    strb w8, [sp, #10]
; CHECK-NEXT:    ldr w8, [sp, #32]
; CHECK-NEXT:    strb w9, [sp, #9]
; CHECK-NEXT:    ptrue p0.b, vl16
; CHECK-NEXT:    strb w10, [sp, #8]
; CHECK-NEXT:    strb w8, [sp, #7]
; CHECK-NEXT:    mov w8, #16 // =0x10
; CHECK-NEXT:    strb w4, [sp, #3]
; CHECK-NEXT:    strb w3, [sp, #2]
; CHECK-NEXT:    strb w2, [sp, #1]
; CHECK-NEXT:    strb w1, [sp]
; CHECK-NEXT:    ldp q1, q0, [sp]
; CHECK-NEXT:    lsl z1.b, z1.b, #7
; CHECK-NEXT:    asr z1.b, z1.b, #7
; CHECK-NEXT:    lsl z0.b, z0.b, #7
; CHECK-NEXT:    asr z0.b, z0.b, #7
; CHECK-NEXT:    cmpne p1.b, p0/z, z0.b, #0
; CHECK-NEXT:    cmpne p0.b, p0/z, z1.b, #0
; CHECK-NEXT:    ld1b { z0.b }, p0/z, [x0]
; CHECK-NEXT:    ld1b { z1.b }, p1/z, [x0, x8]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    add sp, sp, #32
; CHECK-NEXT:    ret
  %load = call <32 x i8> @llvm.masked.load.v32i8(ptr %src, i32 8, <32 x i1> %mask, <32 x i8> zeroinitializer)
  ret <32 x i8> %load
}

define <2 x half> @masked_load_v2f16(ptr %src, <2 x i1> %mask) {
; CHECK-LABEL: masked_load_v2f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    fmov w8, s0
; CHECK-NEXT:    str wzr, [sp, #12]
; CHECK-NEXT:    mov z0.s, z0.s[1]
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    fmov w9, s0
; CHECK-NEXT:    strh w8, [sp, #8]
; CHECK-NEXT:    strh w9, [sp, #10]
; CHECK-NEXT:    ldr d0, [sp, #8]
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    cmpne p0.h, p0/z, z0.h, #0
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %load = call <2 x half> @llvm.masked.load.v2f16(ptr %src, i32 8, <2 x i1> %mask, <2 x half> zeroinitializer)
  ret <2 x half> %load
}

define <4 x half> @masked_load_v4f16(ptr %src, <4 x i1> %mask) {
; CHECK-LABEL: masked_load_v4f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl4
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    cmpne p0.h, p0/z, z0.h, #0
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %load = call <4 x half> @llvm.masked.load.v4f16(ptr %src, i32 8, <4 x i1> %mask, <4 x half> zeroinitializer)
  ret <4 x half> %load
}

define <8 x half> @masked_load_v8f16(ptr %src, <8 x i1> %mask) {
; CHECK-LABEL: masked_load_v8f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    uunpklo z0.h, z0.b
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    cmpne p0.h, p0/z, z0.h, #0
; CHECK-NEXT:    ld1h { z0.h }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %load = call <8 x half> @llvm.masked.load.v8f16(ptr %src, i32 8, <8 x i1> %mask, <8 x half> zeroinitializer)
  ret <8 x half> %load
}

define <16 x half> @masked_load_v16f16(ptr %src, <16 x i1> %mask) {
; CHECK-LABEL: masked_load_v16f16:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $q0 killed $q0 def $z0
; CHECK-NEXT:    uunpklo z1.h, z0.b
; CHECK-NEXT:    mov x8, #8 // =0x8
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    lsl z1.h, z1.h, #15
; CHECK-NEXT:    uunpklo z0.h, z0.b
; CHECK-NEXT:    asr z1.h, z1.h, #15
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    ptrue p0.h, vl8
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    cmpne p1.h, p0/z, z1.h, #0
; CHECK-NEXT:    cmpne p0.h, p0/z, z0.h, #0
; CHECK-NEXT:    ld1h { z0.h }, p1/z, [x0]
; CHECK-NEXT:    ld1h { z1.h }, p0/z, [x0, x8, lsl #1]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    ret
  %load = call <16 x half> @llvm.masked.load.v16f16(ptr %src, i32 8, <16 x i1> %mask, <16 x half> zeroinitializer)
  ret <16 x half> %load
}

define <2 x float> @masked_load_v2f32(ptr %src, <2 x i1> %mask) {
; CHECK-LABEL: masked_load_v2f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl2
; CHECK-NEXT:    lsl z0.s, z0.s, #31
; CHECK-NEXT:    asr z0.s, z0.s, #31
; CHECK-NEXT:    cmpne p0.s, p0/z, z0.s, #0
; CHECK-NEXT:    ld1w { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $d0 killed $d0 killed $z0
; CHECK-NEXT:    ret
  %load = call <2 x float> @llvm.masked.load.v2f32(ptr %src, i32 8, <2 x i1> %mask, <2 x float> zeroinitializer)
  ret <2 x float> %load
}

define <4 x float> @masked_load_v4f32(ptr %src, <4 x i1> %mask) {
; CHECK-LABEL: masked_load_v4f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    lsl z0.s, z0.s, #31
; CHECK-NEXT:    asr z0.s, z0.s, #31
; CHECK-NEXT:    cmpne p0.s, p0/z, z0.s, #0
; CHECK-NEXT:    ld1w { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %load = call <4 x float> @llvm.masked.load.v4f32(ptr %src, i32 8, <4 x i1> %mask, <4 x float> zeroinitializer)
  ret <4 x float> %load
}

define <8 x float> @masked_load_v8f32(ptr %src, <8 x i1> %mask) {
; CHECK-LABEL: masked_load_v8f32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    fmov w8, s0
; CHECK-NEXT:    mov z1.b, z0.b[3]
; CHECK-NEXT:    mov z2.b, z0.b[2]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    mov z3.b, z0.b[1]
; CHECK-NEXT:    mov z4.b, z0.b[7]
; CHECK-NEXT:    mov z5.b, z0.b[6]
; CHECK-NEXT:    mov z6.b, z0.b[5]
; CHECK-NEXT:    fmov w9, s1
; CHECK-NEXT:    mov z0.b, z0.b[4]
; CHECK-NEXT:    fmov w10, s2
; CHECK-NEXT:    strh w8, [sp, #-16]!
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    fmov w8, s3
; CHECK-NEXT:    strh w9, [sp, #6]
; CHECK-NEXT:    fmov w9, s4
; CHECK-NEXT:    strh w10, [sp, #4]
; CHECK-NEXT:    fmov w10, s5
; CHECK-NEXT:    strh w8, [sp, #2]
; CHECK-NEXT:    fmov w8, s6
; CHECK-NEXT:    strh w9, [sp, #14]
; CHECK-NEXT:    fmov w9, s0
; CHECK-NEXT:    strh w10, [sp, #12]
; CHECK-NEXT:    strh w8, [sp, #10]
; CHECK-NEXT:    mov x8, #4 // =0x4
; CHECK-NEXT:    strh w9, [sp, #8]
; CHECK-NEXT:    ldp d0, d1, [sp]
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    uunpklo z1.s, z1.h
; CHECK-NEXT:    lsl z0.s, z0.s, #31
; CHECK-NEXT:    lsl z1.s, z1.s, #31
; CHECK-NEXT:    asr z0.s, z0.s, #31
; CHECK-NEXT:    asr z1.s, z1.s, #31
; CHECK-NEXT:    cmpne p1.s, p0/z, z0.s, #0
; CHECK-NEXT:    cmpne p0.s, p0/z, z1.s, #0
; CHECK-NEXT:    ld1w { z0.s }, p1/z, [x0]
; CHECK-NEXT:    ld1w { z1.s }, p0/z, [x0, x8, lsl #2]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %load = call <8 x float> @llvm.masked.load.v8f32(ptr %src, i32 8, <8 x i1> %mask, <8 x float> zeroinitializer)
  ret <8 x float> %load
}

define <2 x double> @masked_load_v2f64(ptr %src, <2 x i1> %mask) {
; CHECK-LABEL: masked_load_v2f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    uunpklo z0.d, z0.s
; CHECK-NEXT:    lsl z0.d, z0.d, #63
; CHECK-NEXT:    asr z0.d, z0.d, #63
; CHECK-NEXT:    cmpne p0.d, p0/z, z0.d, #0
; CHECK-NEXT:    ld1d { z0.d }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    ret
  %load = call <2 x double> @llvm.masked.load.v2f64(ptr %src, i32 8, <2 x i1> %mask, <2 x double> zeroinitializer)
  ret <2 x double> %load
}

define <4 x double> @masked_load_v4f64(ptr %src, <4 x i1> %mask) {
; CHECK-LABEL: masked_load_v4f64:
; CHECK:       // %bb.0:
; CHECK-NEXT:    // kill: def $d0 killed $d0 def $z0
; CHECK-NEXT:    mov x8, #2 // =0x2
; CHECK-NEXT:    ptrue p0.d, vl2
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    uunpklo z1.d, z0.s
; CHECK-NEXT:    ext z0.b, z0.b, z0.b, #8
; CHECK-NEXT:    uunpklo z0.d, z0.s
; CHECK-NEXT:    lsl z1.d, z1.d, #63
; CHECK-NEXT:    lsl z0.d, z0.d, #63
; CHECK-NEXT:    asr z1.d, z1.d, #63
; CHECK-NEXT:    asr z0.d, z0.d, #63
; CHECK-NEXT:    cmpne p1.d, p0/z, z1.d, #0
; CHECK-NEXT:    cmpne p0.d, p0/z, z0.d, #0
; CHECK-NEXT:    ld1d { z0.d }, p1/z, [x0]
; CHECK-NEXT:    ld1d { z1.d }, p0/z, [x0, x8, lsl #3]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    // kill: def $q1 killed $q1 killed $z1
; CHECK-NEXT:    ret
  %load = call <4 x double> @llvm.masked.load.v4f64(ptr %src, i32 8, <4 x i1> %mask, <4 x double> zeroinitializer)
  ret <4 x double> %load
}

define <3 x i32> @masked_load_zext_v3i32(ptr %load_ptr, <3 x i1> %pm) {
; CHECK-LABEL: masked_load_zext_v3i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    adrp x8, .LCPI13_0
; CHECK-NEXT:    strh w3, [sp, #12]
; CHECK-NEXT:    strh w2, [sp, #10]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    strh w1, [sp, #8]
; CHECK-NEXT:    ldr d0, [x8, :lo12:.LCPI13_0]
; CHECK-NEXT:    ldr d1, [sp, #8]
; CHECK-NEXT:    and z0.d, z1.d, z0.d
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    cmpne p0.s, p0/z, z0.s, #0
; CHECK-NEXT:    ld1h { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %load_value = tail call <3 x i16> @llvm.masked.load.v3i16.p0(ptr %load_ptr, i32 4, <3 x i1> %pm, <3 x i16> zeroinitializer)
  %extend = zext <3 x i16> %load_value to <3 x i32>
  ret <3 x i32> %extend;
}

define <3 x i32> @masked_load_sext_v3i32(ptr %load_ptr, <3 x i1> %pm) {
; CHECK-LABEL: masked_load_sext_v3i32:
; CHECK:       // %bb.0:
; CHECK-NEXT:    sub sp, sp, #16
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    adrp x8, .LCPI14_0
; CHECK-NEXT:    strh w3, [sp, #12]
; CHECK-NEXT:    strh w2, [sp, #10]
; CHECK-NEXT:    ptrue p0.s, vl4
; CHECK-NEXT:    strh w1, [sp, #8]
; CHECK-NEXT:    ldr d0, [x8, :lo12:.LCPI14_0]
; CHECK-NEXT:    ldr d1, [sp, #8]
; CHECK-NEXT:    and z0.d, z1.d, z0.d
; CHECK-NEXT:    lsl z0.h, z0.h, #15
; CHECK-NEXT:    asr z0.h, z0.h, #15
; CHECK-NEXT:    uunpklo z0.s, z0.h
; CHECK-NEXT:    cmpne p0.s, p0/z, z0.s, #0
; CHECK-NEXT:    ld1sh { z0.s }, p0/z, [x0]
; CHECK-NEXT:    // kill: def $q0 killed $q0 killed $z0
; CHECK-NEXT:    add sp, sp, #16
; CHECK-NEXT:    ret
  %load_value = tail call <3 x i16> @llvm.masked.load.v3i16.p0(ptr %load_ptr, i32 4, <3 x i1> %pm, <3 x i16> zeroinitializer)
  %extend = sext <3 x i16> %load_value to <3 x i32>
  ret <3 x i32> %extend;
}

declare <4 x i8> @llvm.masked.load.v4i8(ptr, i32, <4 x i1>, <4 x i8>)
declare <8 x i8> @llvm.masked.load.v8i8(ptr, i32, <8 x i1>, <8 x i8>)
declare <16 x i8> @llvm.masked.load.v16i8(ptr, i32, <16 x i1>, <16 x i8>)
declare <32 x i8> @llvm.masked.load.v32i8(ptr, i32, <32 x i1>, <32 x i8>)

declare <2 x half> @llvm.masked.load.v2f16(ptr, i32, <2 x i1>, <2 x half>)
declare <4 x half> @llvm.masked.load.v4f16(ptr, i32, <4 x i1>, <4 x half>)
declare <8 x half> @llvm.masked.load.v8f16(ptr, i32, <8 x i1>, <8 x half>)
declare <16 x half> @llvm.masked.load.v16f16(ptr, i32, <16 x i1>, <16 x half>)

declare <2 x float> @llvm.masked.load.v2f32(ptr, i32, <2 x i1>, <2 x float>)
declare <4 x float> @llvm.masked.load.v4f32(ptr, i32, <4 x i1>, <4 x float>)
declare <8 x float> @llvm.masked.load.v8f32(ptr, i32, <8 x i1>, <8 x float>)

declare <2 x double> @llvm.masked.load.v2f64(ptr, i32, <2 x i1>, <2 x double>)
declare <4 x double> @llvm.masked.load.v4f64(ptr, i32, <4 x i1>, <4 x double>)

declare <3 x i16> @llvm.masked.load.v3i16.p0(ptr, i32, <3 x i1>, <3 x i16>)
