; RUN: not llvm-as %s -o /dev/null 2>&1 | FileCheck %s

declare void @sm_attrs() "aarch64_pstate_sm_enabled" "aarch64_pstate_sm_compatible";
; CHECK: Attributes 'aarch64_pstate_sm_enabled and aarch64_pstate_sm_compatible' are incompatible!

declare void @za_new_preserved() "aarch64_new_za" "aarch64_preserves_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_new_in() "aarch64_new_za" "aarch64_in_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_new_inout() "aarch64_new_za" "aarch64_inout_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_new_out() "aarch64_new_za" "aarch64_out_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_preserved_in() "aarch64_preserves_za" "aarch64_in_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_preserved_inout() "aarch64_preserves_za" "aarch64_inout_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_preserved_out() "aarch64_preserves_za" "aarch64_out_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_in_inout() "aarch64_in_za" "aarch64_inout_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_in_out() "aarch64_in_za" "aarch64_out_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive

declare void @za_inout_out() "aarch64_inout_za" "aarch64_out_za";
; CHECK: Attributes 'aarch64_new_za', 'aarch64_in_za', 'aarch64_out_za', 'aarch64_inout_za' and 'aarch64_preserves_za' are mutually exclusive
