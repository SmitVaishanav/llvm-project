; RUN: opt < %s -passes=asan -asan-detect-signal-unsafe-writes -S | FileCheck %s
; RUN: opt < %s -passes=asan -S | FileCheck %s --check-prefix=DISABLED

; Test that the signal safety pass instruments non-atomic stores > 8 bytes
; with a check for __asan_signal_handler_registered.

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

;; --- Positive case: 16-byte non-atomic store should be instrumented ---

define void @write_16bytes(ptr %p, <2 x i64> %val) sanitize_address {
; CHECK-LABEL: @write_16bytes
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: icmp ne i32
; CHECK: br i1
; CHECK: call void @__asan_signal_candidate_write
; CHECK: store <2 x i64> %val, ptr %p
;
; DISABLED-LABEL: @write_16bytes
; DISABLED-NOT: @__asan_signal_handler_registered
; DISABLED-NOT: @__asan_signal_candidate_write
entry:
  store <2 x i64> %val, ptr %p, align 16
  ret void
}

;; --- Negative case: 8-byte store should NOT be instrumented ---

define void @write_8bytes(ptr %p, i64 %val) sanitize_address {
; CHECK-LABEL: @write_8bytes
; CHECK-NOT: @__asan_signal_handler_registered
; CHECK-NOT: @__asan_signal_candidate_write
; CHECK: store i64 %val, ptr %p
entry:
  store i64 %val, ptr %p, align 8
  ret void
}

;; --- Negative case: 4-byte store should NOT be instrumented ---

define void @write_4bytes(ptr %p, i32 %val) sanitize_address {
; CHECK-LABEL: @write_4bytes
; CHECK-NOT: @__asan_signal_handler_registered
; CHECK-NOT: @__asan_signal_candidate_write
entry:
  store i32 %val, ptr %p, align 4
  ret void
}

;; --- Negative case: atomic 16-byte store should NOT be instrumented ---

define void @write_16bytes_atomic(ptr %p, i128 %val) sanitize_address {
; CHECK-LABEL: @write_16bytes_atomic
; CHECK-NOT: @__asan_signal_candidate_write
entry:
  store atomic i128 %val, ptr %p seq_cst, align 16
  ret void
}

;; --- Positive case: struct-like 16-byte store ---

define void @write_struct(ptr %p, [2 x i64] %val) sanitize_address {
; CHECK-LABEL: @write_struct
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: call void @__asan_signal_candidate_write
entry:
  store [2 x i64] %val, ptr %p, align 8
  ret void
}
