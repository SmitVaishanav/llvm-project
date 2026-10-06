; RUN: opt < %s -passes=asan -asan-detect-signal-unsafe-gep-writes -S | FileCheck %s
; RUN: opt < %s -passes=asan -S | FileCheck %s --check-prefix=DISABLED

; Test that signal safety GEP write detection instruments stores through
; GEP pointers with a check for __asan_signal_handler_registered.

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.Pair = type { i32, i32 }

;; --- Positive case: store through GEP to struct field ---

define void @write_struct_field(ptr %p) sanitize_address {
; CHECK-LABEL: @write_struct_field
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: icmp ne i32
; CHECK: br i1
; CHECK: call void @__asan_signal_candidate_write
; CHECK: store i32 42
;
; DISABLED-LABEL: @write_struct_field
; DISABLED-NOT: @__asan_signal_handler_registered
; DISABLED-NOT: @__asan_signal_candidate_write
entry:
  %field = getelementptr inbounds %struct.Pair, ptr %p, i64 0, i32 1
  store i32 42, ptr %field, align 4
  ret void
}

;; --- Positive case: store through GEP to array element ---

define void @write_array_element(ptr %arr) sanitize_address {
; CHECK-LABEL: @write_array_element
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: call void @__asan_signal_candidate_write
entry:
  %elem = getelementptr inbounds i32, ptr %arr, i64 3
  store i32 99, ptr %elem, align 4
  ret void
}

;; --- Negative case: store NOT through GEP (direct pointer) ---

define void @write_direct(ptr %p) sanitize_address {
; CHECK-LABEL: @write_direct
; CHECK-NOT: call void @__asan_signal_candidate_write(
entry:
  store i32 7, ptr %p, align 4
  ret void
}
