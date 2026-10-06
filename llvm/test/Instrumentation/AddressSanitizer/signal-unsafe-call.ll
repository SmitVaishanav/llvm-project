; RUN: opt < %s -passes=asan -asan-detect-signal-unsafe-calls -S | FileCheck %s
; RUN: opt < %s -passes=asan -S | FileCheck %s --check-prefix=DISABLED

; Test that the signal safety pass instruments calls to non-async-signal-safe
; functions with a check for __asan_signal_handler_registered.

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

declare ptr @malloc(i64)
declare void @free(ptr)
declare i32 @printf(ptr, ...)
declare i32 @snprintf(ptr, i64, ptr, ...)
declare void @write(i32, ptr, i64)

;; --- Positive case: malloc is async-signal-unsafe ---

define void @calls_malloc() sanitize_address {
; CHECK-LABEL: @calls_malloc
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: icmp ne i32
; CHECK: br i1
; CHECK: call void @__asan_signal_candidate_call
; CHECK: call ptr @malloc
;
; DISABLED-LABEL: @calls_malloc
; DISABLED-NOT: @__asan_signal_handler_registered
; DISABLED-NOT: @__asan_signal_candidate_call
entry:
  %p = call ptr @malloc(i64 32)
  ret void
}

;; --- Positive case: printf is async-signal-unsafe ---

define void @calls_printf(ptr %fmt) sanitize_address {
; CHECK-LABEL: @calls_printf
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: call void @__asan_signal_candidate_call
entry:
  %r = call i32 (ptr, ...) @printf(ptr %fmt)
  ret void
}

;; --- Positive case: snprintf is async-signal-unsafe ---

define void @calls_snprintf(ptr %buf, ptr %fmt) sanitize_address {
; CHECK-LABEL: @calls_snprintf
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: call void @__asan_signal_candidate_call
entry:
  %r = call i32 (ptr, i64, ptr, ...) @snprintf(ptr %buf, i64 128, ptr %fmt)
  ret void
}

;; --- Positive case: free is async-signal-unsafe ---

define void @calls_free(ptr %p) sanitize_address {
; CHECK-LABEL: @calls_free
; CHECK: load i32, ptr @__asan_signal_handler_registered
; CHECK: call void @__asan_signal_candidate_call
entry:
  call void @free(ptr %p)
  ret void
}

;; --- Negative case: write is async-signal-safe ---

define void @calls_write(ptr %buf) sanitize_address {
; CHECK-LABEL: @calls_write
; CHECK-NOT: call void @__asan_signal_candidate_call(
entry:
  call void @write(i32 1, ptr %buf, i64 5)
  ret void
}
