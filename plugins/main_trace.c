/*
  main_trace: minimal MAMBO plugin that records the PC of every instruction
  executed between main's entry and its return (or exit()).

  Works on stripped binaries: main is found without symbols, by watching the
  ELF entry point (_start) and capturing x0 at its BL to __libc_start_main
  (glibc AArch64 _start loads main's address into x0 there). The end of main
  is its return address (LR at main's entry); exit() is also hooked by name
  when libc's .dynsym provides it.

  Single-threaded only: all state is global.

  Output: main_trace.bin
    uint64_t base     load base for PIE (0 for non-PIE); pc - base = ELF vaddr
    uint64_t pc[...]  one entry per executed instruction, in order

  Build: make PLUGINS="plugins/main_trace.c"
*/

#ifdef PLUGINS_NEW

#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "../plugins.h"

#ifndef __aarch64__
  #error "main_trace only supports AArch64"
#endif

#define TRACE_FILE  "main_trace.bin"
#define BUF_ENTRIES (1 << 16)   // must hold one block's (or trace's) worth of PCs

static uint64_t  buf[BUF_ENTRIES];
static uint64_t *buf_ptr = buf;   // written by generated code
static FILE     *trace_out;

static bool      tracing = false; // runtime flag
static uintptr_t entry_addr = 0;  // _start (runtime address)
static uintptr_t main_addr = 0;   // captured at runtime from x0
static uintptr_t main_ret = 0;    // captured at runtime from LR at main's entry
static bool      in_start_block = false; // scan-time state

/* ---------- runtime functions, called from the code cache ---------- */

static void flush(void) {
  size_t n = buf_ptr - buf;
  assert(n <= BUF_ENTRIES);
  if (tracing && n > 0) {
    fwrite(buf, sizeof(uint64_t), n, trace_out);
  }
  buf_ptr = buf;
}

static void record_main(uintptr_t addr) {
  main_addr = addr;
}

static void start_tracing(uintptr_t ret_addr) {
  buf_ptr = buf;        // drop anything recorded before main
  main_ret = ret_addr;
  tracing = true;
}

static void stop_tracing(void) {
  flush();              // write main's last entries while the flag is still set
  tracing = false;
}

/* ---------- small helpers for scan-time code ---------- */

// ldr x<rt>, [x<rn>]
static void emit_load64(mambo_context *ctx, int rt, int rn) {
  emit_a64_LDR_STR_unsigned_immed(ctx, /*size=*/3, /*v=*/0, /*opc=load*/1, /*imm12=*/0, rn, rt);
}

// str x<rt>, [x<rn>]
static void emit_store64(mambo_context *ctx, int rt, int rn) {
  emit_a64_LDR_STR_unsigned_immed(ctx, /*size=*/3, /*v=*/0, /*opc=store*/0, /*imm12=*/0, rn, rt);
}

// Emit a call to fn(x0) that leaves x0 unchanged for the application.
static void emit_call_with_x0(mambo_context *ctx, void *fn) {
  emit_push(ctx, 1 << x0);
  emit_safe_fcall(ctx, fn, 1);
  emit_pop(ctx, 1 << x0);
}

static bool is_bl(uint32_t insn) {
  return (insn & 0xFC000000) == 0x94000000;
}

// Is this event MAMBO's ELF loader mapping the first segment of the app binary?
// (MAP_APP marks the app's own segments; offset 0 is the one at the load base.)
static bool is_app_first_segment(mambo_context *ctx) {
  return mambo_get_vm_op(ctx) == VM_MAP
      && (mambo_get_vm_flags(ctx) & MAP_APP)
      && mambo_get_vm_off(ctx) == 0;
}

static Elf64_Ehdr read_app_elf_header(void) {
  Elf64_Ehdr ehdr;
  int fd = open(global_data.argv[1], O_RDONLY);   // argv[1] is the app MAMBO is running
  assert(fd >= 0);
  ssize_t n = read(fd, &ehdr, sizeof(ehdr));
  assert(n == sizeof(ehdr));
  close(fd);
  return ehdr;
}

/* ---------- scan-time callbacks ---------- */

// Work out where _start will be at runtime, and record the load base.
static int mt_vm_op(mambo_context *ctx) {
  bool already_found = (entry_addr != 0);
  if (already_found || !is_app_first_segment(ctx)) return 0;

  Elf64_Ehdr ehdr = read_app_elf_header();
  bool is_pie = (ehdr.e_type == ET_DYN);
  uint64_t load_base = is_pie ? (uintptr_t)mambo_get_vm_addr(ctx) : 0;

  entry_addr = load_base + ehdr.e_entry;
  fwrite(&load_base, sizeof(load_base), 1, trace_out);   // trace file header
  return 0;
}

static int mt_pre_bb(mambo_context *ctx) {
  uintptr_t block_start = (uintptr_t)mambo_get_source_addr(ctx);
  bool is_main_entry  = (main_addr != 0 && block_start == main_addr);
  bool is_main_return = (main_ret  != 0 && block_start == main_ret);

  // Flush once per block; discards silently while tracing is off.
  emit_safe_fcall(ctx, flush, 0);

  in_start_block = (block_start == entry_addr);

  if (is_main_entry) {
    // On main's first instruction, LR holds its return address
    emit_push(ctx, 1 << x0);
    emit_mov(ctx, x0, lr);
    emit_safe_fcall(ctx, start_tracing, 1);
    emit_pop(ctx, 1 << x0);
  } else if (is_main_return) {
    emit_safe_fcall(ctx, stop_tracing, 0);
  }
  return 0;
}

static int mt_pre_inst(mambo_context *ctx) {
  uintptr_t pc = (uintptr_t)mambo_get_source_addr(ctx);

  // _start's BL to __libc_start_main: at this point x0 holds main's address
  if (in_start_block && is_bl(*(uint32_t *)pc)) {
    in_start_block = false;
    emit_call_with_x0(ctx, record_main);
  }

  // Emit: *buf_ptr++ = pc;
  int r_addr, r_ptr;
  int got = mambo_get_scratch_regs(ctx, 2, &r_addr, &r_ptr);
  assert(got == 2);

  emit_set_reg_ptr(ctx, r_addr, &buf_ptr);
  emit_load64(ctx, r_ptr, r_addr);              // r_ptr = buf_ptr

  emit_set_reg(ctx, r_addr, pc);
  emit_store64(ctx, r_addr, r_ptr);             // *r_ptr = pc

  emit_add_sub_i(ctx, r_ptr, r_ptr, sizeof(uint64_t));
  emit_set_reg_ptr(ctx, r_addr, &buf_ptr);
  emit_store64(ctx, r_ptr, r_addr);             // buf_ptr = r_ptr + 1

  mambo_free_scratch_regs(ctx, (1 << r_addr) | (1 << r_ptr));
  return 0;
}

// exit() called from inside main (libc's .dynsym survives stripping)
static int mt_exit_hook(mambo_context *ctx) {
  emit_safe_fcall(ctx, stop_tracing, 0);
  return 0;
}

static int mt_exit(mambo_context *ctx) {
  flush();              // covers _exit() or anything else that skips the hooks
  fclose(trace_out);
  return 0;
}

__attribute__((constructor)) void main_trace_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  trace_out = fopen(TRACE_FILE, "wb");
  assert(trace_out != NULL);

  mambo_register_vm_op_cb(ctx, &mt_vm_op);
  mambo_register_pre_basic_block_cb(ctx, &mt_pre_bb);
  mambo_register_pre_inst_cb(ctx, &mt_pre_inst);
  mambo_register_function_cb(ctx, "exit", &mt_exit_hook, NULL, 1);
  mambo_register_exit_cb(ctx, &mt_exit);
}

#endif // PLUGINS_NEW
