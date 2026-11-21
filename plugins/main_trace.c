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

/* ---------- scan-time callbacks ---------- */

// Find the app's load base and entry point as MAMBO's ELF loader maps it.
static int mt_vm_op(mambo_context *ctx) {
  if (entry_addr != 0 || mambo_get_vm_op(ctx) != VM_MAP) return 0;
  if (!(mambo_get_vm_flags(ctx) & MAP_APP) || mambo_get_vm_off(ctx) != 0) return 0;

  Elf64_Ehdr ehdr;
  int fd = open(global_data.argv[1], O_RDONLY);
  assert(fd >= 0);
  ssize_t r = read(fd, &ehdr, sizeof(ehdr));
  assert(r == sizeof(ehdr));
  close(fd);

  uint64_t base = (ehdr.e_type == ET_DYN) ? (uintptr_t)mambo_get_vm_addr(ctx) : 0;
  entry_addr = base + ehdr.e_entry;
  fwrite(&base, sizeof(base), 1, trace_out);
  return 0;
}

static int mt_pre_bb(mambo_context *ctx) {
  uintptr_t src = (uintptr_t)mambo_get_source_addr(ctx);

  // Flush once per block; discards silently while tracing is off.
  emit_safe_fcall(ctx, flush, 0);

  in_start_block = (src == entry_addr);

  if (main_addr != 0 && src == main_addr) {
    // LR still holds main's return address on its first instruction
    emit_push(ctx, 1 << x0);
    emit_mov(ctx, x0, lr);
    emit_safe_fcall(ctx, start_tracing, 1);
    emit_pop(ctx, 1 << x0);
  } else if (main_ret != 0 && src == main_ret) {
    emit_safe_fcall(ctx, stop_tracing, 0);
  }
  return 0;
}

static int mt_pre_inst(mambo_context *ctx) {
  uintptr_t src = (uintptr_t)mambo_get_source_addr(ctx);

  // _start's BL to __libc_start_main: x0 holds main's address
  if (in_start_block && (*(uint32_t *)src & 0xFC000000) == 0x94000000) {
    in_start_block = false;
    emit_push(ctx, 1 << x0);           // safe_fcall doesn't preserve the arg register
    emit_safe_fcall(ctx, record_main, 1);
    emit_pop(ctx, 1 << x0);
  }

  // *buf_ptr++ = src
  int r_slot, r_tmp;
  int ret = mambo_get_scratch_regs(ctx, 2, &r_slot, &r_tmp);
  assert(ret == 2);

  emit_set_reg_ptr(ctx, r_slot, &buf_ptr);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 1, 0, r_slot, r_tmp);  // ldr x_tmp, [x_slot]
  emit_set_reg(ctx, r_slot, src);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 0, 0, r_tmp, r_slot);  // str x_pc, [x_tmp]
  emit_add_sub_i(ctx, r_tmp, r_tmp, sizeof(uint64_t));              // add x_tmp, x_tmp, #8
  emit_set_reg_ptr(ctx, r_slot, &buf_ptr);
  emit_a64_LDR_STR_unsigned_immed(ctx, 3, 0, 0, 0, r_slot, r_tmp);  // str x_tmp, [x_slot]

  mambo_free_scratch_regs(ctx, (1 << r_slot) | (1 << r_tmp));
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
