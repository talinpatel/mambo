/*
  main_trace: a minimal MAMBO plugin that records every instruction executed
  in main, as one hex offset per line (offsets match objdump/readelf).

  Finding main without symbols (works on stripped binaries):
    1. The ELF header gives _start's address (e_entry).
    2. glibc's AArch64 _start puts main's address in x0, then calls
       __libc_start_main with `bl`. We read x0 at that `bl`.
    3. On main's first instruction, LR holds main's return address.
       Tracing stops when execution gets back there, or when exit() is called.

  Single-threaded only: all state is global.

  Build: make PLUGINS="plugins/main_trace.c" OUTPUT_FILE=mambo_main_trace
  Run:   MAIN_TRACE_OUT=trace.txt ./mambo_main_trace ./program
         (without MAIN_TRACE_OUT, the trace goes to main_trace.txt)
    
  note: getting the bytes from pc is unoptimised
  so is the printing using printf but not worried about this for now
*/

#ifdef PLUGINS_NEW

#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../plugins.h"

#ifndef __aarch64__
  #error "main_trace only supports AArch64"
#endif

#define DEFAULT_TRACE_FILE "main_trace.txt"

/* ---------- global state ---------- */

static FILE     *trace_file;              // opened in main_trace_init_plugin()
static uintptr_t load_base = 0;           // set in mt_vm_op_cb(); 0 for non-PIE

static uintptr_t main_addr = 0;           // set by record_main_address()
static uintptr_t main_return_addr = 0;    // set by start_tracing()
static bool      tracing = false;

/* ---------- scan-time state ---------- */

static uintptr_t entry_addr = 0;          // _start's runtime address, set in mt_vm_op_cb()
static bool      in_start_block = false;  // true while scanning _start's first block

/* ---------- run-time functions ----------
 * These run while the application executes: the scan-time callbacks
 * emit calls to them into the code cache.
 */

// Called at _start's `bl __libc_start_main`, where x0 holds main's address.
static void record_main_address(uintptr_t main) {
  main_addr = main;
}

// Called on main's first instruction, where LR holds main's return address.
static void start_tracing(uintptr_t return_addr) {
  main_return_addr = return_addr;
  tracing = true;
}

// Called when main returns, or when exit() is called.
static void stop_tracing(void) {
  tracing = false;
}

// Called before every application instruction.
static void trace_instruction(uintptr_t pc) {
  // dereference pc to get the instruction encoding.
  if (tracing) {
    fprintf(trace_file,"%08" PRIx32 "\n", *(uint32_t *)pc);
  }
}

/* ---------- helpers ---------- */

// Is this VM event MAMBO's ELF loader mapping the first segment of the app?
// MAP_APP marks the app's own segments (ld.so's get MAP_INTERP); the segment
// at file offset 0 is the one that sits at the load base.
static bool is_app_first_segment(mambo_context *ctx) {
  return mambo_get_vm_op(ctx) == VM_MAP
      && (mambo_get_vm_flags(ctx) & MAP_APP)
      && mambo_get_vm_off(ctx) == 0;
}

// Read the app's ELF header (what `readelf -h` shows).
// global_data.argv[1] is the program MAMBO was asked to run.
static Elf64_Ehdr read_app_elf_header(void) {
  Elf64_Ehdr ehdr;
  int fd = open(global_data.argv[1], O_RDONLY);
  assert(fd >= 0);
  ssize_t n = read(fd, &ehdr, sizeof(ehdr));
  assert(n == sizeof(ehdr));
  close(fd);
  return ehdr;
}

// Is the instruction at pc a BL? Uses MAMBO's PIE decoder:
// B and BL share one encoding type, told apart by the `op` field (1 = BL).
static bool is_bl(uintptr_t pc) {
  if (a64_decode((uint32_t *)pc) != A64_B_BL) return false;

  unsigned int op, imm26;
  a64_B_BL_decode_fields((uint32_t *)pc, &op, &imm26);
  return op == 1;
}

// Emit a call to fn(reg), where reg's run-time value is passed as the argument.
// x0 carries the argument, so it is saved and restored around the call;
// emit_safe_fcall preserves the other registers and the flags.
static void emit_call_with_reg(mambo_context *ctx, void *fn, enum reg reg) {
  emit_push(ctx, 1 << x0);
  if (reg != x0) {
    emit_mov(ctx, x0, reg);
  }
  emit_safe_fcall(ctx, fn, 1);
  emit_pop(ctx, 1 << x0);
}

/* ---------- scan-time callbacks ----------
 * These run when MAMBO translates code, not when it executes.
 * They emit calls to the run-time functions above.
 */

// Find the load base and _start's runtime address when the app is mapped.
static int mt_vm_op_cb(mambo_context *ctx) {
  if (entry_addr != 0 || !is_app_first_segment(ctx)) return 0;

  Elf64_Ehdr ehdr = read_app_elf_header();
  bool is_pie = (ehdr.e_type == ET_DYN);

  load_base  = is_pie ? (uintptr_t)mambo_get_vm_addr(ctx) : 0;
  entry_addr = load_base + ehdr.e_entry;
  return 0;
}

// At the start of each block: is this _start, main, or where main returns to?
static int mt_pre_bb_cb(mambo_context *ctx) {
  uintptr_t block_addr = (uintptr_t)mambo_get_source_addr(ctx);

  in_start_block = (block_addr == entry_addr);

  if (main_addr != 0 && block_addr == main_addr) {
    emit_call_with_reg(ctx, start_tracing, lr);     // LR = main's return address
  } else if (main_return_addr != 0 && block_addr == main_return_addr) {
    emit_safe_fcall(ctx, stop_tracing, 0);
  }
  return 0;
}

// Before each instruction: emit a call that records its PC.
static int mt_pre_inst_cb(mambo_context *ctx) {
  uintptr_t pc = (uintptr_t)mambo_get_source_addr(ctx);

  if (in_start_block && is_bl(pc)) {
    // _start's `bl __libc_start_main`: x0 holds main's address
    emit_call_with_reg(ctx, record_main_address, x0);
    in_start_block = false;
  }
    
  // number 1 represents number of arguments passed to trace_instruction
  emit_safe_fcall_static_args(ctx, trace_instruction, 1 , pc);
  return 0;
}

// Registered on exit() by name: stop tracing when the program calls exit().
static int mt_exit_fn_cb(mambo_context *ctx) {
  emit_safe_fcall(ctx, stop_tracing, 0);
  return 0;
}

// When the program ends: close the trace file (this also flushes it).
static int mt_exit_cb(mambo_context *ctx) {
  fclose(trace_file);
  return 0;
}

/* ---------- setup ---------- */

__attribute__((constructor)) void main_trace_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  // MAMBO passes all its command-line arguments to the app, so the output
  // path comes from an environment variable instead.
  const char *path = getenv("MAIN_TRACE_OUT");
  if (path == NULL) path = DEFAULT_TRACE_FILE;

  trace_file = fopen(path, "w");
  assert(trace_file != NULL);

  mambo_register_vm_op_cb(ctx, &mt_vm_op_cb);
  mambo_register_pre_basic_block_cb(ctx, &mt_pre_bb_cb);
  mambo_register_pre_inst_cb(ctx, &mt_pre_inst_cb);
  mambo_register_function_cb(ctx, "exit", &mt_exit_fn_cb, NULL, 1);
  mambo_register_exit_cb(ctx, &mt_exit_cb);
}

#endif // PLUGINS_NEW
