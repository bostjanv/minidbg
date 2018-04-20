#pragma once

#include <stdint.h>

struct minidbg_context;
struct minidbg_regs;

struct minidbg_context* minidbg_start(char *const argv[]);
struct minidbg_context* minidbg_attach(int pid);
int minidbg_detach(struct minidbg_context* ctx);
int minidbg_next(struct minidbg_context* ctx);
uintptr_t minidbg_get_pc(struct minidbg_context* ctx);
uintptr_t minidbg_get_reg(struct minidbg_context* ctx, int reg);
int minidbg_get_regs(struct minidbg_context* ctx, struct minidbg_regs* regs);
int minidbg_set_breakpoint(struct minidbg_context* ctx, uintptr_t address);
int minidbg_del_breakpoint(struct minidbg_context* ctx, uintptr_t address);
uintptr_t minidbg_read_memory(struct minidbg_context* ctx, uintptr_t address, void* buf, size_t size);
uintptr_t minidbg_read_string(struct minidbg_context* ctx, uintptr_t address, char* buf, size_t size);
uintptr_t minidbg_write_memory(struct minidbg_context* ctx, uintptr_t address, const void* buf, size_t size);

