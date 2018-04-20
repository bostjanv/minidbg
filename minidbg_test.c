#include <stdio.h>

#include "minidbg.h"

int main()
{
    char *const argv[] = {"./test", NULL};

    struct minidbg_context* ctx = minidbg_start(argv);
    printf("RIP: 0x%016zx\n", minidbg_get_pc(ctx));

    uintptr_t address = 0x400702;
    printf("Setting breakpoint at 0x%016zx\n", address);
    if (minidbg_set_breakpoint(ctx, address)) {
        fprintf(stderr, "minidbg_set_breakpoint failed\n");
    }

    for (int i = 0; i < 10; i++) {
        if (minidbg_next(ctx)) {
            fprintf(stderr, "minidbg_next failed\n");
        }

        printf("RIP: 0x%016zx\n", minidbg_get_pc(ctx));
    }

    if (minidbg_del_breakpoint(ctx, address)) {
        fprintf(stderr, "minidbg_del_breakpoint failed\n");
    }

    minidbg_detach(ctx);

    return 0;
}
