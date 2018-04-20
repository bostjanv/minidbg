#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>

#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unordered_map>

#define LOG_DEBUG(format, ...) \
    fprintf(stderr, "minidbg: " format "\n", ##__VA_ARGS__)

#define LOG_ERROR(format, ...) \
    fprintf(stderr, "minidbg: " format "\n", ##__VA_ARGS__)

static bool g_signaled = false;

int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOG_ERROR("ptrace(PTRACE_ATTACH) failed to attach process %d", pid);
        return -1;
    }

    return 0;
}

int detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        LOG_ERROR("ptrace(PTRACE_DETACH) failed to detach process %d", pid);
        return -1;
    }

    return 0;
}

uint64_t read_register(int pid, int reg)
{
    return ptrace(PTRACE_PEEKUSER, pid, 8 * reg, NULL);
}

int set_breakpoint(pid_t pid, uintptr_t address, long* opcodes)
{
    long ret = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
    if (ret == -1) {
        fprintf(stderr, "ptrace(PEEKTEXT) failed");
        return -1;
    }

    *opcodes = ret;

    if (ptrace(PTRACE_POKETEXT, pid, address, (*opcodes & (~0xff)) | 0xcc) == -1) {
        fprintf(stderr, "ptrace(POKETEXT) failed");
        return -1;
    }

    return 0;
}

int del_breakpoint(pid_t pid, uintptr_t address, long opcodes)
{
    if (ptrace(PTRACE_POKETEXT, pid, address, opcodes) == -1) {
        fprintf(stderr, "ptrace(POKETEXT) failed");
        return -1;
    }

    return 0;
}


int attach_all_threads(pid_t pid)
{
    DIR *proc_dir;
    {
        char dirname[256];
        snprintf(dirname, sizeof(dirname), "/proc/%d/task", pid);
        proc_dir = opendir(dirname);
    }

    int ret;

    if (proc_dir)
    {
        /* /proc available, iterate through tasks... */
        struct dirent *entry;
        while ((entry = readdir(proc_dir)) != NULL)
        {
            if(entry->d_name[0] == '.')
                continue;

            int tid = atoi(entry->d_name);

            attach(tid);
        }

        closedir(proc_dir);
        ret = 0;
    }
    else
    {
        /* /proc not available, act accordingly */
        LOG_ERROR("failed to open task proc directory of process %d", pid);
        ret = -1;
    }

    return ret;
}

void show_registers(struct user_regs_struct *regs)
{
    printf("%s=%08llx ", "r15", regs->r15);
    printf("%s=%08llx ", "r14", regs->r14);
    printf("%s=%08llx ", "r13", regs->r13);
    printf("%s=%08llx ", "r12", regs->r12);
    printf("%s=%08llx ", "rbp", regs->rbp);
    printf("%s=%08llx ", "rbx", regs->rbx);
    printf("%s=%08llx ", "r11", regs->r11);
    printf("%s=%08llx ", "r10", regs->r10);
    printf("%s=%08llx ", "r9", regs->r9);
    printf("%s=%08llx ", "r8", regs->r8);
    printf("%s=%08llx ", "rax", regs->rax);
    printf("%s=%08llx ", "rcx", regs->rcx);
    printf("%s=%08llx ", "rdx", regs->rdx);
    printf("%s=%08llx ", "rsi", regs->rsi);
    printf("%s=%08llx ", "orig_rax", regs->orig_rax);
    printf("%s=%08llx ", "rip", regs->rip);
    printf("%s=%08llx ", "cs", regs->cs);
    printf("%s=%08llx ", "eflags", regs->eflags);
    printf("%s=%08llx ", "rsp", regs->rsp);
    printf("%s=%08llx ", "ss", regs->ss);
    printf("%s=%08llx ", "fs_base", regs->fs_base);
    printf("%s=%08llx ", "gs_base", regs->gs_base);
    printf("%s=%08llx ", "ds", regs->ds);
    printf("%s=%08llx ", "es", regs->es);
    printf("%s=%08llx ", "fs", regs->fs);
    printf("%s=%08llx ", "gs", regs->gs);
    printf("\n");
}


int exec_inferior(char *const cmd[]) {
    if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) < 0) {
        LOG_ERROR("ptrace(PTRACE_TRACEME failed)");
    } else if (execvp(cmd[0], cmd)) {
        LOG_ERROR("execvp failed: %s", strerror(errno));
    }

    return -1;
}

typedef enum
{
    ET_SYSCALL,
    ET_PTRACE_EVENT,
    ET_SIGNAL_DELIVERY,
    ET_GROUP,
    ET_TERMINATED,
} event_type_t;

struct Breakpoint
{
    long bytes;
    bool enabled;
};

typedef struct
{
    event_type_t type;
    pid_t pid;
    uintptr_t sig;
    int ptrace_event;
    int breakpoint;
    uintptr_t address;
    std::unordered_map<uintptr_t,Breakpoint> breakpoints;
} event_t;

int wait_tracee(event_t *event)
{
    siginfo_t si;

#if 0
    if (pid != -1) {
        // Restart the stopped tracee as for PTRACE_CONT, but arrange for the
        // tracee to be stopped at the next entry to or exit from a system call.
        // (The tracee will also, as usual, be stopped upon receipt of a
        // signal.) From the tracer's perspective, the tracee will appear to
        // have been stopped by receipt of a SIGTRAP. So, for PTRACE_SYSCALL,
        // the idea is to inspect the arguments to the system call at the first
        // stop, then do another PTRACE_SYSCALL and inspect the return value of
        // the system call at the second stop.
        //
        // The data argument is treated as for PTRACE_CONT; i.e. If data is
        // nonzero, it is interpreted as the number of a signal to be delivered
        // to the tracee; otherwise, no signal is delivered.  Thus, for example,
        // the tracer can control whether a signal sent to the tracee is
        // delivered or not.
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)sig) == -1) {
            fprintf(stderr,
                    "parent: failed to ptrace(PTRACE_SYSCALL): %s\n",
                    strerror(errno));
            return -1;
        }
    }
#endif

    //
    // wait for a child process to stop or terminate
    //
    int status;
    pid_t child_waited = waitpid(-1, &status, __WALL);
    if (child_waited == -1) {
        if (g_signaled) {
            return 0;
        }
        LOG_ERROR("waitpid(1) failed : %s\n", strerror(errno));
        return -1;
    } else {
        if (WIFSTOPPED(status)) {
            //
            // the following kinds of ptrace-stops exist:
            //
            //   (1) syscall-stops
            //   (2) PTRACE_EVENT stops
            //   (3) group-stops
            //   (4) signal-delivery-stops
            //
            // they all are reported by waitpid(2) with WIFSTOPPED(status) true.
            // They may be differentiated by examining the value status>>8, and if
            // there is ambiguity in that value, by querying PTRACE_GETSIGINFO.
            // (Note: the WSTOPSIG(status) macro can't be used to perform this
            // examination, because it returns the value (status>>8) & 0xff.)
            //
            const int stopsig = WSTOPSIG(status);

            event->pid = child_waited;
            event->sig = stopsig;

            if (stopsig == (SIGTRAP | 0x80)) {
                //
                // (1) Syscall-enter-stop and syscall-exit-stop are observed by the
                // tracer as waitpid(2) returning with WIFSTOPPED(status) true, and-
                // if the PTRACE_O_TRACESYSGOOD option was set by the tracer- then
                // WSTOPSIG(status) will give the value (SIGTRAP | 0x80).
                //
                event->type = ET_SYSCALL;
                LOG_DEBUG("syscall event");

                return 0;
            } else if (stopsig == SIGTRAP) {
                //
                // PTRACE_EVENT stops (2) are observed by the tracer as waitpid(2)
                // returning with WIFSTOPPED(status), and WSTOPSIG(status) returns
                // SIGTRAP.
                //
                const unsigned int ptrace_event = (unsigned int)status >> 16;
                switch (ptrace_event) {
                    case PTRACE_EVENT_VFORK:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_VFORK)");
                        break;
                    case PTRACE_EVENT_FORK:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_FORK)");
                        break;
                    case PTRACE_EVENT_CLONE: {
                         pid_t new_child;
                         ptrace(PTRACE_GETEVENTMSG, child_waited, 0, &new_child);
                         LOG_DEBUG("ptrace event (PTRACE_EVENT_CLONE) [%d]\n", new_child);
                        break;
                    }
                    case PTRACE_EVENT_VFORK_DONE:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_VFORK_DONE)");
                        break;
                    case PTRACE_EVENT_EXEC:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_EXEC)");
                        break;
                    case PTRACE_EVENT_EXIT:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_EXIT)");
                        break;
                    case PTRACE_EVENT_STOP:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_STOP)");
                        break;
                    case PTRACE_EVENT_SECCOMP:
                        LOG_DEBUG("ptrace event (PTRACE_EVENT_SECCOMP)");
                        break;
                    default: {
                        LOG_DEBUG("unknown ptrace event %u, could be a breakpoint event", ptrace_event);

                        uintptr_t address = read_register(event->pid, RIP) - 1;

                        const auto bp = event->breakpoints.find(address);
                        if (bp != event->breakpoints.end()) {
                            LOG_DEBUG("breakpoint at 0x%016zx was hit...", address);

                            // write original instructions
                            if (ptrace(PTRACE_POKETEXT, event->pid, address, bp->second.bytes) == -1) {
                                LOG_ERROR("ptrace(PTRACE_POKETEXT) failed: %s", strerror(errno));
                                return -1;
                            }

                            // decrement rip
                            if (ptrace(PTRACE_POKEUSER, event->pid, 8 * RIP, address) == -1) {
                                LOG_ERROR("ptrace(PTRACE_POKEUSER) failed: %s", strerror(errno));
                                return -1;
                            }

                            event->breakpoint = 1;
                            event->address = address;
                        }
                    }
                }

                event->type = ET_PTRACE_EVENT;
                event->ptrace_event = ptrace_event;
            } else if (ptrace(PTRACE_GETSIGINFO, child_waited, 0, &si) < 0) {
                //
                // (3) group-stop
                //
                LOG_DEBUG("group-stop [%d]", stopsig);

                // When restarting a tracee from a ptrace-stop other than
                // signal-delivery-stop, recommended practice is to always pass 0 in
                // sig.
                //
                event->type = ET_GROUP;
            } else {
                //
                // (4) signal-delivery-stop
                //
                LOG_DEBUG("signal-delivery-stop [%d]", stopsig);

                event->type = ET_SIGNAL_DELIVERY;
            }
        } else {
            //
            // the child process terminated
            //
            LOG_DEBUG("tracee %d terminated", child_waited);
            event->type = ET_TERMINATED;
            return 0;
        }
    }

    return 0;
}

int read_string(int pid, uintptr_t address, char* str, size_t len)
{
    unsigned int count = 0;

    for (uintptr_t a = address; ; a += 8) {
        uint64_t data = ptrace(PTRACE_PEEKDATA, pid, a, NULL);
        const char* p = (const char*)&data;
        for (unsigned int i = 0; i < sizeof(uint64_t); i++) {
            str[count++] = p[i];
            if (count == len || (p[i] == '\0')) {
                str[count - 1] = '\0';
                return count;
            }
        }
    }

    return count;
}

int cont_tracee(event_t* event)
{
    switch (event->type) {
    case ET_SIGNAL_DELIVERY:
        LOG_DEBUG("restarting tracee %d...", event->pid);
        if (ptrace(PTRACE_CONT, event->pid, 0, event->sig) == -1) {
            LOG_ERROR("ptrace(PTRACE_CONT) failed: %s", strerror(errno));
            return -1;
        }
        break;
    case ET_GROUP: {
        if (!g_signaled) {
            LOG_DEBUG("restarting tracee %d...", event->pid);
            if (ptrace(PTRACE_CONT, event->pid, 0, event->sig) == -1) {
                LOG_ERROR("ptrace(PTRACE_CONT) failed: %s", strerror(errno));
                return -1;
            }
        }
        break;
    }
    case ET_TERMINATED: {
        break;
    }
    case ET_PTRACE_EVENT: {
        if (event->ptrace_event == 0) {
            if (event->breakpoint) {
                const auto bp = event->breakpoints.find(event->address);
                if (bp != event->breakpoints.end() && bp->second.enabled) {
                    // reinsert breakpoint

                    if (ptrace(PTRACE_SINGLESTEP, event->pid, NULL, NULL) < 0) {
                        LOG_ERROR("ptrace(PTRACE_SINGLESTEP) failed: %s", strerror(errno));
                        return -1;
                    }

                    if (wait_tracee(event)) {
                        return -1;
                    }

                    assert(event->type == ET_PTRACE_EVENT);
                    assert(event->ptrace_event == 0);

                    // reinsert breakpoint
                    ptrace(PTRACE_POKETEXT, event->pid, event->address, (bp->second.bytes & (~0xff)) | 0xcc);

                }

                event->breakpoint = 0;

                if (ptrace(PTRACE_CONT, event->pid, 0, 0) == -1) {
                    LOG_ERROR("ptrace(PTRACE_CONT) failed: %s", strerror(errno));
                    return -1;
                }
            }

        } else {
            LOG_DEBUG("restarting tracee %d...", event->pid);
            if (ptrace(PTRACE_CONT, event->pid, 0, 0) == -1) {
                LOG_ERROR("ptrace(PTRACE_CONT) failed: %s", strerror(errno));
                return -1;
            }
        }

        break;
    }

    default:
        LOG_DEBUG("restarting tracee %d...", event->pid);
        if (ptrace(PTRACE_CONT, event->pid, 0, 0) == -1) {
            LOG_ERROR("ptrace(PTRACE_CONT) failed: %s", strerror(errno));
            return -1;
        }
        break;
    }

    return 0;
}

#if 0
void tracer(pid_t pid)
{
    //
    // observe the (initial) signal-delivery-stop
    //
    LOG_DEBUG("waiting for initial stop of tracee %d...", pid);
    int status;
    do {
        waitpid(pid, &status, 0);
        if (g_signaled) {
            return;
        }
    } while (!WIFSTOPPED(status));
    LOG_DEBUG("initial stop observed");

    //
    // select ptrace options
    //
    int ptrace_options = 0;

    // When delivering system call traps, set bit 7 in the signal number (i.e.,
    // deliver SIGTRAP|0x80). This makes it easy for the tracer to distinguish
    // normal traps from those caused by a system call. Note:
    // PTRACE_O_TRACESYSGOOD may not work on all architectures.
    ptrace_options |= PTRACE_O_TRACESYSGOOD;

    // Send a SIGKILL signal to the tracee if the tracer exits. This option is
    // useful for ptrace jailers that want to ensure that tracees can never escape
    // the tracer's control.
    ptrace_options |= PTRACE_O_EXITKILL;

    // Stop the tracee at the next clone(2) and automatically start tracing the
    // newly cloned process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP
    // if PTRACE_SEIZE was used.  A waitpid(2) by the tracer will return a status
    // value such that
    //
    //  status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
    //
    // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG. This
    // option may not catch clone(2) calls in all cases.  If the tracee calls
    // clone(2) with the CLONE_VFORK flag, PTRACE_EVENT_VFORK will be delivered
    // instead if PTRACE_O_TRACEVFORK is set; otherwise if the tracee calls
    // clone(2) with the exit signal set to SIGCHLD, PTRACE_EVENT_FORK will be
    // delivered if PTRACE_O_TRACEFORK is set.
    ptrace_options |= PTRACE_O_TRACECLONE;

    //
    // set those options
    //
    LOG_DEBUG("setting ptrace options...");
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_options) == -1) {
        LOG_ERROR("ptrace(PTRACE_SETOPTIONS) failed: %s", strerror(errno));
        return;
    }
    LOG_DEBUG("ptrace options set!");

    printf("Press a key to continue.\n");
    printf(">>> ");
    fflush(stdout);

    char buf[256];
    char* ret = fgets(buf, 256, stdin);
    assert(ret);

    uintptr_t address = 0x400702;
    long opcodes;
    printf("setting breakpoint at 0x%016zx\n", address);
    if (set_breakpoint(pid, address, &opcodes)) {
        return;
    }

    Breakpoint bp{opcodes, true};

    event_t event;
    event.type = ET_SIGNAL_DELIVERY;
    event.pid = pid;
    event.sig = 0;
    event.breakpoint = 0;
    event.breakpoints[address] = bp;

    cont_tracee(&event);

    while (!wait_tracee(&event)) {
        if (g_signaled) {
            //printf("Signaled ...\n");
            //g_signaled = false;

            printf("Enter `q` to quit\n");
            printf(">>> ");
            fflush(stdout);
            ret = fgets(buf, 256, stdin);
            if (buf[0] == 'q') {
                break;
            }
            kill(pid, SIGSTOP);
        } else if (event.breakpoint) {
            printf("Breakpoint at 0x%016zx hit\n", event.address);
            printf("Enter `c` to continue or `d` to disable breakpoint\n");
            printf(">>> ");
            fflush(stdout);
            char* ret = fgets(buf, 256, stdin);
            assert(ret);
            if (buf[0] == 'd') {
                event.breakpoints[event.address].enabled = false;
            }
        } /*else if (event.type == ET_SIGNAL_DELIVERY) {
            do {
                printf("Signal delivery stop. Enter `c` to continue.\n");
                ret = fgets(buf, 256, stdin);
            } while (buf[0] != 'c');

            event.sig = SIGSTOP;
        }*/

        if (cont_tracee(&event)) {
            break;
        }
    }
}
#endif

void tracer_init(pid_t pid)
{
    //
    // observe the (initial) signal-delivery-stop
    //
    LOG_DEBUG("waiting for initial stop of tracee %d...", pid);
    int status;
    do {
        waitpid(pid, &status, 0);
        if (g_signaled) {
            return;
        }
    } while (!WIFSTOPPED(status));
    LOG_DEBUG("initial stop observed");

    //
    // select ptrace options
    //
    int ptrace_options = 0;

    // When delivering system call traps, set bit 7 in the signal number (i.e.,
    // deliver SIGTRAP|0x80). This makes it easy for the tracer to distinguish
    // normal traps from those caused by a system call. Note:
    // PTRACE_O_TRACESYSGOOD may not work on all architectures.
    ptrace_options |= PTRACE_O_TRACESYSGOOD;

    // Send a SIGKILL signal to the tracee if the tracer exits. This option is
    // useful for ptrace jailers that want to ensure that tracees can never escape
    // the tracer's control.
    ptrace_options |= PTRACE_O_EXITKILL;

    // Stop the tracee at the next clone(2) and automatically start tracing the
    // newly cloned process, which will start with a SIGSTOP, or PTRACE_EVENT_STOP
    // if PTRACE_SEIZE was used.  A waitpid(2) by the tracer will return a status
    // value such that
    //
    //  status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
    //
    // The PID of the new process can be retrieved with PTRACE_GETEVENTMSG. This
    // option may not catch clone(2) calls in all cases.  If the tracee calls
    // clone(2) with the CLONE_VFORK flag, PTRACE_EVENT_VFORK will be delivered
    // instead if PTRACE_O_TRACEVFORK is set; otherwise if the tracee calls
    // clone(2) with the exit signal set to SIGCHLD, PTRACE_EVENT_FORK will be
    // delivered if PTRACE_O_TRACEFORK is set.
    ptrace_options |= PTRACE_O_TRACECLONE;

    //
    // set those options
    //
    LOG_DEBUG("setting ptrace options...");
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_options) == -1) {
        LOG_ERROR("ptrace(PTRACE_SETOPTIONS) failed: %s", strerror(errno));
        return;
    }
    LOG_DEBUG("ptrace options set!");
}

static void sighandler(int)
{
    g_signaled = true;
}

void install_sighandler()
{
    struct sigaction sa;
    sa.sa_handler = sighandler;
    sigaction(SIGINT, &sa, NULL);
}

#if 0
int main(int argc, char* argv[])
{
    const char* usage = "Usage: minidbg [<cmd>|-p <pid>]";

    if (argc < 2) {
        puts(usage);
        return 0;
    }

    install_sighandler();

    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3) {
            puts(usage);
        }
        int pid = atoi(argv[2]);

        if (!attach_all_threads(pid)) {
            tracer(pid);
        }
    } else {
        int pid = fork();
        switch(pid) {
            case -1:
                LOG_ERROR("fork failed: %s", strerror(errno));
                return -1;
                break;
            case 0:
                exec_inferior(argv+1);
                break;
            default:
                tracer(pid);
                break;
        }
    }

    return 0;
}
#endif

struct minidbg_context
{
    pid_t pid;
    event_t event;
};

struct minidbg_regs
{

};

extern "C"
struct minidbg_context* minidbg_start(char *const argv[])
{
    int pid = fork();
    switch(pid) {
        case -1:
            LOG_ERROR("fork failed: %s", strerror(errno));
            return nullptr;
            break;
        case 0:
            exec_inferior(argv);
            break;
        default:
            tracer_init(pid);
            break;
    }

    //event_t event {.type = ET_SIGNAL_DELIVERY, .pid = pid};
    //event.type = ET_SIGNAL_DELIVERY;
    //event.pid = pid;
    //event.sig = 0;
    //event.breakpoint = 0;
    //event.breakpoints[address] = bp;

    //cont_tracee(&event);
    uintptr_t address = read_register(pid, RIP);

    minidbg_context* ctx = (minidbg_context*)malloc(sizeof(minidbg_context));
    ctx->pid = pid;
    ctx->event = event_t{ET_SIGNAL_DELIVERY, pid, 0, 0, 0, address, std::unordered_map<uintptr_t, Breakpoint>()};

    return ctx;
}

extern "C"
struct minidbg_context* minidbg_attach(int pid)
{
    if (!attach_all_threads(pid)) {
        tracer_init(pid);
    }

    minidbg_context* ctx = (minidbg_context*)malloc(sizeof(minidbg_context));
    ctx->pid = pid;

    return ctx;

}

extern "C"
int minidbg_detach(struct minidbg_context* ctx)
{
    kill(ctx->pid, SIGSTOP);

    ctx->event.breakpoint = false;

    do {
        if (cont_tracee(&ctx->event))
            return -1;
        if (wait_tracee(&ctx->event))
            return -1;
    } while (1);

    int ret = detach(ctx->pid);
    free(ctx);
    return ret;
}

extern "C"
int minidbg_next(struct minidbg_context* ctx)
{
    do {
        if (cont_tracee(&ctx->event))
            return -1;
        if (wait_tracee(&ctx->event))
            return -1;
    } while (!ctx->event.breakpoint);

    return 0;
}

extern "C"
uintptr_t minidbg_get_pc(struct minidbg_context* ctx)
{
    return ctx->event.address;
}

extern "C"
uintptr_t minidbg_get_reg(struct minidbg_context* ctx, int reg)
{
    return 0;
}

extern "C"
int minidbg_get_regs(struct minidbg_context* ctx, struct regs* regs)
{
    return 0;
}

extern "C"
int minidbg_set_breakpoint(struct minidbg_context* ctx, uintptr_t address)
{
    long opcodes;

    if (set_breakpoint(ctx->event.pid, address, &opcodes))
        return -1;

    ctx->event.breakpoints[address] = Breakpoint {opcodes, true};

    return 0;
}

extern "C"
int minidbg_del_breakpoint(struct minidbg_context* ctx, uintptr_t address)
{
    const auto bp = ctx->event.breakpoints.find(address);
    if (bp == ctx->event.breakpoints.end()) {
        return -1;
    }

    return del_breakpoint(ctx->event.pid, address, bp->second.bytes);
}

extern "C"
uintptr_t minidbg_read_memory(struct minidbg_context* ctx, void* buf, size_t size)
{
    return 0;
}

extern "C"
uintptr_t minidbg_read_string(struct minidbg_context* ctx, char* buf, size_t size)
{
    return 0;
}

extern "C"
uintptr_t minidbg_write_memory(struct minidbg_context* ctx, const void* buf, size_t size)
{
    return 0;
}
