#include "program.h"
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define CCPATH "/usr/bin/clang"
#define CCFLAGS "-Weverything"

static inline int read_pipe(int fd, char *buf, int n);

int compile_program(char *cmpin, char *cmpout, char *output, uint32_t *outsz, uint32_t timeout)
{
    *outsz = 0;
    sigset_t mask, orig_mask;
    struct timespec ts = { .tv_sec = timeout, .tv_nsec = 0 };
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0)
        return CMPINTERR;

    int ret;
    int fds[2];
    if (pipe(fds) < 0)
        return CMPINTERR;
    
    pid_t pid = fork();
    if (pid == 0) {
        while ((dup2(fds[1], STDERR_FILENO) == -1) && (errno == EINTR));
        while ((dup2(fds[1], STDOUT_FILENO) == -1) && (errno == EINTR));
        close(fds[0]);
        close(fds[1]);

        char *argv[] = { "/usr/bin/clang", "-Weverything", "-xc", cmpin, "-o", cmpout, NULL };
        execv("/usr/bin/clang", argv);
        // TODO: Error handling below.
        _exit(CMPINTERR);
    } else {
        close(fds[1]);
        do {
            if (sigtimedwait(&mask, NULL, &ts) < 0) {
                if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN) {
                    kill(pid, SIGKILL);
                    fprintf(stderr, "Timeout. Child killed.\n");
                    ret = CMPTIMEOUT;
                    goto out;
                } else {
                    ret = CMPTIMEOUT;
                    goto out;
                }
            }
            break;
        } while(1);

        int status;
        waitpid(pid, &status, 0);
        ret = WEXITSTATUS(status);
        int n = read_pipe(fds[0], output, PGMMAXOUT);
        if (n < 0) {
            ret = CMPINTERR;
            goto out;
        }
        *outsz = (uint32_t)n;
out:
        close(fds[0]);
        if (sigprocmask(SIG_SETMASK, &orig_mask, NULL) < 0)
            return CMPINTERR;
        return ret;
    }
}

int run_program(char *path, char *output, uint32_t *outsz, uint32_t timeout)
{
    *outsz = 0;

    sigset_t mask, orig_mask;
    struct timespec ts = { .tv_sec = timeout, .tv_nsec = 0 };
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &mask, &orig_mask) < 0)
        return PGMINTERR;

    int ret;
    int fds[2];
    if (pipe(fds) < 0)
        return PGMINTERR;

    pid_t pid = fork();
    if (pid < 0)
        return PGMINTERR;

    if (pid == 0) {
        while ((dup2(fds[1], STDERR_FILENO) == -1) && (errno == EINTR));
        while ((dup2(fds[1], STDOUT_FILENO) == -1) && (errno == EINTR));
        close(fds[0]);
        close(fds[1]);
        
        // Seccomp
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL & SCMP_ACT_LOG);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
        seccomp_load(ctx);

        char *argv[] = { path, NULL };
        execv(path, argv);
        _exit(EXIT_FAILURE);
    } else {
        close(fds[1]);
        do {
            if (sigtimedwait(&mask, NULL, &ts) < 0) {
                if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN) {
                    kill(pid, SIGKILL);
                    fprintf(stderr, "Timeout. Child killed.\n");
                    ret = PGMTIMEOUT;
                    goto out;
                } else {
                    ret = PGMINTERR;
                    goto out;
                }
            }
            break;
        } while(1);

        int status;
        waitpid(pid, &status, 0);
        int n = read_pipe(fds[0], output, PGMMAXOUT);
        if (n < 0) {
            ret = PGMINTERR;
            goto out;
        }
        *outsz = (uint32_t)n;

        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
            ret = PGMRTERR;
        } else {
            ret = PGMOK;
        }
out:
        close(fds[0]);
        if (sigprocmask(SIG_SETMASK, &orig_mask, NULL) < 0)
            return PGMINTERR;
        return ret;
    }
}

static inline int read_pipe(int fd, char *buf, int n)
{
    int rb = 0;
    while (rb < n) {
        ssize_t count = read(fd, buf+rb, (size_t)(n-rb));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        } else if (count == 0) {
            break;
        } else {
            rb += count;
        }
    }
    return rb;
}
