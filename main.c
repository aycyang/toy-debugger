#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <sys/wait.h>
#include <spawn.h>
#include <sys/user.h>
#include <unistd.h>

/**
 * #include <sys/p}trace.h>
 * long ptrace(enum __ptrace_request op, pid_t pid,
 *             void *addr, void *data);
 *
 * milestones:
 * 1. attach to a process and read its registers
 */

int has_zero_byte(long l) {
	return
		(l & 0x000000ff) == 0 ||
		(l & 0x0000ff00) == 0 ||
		(l & 0x00ff0000) == 0 ||
		(l & 0xff000000) == 0;
}

int main(int argc, char** argv) {
	assert(argc == 1);
	// Spawn a child process.
	pid_t child_pid;
	assert(posix_spawn(&child_pid, "register", NULL, NULL, &argv[0], NULL) == 0);
	sleep(1);
	// Attach to the child process.
	assert(ptrace(PTRACE_ATTACH, child_pid, NULL, NULL) != -1);
	int wstatus;
	int r_pid = waitpid(child_pid, &wstatus, 0);
	printf("r_pid=%d,pid=%d,wstatus=%d\n", r_pid, child_pid, wstatus);
	assert(r_pid == child_pid);
	// Read the child process's register %rax.
	struct user_regs_struct regs = {0};
	printf("%lld\n", regs.rax);
	assert(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != -1);
	printf("%lld\n", regs.rax);
	// Read a null-terminated string in the child process's memory at the address in register %rax.
	long long int addr = regs.rax;
	long buf[16];
	int i = 0;
	long word;
	do {
		word = ptrace(PTRACE_PEEKDATA, child_pid, addr + i * sizeof(long long int), NULL);
		buf[i] = word;
		i++;
	} while (!has_zero_byte(word));
	// Print the string we got from the child process's memory.
	printf("%s\n", (char*)buf);
	return 0;
}
