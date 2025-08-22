#include <assert.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "payload.h"

int has_zero_byte(long l) {
	return
		(l & 0x000000ff) == 0 ||
		(l & 0x0000ff00) == 0 ||
		(l & 0x00ff0000) == 0 ||
		(l & 0xff000000) == 0;
}

// Warning: this can very easily overflow the passed-in buffer if the string is
// too long, or isn't null-terminated, or isn't a string at all.
void read_string_from_process_memory(pid_t child_pid, long long int addr, long* buf) {
  int i = 0;
  long word;
  do {
    word = ptrace(PTRACE_PEEKDATA, child_pid, addr + i * sizeof(long long int), NULL);
    buf[i] = word;
    i++;
  } while (!has_zero_byte(word));
}

int main(int argc, char** argv) {
	assert(argc == 1);
	// Spawn a child process.
	pid_t child_pid;
	assert(posix_spawn(&child_pid, "register", NULL, NULL, &argv[0], NULL) == 0);
	// Attach to the child process.
	assert(ptrace(PTRACE_ATTACH, child_pid, NULL, NULL) != -1);
	int wstatus;
	int r_pid = waitpid(child_pid, &wstatus, 0);
	assert(r_pid == child_pid);
  printf("tracee stopped\n");
  // At this point the process is stopped, and it probably hasn't been scheduled yet.
  // Get the instruction pointer register.
  struct user_regs_struct regs = {0};
  assert(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != -1);
  printf("%%rip=%llx\n", regs.rip);
  printf("press ENTER to continue execution\n");
  getchar();
  assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);

	//long buf[16];
  //read_string_from_process_memory(child_pid, regs.rax, buf);
	// Print the string we got from the child process's memory.
	//printf("%s\n", (char*)buf);
  kill(child_pid, SIGTERM);
  printf("sent SIGTERM to tracee\n");
	return 0;
}
