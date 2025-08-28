#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "payload.h"

typedef struct {
  long long int addr;
  char byte;
  bool enabled;
} breakpoint_t;

#define MAX_BREAKPOINTS 32
breakpoint_t breakpoints[MAX_BREAKPOINTS] = {0};

void enable_breakpoint(pid_t pid, long long int addr) {
  breakpoint_t* bp;
  for (int i = 0; i < MAX_BREAKPOINTS; i++) {
    bp = &breakpoints[i];
    if (!bp->enabled) break;
  }
  assert(!bp->enabled);
  bp->addr = addr;
  long word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
  bp->byte = word;
  word = (word & ~0xff) | 0xcc;
  assert(ptrace(PTRACE_POKEDATA, pid, addr, word) != -1);
}

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

void debug_wait_status(int wait_status) {
  if (WIFEXITED(wait_status)) {
    printf("child process exited\n");
  } else if (WIFSTOPPED(wait_status)) {
    int signum = WSTOPSIG(wait_status);
    const char* str = strsignal(signum);
    printf("child process stopped because: %s\n", str);
  } else {
    printf("child process status unknown\n");
  }
}

void read_proc_pid_maps(pid_t pid) {
  long long unsigned int first_start = 0, first_end = 0;
  {
    char path[32];
    snprintf(path, 32, "/proc/%d/maps", pid);
    //printf("%s\n", path);
    FILE *file = fopen(path, "r");

    char line[256];
    while (fgets(line, 256, file)) {
      long long unsigned int start, end;
      sscanf(line, "%llx-%llx", &start, &end);
      //printf("%s", line);
      //printf("%llx, %llx\n", start, end);
      if (first_start == 0) first_start = start;
      if (first_end == 0) first_end = end;
    }
  }

  // tmp
  {
    char path[32];
    snprintf(path ,32, "/proc/%d/mem", pid);
    //printf("%s\n", path);
    FILE *file = fopen(path, "r");
    if (!file) {
      printf("errno=%d\n", errno);
      assert(0);
    }
    assert(fseek(file, first_start, SEEK_SET) == 0);
    char tst[5] = "\0\0\0\0\0";
    fread(tst, sizeof(char), 4, file);
    //printf("%s\n", tst);
  }
}

int main(int argc, char** argv) {
  if (argc <= 1) {
    printf("Please pass in the path to the executable you want to debug,"
      " followed by any arguments you want to pass to that executable.\n");
    return 1;
  }
  char* exe_path = argv[1];
  pid_t child_pid = fork();
  assert(child_pid != -1);
  if (child_pid == 0) {
    // The child process follows this codepath.

    // Supposedly, PTRACE_TRACEME does the following:
    // "all subsequent calls to exec() by this process will cause a SIGTRAP to
    // be sent to it, giving the parent a chance to gain control before the new
    // program begins execution."
    // Source:
    // https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1
    // ... but this isn't explicitly stated in the ptrace man page.
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    // Turn off ASLR for the child process.
    personality(ADDR_NO_RANDOMIZE);

    execv(exe_path, &argv[1]);
  }
  // The parent process follows this codepath.
  int wstatus;
  assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  debug_wait_status(wstatus);
  // We are now attached to the child process.

  // WIP
  read_proc_pid_maps(child_pid);

  // Set a breakpoint.
  enable_breakpoint(child_pid, 0x55555555516b);
  //assert(ptrace(PTRACE_POKEDATA, child_pid, /*addr=*/0x55555555516b, /*data=*/0x90909090909090cc) != -1);
  assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);
  assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  debug_wait_status(wstatus);

  // Continue from breakpoint.
  assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);
  assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  debug_wait_status(wstatus);

  return 0;
}
