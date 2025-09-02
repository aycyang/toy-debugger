// Expose strsignal() and kill()
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

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#include "payload.h"

#define MAX_LINE_SIZE (256)

typedef struct {
  pid_t child_pid;
  bool is_running;
} session_t;

typedef struct {
  long long int addr;
  char byte;
} breakpoint_t;

breakpoint_t* breakpoints = NULL;

void enable_breakpoint(pid_t pid, long long int addr) {
  breakpoint_t bp;
  bp.addr = addr;
  long word = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
  // Save the least-signficant byte so the instruction can be restored to its
  // original state later.
  bp.byte = word;
  // Overwrite the least-significant byte with 0xcc, which is the x86 int3
  // instruction.
  word = (word & ~0xff) | 0xcc;
  assert(ptrace(PTRACE_POKEDATA, pid, addr, word) != -1);
  arrput(breakpoints, bp);
}

void disable_breakpoint(pid_t pid, long long int addr) {
  int i = -1;
  for (int j = 0; j < arrlen(breakpoints); j++) {
    if (breakpoints[i].addr == addr) {
      i = j;
      break;
    }
  }
  if (i == -1) {
    printf("breakpoint not found at address 0x%llx\n", addr);
    return;
  }
  // Restore the instruction to its original state.
  breakpoint_t *bp = &breakpoints[i];
  long word = ptrace(PTRACE_PEEKDATA, pid, bp->addr, NULL);
  word = (word & ~0xff) | (0xff & bp->byte);
  assert(ptrace(PTRACE_POKEDATA, pid, bp->addr, word) != -1);
  arrdel(breakpoints, i);
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

void update_rip(pid_t pid, int incr) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, pid, /*addr=*/NULL, /*data=*/&regs) != -1);
  regs.rip += incr;
  assert(ptrace(PTRACE_SETREGS, pid, /*addr=*/NULL, /*data=*/&regs) != -1);
}

void debug_r15(pid_t pid) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, pid, /*addr=*/NULL, /*data=*/&regs) != -1);
  printf("%%r15=0x%llx\n", regs.r15);
}

void debug_rip(pid_t pid) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, pid, /*addr=*/NULL, /*data=*/&regs) != -1);
  printf("%%rip=0x%llx\n", regs.rip);
}

void debug_bps(void) {
  printf("=== BREAKPOINTS ===\n");
  for (int i = 0; i < arrlen(breakpoints); i++) {
    printf("0x%llx\n", breakpoints[i].addr);
  }
  printf("===================\n");
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
      printf("%s", line);
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

void session_run(session_t* session, char** argv) {
  if (session->is_running) {
    printf("already running\n");
    return;
  }
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

    execv(argv[0], argv);
  }
  // The parent process follows this codepath.
  int wstatus;
  assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  debug_wait_status(wstatus);
  // We are now attached to the child process.
  session->is_running = true;
  session->child_pid = child_pid;
}

bool is_whitespace(char c) {
  return c == ' ' || c == '\n' || c == '\t';
}

// Takes in a null-terminated input string, replacing all whitespace in-place
// with null bytes, and returning pointers to the first two tokens.
bool tokenize2(char* in, char** out1, char** out2) {
  assert(in != NULL);
  assert(*out1 == NULL);
  assert(*out2 == NULL);
  size_t size = strlen(in);
  bool is_consuming_token = false;
  for (size_t i = 0; i < size; i++) {
    char c = *(in + i);
    if (is_whitespace(c)) {
      *(in + i) = '\0';
      is_consuming_token = false;
      if (*out2 != NULL) break;
      continue;
    }
    if (*out1 == NULL && !is_consuming_token) {
      *out1 = in + i;
      is_consuming_token = true;
      continue;
    }
    if (*out2 == NULL && !is_consuming_token) {
      *out2 = in + i;
      is_consuming_token = true;
      continue;
    }
  }
  return *out1 != NULL && *out2 != NULL;
}

int main(int argc, char** argv) {
  if (argc <= 1) {
    printf("Please pass in the path to the executable you want to debug,"
      " followed by any arguments you want to pass to that executable.\n");
    return 1;
  }

  session_t session = {0};

  printf("Ready to run:");
  for (int i = 1; i < argc; i++) {
    printf(" %s", argv[i]);
  }
  printf("\n");

  printf("> ");
  char line[MAX_LINE_SIZE];
  while (fgets(line, MAX_LINE_SIZE, stdin)) {
    char* t1 = NULL;
    char* t2 = NULL;
    tokenize2(line, &t1, &t2);
    printf("t1: %s\n", t1);
    printf("t2: %s\n", t2);
    if (false) {
      session_run(&session, &argv[1]);
    }
    printf("> ");
  }
  printf("\n");

  /*

  // WIP
  //read_proc_pid_maps(child_pid);

  debug_rip(child_pid);
  debug_r15(child_pid);

  // Set a breakpoint.
  enable_breakpoint(child_pid, 0x555555555164);
  enable_breakpoint(child_pid, 0x55555555516b);
  debug_bps();
  */

  // Execute up to the breakpoint.
  //assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);
  //int wstatus;
  //assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  //debug_wait_status(wstatus);

  /*
  // %r15 should be not equal to 0x42.
  debug_rip(child_pid);
  debug_r15(child_pid);

  // Rewind instruction pointer, restore the original instruction, and continue
  // from there.
  update_rip(child_pid, -1);
  disable_breakpoint(child_pid, 0);
  debug_bps();
  */

  // Continue to second breakpoint.
  //assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);
  //assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  //debug_wait_status(wstatus);

  // %r15 should be equal to 0x42.
  //debug_rip(child_pid);
  //debug_r15(child_pid);

  // Continue to end.
  //update_rip(child_pid, -1);
  //disable_breakpoint(child_pid, 0);
  //debug_bps();
  //assert(ptrace(PTRACE_CONT, child_pid, /*addr=*/NULL, /*data=*/NULL) != -1);
  //assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  //debug_wait_status(wstatus);

  return 0;
}
