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
#define UNUSED(x) (void)(x)


typedef struct {
  long long unsigned int addr;
  char byte;
  // User-controlled toggle.
  bool is_enabled;
} breakpoint_t;

breakpoint_t* breakpoints = NULL;

typedef struct {
  char** argv;
  pid_t child_pid;
  bool is_running;
  breakpoint_t* breakpoints;
  // This is set to the breakpoint at which the tracee is stopped.
  // If the tracee is not stopped at any breakpoint, this is NULL.
  breakpoint_t* current_breakpoint;
} session_t;

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

breakpoint_t* find_breakpoint(breakpoint_t* bps, long long unsigned int addr) {
  for (int i = 0; i < arrlen(bps); i++) {
    if (bps[i].addr == addr) {
      return &bps[i];
    }
  }
  return NULL;
}

void session_breakpoint_reactivate(session_t* session) {
  assert(session->current_breakpoint != NULL);
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, session->current_breakpoint->addr, NULL);
  // Overwrite the least-significant byte with 0xcc, which is the x86 int3
  // instruction.
  word = (word & ~0xff) | 0xcc;
  assert(ptrace(PTRACE_POKEDATA, session->child_pid, session->current_breakpoint->addr, word) != -1);
}

void session_breakpoint_deactivate(session_t* session) {
  assert(session->current_breakpoint != NULL);
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, session->current_breakpoint->addr, NULL);
  assert((word & 0xff) == 0xcc);
  word = (word & ~0xff) | (0xff & session->current_breakpoint->byte);
  assert(ptrace(PTRACE_POKEDATA, session->child_pid, session->current_breakpoint->addr, word) != -1);
}

void session_set_ip(session_t* session, long long unsigned int addr) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  regs.rip = addr;
  assert(ptrace(PTRACE_SETREGS, session->child_pid, NULL, &regs) != -1);
}

long long unsigned int session_get_ip(session_t* session) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  return regs.rip;
}

void session_step(session_t* session, __attribute__((__unused__)) char* arg) {
  printf("Stepping...\n");
  assert(ptrace(PTRACE_SINGLESTEP, session->child_pid, NULL, NULL) != -1);
  if (session->current_breakpoint != NULL) {
    session_breakpoint_reactivate(session);
    session->current_breakpoint = NULL;
  }
}

void session_continue(session_t* session, __attribute__((__unused__)) char* arg) {
  printf("Continuing...\n");
  if (!session->is_running) {
    printf("No child process to continue.\n");
    return;
  }
  if (session->current_breakpoint != NULL) {
    session_step(session, NULL);
  }
  assert(ptrace(PTRACE_CONT, session->child_pid, NULL, NULL) != -1);
  int wstatus;
  assert(waitpid(session->child_pid, &wstatus, 0) == session->child_pid);
  debug_wait_status(wstatus);
  if (WIFEXITED(wstatus)) {
    session->is_running = false;
  } else if (WIFSTOPPED(wstatus)) {
    switch (WSTOPSIG(wstatus)) {
      case SIGTRAP: {
        // TODO Find breakpoint, restore the original byte, and rewind the
        // instruction pointer.
        long long unsigned int addr = session_get_ip(session);
        printf("%llx\n", addr);
        session->current_breakpoint = find_breakpoint(session->breakpoints, addr - 1);
        assert(session->current_breakpoint != NULL);
        assert(session->current_breakpoint->is_enabled);
        session_breakpoint_deactivate(session);
        session_set_ip(session, addr - 1);
      } break;
      case SIGTERM:
        session->is_running = false;
        break;
    }
  }
}

void session_kill(session_t* session, __attribute__((__unused__)) char* arg) {
  printf("Killing child process...\n");
  if (session->is_running) {
    printf("Sending SIGTERM to child process %d...\n", session->child_pid);
    kill(session->child_pid, SIGTERM);
    session_continue(session, NULL);
    // TODO Assumes child process actually honored SIGTERM.
    session->is_running = false;
  } else {
    printf("No child process to kill.\n");
  }
}

void session_quit(session_t* session, __attribute__((__unused__)) char* arg) {
  if (session->is_running) {
    session_kill(session, arg);
  }
  printf("Bye!\n");
  exit(0);
}

void session_peek(session_t* session, char* arg) {
  long long unsigned int addr;
  if (sscanf(arg, "%llx", &addr) != 1) {
    printf("Failed to parse: %s\n", arg);
    return;
  }
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, addr, NULL);
  printf("%llx: %lx\n", addr, word);
}

void session_run(session_t* session, __attribute__((__unused__)) char* arg) {
  printf("Running...\n");
  if (session->is_running) {
    printf("Already running!\n");
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

    execv(session->argv[0], session->argv);
  }
  // The parent process follows this codepath.
  int wstatus;
  assert(waitpid(child_pid, &wstatus, 0) == child_pid);
  debug_wait_status(wstatus);
  // We are now attached to the child process.
  session->is_running = true;
  session->child_pid = child_pid;
}

void session_regs(session_t* session, __attribute__((__unused__)) char* arg) {
  if (!session->is_running) {
    printf("No child process to inspect.\n");
    return;
  }
  printf("Registers:\n");
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  printf("%%rip=0x%llx\n", regs.rip);
  printf("%%r15=0x%llx\n", regs.r15);
  printf("%%rdi=0x%llx\n", regs.rdi);
}

void session_break(session_t* session, char* arg) {
  if (arg == NULL) {
    printf("Usage: break <address>\n");
    return;
  }
  if (!session->is_running) {
    printf("Please run the child process before setting any breakpoints.\n");
    return;
  }
  long long unsigned int addr;
  if (sscanf(arg, "%llx", &addr) != 1) {
    printf("Failed to parse: %s\n", arg);
    return;
  }

  // TODO If breakpoint exists, don't create a new one.

  breakpoint_t bp = {0};
  bp.is_enabled = true;
  bp.addr = addr;
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, addr, NULL);
  // Save the least-signficant byte so the instruction can be restored to its
  // original state later.
  bp.byte = word; // This assignment implicitly truncates.

  // Overwrite the least-significant byte with 0xcc, which is the x86 int3
  // instruction.
  word = (word & ~0xff) | 0xcc;
  assert(ptrace(PTRACE_POKEDATA, session->child_pid, addr, word) != -1);
  arrput(session->breakpoints, bp);
  printf("Set a breakpoint at %llx\n", addr);
}

typedef struct command {
  char* name;
  void (*function) (session_t*, char*);
} command_t;
const command_t commands[] = {
  { "peek", session_peek },
  { "s", session_step },
  { "regs", session_regs },
  { "reg", session_regs },
  { "break", session_break },
  { "b", session_break },
  { "continue", session_continue },
  { "cont", session_continue },
  { "c", session_continue },
  { "run", session_run },
  { "r", session_run },
  { "kill", session_kill },
  { "k", session_kill },
  { "quit", session_quit },
  { "q", session_quit },
};
const size_t num_commands = sizeof(commands) / sizeof(command_t);

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
  session.argv = &argv[1];

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
    if (t1 != NULL) {
      bool command_found = false;
      for (size_t i = 0; i < num_commands; i++) {
        if (strcmp(t1, commands[i].name) == 0) {
          commands[i].function(&session, t2);
          command_found = true;
          break;
        }
      }
      if (!command_found) {
        printf("Unrecognized command: %s\n", t1);
      }
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
