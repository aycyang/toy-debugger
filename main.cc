// Expose strsignal() and kill()
#define _POSIX_C_SOURCE 200809L

#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>

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
#include <locale.h>

#include <Zydis/Zydis.h>

#include <curses.h>

#define MAX_LINE_SIZE (256)
#define UNUSED(x) (void)(x)

typedef struct {
  long long unsigned int addr = 0;
  char byte = 0;
  // User-controlled toggle.
  bool is_enabled = 0;
} breakpoint_t;

breakpoint_t* breakpoints = NULL;

typedef struct {
  char** argv = 0;
  pid_t child_pid = 0;
  bool is_running = 0;
  // TODO make this a ring buffer so it's not growing unboundedly
  std::basic_stringstream<char> scrollback_buf;
  std::vector<breakpoint_t> breakpoints;
  // This is set to the breakpoint at which the tracee is stopped.
  // If the tracee is not stopped at any breakpoint, this is NULL.
  breakpoint_t* current_breakpoint = 0;
  ZydisDecoder zydis_decoder;
  ZydisFormatter zydis_formatter;
} session_t;

void debug_wait_status(session_t* session, int wait_status) {
  if (WIFEXITED(wait_status)) {
    session->scrollback_buf << "child process exited\n";
  } else if (WIFSTOPPED(wait_status)) {
    int signum = WSTOPSIG(wait_status);
    const char* str = strsignal(signum);
    session->scrollback_buf << "child process stopped because: " << str << std::endl;
  } else {
    session->scrollback_buf << "child process status unknown\n";
  }
}

breakpoint_t* find_breakpoint(std::vector<breakpoint_t>& bps, long long unsigned int addr) {
  for (auto& bp : bps) {
    if (bp.addr == addr) {
      return &bp;
    }
  }
  return NULL;
}

void session_breakpoint_reactivate(session_t* session) {
  assert(session->current_breakpoint != NULL);
  errno = 0;
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, session->current_breakpoint->addr, NULL);
  if (errno != 0) {
    session->scrollback_buf << "peek data failed: " << errno << std::endl;
    exit(1);
  }
  // Overwrite the least-significant byte with 0xcc, which is the x86 int3
  // instruction.
  word = (word & ~0xff) | 0xcc;
  assert(ptrace(PTRACE_POKEDATA, session->child_pid, session->current_breakpoint->addr, word) != -1);
}

void session_breakpoint_deactivate(session_t* session) {
  assert(session->current_breakpoint != NULL);
  errno = 0;
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, session->current_breakpoint->addr, NULL);
  if (errno != 0) {
    session->scrollback_buf << "peek data failed: " << errno << std::endl;
    exit(1);
  }
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

void session_step(session_t* session, __attribute__((__unused__)) std::string arg) {
  session->scrollback_buf << "Stepping...\n";
  assert(ptrace(PTRACE_SINGLESTEP, session->child_pid, NULL, NULL) != -1);
  int wstatus;
  assert(waitpid(session->child_pid, &wstatus, 0) == session->child_pid);
  debug_wait_status(session, wstatus);
  if (session->current_breakpoint != NULL) {
    session_breakpoint_reactivate(session);
    session->current_breakpoint = NULL;
  }
}

void session_disasm(session_t* session, long long unsigned int addr) {
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, addr, NULL);
  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[10];
  assert(ZYAN_SUCCESS(ZydisDecoderDecodeFull(&session->zydis_decoder, &word, sizeof(word), &instruction, operands)));
  char buffer[256];
  ZydisFormatterFormatInstruction(&session->zydis_formatter, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, buffer, sizeof(buffer), addr, ZYAN_NULL);
  session->scrollback_buf << "0x" << addr << "  " << buffer << std::endl;
}

void session_continue(session_t* session, __attribute__((__unused__)) std::string arg) {
  session->scrollback_buf << "Continuing...\n";
  if (!session->is_running) {
    session->scrollback_buf << "No child process to continue.\n";
    return;
  }
  if (session->current_breakpoint != NULL) {
    session_step(session, NULL);
  }
  assert(ptrace(PTRACE_CONT, session->child_pid, NULL, NULL) != -1);
  int wstatus;
  assert(waitpid(session->child_pid, &wstatus, 0) == session->child_pid);
  debug_wait_status(session, wstatus);
  if (WIFEXITED(wstatus)) {
    session->is_running = false;
  } else if (WIFSTOPPED(wstatus)) {
    switch (WSTOPSIG(wstatus)) {
      case SIGTRAP: {
        // Find breakpoint, restore the original byte, and rewind the
        // instruction pointer.
        // TODO Rewind the instruction pointer and return it at the same time
        // to save on ptrace calls.
        long long unsigned int ip = session_get_ip(session);
        session->current_breakpoint = find_breakpoint(session->breakpoints, ip - 1);
        assert(session->current_breakpoint != NULL);
        assert(session->current_breakpoint->is_enabled);
        session_breakpoint_deactivate(session);
        session_set_ip(session, ip - 1);
        session_disasm(session, ip - 1);
      } break;
      case SIGTERM:
        session->is_running = false;
        break;
    }
  }
}

void session_kill(session_t* session, __attribute__((__unused__)) std::string arg) {
  session->scrollback_buf << "Killing child process...\n";
  if (session->is_running) {
    session->scrollback_buf << "Sending SIGTERM to child process " << session->child_pid << "...\n";
    kill(session->child_pid, SIGTERM);
    session_continue(session, NULL);
    // TODO Assumes child process actually honored SIGTERM.
    session->is_running = false;
  } else {
    session->scrollback_buf << "No child process to kill.\n";
  }
}

void session_quit(session_t* session, __attribute__((__unused__)) std::string arg) {
  if (session->is_running) {
    session_kill(session, arg);
  }
  endwin();
  printf("Bye!\n");
  exit(0);
}

void session_backtrace(session_t* session, __attribute__((__unused__)) std::string arg) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  long cur = regs.rbp;
  while (cur != 0) {
    session->scrollback_buf << "frame=" << cur << std::endl;
    cur = ptrace(PTRACE_PEEKDATA, session->child_pid, cur, NULL);
    long value = ptrace(PTRACE_PEEKDATA, session->child_pid, cur+8, NULL);
    session->scrollback_buf << "ip=" << value << std::endl;
  }
}

void session_peek(session_t* session, std::string arg) {
  long long unsigned int addr;
  if (sscanf(arg.c_str(), "%llx", &addr) != 1) {
    session->scrollback_buf << "Failed to parse: " << arg << std::endl;
    return;
  }
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, addr, NULL);
  session->scrollback_buf << addr << ": " << word << std::endl;
}

void session_run(session_t* session, __attribute__((__unused__)) std::string arg) {
  session->scrollback_buf << "Running...\n";
  if (session->is_running) {
    session->scrollback_buf << "Already running!\n";
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
  debug_wait_status(session, wstatus);
  // We are now attached to the child process.
  session->is_running = true;
  session->child_pid = child_pid;
}

void session_regs(session_t* session, __attribute__((__unused__)) std::string arg) {
  if (!session->is_running) {
    session->scrollback_buf << "No child process to inspect.\n";
    return;
  }
  session->scrollback_buf << "Registers:\n";
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  session->scrollback_buf << "%rip=0x" << regs.rip << std::endl;
  session->scrollback_buf << "%r15=0x" << regs.r15 << std::endl;
  session->scrollback_buf << "%rdi=0x" << regs.rdi << std::endl;
}

void session_break(session_t* session, std::string arg) {
  if (arg.empty()) {
    session->scrollback_buf << "Usage: break <address>\n";
    return;
  }
  if (!session->is_running) {
    session->scrollback_buf << "Please run the child process before setting any breakpoints.\n";
    return;
  }
  long long unsigned int addr;
  if (sscanf(arg.c_str(), "%llx", &addr) != 1) {
    session->scrollback_buf << "Failed to parse: " << arg << std::endl;
    return;
  }

  // TODO If breakpoint exists, don't create a new one.

  breakpoint_t bp;
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
  session->breakpoints.push_back(bp);
  session->scrollback_buf << "Set a breakpoint at " << addr << std::endl;
}

typedef struct command {
  std::string name;
  void (*function) (session_t*, std::string);
} command_t;
std::vector<command_t> commands = {
  { "peek", session_peek },
  { "step", session_step },
  { "s", session_step },
  { "regs", session_regs },
  { "reg", session_regs },
  { "break", session_break },
  { "b", session_break },
  { "bt", session_backtrace },
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

std::vector<std::string> split(std::string str, char separator = ' ') {
  std::vector<std::string> result;
  std::string cur;
  for (const char c : str) {
    if (c == separator) {
      if (!cur.empty()) {
        result.push_back(std::move(cur));
        cur.clear();
      }
      continue;
    }
    cur += c;
  }
  if (!cur.empty()) {
    result.push_back(std::move(cur));
  }
  return result;
}

void dispatchCmd(session_t* session, std::string line) {
  std::vector<std::string> tokens = split(line);
  if (tokens.empty()) {
    return;
  }
  auto it = std::find_if(commands.begin(), commands.end(), [&](command_t& cmd) {
    return cmd.name == tokens[0];
  });
  if (it == commands.end()) {
    session->scrollback_buf << "Unrecognized command: " << tokens[0] << std::endl;
    return;
  }
  if (tokens.size() == 1) {
    it->function(session, "");
  } else {
    it->function(session, tokens[1]);
  }
}

int main(int argc, char** argv) {
  if (argc <= 1) {
    printf("Please pass in the path to the executable you want to debug,"
      " followed by any arguments you want to pass to that executable.\n");
    return 1;
  }

  session_t session;
  ZydisDecoderInit(&session.zydis_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
  ZydisFormatterInit(&session.zydis_formatter, ZYDIS_FORMATTER_STYLE_ATT);
  session.argv = &argv[1];

  // ncurses preamble
  setlocale(LC_ALL, "");
  initscr();
  noecho();
  cbreak();
  intrflush(stdscr, FALSE);
  keypad(stdscr, TRUE);

  auto* win = newwin(10, 80, 3, 8);

  int ch;
  int height = getmaxy(stdscr);
  mvprintw(height - 1, 0, ">");
  std::string cur_line;
  // main loop
  while ((ch = getch()) != 4) { // Ctrl-D
    int row, col;
    getyx(stdscr, row, col);
    move(height - 2, 0);
    clrtoeol();
    printw("%d", ch);
    move(row, col);
    switch (ch) {
      case 258: // down
        break;
      case 259: // up
        break;
      case 260: // left
        break;
      case 261: // right
        break;
      case 263: // backspace
        if (col <= 1) break;
        cur_line.pop_back();
        move(row, col - 1);
        delch();
        break;
      case 10: // enter
        session.scrollback_buf << "> " << cur_line << std::endl;
        if (!cur_line.empty()) {
          dispatchCmd(&session, cur_line);
        }
        cur_line.clear();
        move(row, 1);
        clrtoeol();
        break;
      default:
        cur_line += ch;
        addch(ch);
        move(row, col + 1);
        break;
    }

    {
      wclear(win);
      mvwprintw(win, 1, 1, "%s\n", session.scrollback_buf.str().c_str());
      wborder(win, 0, 0, 0, 0, 0, 0, 0, 0);
      wrefresh(win);
    }

  }
  refresh();

  // ncurses teardown
  return endwin();
}
