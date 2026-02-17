// Expose strsignal() and kill()
#define _POSIX_C_SOURCE 200809L

#include <algorithm>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <memory>

#include <elf.h>
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

#include "util.h"
#include "mem.h"
#include "disasm.h"

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
  void log(std::basic_stringstream<char> ss) {
    output_lines.push_back(ss.str());
  }
  void log(std::string s) {
    output_lines.push_back(s);
  }
  void UpdateDisasm();
  char** argv = 0;
  pid_t child_pid = 0;
  bool is_running = 0;
  // TODO make this a ring buffer so it's not growing unboundedly
  std::vector<std::string> output_lines;
  std::vector<breakpoint_t> breakpoints;
  // This is set to the breakpoint at which the tracee is stopped.
  // If the tracee is not stopped at any breakpoint, this is NULL.
  breakpoint_t* current_breakpoint = 0;
  std::unique_ptr<VirtualMemory> vm;
  std::unique_ptr<DisasmCache> disasm_cache;
  std::vector<std::string> disasm;
  ZydisDecoder zydis_decoder;
  ZydisFormatter zydis_formatter;
} session_t;

void session_t::UpdateDisasm() {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) != -1);
  uintptr_t rip = regs.rip;
  log(std::basic_stringstream<char>() << "rip=" << std::hex << rip);
  disasm = disasm_cache->GetDisasmAround(rip, 10);
}

void debug_wait_status(session_t* session, int wait_status) {
  if (WIFEXITED(wait_status)) {
    session->log("child process exited");
  } else if (WIFSTOPPED(wait_status)) {
    int signum = WSTOPSIG(wait_status);
    const char* str = strsignal(signum);
    session->log(std::string("child process stopped because: ") + str);
  } else {
    session->log("child process status unknown");
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
    session->log(std::basic_stringstream<char>() << "peek data failed: " << errno);
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
    session->log(std::basic_stringstream<char>() << "peek data failed: " << errno);
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

void session_step(session_t* session, std::string arg) {
  session->log("Stepping...");
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
  session->log(std::basic_stringstream<char>() << "0x" << std::hex << addr << "  " << buffer);
}

void session_continue(session_t* session, std::string arg) {
  session->log("Continuing...");
  if (!session->is_running) {
    session->log("No child process to continue.");
    return;
  }
  if (session->current_breakpoint != NULL) {
    session_step(session, "");
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
        session->UpdateDisasm();
      } break;
      case SIGTERM:
        session->is_running = false;
        break;
    }
  }
}

void session_kill(session_t* session, std::string arg) {
  session->log("Killing child process...");
  if (session->is_running) {
    session->log(std::basic_stringstream<char>() << "Sending SIGTERM to child process " << session->child_pid);
    kill(session->child_pid, SIGTERM);
    session_continue(session, "");
    // TODO Assumes child process actually honored SIGTERM.
    session->is_running = false;
  } else {
    session->log("No child process to kill.");
  }
}

void session_quit(session_t* session, std::string arg) {
  if (session->is_running) {
    session_kill(session, arg);
  }
  endwin();
  printf("Bye!\n");
  exit(0);
}

void session_backtrace(session_t* session, std::string arg) {
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  long cur = regs.rbp;
  while (cur != 0) {
    session->log(std::basic_stringstream<char>() << "frame=" << cur);
    cur = ptrace(PTRACE_PEEKDATA, session->child_pid, cur, NULL);
    long value = ptrace(PTRACE_PEEKDATA, session->child_pid, cur+8, NULL);
    session->log(std::basic_stringstream<char>() << "ip=" << value);
  }
}

void session_peek(session_t* session, std::string arg) {
  long long unsigned int addr;
  if (sscanf(arg.c_str(), "%llx", &addr) != 1) {
    session->log(std::basic_stringstream<char>() << "Failed to parse: " << arg);
    return;
  }
  long word = ptrace(PTRACE_PEEKDATA, session->child_pid, addr, NULL);
  session->log(std::basic_stringstream<char>() << "0x" << std::hex << addr << ": " << word);
}

void session_run(session_t* session, std::string arg) {
  session->log( "Running...");
  if (session->is_running) {
    session->log( "Already running!");
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

  // tmp
  session->vm = std::make_unique<VirtualMemory>(session->child_pid);
  session->vm->Update();

  session->log(std::basic_stringstream<char>() << *session->vm);

  session->disasm_cache = std::make_unique<DisasmCache>(session->vm.get());

  session->UpdateDisasm();
}

void session_regs(session_t* session, std::string arg) {
  if (!session->is_running) {
    session->log( "No child process to inspect.");
    return;
  }
  session->log( "Registers:");
  struct user_regs_struct regs;
  assert(ptrace(PTRACE_GETREGS, session->child_pid, NULL, &regs) != -1);
  session->log(std::basic_stringstream<char>() << "%rip=0x" << std::hex << regs.rip);
  session->log(std::basic_stringstream<char>() << "%r15=0x" << std::hex << regs.r15);
  session->log(std::basic_stringstream<char>() << "%rdi=0x" << std::hex << regs.rdi);
}

void session_break(session_t* session, std::string arg) {
  if (arg.empty()) {
    session->log( "Usage: break <address>");
    return;
  }
  if (!session->is_running) {
    session->log( "Please run the child process before setting any breakpoints.");
    return;
  }
  long long unsigned int addr;
  if (sscanf(arg.c_str(), "%llx", &addr) != 1) {
    session->log( std::basic_stringstream<char>() << "Failed to parse: " << arg);
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
  session->log( std::basic_stringstream<char>() << "Set a breakpoint at 0x" << std::hex << addr);
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

void dispatchCmd(session_t* session, std::string line) {
  std::vector<std::string> tokens = split(line, " ");
  if (tokens.empty()) {
    return;
  }
  auto it = std::find_if(commands.begin(), commands.end(), [&](command_t& cmd) {
    return cmd.name == tokens[0];
  });
  if (it == commands.end()) {
    session->log( std::basic_stringstream<char>() << "Unrecognized command: " << tokens[0]);
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

  auto* win = newwin(30, 80, 3, 8);
  auto* win2 = newwin(30, 50, 3, 88);

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
        session.log("> " + cur_line);
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
      wborder(win, 0, 0, 0, 0, 0, 0, 0, 0);

      const size_t height = 30;
      const size_t width = 80;
      std::vector<std::string> visible_lines;
      for (auto it = session.output_lines.rbegin(); it != session.output_lines.rend(); it++) {
        std::vector<std::string> wrapped_lines = wrapTo(*it, width - 2);
        for (auto it2 = wrapped_lines.rbegin(); it2 != wrapped_lines.rend(); it2++) {
          visible_lines.push_back(*it2);
          if (visible_lines.size() >= height - 2) break;
        }
        if (visible_lines.size() >= height - 2) break;
      }

      std::reverse(visible_lines.begin(), visible_lines.end());
      for (size_t i = 0; i < visible_lines.size(); i++) {
        mvwprintw(win, 1 + i, 1, "%s", visible_lines[i].c_str());
      }

      wrefresh(win);
    }

    {
      wclear(win2);
      wborder(win2, 0, 0, 0, 0, 0, 0, 0, 0);

      const int width = 50;
      for (size_t i = 0; i < session.disasm.size(); i++) {
        mvwprintw(win2, 1 + i, 1, "%.*s", width - 2, session.disasm[i].c_str());
      }

      wrefresh(win2);
    }

  }
  refresh();

  // ncurses teardown
  return endwin();
}
