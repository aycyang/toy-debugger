# (WIP) Toy Debugger

### Quick start

```
cmake -B build
cmake --build build
build/ToyDebugger build/TestProgram
run
break 55555555511d # figure this out using /proc/pid/maps and objdump -d
continue
regs
step
regs
continue
quit
```

### To-do

- [ ] get memory region containing address
- [ ] for each mapped page in maps file, check if ELF header is present.
      if present, find all code segments and disassemble all instructions.
      store formatted disassembly in memory.
- [ ] show disassembly in a window
- [ ] handle dynamic terminal resize
- [ ] support non-wrapping text overflow for windows
- [ ] think about how to differentiate vertical vs horizontal scrolling
- [ ] implement mouse event handling
- [ ] implement mouse scrolling
- [ ] target embedded linux
- [ ] target OpenBSD
- [x] handle newlines in log line
- [x] find the virtual address of the page where the executable file is mapped
- [x] implement text wrapping utility for wrapping text in a window
- [x] poc render text in boxes
- [x] write command history to a scrollback buffer
- [x] re-integrate with command system
- [x] draw borders around windows for debugging purposes
- [x] migrate codebase from C to C++
- [x] parse line into tokens
- [x] command line interface
- [x] breakpoint states: inactive/active (not user-controlled), enabled/disabled (user-controlled)
  - enabled+active means the tracee will stop when the breakpoint is reached
  - enabled+inactive means the tracee has hit the breakpoint and is currently stopped, and can hit the breakpoint again
  - disabled+(anything) means the tracee will not stop when the breakpoint is reached
- [x] as soon as tracee hits a breakpoint, we make the breakpoint inactive (temporarily) and rewind the instruction pointer
- [x] to continue, we single step, make the breakpoint active, put the int3 instruction back in if needed, then continue
- [x] link zydis
- [x] implement ncurses ui

### Long-term goals

- Snapshot and restore a Linux process
- Time-travel debugging (i.e. reverse stepping)

### Reading material

- https://iafisher.com/blog/2024/08/linux-process-tricks
- https://github.com/checkpoint-restore/criu
- https://medium.com/@lizrice/a-debugger-from-scratch-part-1-7f55417bc85f
- https://tartanllama.xyz/posts/writing-a-linux-debugger/
- https://rfc.archlinux.page/0026-fno-omit-frame-pointer/
- https://thume.ca/2020/04/18/telefork-forking-a-process-onto-a-different-computer/
