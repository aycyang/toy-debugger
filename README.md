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

- [x] poc render text in boxes
- [x] write command history to a scrollback buffer
- [x] re-integrate with command system
- [x] draw borders around windows for debugging purposes
- [ ] implement text wrapping utility for wrapping text in a window
- [ ] support non-wrapping text overflow for windows as well
- [ ] show disassembly in a box
- [ ] support terminal resizing
- [ ] make core backend-agnostic and implement imgui and curses backends
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
