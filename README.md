# (WIP) Toy Debugger

### To-do

- [x] parse line into tokens
- [x] command line interface
- [x] breakpoint states: inactive/active (not user-controlled), enabled/disabled (user-controlled)
  - enabled+active means the tracee will stop when the breakpoint is reached
  - enabled+inactive means the tracee has hit the breakpoint and is currently stopped, and can hit the breakpoint again
  - disabled+(anything) means the tracee will not stop when the breakpoint is reached
- [x] as soon as tracee hits a breakpoint, we make the breakpoint inactive (temporarily) and rewind the instruction pointer
- [x] to continue, we single step, make the breakpoint active, put the int3 instruction back in if needed, then continue
- [x] link zydis
- [ ] implement ncurses ui

### Long-term goals

- Snapshot and restore a Linux process
- Attach to running processes and set breakpoints on them

### Reading material

- https://iafisher.com/blog/2024/08/linux-process-tricks
- https://github.com/checkpoint-restore/criu
- https://medium.com/@lizrice/a-debugger-from-scratch-part-1-7f55417bc85f
- https://tartanllama.xyz/posts/writing-a-linux-debugger/
- https://rfc.archlinux.page/0026-fno-omit-frame-pointer/
- https://thume.ca/2020/04/18/telefork-forking-a-process-onto-a-different-computer/
