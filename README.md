# (WIP) Linux Process Snapshot

Toy project to snapshot and restore a Linux process.

Reading material:

- https://iafisher.com/blog/2024/08/linux-process-tricks
- https://github.com/checkpoint-restore/criu

TODO

- [ ] dump all registers
- [ ] dump all memory into a file
- [ ] store open file descriptors (idea for restore: syscall indirection to map fds)
