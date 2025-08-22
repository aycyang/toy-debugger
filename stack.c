#include <stdio.h>
#include <stdint.h>
#include <signal.h>

int f(void) {
  int i = 0xaa;
  raise(SIGTRAP);
  return i;
}

int main(void) {
  uint8_t i = 0x55;
  printf("allocated on the stack: %d\n", i);
  raise(SIGTRAP);
  f();
  return 0;
}
