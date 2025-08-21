#include <stdio.h>
#include <stdint.h>
#include <signal.h>

int main(void) {
  uint8_t i = 0x55;
  printf("allocated on the stack: %d\n", i);
  raise(SIGTRAP);
  return 0;
}
