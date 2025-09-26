#include <stdio.h>
#include <stdint.h>

int64_t fun2(int64_t arg) {
  return arg + 1;
}

int64_t fun1(int64_t arg) {
  return fun2(arg + 1);
}

int main(void) {
  printf("%ld\n", fun1(0x42424242));
}
