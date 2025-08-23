#include <signal.h>
static char my_string[256] = "tomato";
int main(void) {
	__asm__("mov $0x42, %r15\n  "
          "nop");
	return 0;
}
