#include <signal.h>
int main(void) {
	__asm__("mov $0x42, %r15;");
	return 0;
}
