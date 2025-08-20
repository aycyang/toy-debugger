static char my_string[256] = "tomato";
int main(void) {
	__asm__("" : : "r" (my_string));
	while(1) {
		__asm__("pause");
	}
	return 0;
}
