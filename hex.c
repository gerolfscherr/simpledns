#include <stdio.h>
#include "hex.h"



static const char hex_table[] = "0123456789abcdef";

void print_hex_char(int c) {
	putchar(hex_table[(c>>4) & 0xf]);
	putchar(hex_table[c & 0xf]);
}

void print_hex_line(const char*data, int len) {
	for (int i =0; i < len; i++) {
		char c = *data++;
		print_hex_char(c);
		putchar(' ');
		if (i == 7) putchar(' ');
	}
}

void print_ascii_line(const char*data, int l) {
	while (l--) {
		char c = *data++;
		if (c > 31) { putchar(c);
		} else {
			putchar('_');
		}
		if (l == 8) putchar(' ');
	}
}


void print_hex_dump(const char* data, int len) {
	int l;
	while(len) {
		l = len > 16 ? 16 : len;
		print_hex_line(data, l);
		if (l < 16) {
			for(int i = 0;i < (16-l)*3;i++) putchar('-'); // padden
			if ((16-l) > 8) putchar('_'); // ka
		}
		fputs("   ", stdout);
		print_ascii_line(data, l);

		putchar('\n');
		data += l;
		len -= l;
	}

	putchar('\n');
}

void print_hex(const char *data, int len) {
	int l = 0;
	while (len--) {
		char c = *data++;
		print_hex_char(c);
		putchar(' ');
		if (l++ == 7) putchar(' ');
		else if (l == 16) { putchar('\n'); l = 0; }
	}
	putchar('\n');
}


