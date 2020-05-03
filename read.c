#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <malloc.h>
#include "read.h"




int read_db_entries(const char* fn, struct db_entry_t **t) {
	FILE *f = fopen(fn, "r");
	if (!f) return -ENOENT;
	#define SZ 512
	char s[SZ];
	int r = -1;
	int n=0;
	int blocksz = 32;
	*t = (struct db_entry_t*)malloc(sizeof(struct db_entry_t)*blocksz);
	if (!t) goto read_end;
	while (fgets((char*)&s, SZ, f)) {
		if(s[0] == '#') continue;
		int len = strlen(s);
		int eq = -1;
		for (int i = 0 ; i < len; i++) {
	//		putchar(s[i]);
			if (s[i] == '=') { eq = i; break; }
		}

		if (eq == -1) continue;
		if (eq+1 > DB_ENTRY_NAME_SZ) {
			continue;
		}
		s[eq] = 0; // am == trennen
		if (s[len-1] == '\n') s[len-1] = 0;
		struct in_addr addr;
		if (!inet_aton((char*)&s[eq+1], &addr )) continue;
		
				
		printf("%s\t%s\t(%s)\n",s, &s[eq+1] , inet_ntoa(addr));

		if (r == blocksz) {
			puts("realloc!");
			blocksz += blocksz;
			*t = (struct db_entry_t*)realloc(*t, sizeof(struct db_entry_t)*blocksz);
			if (!t) goto read_end;
		}
		memcpy(&(*t)[n].name, s, eq+1);
		memcpy(&(*t)[n].addr, &addr, sizeof(addr));
		n++;
		printf("line: %s\n", s);
	}
	printf("final count:%d\n", n);
	*t = (struct db_entry_t*)realloc(*t, sizeof(struct db_entry_t)*n);
	if (!t) goto read_end;
	r = n;
	read_end:
	fclose(f);
	return r;
}

void dump_db_entries(struct db_entry_t* list, int sz) {
	for (int i = 0 ; i < sz; i++) {
	//	printf("%s -> %s\n", list[i].name, list[i].addr);
		printf("%s %s\n", list[i].name, inet_ntoa(list[i].addr));



	}
}
#ifdef STANDALONE
int main(int argc, char** argv) {
	struct db_entry_t *list;
	int sz = read_db_entries("smartdns.conf", &list);
	if (sz < 0) {
		perror("no liste");
	}
	dump_db_entries(list, sz);
	free(list);

}
#endif
