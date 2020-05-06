#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <arpa/inet.h>
#include <stralloc.h>
#include <dns.h>
#include <limits.h>
#include <errno.h>

#include <uint16.h>
#include <byte.h>
#include "hex.h"
#include "read.h"

// https://gcc.gnu.org/gcc-4.4/changes.html
 #pragma pack(push, 1)
struct __attribute__((__packed__)) dns_header_t   {
	uint16_t id:16;
	union {
		struct {
			uint8_t rd : 1;
			uint8_t tc : 1;
			uint8_t aa : 1;
			uint8_t opcode:4;
			uint8_t qr:1;
// 2nd byte		
			uint8_t rcode:4;
			uint8_t zero:3;
			uint8_t ra : 1;
		} f;
		struct {
			uint8_t flags1 : 8;
			uint8_t flags2 : 8;
		} ff;
		uint16_t flags16: 16;

	};
	uint16_t qdcount:16, ancount:16, nscount:16, arcount:16;
};
#pragma pack(pop)



static struct db_entry_t *my_db;
static int my_db_sz;
static int my_db_defaultindex=-1;
static int my_verbose;
static uid_t my_uid;
static gid_t my_gid;

static void print_dns_header(const struct dns_header_t*buf) {
	printf("id:%d qr:%d opcode:%d aa:%d tc:%d, rd:%d, ra:%d, z:%d, rcode:%d, qdcount:%d, ancount:%d, nscount:%d, arcount:%d, f1:%d f2:%d flags16:%x\n", ntohs(buf->id), buf->f.qr, buf->f.opcode, buf->f.aa, buf->f.tc, buf->f.rd, buf->f.ra, buf->f.zero, buf->f.rcode, ntohs(buf->qdcount), ntohs(buf->ancount), ntohs(buf->nscount), ntohs(buf->arcount), buf->ff.flags1, buf->ff.flags2, buf->flags16);
//	printf("id:%d flags1:%d flags2:%d qdcount:%d ancount:%d nscount:%d arcount:%d\n",ntohs(buf->id), buf->flags1, buf->flags2,buf->qdcount, buf->ancount, buf->nscount, buf->arcount);
}


static void die(const char* msg) {
	perror(msg);
	exit(123);
}


static int lookup(char*buf, stralloc*name) {
	for (int i = 0 ; i< my_db_sz; i++) {
		if (!strncmp(my_db[i].name, name->s, name->len)) {
			memcpy(buf, &my_db[i].addr, sizeof(struct in_addr));
			return sizeof(struct in_addr);
		}
	}
	// nothing found
	printf("returning default\n");
	memcpy(buf, &my_db[my_db_defaultindex].addr, sizeof(struct in_addr));
	return sizeof(struct in_addr);
}

// https://tools.ietf.org/html/rfc1035 section 4:
//
static int process_query(char* buf, int len) {
	const char*buf0 = buf;
	const char*end = buf+len;
	int ret = -1;
	struct dns_header_t* header = (struct dns_header_t*)buf;
		

	print_dns_header(header);

	buf+= sizeof(struct dns_header_t);


	printf("sz:%ld\n", sizeof(struct dns_header_t));
	stralloc name={0};
	int i =0;
	do {
		int sz = *buf++;
		if (buf >= end) return -1;
		if (sz == 0) break;
		if (sz > 63) return -1;
		if (name.len > 255) return -1;
		// nach jedem tag einen . einfuegen
		if (name.len && !stralloc_append(&name, ".")) goto process_end;
		while(sz--) {
			if (!stralloc_append(&name, buf++)) goto process_end;
		}
	} while(1);
	stralloc_0(&name);
	printf("name:%s\n", name.s);

	uint16_t qtype = ntohs(*((uint16_t*)buf));
	buf += 2;
	uint16_t qclass = ntohs(*((uint16_t*)buf));
	buf +=2;

	printf("qtype: %d qclass%d\n", qtype, qclass);

	if (!stralloc_equals(&name, "www.orf.at")) {
		printf("gotit\n");

		header->f.qr=1;
		header->f.rd=1;
		header->f.ra=1; // das setzt irgendwie das result
		header->f.rcode = 0;
		header->qdcount=htons(1);
		header->ancount=htons(1);
		header->nscount=htons(0);
		header->arcount=htons(0);
		print_dns_header(header);
		*(uint16_t*)buf= htons(0xc000| 12); // pointer to record this answer belongs to: two MSB bits set, 0ffset from header;
		buf +=2;
		*(uint16_t*)buf = htons(1); // type
		buf +=2;
		*(uint16_t*)buf = htons(1); // class
		buf +=2;
		*(uint32_t*)buf = htonl(6528); // ttl
		buf +=4;
		*(uint16_t*)buf = htons(4); // length of ip
		buf +=2;

		lookup(buf, &name); //		memcpy(buf, &my_db[0].addr,sizeof(struct in_addr));
		buf +=4;
#if 0
		*buf++=123;
		*buf++=45;
		*buf++=67;
		*buf++=89;
#endif

	print_dns_header(header);
	 print_hex_dump(buf0, len);

	//	header->nscount=0;
	//	header->arcount=0;

	}	
	if (buf > end) {
		die("buf > end");
	}
	ret = buf - buf0;
process_end:
	stralloc_free(&name);
	return ret;

}




static void maybe_drop_privileges() {

	printf("before:getgid:%d getegid:%d getuid:%d geteuid:%d my_uid:%d my_gid:%d\n",
		getgid(), getegid(), getuid(), geteuid(), my_uid, my_gid);
	
	if ((getgid()==0 || getegid()==0 || getuid()==0 || geteuid()==0) && (my_gid == 0 || my_uid == 0) ) {
		errno=1;
		perror("running as root oder sudo root but no uid set for dropping privileges");
		exit(123);
	}
	if (my_gid == 0 || my_uid == 0) {
		perror("either user id or gid is set to 0, refusing to run");
		exit(123);
	}
	
	if ( (my_gid > 0 ) &&    (-1 == setresgid(my_gid, my_gid, my_gid))) {
		perror("cant set gid");
		exit(123);
	}

	if ( (my_uid > 0 ) &&  (-1 == setresuid(my_uid, my_uid, my_uid))) {
		perror("cant set uid");
		exit(123);
	}
	printf("after:getgid:%d getegid:%d getuid:%d geteuid:%d my_uid:%d my_gid:%d\n",
		getgid(), getegid(), getuid(), geteuid(), my_uid, my_gid);
	
}




static int start(int port, struct in_addr * bind_addr) {
	printf("listening at %d\n", port);
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}
	printf("got socket:%d\n", sock);

	struct sockaddr_in srv;
	bzero(&srv, sizeof(struct sockaddr_in));
	srv.sin_family = AF_INET;

	if (bind_addr == NULL) {
	srv.sin_addr.s_addr= htonl(INADDR_ANY); // auf alle listenen
	} else {
		memcpy(&srv.sin_addr, bind_addr, sizeof(struct in_addr));
	}

	srv.sin_port = htons(port);
	if (bind(sock, (const struct sockaddr*) &srv, sizeof(srv)) < 0) {
		perror("bind");
		return -1;
	}
	maybe_drop_privileges();

	#define BUF_SZ 1024
	char buf[BUF_SZ];
	struct sockaddr_in cli_addr;
	ssize_t len;
	socklen_t cli_len = sizeof(cli_addr);
	while(1) {
		printf("recvfrom\n");
		len = recvfrom(sock, &buf, BUF_SZ, 0, (struct sockaddr*)&cli_addr, &cli_len);
		printf("got: %ld from %s, cli_len:%d\n", len, inet_ntoa(cli_addr.sin_addr), cli_len);
		print_hex((const char*)&buf, len);
		print_hex_dump((const char*)&buf, len);
		int r = process_query(buf, len);
		if (r == -1) {
			printf("error\n");
		} else {
			printf("sendto start %d\n", r);
			int x = sendto(sock, &buf, r, MSG_CONFIRM, (const struct sockaddr*)&cli_addr, cli_len); 
			if (x == -1) { // address family not supported by protocol
				perror("send");
			}
			printf("sendto:end:%d\n", x);

//			exit(123);
		}
	}
			

start_end:
	close(sock);

}

static void atshutdown() {
	if(my_db) free(my_db);
}


int main(int argc, char** argv) {
	atexit(atshutdown);

	char conffn[PATH_MAX] = "simpledns.conf";
	int c;
	int port = 10053;
	int ret = 0;	
	struct in_addr* bind_addr = NULL;
	struct in_addr addr;
	while ((c = getopt(argc, argv, "b:hvp:f:u:g:")) != -1) {
		switch (c) {
			case 'h':	
				 printf("-u uid -g gid -p port : port, -f conffile -v : verbose, -?: help, -b: bindaddress\n");
				 exit(0);
			break;
			case 'v':my_verbose=1;
			break;

			case 'p':
				port = atoi(optarg);
				if (!port) {
					printf("invalid port: %s\n", optarg);
					exit(123);
				}
			break;
			case 'f':
				memcpy(&conffn, optarg, strlen(optarg));
			break;
			case 'b':
				printf("converting:%s\n", optarg);
				if (!optarg || (inet_aton(optarg, &addr) == -1)) {
					printf("invalid bind address:%s\n", optarg);
					exit(123);
				}
				bind_addr = &addr;
			break;
			case 'u':
				my_uid = atoi(optarg);
			break;
			case 'g':
				my_gid = atoi(optarg);
			break;
		}
	}



	if (my_verbose) {
		printf("starting with conffile: %s at port %d\n", conffn, port);
		printf("uid:%d gid:%d\n", my_uid, my_gid);
	}

	my_db_sz = read_db_entries(conffn, &my_db);

	if (my_db_sz <=0) {
		perror("could not read config file");
		ret = 123;
		goto main_end;
	}


	for (int i = 0 ; i < my_db_sz; i++) {
		if (!strcmp(my_db[i].name, "*")) {
			my_db_defaultindex = i;
			break;
		}
	}
	if (my_db_defaultindex == -1) {
		perror("no default entry * found :-(");
		exit(123);
	}

	start(port, bind_addr);
	main_end:
	return ret;
}

