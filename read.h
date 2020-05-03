#ifndef __read_h__
#define __read_h__

#define DB_ENTRY_NAME_SZ 128
struct db_entry_t {
	char name[DB_ENTRY_NAME_SZ];
	struct in_addr addr;
};

int read_db_entries(const char* fn, struct db_entry_t** data);

#endif
