#ifndef _DATABASE_H
#define _DATABASE_H

#include <stdint.h>
#include <mysql/mysql.h>
#include "macro.h"


#define FOREACH_FLD(S, F, I, ARG)			\
	ARG##_F(S, F, I, ID)				\
	ARG(S, F, I, IP)				\
	ARG(S, F, I, Port)				\
	ARG(S, F, I, TerminalMac)			\
	ARG(S, F, I, SSLCert)				\
	ARG(S, F, I, SSLKey)				\
	ARG(S, F, I, TerminalID)			\
	ARG(S, F, I, MerchantID)			\
	ARG(S, F, I, Version)				\
	ARG(S, F, I, Ping)				\
	ARG(S, F, I, LastOnlineTime)			\
	ARG##_L(S, F, I, OwnerID)			\

#define FLD_COUNT (OwnerID + 1 - ID)

#define GENERATE_ENUM_F(_1, _2,_3, ENUM) ENUM,
#define GENERATE_ENUM(_1, _2,_3, ENUM) ENUM,
#define GENERATE_ENUM_L(_1, _2,_3, ENUM) ENUM,

#define GENERATE_CMP_F(S, F, I, CMP) do {if (!strcmp(S, #CMP)) F[CMP] = I;
#define GENERATE_CMP(S, F, I, CMP) else if (!strcmp(S, #CMP)) F[CMP] = I;
#define GENERATE_CMP_L(S, F, I, CMP) else if (!strcmp(S, #CMP)) F[CMP] = I;} while (0)

enum fld_types {
	FOREACH_FLD(0, 0, 0, GENERATE_ENUM)
};

#undef GENERATE_ENUM_F
#undef GENERATE_ENUM
#undef GENERATE_ENUM_L


struct packet_log_entry {
	size_t sid;
	int type;
	time_t time;
	enum direction {
		SERTOCLI,
		CLITOSER,
	} direction;
	uint8_t *data;
	size_t len;
};

struct log_entry {
	size_t sid;
	time_t time;
	int log_part;
	int log_type;
	int log_code;
	char *text;
	size_t text_len;
};

struct terminals_entry {
	uint64_t mac;
	char *ssl_cert;
	char *ssl_key;
	char *terminal_id;
	char *merchant_id;
	int version;
	int ping;
	char *last_online;
	int owner;
};

struct sessions_entry {
	size_t sid;
	uint32_t ip;
	uint64_t mac;
	time_t start_time;
	time_t end_time;
};

struct bpc_entries {
	size_t id;
	uint32_t ip;
	uint16_t port;

	struct list_node _list;
};

struct transactions_entry {
	float amount;
	char *rrn;
	char *approval_num;
	int response_code;
	char *terminal_id;
	uint64_t terminal_mac;
	time_t time;
	int result;
	char *cashbox_fn;
	char *cashbox_i;
	char *cashbox_fd;
};


MYSQL *db_init(char *host, int port, char *user, char *passwd, char *db);

// add to database
int db_log_packet(MYSQL *mysql, struct packet_log_entry *plog);
int db_log(MYSQL *mysql, struct log_entry *log);
int db_new_session(MYSQL *mysql, struct sessions_entry *session);
int db_end_session(MYSQL *mysql, struct sessions_entry *session);
int db_new_transaction(MYSQL *mysql, struct transactions_entry *ta);

// get from database
struct terminals_entry *db_search_by_mac(MYSQL *mysql, uint64_t mac);
void db_free_terminals_entry(struct terminals_entry *entry);
struct bpc_entries *db_get_bpc_hosts(MYSQL *mysql);
void db_free_bpc_entries(struct bpc_entries *entries);

#endif // _DATABASE_H
