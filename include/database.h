#ifndef _DATABASE_H
#define _DATABASE_H

#include <stdint.h>

#include <mysql/mysql.h>


#define FOREACH_FLD(S, F, I, ARG)			\
	ARG##_F(S, F, I, ID)				\
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
	int time;
	enum direction {
		SERTOCLI,
		CLITOSER,
	} direction;
	uint8_t *data;
	size_t len;
};

struct log_entry {
	size_t sid;
	int log_part;
	int log_type;
	int log_code;
	char *text;
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

MYSQL *db_init(char *host, int port, char *user, char *passwd, char *db);

int db_log_packet(MYSQL *mysql, struct packet_log_entry *plog);
int db_log(MYSQL *mysql, struct log_entry *log);

struct terminals_entry *db_search_by_mac(MYSQL *mysql, uint64_t mac);

int db_print_table(MYSQL *mysql, const char *tbl);

#endif // _DATABASE_H
