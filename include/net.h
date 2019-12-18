#ifndef _NET_H
#define _NET_H

#include <netinet/in.h>

#define SOCKLEN sizeof (struct sockaddr_in)
#define SEC_PORT   1085
#define UNSEC_PORT 1082

struct net_ctx {
	int fd;
	MYSQL *mysql;
	struct sockaddr_in addr;
	enum conn_type {
		SECURE,
		UNSECURE,
	} type;

	size_t sid;
	struct sessions_entry session;
	uint8_t inp_pkt_num;
	uint8_t out_pkt_num;

	SSL *ssl;
};

int net_init(int port);
void crc16_init(void);
void *net_thread(void *args);

#endif // _NET_H
