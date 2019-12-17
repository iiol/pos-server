#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <alloca.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#include "database.h"
#include "macro.h"
#include "net.h"


struct packet {
	uint16_t len;
	uint16_t crc16;
	uint64_t mac;
	uint8_t num;

	enum type {
		AUTH_PKT     = 0x01,
		PING_PKT     = 0x02,
		LOG_PKT      = 0x05,
		PURCHASE_PKT = 0x0D,
	} type;

	// special fields in packet body
	union {
		uint16_t version;

		struct {
			uint32_t cli_time;
			uint16_t ms_time;
		};
	};
};

uint16_t crc_table[256];


static int
real_write(int fd, uint8_t *buf, size_t len)
{
	int ret;
	size_t written;

	for (written = 0; written < len; written += ret) {
		ret = write(fd, buf + written, len);
		if (ret <= 0)
			return -1;
	}

	return 0;
}

static int
real_read(int fd, uint8_t *buf, size_t len)
{
	int ret;
	size_t bytes_read;

	for (bytes_read = 0; bytes_read < len; bytes_read += ret) {
		ret = read(fd, buf + bytes_read, len - bytes_read);
		if (ret <= 0)
			return -1;
	}

	return 0;
}

void
crc16_init(void)
{
	uint16_t r;
	int s, s1;

	for(s = 0; s < 256; ++s) {
		r = (uint16_t)s << 8;

		for (s1 = 0; s1 < 8; s1++) {
			if (r&(1 << 15))
				r = (r << 1)^0x8005;
			else
				r = r << 1;
		}
		crc_table[s] = r;
	}
}

static uint16_t
get_crc16(const uint8_t *buf, uint16_t len)
{
	uint16_t crc = 0xFFFF;

	while (len--)
		crc = crc_table[((crc>>8)^*buf++)&0xFF] ^ (crc<<8);

	crc ^= 0xFFFF;

	return crc;
}

int
net_init(int port)
{
	int fd;
	struct sockaddr_in addr_in = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_ANY),
		.sin_port = htons(port),
	};

	fd = SYSCALL(1, socket, AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SYSCALL(1, bind, fd, (struct sockaddr*)&addr_in, SOCKLEN);
	SYSCALL(1, listen, fd, 32);

	return fd;
}

static struct packet*
receive_pkt(struct net_ctx *ctx)
{
	int i;
	struct msghdr msg = {0};
	int ret;
	uint8_t *buf;
	//
	MYSQL *mysql = ctx->mysql;
	int fd = ctx->fd;
	//
	char mac_str[18];
	//
	struct terminals_entry *entry;
	struct log_entry log;
	struct packet_log_entry pkt_log;
	//
	char *text;
	struct packet *pkt;

	msg.msg_iov = xmalloc(sizeof (struct iovec));
	msg.msg_iov->iov_base = xmalloc(12);
	msg.msg_iov->iov_len = 12;
	msg.msg_iovlen = 1;

	// TODO: check return value
	recvmsg(fd, &msg, MSG_PEEK);
	buf = msg.msg_iov->iov_base;

	pkt = xmalloc(sizeof (struct packet));
	pkt->len = ((uint16_t)buf[1] << 8) + (uint16_t)buf[0] + 4;
	pkt->crc16 = ((uint16_t)buf[3] << 8) + (uint16_t)buf[2];
	pkt->num = buf[10];
	pkt->type = buf[11];

	for (i = pkt->mac = 0; i < 6; ++i)
		pkt->mac += (uint64_t)buf[4 + i] << 8*i;

	free(msg.msg_iov->iov_base);
	free(msg.msg_iov);

	ctx->session.ip = ntohl(ctx->addr.sin_addr.s_addr);
	ctx->session.mac = pkt->mac;
	ctx->session.start_time = time(NULL);

	db_new_session(mysql, &ctx->session);
	ctx->sid = ctx->session.sid;

	if (pkt->num != ctx->inp_pkt_num++) {
		text = alloca(256);
		sprintf(text, "Expected packet number: %d, but in packet: %d",
		    ctx->inp_pkt_num - 1, pkt->num);

		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(pkt);

		return NULL;
	}

	// TODO: add other packet lengths
	if ((pkt->type == AUTH_PKT && pkt->len > 14) ||
	    (pkt->type == PING_PKT && pkt->len > 18) ||
	    pkt->len > 1412) {
		text = alloca(256);
		sprintf(text, "Packet length is too big: %d", pkt->len);

		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(pkt);

		return NULL;
	}
	else if ((pkt->type == AUTH_PKT && pkt->len < 14) ||
		 (pkt->type == PING_PKT && pkt->len < 18) ||
		 pkt->len < 12) {
		text = alloca(256);
		sprintf(text, "Packet length is too small: type: 0x%02x, len: %d",
		    pkt->type, pkt->len);

		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(pkt);

		return NULL;
	}

	buf = xmalloc(pkt->len);

	ret = real_read(fd, buf, pkt->len);
	if (ret < 0) {
		text = "Can't get full packet";

		// TODO
		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(buf);
		free(pkt);

		return NULL;
	}

	if (pkt->crc16 != get_crc16(buf + 4, pkt->len - 4)) {
		text = alloca(256);
		sprintf(text, "crc16 of packet doesn't match: in packet: %d, calculated: %d",
		    pkt->crc16, get_crc16(buf + 4, pkt->len - 4));

		// TODO
		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(buf);
		free(pkt);

		return NULL;
	}

	for (i = 0; i < 6; ++i)
		sprintf(mac_str + 3*i, "%.2x:", buf[9 - i]);
	mac_str[17] = '\0';

	entry = db_search_by_mac(mysql, pkt->mac);
	if (!entry) {
		text = alloca(256);
		sprintf(text, "Can't find '%s' in Terminals\n", mac_str);

		// TODO
		log.sid = 1;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		free(buf);
		free(pkt);

		return NULL;
	}

	// TODO
	pkt_log.sid = 1;
	pkt_log.type = pkt->type;
	pkt_log.time = time(NULL);
	pkt_log.direction = CLITOSER;
	pkt_log.len = pkt->len;
	pkt_log.data = buf;
	db_log_packet(mysql, &pkt_log);

	switch (pkt->type) {
	case AUTH_PKT:
		pkt->version = ((uint16_t)buf[13] << 8) + buf[12];
		break;

	case PING_PKT:
		for (i = pkt->cli_time = 0; i < 4; ++i)
			pkt->cli_time += buf[13 + i] << 8*i;

		pkt->ms_time =  ((uint16_t)buf[18] << 8) + buf[17];

		break;

	case LOG_PKT:
	case PURCHASE_PKT:
		break;
	}

	free(buf);

	return pkt;
}

static int
send_pkt(struct net_ctx *ctx, struct packet *pkt)
{
	int i;
	int fd = ctx->fd;
	MYSQL *mysql = ctx->mysql;
	uint64_t mac = pkt->mac;
	uint16_t crc16;
	uint32_t date;
	uint16_t len;
	uint8_t *buf;
	int ret;
	struct packet_log_entry pkt_log;

	switch (pkt->type) {
	case AUTH_PKT:
		len = 16;
		buf = alloca(len);
		date = time(NULL);

		buf[0] = (len - 4) & 0xFF;
		buf[1] = ((len - 4) >> 8) & 0xFF;

		for (i = 0; i < 6; ++i)
			buf[4 + i] = (mac >> 8*i) & 0xFF;

		// TODO
		buf[10] = ctx->out_pkt_num++;
		buf[11] = pkt->type;

		for (i = 0; i < 4; ++i)
			buf[12 + i] = (date >> 8*i) & 0xFF;

		crc16 = get_crc16(buf + 4, len - 4);

		buf[2] = crc16 & 0xFF;
		buf[3] = (crc16 >> 8) & 0xFF;

		ret = real_write(fd, buf, len);
		if (ret < 0) {
			fprintf(stderr, "Can't write full packet\n");
			return -1;
		}

		break;

	case PING_PKT:
	case LOG_PKT:
	case PURCHASE_PKT:
		break;
	}

	pkt_log.sid = 1;
	pkt_log.type = pkt->type;
	pkt_log.time = time(NULL);
	pkt_log.direction = SERTOCLI;
	pkt_log.len = len;
	pkt_log.data = buf;
	db_log_packet(mysql, &pkt_log);

	return 0;
}

void*
net_thread(void *args)
{
	int ret;
	struct net_ctx *ctx = args;
	MYSQL *mysql = ctx->mysql;
	char *text;
	struct packet *pkt;

	if (ctx->type == SECURE)
		text = "Secure";
	else
		text = "Unsecure";

	printf("%s connect: %s:%d\n", text, inet_ntoa(ctx->addr.sin_addr),
	    ntohs(ctx->addr.sin_port));

	ctx->inp_pkt_num = ctx->out_pkt_num = 0;

	pkt = receive_pkt(ctx);
	if (!pkt) {
		fprintf(stderr, "Can't get packet\n");
		goto finalize;
	}

	switch (pkt->type) {
	case AUTH_PKT:
		printf("Client version: %d\n", pkt->version);

		ret = send_pkt(ctx, pkt);
		if (ret) {
			fprintf(stderr, "Can't send packet\n");
			free(pkt);
			goto finalize;
		}

		free(pkt);

		break;

	case PING_PKT:
		//ret = send_ping_pkt(mysql, ctx->fd, pkt);
		free(pkt);
		break;

	case LOG_PKT:
	case PURCHASE_PKT:
		break;
	}

finalize:
	ctx->session.end_time = time(NULL);
	db_end_session(mysql, &ctx->session);

	close(ctx->fd);
	free(ctx);

	return NULL;
}
