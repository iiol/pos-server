#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
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
	// TODO delete pkt
	uint16_t len;
	uint16_t crc16;
	uint64_t mac;
	uint8_t num;
	uint8_t type;
	uint16_t version;
};

uint16_t crc_table[256];


void
crc16_init(void)
{
	uint16_t r;
	int s, s1;

	for(s = 0; s < 256; ++s) {
		r = ((uint16_t)s) << 8;

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
net_receive_auth_pkt(MYSQL *mysql, int fd)
{
	int i;
	struct msghdr msg = {0};
	int bytes_read;
	int ret;
	int pkt_len;
	uint8_t *buf;
	uint16_t crc16;
	struct packet *packet;
	uint64_t mac;
	char mac_str[18];
	struct terminals_entry *entry;
	struct log_entry log;
	struct packet_log_entry pkt_log;
	char *text = "Can't get full packet";

	msg.msg_iov = xmalloc(sizeof (struct iovec));
	msg.msg_iov->iov_base = xmalloc(4);
	msg.msg_iov->iov_len = 4;
	msg.msg_iovlen = 1;

	// TODO
	ret = recvmsg(fd, &msg, MSG_PEEK);

	buf = msg.msg_iov->iov_base;
	pkt_len = ((uint16_t)buf[1] << 8) + (uint16_t)buf[0] + 4;
	crc16 = ((uint16_t)buf[3] << 8) + (uint16_t)buf[2];

	free(msg.msg_iov);
	free(msg.msg_iov->iov_base);

	if (pkt_len > 1412) {
		text = alloca(256);
		sprintf(text, "Packet length is too big: %d", pkt_len);

		log.sid = 1;
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);

		return NULL;
	}

	buf = xmalloc(pkt_len);

	for (bytes_read = 0; bytes_read < pkt_len; bytes_read += ret) {
		ret = read(fd, buf + bytes_read, pkt_len - bytes_read);
		if (ret <= 0) {
			text = "Can't get full packet";

			// TODO
			log.sid = 1;
			log.log_part = 1;
			log.log_type = 1;
			log.log_code = 1;
			log.text = text;

			db_log(mysql, &log);
			fprintf(stderr, "%s\n", text);
			free(buf);

			return NULL;
		}
	}

	if (crc16 != get_crc16(buf + 4, pkt_len - 4)) {
		text = alloca(256);
		sprintf(text, "crc16 of packet doesn't match: in packet: %d, calculated: %d",
		    crc16, get_crc16(buf + 4, pkt_len - 4));

		// TODO
		log.sid = 1;
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);
		free(buf);

		return NULL;
	}

	for (i = mac = 0; i < 6; ++i)
		mac += (uint64_t)buf[4 + i] << 8*i;

	for (i = 0; i < 6; ++i)
		sprintf(mac_str + 3*i, "%.2x:", buf[9 - i]);
	mac_str[17] = '\0';

	entry = db_search_by_mac(mysql, mac);
	if (!entry) {
		text = alloca(256);
		sprintf(text, "Can't find '%s' in Terminals\n", mac_str);

		// TODO
		log.sid = 1;
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;

		db_log(mysql, &log);
		fprintf(stderr, "%s\n", text);
		free(buf);

		return NULL;
	}

	// TODO
	pkt_log.sid = 1;
	pkt_log.type = 1;
	pkt_log.time = 1;
	pkt_log.direction = CLITOSER;
	pkt_log.len = pkt_len;
	pkt_log.data = buf;
	db_log_packet(mysql, &pkt_log);


	packet = xmalloc(sizeof (struct packet));
	packet->crc16 = crc16;
	packet->mac = mac;
	// TODO
	packet->num = 0;
	packet->type = 1;
	packet->len = pkt_len - 4;
	packet->version = ((uint16_t)buf[13] << 8) + buf[12];

	free(buf);

	return packet;
}

int
net_send_auth_pkt(MYSQL *mysql, uint64_t mac, int fd)
{
	int i;
	uint16_t crc16;
	uint32_t date;
	uint16_t len = 16;
	uint8_t buf[len];
	int ret, written;

	date = time(NULL);
	buf[0] = (len - 4) & 0xFF;
	buf[1] = ((len - 4) >> 8) & 0xFF;

	for (i = 0; i < 6; ++i)
		buf[4 + i] = (mac >> 8*i) & 0xFF;

	// TODO
	buf[10] = 0x00;	// serial number
	buf[11] = 0x01; // type of packet

	for (i = 0; i < 4; ++i)
		buf[12 + i] = (date >> 8*i) & 0xFF;

	crc16 = get_crc16(buf + 4, len - 4);

	buf[2] = crc16 & 0xFF;
	buf[3] = (crc16 >> 8) & 0xFF;

	for (written = 0; written < len; written += ret) {
		ret = write(fd, buf + written, len);
		if (ret <= 0) {
			fprintf(stderr, "Can't write full packet\n");
			return -1;
		}
	}

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

	pkt = net_receive_auth_pkt(mysql, ctx->fd);
	if (!pkt) {
		fprintf(stderr, "Can't get packet\n");
		goto close_fd;
	}

	printf("Client version: %d\n", pkt->version);

	ret = net_send_auth_pkt(mysql, pkt->mac, ctx->fd);
	if (ret) {
		fprintf(stderr, "Can't send packet\n");
		goto free_pkt;
	}

free_pkt:
	free(pkt);

close_fd:
	close(ctx->fd);
	free(ctx);

	return NULL;
}
