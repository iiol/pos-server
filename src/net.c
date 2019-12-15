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


uint16_t crc_table[256];


static void
reverse(uint8_t *buf, int len)
{
	int start, end;

	for (start = 0, end = len - 1; start < end; ++start, --end) {
		buf[start] ^= buf[end];
		buf[end] ^= buf[start];
		buf[start] ^= buf[end];
	}
}

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
get_ctc16(const uint8_t *buf, uint16_t len)
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
	SYSCALL(1, listen, fd, 50);

	return fd;
}

struct packet*
net_receive_pkt(MYSQL *mysql, int fd)
{
	struct msghdr msg = {0};
	int bytes_read;
	int ret;
	int pkt_len;
	uint8_t *buf;
	uint16_t crc16;
	struct packet *packet;

	msg.msg_iov = xmalloc(sizeof (struct iovec));
	msg.msg_iov->iov_base = xmalloc(4);
	msg.msg_iov->iov_len = 4;
	msg.msg_iovlen = 1;

	// TODO
	ret = recvmsg(fd, &msg, MSG_PEEK);

	buf = msg.msg_iov->iov_base;
	pkt_len = (((uint16_t)buf[1]) << 8) + (uint16_t)buf[0] + 4;
	crc16 = (((uint16_t)buf[3]) << 8) + (uint16_t)buf[2];

	free(msg.msg_iov);
	free(msg.msg_iov->iov_base);

	if (pkt_len > 1412) {
		fprintf(stderr, "Packet length is too big: %d\n", pkt_len);
		return NULL;
	}

	buf = xmalloc(pkt_len);

	for (bytes_read = 0; bytes_read < pkt_len; bytes_read += ret) {
		ret = read(fd, buf + bytes_read, pkt_len - bytes_read);
		if (ret <= 0) {
			fprintf(stderr, "Can't get full packet\n");
			free(buf);
			return NULL;
		}
	}

	if (crc16 != get_ctc16(buf + 4, pkt_len - 4)) {
		fprintf(stderr, "crc16 of packet doesn't match: %d:%d\n", crc16, get_ctc16(buf + 4, pkt_len - 4));
		free(buf);
		return NULL;
	}

	int i;
	uint8_t mac[6];
	char mac_str[18];

	memcpy(mac, buf + 4, 6);
	reverse(mac, 6);

	for (i = 0; i < 6; ++i)
		sprintf(mac_str + 3*i, "%.2x:", mac[i]);

	mac_str[17] = '\0';

	struct terminals_entry *entry;

	entry = db_search_by_mac(mysql, mac_str);
	if (!entry) {
		fprintf(stderr, "Can't find '%s' in Terminals", mac_str);
		return NULL;
	}
	printf("%s\n", entry->ssl_cert);

	packet = xmalloc(sizeof (struct packet));
	packet->data = buf;
	packet->len = pkt_len;

	return packet;
}

void*
net_thread(void *args)
{
	struct net_ctx *ctx = args;
	char *text;
	struct packet *pkt;

	if (ctx->type == SECURE)
		text = "Secure";
	else
		text = "Unsecure";

	printf("%s connect: %s:%d\n", text, inet_ntoa(ctx->addr.sin_addr),
	    ntohs(ctx->addr.sin_port));

	pkt = net_receive_pkt(ctx->mysql, ctx->fd);
	if (pkt == NULL) {
		fprintf(stderr, "Can't get packet\n");
		goto finalize;
	}

	free(pkt->data);
	free(pkt);

finalize:
	close(ctx->fd);
	free(ctx);

	return NULL;
}
