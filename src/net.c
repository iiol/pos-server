#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <alloca.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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
		// auth packet
		uint16_t version;

		// ping packet
		struct {
			uint32_t cli_time;
			uint16_t ms_time;
		};

		// log packet
		struct {
			uint8_t log_part;
			uint8_t log_type;
			uint16_t log_code;
			uint8_t text_len;
			char *text;
		};

		struct {
			uint32_t amount;
			uint8_t details_len;
			uint8_t *card_details;
			uint8_t cryptogram_len;
			uint8_t *cryptogram;
		};
	};
};

uint16_t crc_table[256];

static void
pkt_free(struct packet *pkt)
{
	switch (pkt->type) {
	case AUTH_PKT:
	case PING_PKT:
		break;

	case LOG_PKT:
		free(pkt->text);
		break;

	case PURCHASE_PKT:
		free(pkt->card_details);
		free(pkt->cryptogram);
		break;

	default:
		fprintf(stderr, "pkt_free(): Unknown packet type: %02x\n", pkt->type);
		exit(1);
		break;
	}

	free(pkt);
}


static int
xread(struct net_ctx *ctx, uint8_t *buf, size_t len)
{
	int ret;
	size_t bytes_read;

	switch (ctx->type) {
	case SECURE:
		ret = SSL_read(ctx->ssl, buf, len);
		if (!ret)
			return -1;

		break;

	case UNSECURE:
		for (bytes_read = 0; bytes_read < len; bytes_read += ret) {
			ret = read(ctx->fd, buf + bytes_read, len - bytes_read);
			if (ret <= 0)
				return -1;
		}

		break;
	}

	return 0;
}

static int
xpeek(struct net_ctx *ctx, uint8_t *buf, size_t len)
{
	int ret;
	size_t bytes_read;
	struct msghdr msg = {0};

	switch (ctx->type) {
	case SECURE:
		ret = SSL_peek(ctx->ssl, buf, len);
		if (!ret)
			return -1;

		break;

	case UNSECURE:
		msg.msg_iov = alloca(sizeof (struct iovec));
		msg.msg_iov->iov_base = buf;
		msg.msg_iovlen = 1;

		for (bytes_read = 0; bytes_read < len; bytes_read += ret) {
			msg.msg_iov->iov_len = len - bytes_read;
			msg.msg_iov->iov_base = buf + bytes_read;
			ret = recvmsg(ctx->fd, &msg, MSG_PEEK);
			if (ret <= 0)
				return -1;
		}

		break;
	}

	return 0;
}

static int
xwrite(struct net_ctx *ctx, uint8_t *buf, size_t len)
{
	int ret;
	size_t written;

	switch (ctx->type) {
	case SECURE:
		ret = SSL_write(ctx->ssl, buf, len);
		if (!ret)
			return -1;

		break;

	case UNSECURE:
		for (written = 0; written < len; written += ret) {
			ret = write(ctx->fd, buf + written, len);
			if (ret <= 0)
				return -1;
		}

		break;
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
	int ret;
	uint8_t *buf;
	//
	MYSQL *mysql = ctx->mysql;
	//
	char mac_str[18];
	//
	struct terminals_entry *entry;
	struct log_entry log;
	struct packet_log_entry pkt_log;
	//
	char *text;
	struct packet *pkt;

	buf = xmalloc(12);
	ret = xpeek(ctx, buf, 12);
	if (ret < 0) {
		free(buf);
		return NULL;
	}

	pkt = xmalloc(sizeof (struct packet));
	pkt->len = ((uint16_t)buf[1] << 8) + (uint16_t)buf[0] + 4;
	pkt->crc16 = ((uint16_t)buf[3] << 8) + (uint16_t)buf[2];

	for (i = pkt->mac = 0; i < 6; ++i)
		pkt->mac += (uint64_t)buf[4 + i] << 8*i;

	pkt->num = buf[10];
	pkt->type = buf[11];

	free(buf);

	ctx->session.ip = ntohl(ctx->addr.sin_addr.s_addr);
	ctx->session.mac = pkt->mac;
	ctx->session.start_time = time(NULL);
	db_new_session(mysql, &ctx->session);
	ctx->sid = ctx->session.sid;

	if (pkt->type != AUTH_PKT     &&
	    pkt->type != PING_PKT     &&
	    pkt->type != LOG_PKT      &&
	    pkt->type != PURCHASE_PKT) {
		fprintf(stderr, "Unknown packet type: %02x\n", pkt->type);
		free(pkt);

		return NULL;
	}

	if (pkt->num != ctx->inp_pkt_num++) {
		text = alloca(256);
		sprintf(text, "Expected packet number: %d, but in packet: %d",
		    ctx->inp_pkt_num - 1, pkt->num);

		log.sid = ctx->sid;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;
		log.text_len = strlen(text);
		db_log(mysql, &log);

		fprintf(stderr, "%s\n", text);
		free(pkt);

		return NULL;
	}

	if ((pkt->type == AUTH_PKT     && pkt->len != 14)    ||
	    (pkt->type == PING_PKT     && pkt->len != 18)    ||
	    (pkt->type == LOG_PKT      && pkt->len <  17)    ||
	    (pkt->type == PURCHASE_PKT && pkt->len <  17)) {
		text = alloca(256);
		sprintf(text, "Packet length is wrong: type: 0x%02x, len: %d",
		    pkt->type, pkt->len);

		log.sid = ctx->sid;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;
		log.text_len = strlen(text);
		db_log(mysql, &log);

		fprintf(stderr, "%s\n", text);
		free(pkt);

		return NULL;
	}

	buf = xmalloc(pkt->len);

	ret = xread(ctx, buf, pkt->len);
	if (ret < 0) {
		text = "Can't get full packet";

		log.sid = ctx->sid;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;
		log.text_len = strlen(text);
		db_log(mysql, &log);

		fprintf(stderr, "%s\n", text);
		free(pkt);
		free(buf);

		return NULL;
	}

	if (pkt->crc16 != get_crc16(buf + 4, pkt->len - 4)) {
		text = alloca(256);
		sprintf(text, "crc16 of packet doesn't match: in packet: %d, calculated: %d",
		    pkt->crc16, get_crc16(buf + 4, pkt->len - 4));

		log.sid = ctx->sid;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;
		log.text_len = strlen(text);
		db_log(mysql, &log);

		fprintf(stderr, "%s\n", text);
		free(pkt);
		free(buf);

		return NULL;
	}

	for (i = 0; i < 6; ++i)
		sprintf(mac_str + 3*i, "%.2x:", buf[9 - i]);
	mac_str[17] = '\0';

	entry = db_search_by_mac(mysql, pkt->mac);
	if (!entry) {
		text = alloca(256);
		sprintf(text, "Can't find '%s' in Terminals\n", mac_str);

		log.sid = ctx->sid;
		log.time = time(NULL);
		log.log_part = 1;
		log.log_type = 1;
		log.log_code = 1;
		log.text = text;
		log.text_len = strlen(text);
		db_log(mysql, &log);

		fprintf(stderr, "%s\n", text);
		free(pkt);
		free(buf);

		return NULL;
	}

	pkt_log.sid = ctx->sid;
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
			pkt->cli_time += buf[12 + i] << 8*i;

		pkt->ms_time = ((uint16_t)buf[17] << 8) + buf[16];

		break;

	case LOG_PKT:
		pkt->log_part = buf[12];
		pkt->log_type = buf[13];
		pkt->log_code = ((uint16_t)buf[15] << 8) + buf[14];
		pkt->text_len = buf[16];

		if (pkt->len != 17 + buf[16]) {
			fprintf(stderr, "Size in first header and size of text not match\n");

			free(buf);
			free(pkt);
			db_free_terminals_entry(entry);

			return NULL;
		}

		pkt->text = xmalloc(pkt->text_len);
		memcpy(pkt->text, buf + 17, pkt->text_len);

		break;

	case PURCHASE_PKT:
		for (i = pkt->amount = 0; i < 4; ++i)
			pkt->amount += buf[12 + i] << 8*i;

		pkt->details_len = buf[16];
		if (17 + pkt->details_len >= pkt->len) {
			fprintf(stderr, "Wrong card details field length\n");

			free(buf);
			free(pkt);
			db_free_terminals_entry(entry);

			return NULL;
		}

		pkt->cryptogram_len = buf[17 + pkt->details_len];
		if (18 + pkt->details_len + pkt->cryptogram_len != pkt->len) {
			fprintf(stderr, "Wrong crytogram field length\n");
			fprintf(stderr, "crypto len: %02x\n", pkt->cryptogram_len);

			free(buf);
			free(pkt);
			db_free_terminals_entry(entry);

			return NULL;
		}

		pkt->card_details = xmalloc(pkt->details_len);
		pkt->cryptogram = xmalloc(pkt->cryptogram_len);

		memcpy(pkt->card_details, buf + 17, pkt->details_len);
		memcpy(pkt->cryptogram, buf + 18 + pkt->details_len, pkt->cryptogram_len);

		break;
	}

	free(buf);
	db_free_terminals_entry(entry);

	return pkt;
}

static int
send_pkt(struct net_ctx *ctx, struct packet *pkt)
{
	int i;
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

		buf[10] = ctx->out_pkt_num++;
		buf[11] = pkt->type;

		for (i = 0; i < 4; ++i)
			buf[12 + i] = (date >> 8*i) & 0xFF;

		break;

	case PING_PKT:
		len = 18;
		buf = alloca(len);

		buf[0] = (len - 4) & 0xFF;
		buf[1] = ((len - 4) >> 8) & 0xFF;

		for (i = 0; i < 6; ++i)
			buf[4 + i] = (mac >> 8*i) & 0xFF;

		buf[10] = ctx->out_pkt_num++;
		buf[11] = pkt->type;

		for (i = 0; i < 4; ++i)
			buf[12] = (pkt->cli_time >> 8*i) & 0xFF;

		break;

	case LOG_PKT:
		break;

	case PURCHASE_PKT:
		break;

	default:
		fprintf(stderr, "send_pkt(): Unknown packet type: %02x\n", pkt->type);
		exit(1);
		break;
	}

	crc16 = get_crc16(buf + 4, len - 4);

	buf[2] = crc16 & 0xFF;
	buf[3] = (crc16 >> 8) & 0xFF;

	ret = xwrite(ctx, buf, len);
	if (ret < 0) {
		fprintf(stderr, "Can't write full packet\n");
		return -1;
	}

	pkt_log.sid = ctx->sid;
	pkt_log.type = pkt->type;
	pkt_log.time = time(NULL);
	pkt_log.direction = SERTOCLI;
	pkt_log.len = len;
	pkt_log.data = buf;
	db_log_packet(mysql, &pkt_log);

	return 0;
}

static int
send_to_bank(SSL *ssl, struct packet *pkt, struct terminals_entry *term)
{
	int pkt_size = 100 + pkt->details_len + pkt->cryptogram_len;
	char buf[pkt_size];
	char bitmap[] = {0x32, 0x30, 0x05, 0x80, 0x20, 0xC0, 0x82, 0x00};
	struct tm tm;
	time_t t;
	char time_str[12];
	int pos;

	t = time(NULL);
	localtime_r(&t, &tm);
	strftime(time_str, 12, "%y%m%d%H%M%S", &tm);

	pos = 0;
	pos += sprintf(buf, "%04d", pkt_size);
	pos += sprintf(buf + pos, "0200");
	memcpy(buf + pos, bitmap, 8);
	pos += 8;
	pos += sprintf(buf + pos, "000000");
	pos += sprintf(buf + pos, "%012d", pkt->amount);
	pos += sprintf(buf + pos, "%s", time_str + 2);
	pos += sprintf(buf + pos, "000001"); // TODO
	pos += sprintf(buf + pos, "%s", time_str);
	pos += sprintf(buf + pos, "070");			// pos entry mode
	pos += sprintf(buf + pos, "200");			// function code
	pos += sprintf(buf + pos, "02");			// pos condition code
	pos += sprintf(buf + pos, "%02d", pkt->details_len);
	memcpy(buf + pos, pkt->card_details, pkt->details_len);
	pos += pkt->details_len;
	pos += sprintf(buf + pos, "%8s", term->terminal_id);
	pos += sprintf(buf + pos, "%15s", term->merchant_id);
	pos += sprintf(buf + pos, "643");
	pos += sprintf(buf + pos, "%02d", pkt->cryptogram_len);
	memcpy(buf + pos, pkt->cryptogram, pkt->cryptogram_len);

	SSL_write(ssl, buf, pkt_size);

	return 0;
}

static int
purchase_proc(struct net_ctx *ctx, struct packet *pkt)
{
	int ret;
	struct terminals_entry *term;
	struct bpc_entries *bpc_head, *bpc;
	const SSL_METHOD *ssl_mtd;
	SSL_CTX *ssl_ctx;
	int cfd, kfd;
	char cpath[] = "/tmp/cert.XXXXXX";
	char kpath[] = "/tmp/key.XXXXXX";

	term = db_search_by_mac(ctx->mysql, pkt->mac);
	bpc_head = db_get_bpc_hosts(ctx->mysql);
	if (term == NULL || bpc_head == NULL) {
		db_free_bpc_entries(bpc_head);
		db_free_terminals_entry(term);

		return 1;
	}

	cfd = open(mktemp(cpath), O_WRONLY | O_CREAT, 0600);
	kfd = open(mktemp(kpath), O_WRONLY | O_CREAT, 0600);
	write(cfd, term->ssl_cert, strlen(term->ssl_cert));
	write(kfd, term->ssl_key,  strlen(term->ssl_key));
	close(cfd);
	close(kfd);

	ssl_mtd = SSLv23_client_method();
	ssl_ctx = SSL_CTX_new(ssl_mtd);
	if (!ssl_ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		unlink(cpath);
		unlink(kpath);
		return 1;
	}

	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

	if (SSL_CTX_use_certificate_file(ssl_ctx, cpath, SSL_FILETYPE_PEM) <= 0 ||
	    SSL_CTX_use_PrivateKey_file(ssl_ctx, kpath, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		unlink(cpath);
		unlink(kpath);
		return 1;
	}

	unlink(cpath);
	unlink(kpath);

	list_foreach (bpc_head, bpc) {
		SSL *ssl;
		int fd;
		struct sockaddr_in addr_in = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(INADDR_ANY),
			.sin_port = htons(0),
		};
		struct sockaddr_in host_in = {
			.sin_family = AF_INET,
			.sin_addr.s_addr = htonl(bpc->ip),
			.sin_port = htons(bpc->port),
		};

		fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (fd == -1) {
			perror("socket()");
			continue;
		}

		ret = bind(fd, (struct sockaddr*)&addr_in, SOCKLEN);
		if (ret == -1) {
			perror("bind()");
			close(fd);
			continue;
		}

		ret = connect(fd, (struct sockaddr*)&host_in, SOCKLEN);
		if (ret == -1) {
			perror("connect()");
			close(fd);
			continue;
		}

		ssl = SSL_new(ssl_ctx);

		SSL_set_fd(ssl, fd);
		if (SSL_connect(ssl) <= 0) {
			ERR_print_errors_fp(stderr);

			goto next_host;
		}

		ret = send_to_bank(ssl, pkt, term);
		if (ret)
			goto next_host;

		// ret = recv_from_bank(ssl); // TODO

		// TODO

next_host:
		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(fd);
	}

	SSL_CTX_free(ssl_ctx);
	db_free_terminals_entry(term);
	db_free_bpc_entries(bpc_head);

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
	struct log_entry log;

	if (ctx->type == SECURE) {
		text = "Secure";
	}
	else
		text = "Unsecure";

	printf("%s connect: %s:%d\n", text, inet_ntoa(ctx->addr.sin_addr),
	    ntohs(ctx->addr.sin_port));

	ctx->inp_pkt_num = ctx->out_pkt_num = 0;

	while (1) {
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
				goto free_pkt;
			}

			break;

		case PING_PKT:
			ret = send_pkt(ctx, pkt);
			if (ret) {
				fprintf(stderr, "Can't send packet\n");
				goto free_pkt;
			}

			break;

		case LOG_PKT:
			log.sid = ctx->sid;
			log.time = time(NULL);
			log.log_part = pkt->log_part;
			log.log_type = pkt->log_type;
			log.log_code = pkt->log_code;
			log.text = pkt->text;
			log.text_len = pkt->text_len;
			db_log(mysql, &log);

			break;

		case PURCHASE_PKT:
			ret = purchase_proc(ctx, pkt);
			if (ret) {
				fprintf(stderr, "Can't connect to bank host\n");
				continue;
			}

			break;
		}

		pkt_free(pkt);
	}

free_pkt:
	pkt_free(pkt);

finalize:
	ctx->session.end_time = time(NULL);
	db_end_session(mysql, &ctx->session);

	if (ctx->type == SECURE) {
		SSL_shutdown(ctx->ssl);
		SSL_free(ctx->ssl);
	}

	close(ctx->fd);
	free(ctx);

	return NULL;
}
