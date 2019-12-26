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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "database.h"
#include "macro.h"
#include "net.h"

int
main(void)
{
	MYSQL *mysql;
	int ret;
	int sec_fd, unsec_fd;
	struct packet_log_entry plog;
	fd_set fds;
	int max_fd;
	const SSL_METHOD *ssl_mtd;
	SSL_CTX *ssl_ctx;

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ssl_mtd = SSLv23_server_method();
	ssl_ctx = SSL_CTX_new(ssl_mtd);
	if (!ssl_ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return 1;
	}

	SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

	if (SSL_CTX_use_certificate_file(ssl_ctx, "ssl/cert_server.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "ssl/key_server.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	crc16_init();

	mysql = db_init("127.0.0.1", 3306, "user", "P@ssw0rd", "test_db");
	if (!mysql) {
		error("Can't connect to mysql");
		return 1;
	}

	plog.sid = 10;
	plog.type = 5;
	plog.direction = SERTOCLI;
	plog.data = (uint8_t*)"Hi";
	plog.len = strlen((char*)plog.data);

	sec_fd = net_bind_sock(SEC_PORT);
	unsec_fd = net_bind_sock(UNSEC_PORT);
	max_fd = (sec_fd > unsec_fd) ? sec_fd : unsec_fd;

	while (1) {
		int cfd;
		struct sockaddr_in cli_addr;
		socklen_t socklen = SOCKLEN;
		pthread_t thread;
		struct net_ctx *ctx;

		FD_ZERO(&fds);
		FD_SET(sec_fd, &fds);
		FD_SET(unsec_fd, &fds);

		ret = SYSCALL(0, select, max_fd + 1, &fds, NULL, NULL, NULL);
		if (ret == -1)
			continue;

		if (FD_ISSET(sec_fd, &fds)) {
			cfd = SYSCALL(0, accept, sec_fd, (struct sockaddr*)&cli_addr, &socklen);
			if (cfd == -1)
				continue;

			ctx = xmalloc(sizeof (struct net_ctx));
			ctx->fd = cfd;
			ctx->addr = cli_addr;
			ctx->type = SECURE;
			ctx->mysql = mysql;
			ctx->ssl = SSL_new(ssl_ctx);

			SSL_set_fd(ctx->ssl, cfd);
			if (SSL_accept(ctx->ssl) <= 0) {
				ERR_print_errors_fp(stderr);

				SSL_shutdown(ctx->ssl);
				SSL_free(ctx->ssl);
				SYSCALL(0, close, cfd);
				free(ctx);

				continue;
			}

			errno = pthread_create(&thread, NULL, net_thread, ctx);
			if (errno) {
				perror("pthread_create()");

				SSL_shutdown(ctx->ssl);
				SSL_free(ctx->ssl);
				SYSCALL(0, close, cfd);
				free(ctx);
			}
		}
		else if (FD_ISSET(unsec_fd, &fds)) {
			cfd = SYSCALL(0, accept, unsec_fd, (struct sockaddr*)&cli_addr, &socklen);
			if (cfd == -1)
				continue;

			ctx = xmalloc(sizeof (struct net_ctx));
			ctx->fd = cfd;
			ctx->addr = cli_addr;
			ctx->type = UNSECURE;
			ctx->mysql = mysql;

			pthread_create(&thread, NULL, net_thread, ctx);
		}
	}

	SYSCALL(0, close, sec_fd);
	SYSCALL(0, close, unsec_fd);
	mysql_close(mysql);
	SSL_CTX_free(ssl_ctx);
	EVP_cleanup();

	return 0;
}
