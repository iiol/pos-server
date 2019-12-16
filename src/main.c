#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "database.h"
#include "macro.h"
#include "net.h"

int
main(void)
{
	MYSQL *mysql;
	int sec_fd, unsec_fd;
	struct packet_log_entry plog;
	fd_set fds;
	int max_fd;

	crc16_init();

	mysql = db_init("127.0.0.1", 3306, "user", "P@ssw0rd", "test_db");
	if (!mysql)
		return 1;

	plog.sid = 10;
	plog.type = 5;
	plog.direction = SERTOCLI;
	plog.data = (uint8_t*)"Hi";
	plog.len = strlen((char*)plog.data);

	sec_fd = net_init(SEC_PORT);
	unsec_fd = net_init(UNSEC_PORT);
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

		SYSCALL(1, select, max_fd + 1, &fds, NULL, NULL, NULL);
		if (FD_ISSET(sec_fd, &fds)) {
			cfd = SYSCALL(1, accept, sec_fd, (struct sockaddr*)&cli_addr, &socklen);

			ctx = xmalloc(sizeof (struct net_ctx));
			ctx->fd = cfd;
			ctx->addr = cli_addr;
			ctx->type = SECURE;
			ctx->mysql = mysql;

			pthread_create(&thread, NULL, net_thread, ctx);
		}
		else if (FD_ISSET(unsec_fd, &fds)) {
			cfd = SYSCALL(1, accept, unsec_fd, (struct sockaddr*)&cli_addr, &socklen);

			ctx = xmalloc(sizeof (struct net_ctx));
			ctx->fd = cfd;
			ctx->addr = cli_addr;
			ctx->type = UNSECURE;
			ctx->mysql = mysql;

			pthread_create(&thread, NULL, net_thread, ctx);
		}
	}

	close(sec_fd);
	close(unsec_fd);
	mysql_close(mysql);

	return 0;
}
