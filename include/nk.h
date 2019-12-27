#ifndef _NK_H
#define _NK_H

#include <stdint.h>

#include "macro.h"

struct nk_ans {
	enum status stat;
	char *qr_code;
	char *fn_num;
	char *num_fp;
	char *num_fd;
};

struct nk_check {
	char *amount;
};

struct nk_ans *nk_send_check(struct nk_check *check);
void nk_free_ans(struct nk_ans *ans);

#endif // _NK_H
