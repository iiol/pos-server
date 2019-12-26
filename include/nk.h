#ifndef _NK_H
#define _NK_H

#include <stdint.h>

#include "macro.h"

struct nk_ans {
	enum status stat;
	uint8_t *qr_code;
	int qr_code_len;
};

struct nk_check {
	char *amount;
};

struct nk_ans *nk_send_check(struct nk_check *check);
void nk_free_ans(struct nk_ans *ans);

#endif // _NK_H
