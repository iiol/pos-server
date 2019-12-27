#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <alloca.h>

#include <json-c/json.h>
#include <curl/curl.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "macro.h"
#include "nk.h"

#define NK_URL "https://nanokassa.ru"
#define FP_NK_URL "https://fp.nanokassa.com/getfp"

#define KEY_FILE1 "ssl/nk_key1.pem"
#define KEY_FILE2 "ssl/nk_key2.pem"

#define PRIZNAK_PREDMETA_RASCHETA 1
#define PRIZNAK_AGENTA "none"
#define REZHIM_NALOG 1
#define CLIENT_EMAIL "support@nanokassa.ru"
#define CLIENT_PHONE "12345678910"
#define KASSAID "123456"
#define KASSATOKEN "12345678912345678912345678912345"
#define CMS "ss7-7.3.0.209"

#define json_foreach(obj, key, val)						\
	for(struct lh_entry *entry ## key = json_object_get_object(obj)->head,	\
		   *entry_next ## key = NULL;					\
		({ if(entry ## key) {						\
			key = (char*)entry ## key->k;				\
			val = (struct json_object*)entry ## key->v;		\
			entry_next ## key = entry ## key->next;			\
		} ; entry ## key; });						\
		entry ## key = entry_next ## key )


enum enc_types {
	ENC_FIRST,
	ENC_SECOND,
};

struct string {
	char *str;
	size_t len;
};

static size_t
cb_curl_write(char *ptr, size_t size, size_t nmemb, void *data)
{
	struct string *str = data;
	size_t new_len = str->len + size * nmemb;

	str->str = xrealloc(str->str, new_len + 1);
	memcpy(str->str + str->len, ptr, size * nmemb);

	str->str[new_len] = '\0';
	str->len = new_len;

	return size * nmemb;
}

static struct nk_ans*
nk_send(const char *msg)
{
	CURL *curl;
	CURLcode ret;
	struct curl_slist *header = NULL;
	struct string str = {0};
	json_object *jobj;
	char *nuid = NULL, *qnuid = NULL;
	enum status stat;
	char *key;
	struct json_object *val;
	char *url;
	struct nk_ans *ans;

	assert(msg && "Argument is NULL");

	curl_slist_append(header, "Content-type: application/json");

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, NK_URL);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER , 0);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, msg);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curl_write);

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		debug("Can't connect to nanokassa");
		curl_slist_free_all(header);
		curl_easy_cleanup(curl);
		return NULL;
	}

	jobj = json_tokener_parse(str.str);
	free(str.str);
	str.str = NULL;
	if (!jobj) {
		debug("Can't parse nanokassa answer");
		curl_slist_free_all(header);
		curl_easy_cleanup(curl);
		return NULL;
	}

	stat = FAIL;

	json_foreach(jobj, key, val) {
		switch ((int)json_object_get_type(val)) {
		case json_type_string:
		    {
			const char *s = json_object_to_json_string(val);

			if (!strcmp(key, "status")) {
				if (!strcmp(s, "success"))
					stat = SUCCESS;
				else
					stat = FAIL;
			}
			else if (!strcmp(key, "nuid")) {
				nuid = xmalloc(strlen(s) + 1);
				strcpy(nuid, s);
			}
			else if (!strcmp(key, "qnuid")) {
				qnuid = xmalloc(strlen(s) + 1);
				strcpy(qnuid, s);
			}

			break;
		    }
		}
	}

	curl_slist_free_all(header);
	curl_easy_cleanup(curl);
	json_object_put(jobj);
	str.len = 0;

	if (stat == FAIL) {
		ans = xmalloc(sizeof (struct nk_ans));
		ans->stat = FAIL;
		free(qnuid);
		free(nuid);

		return ans;
	}

	url = alloca(sizeof (FP_NK_URL) + strlen(nuid) + strlen(nuid) + 32);

	strcpy(url, FP_NK_URL);
	sprintf(url + strlen(FP_NK_URL), "?nuid=%s&qnuid=%s&auth=base", nuid, qnuid);

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb_curl_write);

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		debug("Can't connect to nanokassa");
		curl_easy_cleanup(curl);
		return NULL;
	}

	jobj = json_tokener_parse(str.str);
	free(str.str);
	if (!jobj) {
		debug("Can't parse nanokassa answer");
		curl_easy_cleanup(curl);
		return NULL;
	}

	ans = xmalloc(sizeof (struct nk_ans));
	ans->stat = SUCCESS;

	json_foreach(jobj, key, val) {
		switch ((int)json_object_get_type(val)) {
		case json_type_string:
		    {
			const char *s = json_object_to_json_string(val);

			if (!strcmp(key, "check_qr_code")) {
				ans->qr_code = xmalloc(strlen(s) + 1);
				strcpy(ans->qr_code, s);
			}
			else if (!strcmp(key, "check_fn_num")) {
				ans->fn_num = xmalloc(strlen(s) + 1);
				strcpy(ans->fn_num, s);
			}

			break;
		    }

		case json_type_int:
		    {
			const char *num = json_object_to_json_string(val);

			if (!strcmp(key, "check_num_fd")) {
				ans->num_fd = xmalloc(strlen(num) + 1);
				strcpy(ans->fn_num, num);
			}
			else if (!strcmp(key, "check_num_fp")) {
				ans->num_fp = xmalloc(strlen(num) + 1);
				strcpy(ans->fn_num, num);
			}

			break;
		    }
		}
	}

	return ans;
}

static json_object*
json_encrypt(json_object *iobj, enum enc_types type, char *key_file)
{
	int i;
	json_object *oobj;
	int ret;
	uint8_t aes_key[32];
	uint8_t aes_iv[16];
	EVP_CIPHER_CTX *ctx;
	uint8_t *buf;
	char *de, *ab, *plaintext;
	int len, ciphertext_len, plaintext_len;
	uint8_t hash[64];
	RSA *rsa;
	FILE *fp;
	static int init = 0;
	char *key;
	struct json_object *val;

	assert(iobj && "Argument is NULL");
	assert(key_file && "Argument is NULL");

	if (init == 0) {
		srand(time(NULL));
		init = 1;
	}

	for (i = 0; i < 32; ++i) {
		aes_key[i] = rand();
		if (i < 16)
			aes_iv[i] = rand();
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv);
	if (!ret) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	// get field 'de'
	plaintext = (char*)json_object_to_json_string(iobj);
	plaintext_len = strlen(plaintext);
	buf = alloca(64 + 16 + plaintext_len); // 64 bytes for hash; 16 bytes for iv
	de = alloca(4*((64 + 16 + plaintext_len)/3) + 1);

	ret = EVP_EncryptUpdate(ctx, buf + 80, &len, (uint8_t*)plaintext, plaintext_len);
	if (!ret) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	ciphertext_len = len;

	ret = EVP_EncryptFinal_ex(ctx, buf + 80 + len, &len);
	if (!ret) {
		ERR_print_errors_fp(stderr);
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	ciphertext_len += len;

	memcpy(buf + 64, aes_iv, 16);
	SHA512(buf + 64, ciphertext_len + 16, hash);
	memcpy(buf, hash, 64);

	EVP_EncodeBlock((uint8_t*)de, buf, ciphertext_len + 80);
	EVP_CIPHER_CTX_free(ctx);


	// calculate field 'ab'
	fp = fopen(key_file, "r");
	if (fp == NULL) {
		warning("Can't open key_file: %s", key_file);
		return NULL;
	}

	rsa = RSA_new();
	PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
	ret = RSA_public_encrypt(32, aes_key, buf, rsa, RSA_PKCS1_OAEP_PADDING);
	ab = alloca(4*(ret/3) + 1);
	EVP_EncodeBlock((uint8_t*)ab, buf, ret);

	RSA_free(rsa);
	fclose(fp);


	oobj = json_object_new_object();

	json_foreach(iobj, key, val) {
		switch ((int)json_object_get_type(val)) {
		case json_type_string:
			switch (type) {
			case ENC_FIRST:
				if (!strcmp("kassaid", key) ||
				    !strcmp("kassatoken", key))
					json_object_object_add(oobj, key, val);

				break;

			case ENC_SECOND:
				if (!strcmp("test", key))
					json_object_object_add(oobj, key, val);

				break;
			}

			break;
		}
	}

	switch (type) {
	case ENC_FIRST:
		json_object_object_add(oobj, "check_type", json_object_new_string("standart"));
		json_object_object_add(oobj, "test", json_object_new_string("1"));

		json_object_object_add(oobj, "ab", json_object_new_string(ab));
		json_object_object_add(oobj, "de", json_object_new_string(de));

		break;

	case ENC_SECOND:
		json_object_object_add(oobj, "aab", json_object_new_string(ab));
		json_object_object_add(oobj, "dde", json_object_new_string(de));

		break;
	}

	return oobj;
}

struct nk_ans*
nk_send_check(struct nk_check *check)
{
	json_object *jobj;
	json_object *products_arr;
	json_object *product;
	json_object *payment;
	json_object *total;
	json_object *fobj, *sobj;
	size_t prise;
	json_object *json_prise;
	struct nk_ans *ans;

	assert(check && "Argument is NULL");

	prise = atoll(check->amount);
	json_prise = json_object_new_int(prise);

	jobj = json_object_new_object();
	payment = json_object_new_object();
	products_arr = json_object_new_array();
	product = json_object_new_object();
	total = json_object_new_object();

	json_object_object_add(product, "name_tovar", json_object_new_string("Товар"));
	json_object_object_add(product, "price_piece", json_prise);
	json_object_object_add(product, "kolvo", json_object_new_int(1));
	json_object_object_add(product, "summa", json_prise);
	json_object_object_add(product, "stavka_nds", json_object_new_int(1));
	json_object_object_add(product, "priznak_sposoba_rascheta", json_object_new_int(4));
	json_object_object_add(product, "priznak_predmeta_rascheta", json_object_new_int(PRIZNAK_PREDMETA_RASCHETA));
	json_object_object_add(product, "priznak_agenta", json_object_new_string(PRIZNAK_AGENTA));
	json_object_array_add(products_arr, product);

	json_object_object_add(payment, "rezhim_nalog", json_object_new_int(REZHIM_NALOG));
	json_object_object_add(payment, "money_nal", json_object_new_int(0));
	json_object_object_add(payment, "money_electro", json_prise);
	json_object_object_add(payment, "money_predoplata", json_object_new_int(0));
	json_object_object_add(payment, "money_postoplata", json_object_new_int(0));
	json_object_object_add(payment, "money_vstrecha", json_object_new_int(0));
	json_object_object_add(payment, "kassir_inn", json_object_new_string(""));
	json_object_object_add(payment, "kassir_fio", json_object_new_string(""));
	json_object_object_add(payment, "client_email", json_object_new_string(CLIENT_EMAIL));
	json_object_object_add(payment, "client_phone", json_object_new_string(CLIENT_PHONE));

	json_object_object_add(total, "priznak_rascheta", json_object_new_int(1));
	json_object_object_add(total, "itog_cheka", json_prise);

	json_object_object_add(jobj, "kassaid", json_object_new_string(KASSAID));
	json_object_object_add(jobj, "kassatoken", json_object_new_string(KASSATOKEN));
	json_object_object_add(jobj, "cms", json_object_new_string(CMS));
	json_object_object_add(jobj, "check_send_type", json_object_new_string("email"));
	json_object_object_add(jobj, "products_arr", products_arr);
	json_object_object_add(jobj, "oplata_arr", payment);
	json_object_object_add(jobj, "itog_arr", total);

	fobj = json_encrypt(jobj, ENC_FIRST, KEY_FILE1);
	if (!fobj) {
		json_object_put(jobj);
		return NULL;
	}

	sobj = json_encrypt(fobj, ENC_SECOND, KEY_FILE2);
	if (!sobj) {
		json_object_put(jobj);
		json_object_put(fobj);
		return NULL;
	}

	ans = nk_send(json_object_to_json_string(sobj));

	json_object_put(jobj);
	json_object_put(fobj);
	json_object_put(sobj);

	return ans;
}

void
nk_free_ans(struct nk_ans *ans)
{
	if (ans == NULL)
		return;

	free(ans->qr_code);
	free(ans->fn_num);
	free(ans->num_fd);
	free(ans->num_fp);
	free(ans);
}
