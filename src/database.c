#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <alloca.h>

#include "database.h"
#include "macro.h"

char*
null_terminating(char *str, unsigned int len)
{
	char *ret;

	assert(str && "Argument is NULL");

	if (strnlen(str, len) == len) {
		ret = xmalloc(len + 1);
		memcpy(ret, str, len);
		ret[len] = '\0';
	}
	else {
		ret = xmalloc(len);
		memcpy(ret, str, len);
	}

	return ret;
}

MYSQL*
db_init(char *host, int port, char *user, char *passwd, char *db)
{
	MYSQL *mysql;
	unsigned long mysql_ver;

	assert(host   && "Argument is NULL");
	assert(user   && "Argument is NULL");
	assert(passwd && "Argument is NULL");
	assert(db     && "Argument is NULL");

	mysql = mysql_init(NULL);
	if (!mysql)
		return NULL;

	if (!mysql_real_connect(mysql, host, user, passwd, db, port, NULL, 0))
		return NULL;

	mysql_ver = mysql_get_server_version(mysql);
	debug("MySql server version: %ld.%ld.%ld",
	    mysql_ver/10000, (mysql_ver/100)%100, mysql_ver%100);

	return mysql;
}

int
db_log_packet(MYSQL *mysql, struct packet_log_entry *plog)
{
	size_t size;
	char *query;
	char time[64];
	struct tm tm;

	assert(mysql && "Argument is NULL");
	assert(plog  && "Argument is NULL");

	query = alloca(512 + 2*plog->len);

	localtime_r(&plog->time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "INSERT INTO PacketLog ");
	size += sprintf(query + size, "(SessionID, Type, Time, Direction, Data) ");
	size += sprintf(query + size, "VALUES(%ld, %d, '%s', %d, '",
	    plog->sid, plog->type, time, plog->direction);
	size += mysql_real_escape_string(mysql, query + size, (char*)plog->data, plog->len);
	size += sprintf(query + size, "')");

	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	return 0;
}

int
db_log(MYSQL *mysql, struct log_entry *log)
{
	size_t size;
	char *query;
	char time[64];
	struct tm tm;

	assert(mysql && "Argument is NULL");
	assert(log   && "Argument is NULL");

	query = alloca(512 + 2*strlen(log->text));

	localtime_r(&log->time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size  = sprintf(query, "INSERT INTO Log ");
	size += sprintf(query + size, "(SessionID, Time, LogPart, LogType, LogCode, Text) ");
	size += sprintf(query + size, "VALUES(%ld, '%s', %d, %d, %d, '",
	    log->sid, time, log->log_part, log->log_type, log->log_code);
	size += mysql_real_escape_string(mysql, query + size, log->text, log->text_len);
	size += sprintf(query + size, "')");

	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	return 0;
}

int
db_new_session(MYSQL *mysql, struct sessions_entry *session)
{
	size_t size;
	char query[512];
	char time[64];
	struct tm tm;
	MYSQL_RES *result;
	MYSQL_ROW row;

	assert(mysql   && "Argument is NULL");
	assert(session && "Argument is NULL");

	localtime_r(&session->start_time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "INSERT INTO Sessions ");
	size += sprintf(query + size, "(ID, IP, TerminalMac, TimeStart) ");
	size += sprintf(query + size, "VALUES(0, %d, %ld, '%s')",
	    session->ip, session->mac, time);

	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	size = sprintf(query, "SELECT ID, TerminalMac FROM Sessions");
	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	result = mysql_use_result(mysql);
	if (!result) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	while ((row = mysql_fetch_row(result)) != NULL) {
		unsigned long *lengths;
		uint64_t mac;
		char *text;

		lengths = mysql_fetch_lengths(result);
		text = null_terminating(row[1], lengths[1]);
		mac = atoll(text);
		free(text);

		if (mac == session->mac) {
			text = null_terminating(row[0], lengths[0]);
			session->sid = atoll(text);
			free(text);
		}

	}

	mysql_free_result(result);

	return 0;
}

int
db_end_session(MYSQL *mysql, struct sessions_entry *session)
{
	size_t size;
	char query[512];
	char time[64];
	struct tm tm;

	assert(mysql   && "Argument is NULL");
	assert(session && "Argument is NULL");

	localtime_r(&session->end_time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "UPDATE Sessions SET TimeEnd = '%s' WHERE ID = %ld",
	    time, session->sid);

	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	return 0;
}

int
db_new_transaction(MYSQL *mysql, struct transactions_entry *ta)
{
	size_t size;
	char *query;
	char time[64];
	struct tm tm;

	assert(mysql && "Argument is NULL");
	assert(ta && ta->rrn && ta->approval_num && ta->terminal_id &&
	    ta->cashbox_fn && ta->cashbox_fn && ta->cashbox_i && ta->cashbox_fd &&
	    "Argument is NULL");

	size = 512 + 2*(strlen(ta->rrn) + strlen(ta->approval_num) +
	    strlen(ta->terminal_id) + strlen(ta->cashbox_fn) +
	    strlen(ta->cashbox_i) + strlen(ta->cashbox_fd));
	query = alloca(size);

	localtime_r(&ta->time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "INSERT INTO Transactions ");
	size += sprintf(query + size, "(Summ, ResponseCode, TerminalMac, Time, "
	    "Result, RRN, ApprovalNumber, TerminalID, Kassa_fn, Kassa_i, Kassa_fd) "
	    "VALUES(%f, %d, %ld, '%s', %d, '",
	    ta->amount, ta->response_code, ta->terminal_mac, time, ta->result);
	size += mysql_real_escape_string(mysql, query + size, ta->rrn, strlen(ta->rrn));
	size += sprintf(query + size, "', '");
	size += mysql_real_escape_string(mysql, query + size, ta->approval_num, strlen(ta->approval_num));
	size += sprintf(query + size, "', '");
	size += mysql_real_escape_string(mysql, query + size, ta->terminal_id, strlen(ta->terminal_id));
	size += sprintf(query + size, "', '");
	size += mysql_real_escape_string(mysql, query + size, ta->cashbox_fn, strlen(ta->cashbox_fn));
	size += sprintf(query + size, "', '");
	size += mysql_real_escape_string(mysql, query + size, ta->cashbox_i, strlen(ta->cashbox_i));
	size += sprintf(query + size, "', '");
	size += mysql_real_escape_string(mysql, query + size, ta->cashbox_fd, strlen(ta->cashbox_fd));
	size += sprintf(query + size, "')");

	if (mysql_real_query(mysql, query, size)) {
		warning("%s", mysql_error(mysql));
		return 1;
	}

	return 0;
}

struct terminals_entry*
db_search_by_mac(MYSQL *mysql, uint64_t mac)
{
	int i;
	int ret;
	char *query = "SELECT * FROM Terminals";
	MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL_FIELD *field;
	unsigned long *lengths;
	int f[FLD_COUNT];
	struct terminals_entry *entry;
	char *s;

	assert(mysql && "Argument is NULL");

	ret = mysql_real_query(mysql, query, strlen(query));
	if (ret) {
		warning("%s", mysql_error(mysql));
		return NULL;
	}

	result = mysql_store_result(mysql);
	if (!result) {
		warning("%s", mysql_error(mysql));
		return NULL;
	}

	// Generate array 'f' where
	// index is field name (in enum fld_types) and
	// value is number of field in table
	for (i = 0; (field = mysql_fetch_field(result)) != NULL; ++i)
		FOREACH_FLD(field->name, f, i, GENERATE_CMP);

	while ((row = mysql_fetch_row(result)) != NULL) {
		char mac_str[32];

		sprintf(mac_str, "%ld", mac);

		lengths = mysql_fetch_lengths(result);
		if (!strncmp(row[f[TerminalMac]], mac_str, lengths[f[TerminalMac]]))
			break;
	}

	if (row == NULL) {
		mysql_free_result(result);
		return NULL;
	}

	entry = xmalloc(sizeof (struct terminals_entry));

	s = null_terminating(row[f[TerminalMac]], lengths[f[TerminalMac]]);
	entry->mac         = atoll(s);
	free(s);

	entry->ssl_cert    = null_terminating(row[f[SSLCert]], lengths[f[SSLCert]]);
	entry->ssl_key     = null_terminating(row[f[SSLKey]], lengths[f[SSLKey]]);
	entry->terminal_id = null_terminating(row[f[TerminalID]], lengths[f[TerminalID]]);
	entry->merchant_id = null_terminating(row[f[MerchantID]], lengths[f[MerchantID]]);

	s = null_terminating(row[f[Version]], lengths[f[Version]]);
	entry->version     = atoi(s);
	free(s);

	s = null_terminating(row[f[Ping]], lengths[f[Ping]]);
	entry->ping        = atoi(s);
	free(s);

	entry->last_online = null_terminating(row[f[LastOnlineTime]], lengths[f[LastOnlineTime]]);

	s = null_terminating(row[f[OwnerID]], lengths[f[OwnerID]]);
	entry->owner       = atoi(s);
	free(s);

	mysql_free_result(result);

	return entry;
}

void
db_free_terminals_entry(struct terminals_entry *entry)
{
	if (entry == NULL)
		return;

	free(entry->ssl_cert);
	free(entry->ssl_key);
	free(entry->terminal_id);
	free(entry->merchant_id);
	free(entry->last_online);
	free(entry);
}

struct bpc_entries*
db_get_bpc_hosts(MYSQL *mysql)
{
	int i;
	struct bpc_entries *bpc_head = NULL;
	int ret;
	char *query = "SELECT * FROM BpcHosts";
	MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL_FIELD *field;
	int f[FLD_COUNT];

	assert(mysql && "Argument is NULL");

	ret = mysql_real_query(mysql, query, strlen(query));
	if (ret) {
		warning("%s", mysql_error(mysql));
		return NULL;
	}

	result = mysql_use_result(mysql);
	if (!result) {
		warning("%s", mysql_error(mysql));
		return NULL;
	}

	// Generate array 'f' where
	// index is field name (in enum fld_types) and
	// value is number of field in table
	for (i = 0; (field = mysql_fetch_field(result)) != NULL; ++i)
		FOREACH_FLD(field->name, f, i, GENERATE_CMP);

	while ((row = mysql_fetch_row(result)) != NULL) {
		char *s;
		unsigned long *lengths;

		lengths = mysql_fetch_lengths(result);
		bpc_head = list_alloc_at_end(bpc_head);

		s = null_terminating(row[f[ID]], lengths[f[ID]]);
		bpc_head->id = atoll(s);
		free(s);

		s = null_terminating(row[f[IP]], lengths[f[IP]]);
		bpc_head->ip = atoll(s);
		free(s);

		s = null_terminating(row[f[Port]], lengths[f[Port]]);
		bpc_head->port = atoll(s);
		free(s);
	}

	return list_get_head(bpc_head);
}

void
db_free_bpc_entries(struct bpc_entries *entries)
{
	if (entries == NULL)
		return;

	for (; entries != NULL; entries = list_delete(entries))
		;
}
