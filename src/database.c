#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database.h"
#include "macro.h"

char*
null_terminating(char *str, unsigned int len)
{
	char *ret;

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
	unsigned long version;

	mysql = mysql_init(NULL);
	if (!mysql) {
		fprintf(stderr, "Can't init mysql\n");
		return NULL;
	}

	if (!mysql_real_connect(mysql, host, user, passwd, db, port, NULL, 0)) {
		fprintf(stderr, "Connect to '%s' %s@%s:%d failed: %s \n",
		    db, user, host, port, mysql_error(mysql));
		return NULL;
	}

	version = mysql_get_server_version(mysql);
	printf("MySql server version: %ld.%ld.%ld\n",
	    version/10000, (version/100)%100, version%100);

	return mysql;
}

int
db_log_packet(MYSQL *mysql, struct packet_log_entry *plog)
{
	size_t size;
	char query[512 + 2*plog->len];
	char time[64];
	struct tm tm;

	localtime_r(&plog->time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "INSERT INTO PacketLog ");
	size += sprintf(query + size, "(SessionID, Type, Time, Direction, Data) ");
	size += sprintf(query + size, "VALUES(%ld, %d, '%s', %d, '",
	    plog->sid, plog->type, time, plog->direction);
	size += mysql_real_escape_string(mysql, query + size, (char*)plog->data, plog->len);
	size += sprintf(query + size, "')");

	if (mysql_real_query(mysql, query, size)) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return 1;
	}

	return 0;
}

int
db_log(MYSQL *mysql, struct log_entry *log)
{
	size_t size;
	char query[512 + 2*strlen(log->text)];

	size  = sprintf(query, "INSERT INTO Log ");
	size += sprintf(query + size, "(SessionID, Time, LogPart, LogType, LogCode, Text) ");
	size += sprintf(query + size, "VALUES(%ld, NULL, %d, %d, %d, '",
	    log->sid, log->log_part, log->log_type, log->log_code);
	size += mysql_real_escape_string(mysql, query + size, log->text, strlen(log->text));
	size += sprintf(query + size, "')");

	if (mysql_real_query(mysql, query, size)) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
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

	localtime_r(&session->start_time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "INSERT INTO Sessions ");
	size += sprintf(query + size, "(ID, IP, TerminalMac, TimeStart) ");
	size += sprintf(query + size, "VALUES(0, %d, %ld, '%s')",
	    session->ip, session->mac, time);

	if (mysql_real_query(mysql, query, size)) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return 1;
	}

	size = sprintf(query, "SELECT ID, TerminalMac FROM Sessions");
	if (mysql_real_query(mysql, query, size)) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return 1;
	}

	result = mysql_use_result(mysql);
	if (!result) {
		fprintf(stderr, "mysql_use_result() error: %s\n", mysql_error(mysql));
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

	localtime_r(&session->end_time, &tm);
	strftime(time, 64, "%F %T", &tm);

	size = sprintf(query, "UPDATE Sessions SET TimeEnd = '%s' WHERE ID = %ld",
	    time, session->sid);

	if (mysql_real_query(mysql, query, size)) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return 1;
	}

	return 0;
}

int
db_print_table(MYSQL *mysql, const char *tbl)
{
	int i;
	int ret;
	unsigned int num_fields;
	MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL_FIELD *field;
	char query[2048] = "SELECT * FROM ";

	strncat(query, tbl, 2048);
	ret = mysql_real_query(mysql, query, strlen(query));
	if (ret) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return 1;
	}

	result = mysql_use_result(mysql);
	if (!result) {
		fprintf(stderr, "mysql_use_result() error: %s\n", mysql_error(mysql));
		return 1;
	}

	while ((field = mysql_fetch_field(result)) != NULL)
		printf("%s ", field->name);
	putchar('\n');

	num_fields = mysql_num_fields(result);
	while ((row = mysql_fetch_row(result)) != NULL) {
		unsigned long *lengths;

		lengths = mysql_fetch_lengths(result);
		for(i = 0; i < num_fields; i++)
			printf("[%.*s] ", (int)lengths[i], row[i] ? row[i] : "NULL");
		putchar('\n');
	}

	mysql_free_result(result);

	return 0;
}

struct terminals_entry*
db_search_by_mac(MYSQL *mysql, uint64_t mac)
{
	int i;
	int ret;
	char query[] = "SELECT * FROM Terminals";
	MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL_FIELD *field;
	unsigned long *lengths;
	int f[FLD_COUNT];
	struct terminals_entry *entry;
	char *s;

	ret = mysql_real_query(mysql, query, strlen(query));
	if (ret) {
		fprintf(stderr, "mysql_real_query() error: %s\n", mysql_error(mysql));
		return NULL;
	}

	result = mysql_store_result(mysql);
	if (!result) {
		fprintf(stderr, "mysql_store_result() error: %s\n", mysql_error(mysql));
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
	free(entry->ssl_cert);
	free(entry->ssl_key);
	free(entry->terminal_id);
	free(entry->merchant_id);
	free(entry->last_online);
	free(entry);
}
