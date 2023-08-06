#pragma once

enum STAT_STATUS
{
	STAT_STATUS_SUCCESS=0,
	STAT_STATUS_FAIL
};

//table: inject, mirror, set_timeout, tamper
enum FLOW_STAT
{
	FLOW_STAT_INJECT=0,
	FLOW_STAT_MIRROR_PKT,
	FLOW_STAT_MIRROR_BYTE,
	FLOW_STAT_SET_TIMEOUT,
	FLOW_STAT_TAMPER,
	FLOW_STAT_MAX
};

//table: LPI, DPKT, THRID, USER_DEFINE, BUILT_IN
enum SYNC_APP
{
	SYNC_APP_LPI=0,
	SYNC_APP_DPKT,
	SYNC_APP_THRID,
	SYNC_APP_USER_DEFINE,
	SYNC_APP_BUILT_IN,
	SYNC_APP_MAX
};

//table: add del
//asn, gtpc, location, fqdn_category, subscriber, compile, mirror, http_response, dns_response, app_id_dict, tunnel_catalog, tunnel_endpoint, tunnel_label
enum SYNC_EXDATA_ROW
{
	SYNC_EXDATA_ROW_ASN=0,
	SYNC_EXDATA_ROW_GTPC,
	SYNC_EXDATA_ROW_LOCATION,
	SYNC_EXDATA_ROW_FQDN_CATEGORY,
	SYNC_EXDATA_ROW_SUBSCRIBER,
	SYNC_EXDATA_ROW_COMPILE,
	SYNC_EXDATA_ROW_MIRRORED,
	SYNC_EXDATA_ROW_HTTP_RESPONSE,
	SYNC_EXDATA_ROW_DNS_RESPONSE,
	SYNC_EXDATA_ROW_APP_ID_DICT,
	SYNC_EXDATA_ROW_TUNNEL_CATALOG,
	SYNC_EXDATA_ROW_TUNNEL_ENDPOINT,
	SYNC_EXDATA_ROW_TUNNEL_LABEL,
	SYNC_EXDATA_ROW_STATISTICS_TEMPLATE,
	SYNC_EXDATA_ROW_STATISTICS_CHART,
	SYNC_EXDATA_ROW_MAX
};

//table: success, success/s, fail, fail/s, drop, drop/s
enum LOG_STATUS
{
	LOG_STATUS_SUCCESS=0,
	LOG_STATUS_SUCCESS_S,
	LOG_STATUS_FAIL,
	LOG_STATUS_FAIL_S,
	LOG_STATUS_DROP,
	LOG_STATUS_DROP_S,
	LOG_STATUS_MAX
};

//table: create, duplication, append, free_count, free_size, free_capacity

enum LOG_HANDLE
{
	LOG_HANDLE_CREATE_CNT=0,
	LOG_HANDLE_DUP_CNT,
	LOG_HANDLE_APPEND_CNT,
	LOG_HANDLE_FREE_CNT,
	LOG_HANDLE_FREE_SIZE,
	LOG_HANDLE_FREE_CAPACITY,
	LOG_HANDLE_MAX
};

//table: unknown, shunt, allow, deny, shaping, intercept, no_intercept, service_chaining, monitor

enum RULE_TYPE
{
	RULE_TYPE_UNKNOW=0,
	RULE_TYPE_SHUNT,
	RULE_TYPE_ALLOW,
	RULE_TYPE_DENY,
	RULE_TYPE_SHAPING,
	RULE_TYPE_INTERCEPT,
	RULE_TYPE_NO_INTERCEPT,
	RULE_TYPE_SERVICE_CHAINING,
	RULE_TYPE_MONITOR,
	RULE_TYPE_MAX
};

//table: unknown, rstall, opening, activing, log_update, closing
enum CTRL_SYNC
{
	CTRL_SYNC_UNKNOWN=0,
	CTRL_SYNC_RSTALL,
	CTRL_SYNC_OPENING,
	CTRL_SYNC_ACTIVING,
	CTRL_SYNC_LOG_UPDATE,
	CTRL_SYNC_CLOSING,
	CTRL_SYNC_MAX
};

//table: activing, updating
enum CTRL_SERVICE
{
	CTRL_SERVICE_UNKNOWN=0,
	CTRL_SERVICE_CHAINING,
	CTRL_SERVICE_SHAPING,
	CTRL_SERVICE_INTERCEPT,
	CTRL_SERVICE_MAX
};

int tsg_stat_create(const char *conffile);
int tsg_stat_init(void);
int tsg_stat_sendlog_row_init(const char *row_name);
void tsg_stat_start(void);
// return row index

void tsg_stat_abort_rule_update(enum RULE_TYPE column_idx, long long increase);
void tsg_stat_send_rule_update(enum RULE_TYPE column_idx, long long increase);
void tsg_stat_log_handle_update(enum LOG_HANDLE column_idx, long long increase);
void tsg_stat_sync_exdata_add_update(enum SYNC_EXDATA_ROW row_idx, long long increase);
void tsg_stat_sync_exdata_del_update(enum SYNC_EXDATA_ROW row_idx, long long increase);
void tsg_stat_sync_application_update(enum SYNC_APP column_idx, long long increase);
void tsg_stat_sendlog_update(int row_idx, enum LOG_STATUS column_idx, long long increase);
void tsg_stat_flow_update(enum STAT_STATUS status, enum FLOW_STAT column_idx, long long increase);
void tsg_stat_sync_ctrl_update(enum STAT_STATUS status, enum CTRL_SYNC column_idx, long long increase);
void tsg_stat_ctrl_service_activing_update(enum STAT_STATUS status, enum CTRL_SERVICE column_idx, long long increase);
void tsg_stat_ctrl_service_updating_update(enum STAT_STATUS status, enum CTRL_SERVICE column_idx, long long increase);

