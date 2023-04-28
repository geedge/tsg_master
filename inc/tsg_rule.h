#pragma once

#include "tsg_label.h"

#define	TSG_ACTION_NONE			0x00
#define	TSG_ACTION_MONITOR		0x01
#define	TSG_ACTION_INTERCEPT	0x02
#define	TSG_ACTION_DENY			0x10
#define	TSG_ACTION_SHAPING		0x20
#define	TSG_ACTION_MANIPULATE	0x30
#define	TSG_ACTION_S_CHAINING	0x40
#define	TSG_ACTION_BYPASS		0x60
#define	TSG_ACTION_SHUNT		0x80
#define	TSG_ACTION_MAX			0x80

enum TSG_SERVICE
{
	TSG_SERVICE_SECURITY=2,
	TSG_SERVICE_INTERCEPT=3,
	TSG_SERVICE_CHAINING=5,
	TSG_SERVICE_SHAPING=6,
	TSG_SERVICE_PRE_SIGNATURE=7,
	TSG_SERVICE_SIGNATURE=8,
	TSG_SERVICE_MAX
};

enum TSG_METHOD_TYPE
{
	TSG_METHOD_TYPE_UNKNOWN=0,
	TSG_METHOD_TYPE_DROP,
	TSG_METHOD_TYPE_REDIRECTION,
	TSG_METHOD_TYPE_BLOCK,
	TSG_METHOD_TYPE_RESET,
	TSG_METHOD_TYPE_RST,
	TSG_METHOD_TYPE_ALERT,
	TSG_METHOD_TYPE_RATE_LIMIT,
	TSG_METHOD_TYPE_MIRRORED,
	TSG_METHOD_TYPE_TAMPER,
	TSG_METHOD_TYPE_DEFAULT,
	TSG_METHOD_TYPE_APP_DROP,
	TSG_METHOD_TYPE_ALLOW,
	TSG_METHOD_TYPE_SHUNT,
	TSG_METHOD_TYPE_MAX
};

enum ACTION_RETURN_TYPE
{
	ACTION_RETURN_TYPE_PROT=0,
	ACTION_RETURN_TYPE_APP,
	ACTION_RETURN_TYPE_TCPALL
};

extern struct maat *g_tsg_maat_feather;

struct maat_rule
{
	long long rule_id;
	unsigned char action;
	unsigned char service_id;
	unsigned char do_log;
	unsigned char padding;
	int vsys_id;
};

struct matched_policy_rules
{
	size_t n_rules;
	struct maat_rule rules[MAX_RESULT_NUM];
};

int session_packet_capture_by_rules_notify(const struct streaminfo * a_stream, struct maat_rule * rules, size_t n_rules, int thread_seq);
void session_matched_rules_notify(const struct streaminfo *a_stream, TSG_SERVICE service, struct maat_rule *rules, size_t n_rules, int thread_seq);
size_t tsg_matched_rules_select(struct maat *feather, TSG_SERVICE service, long long *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules);
size_t tsg_scan_nesting_addr(const struct streaminfo *a_stream, struct maat *feather, enum TSG_PROTOCOL proto, struct maat_state *s_mid, struct maat_rule *rules, size_t n_rules);
size_t session_matched_rules_copy(const struct streaminfo *a_stream, enum TSG_SERVICE service, struct maat_rule *rules, size_t n_rules);

int tsg_get_fqdn_category_ids(struct maat *feather, char *fqdn, unsigned int *category_ids, int n_category_ids);

unsigned char tsg_enforing_deny(const struct streaminfo *a_stream, struct maat_rule *p_result, enum TSG_PROTOCOL protocol, enum ACTION_RETURN_TYPE type, const void *user_data);

