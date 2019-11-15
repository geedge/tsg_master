#ifndef	__TSG_ENTRY_H__
#define	__TSG_ENTRY_H__

#include <MESA/Maat_rule.h>
#include "tsg_types.h"

#define	FW_ACTION_UNKNOWN	0x00
#define	FW_ACTION_DROP		0x01
#define	FW_ACTION_RESET		0x02
#define	FW_ACTION_BLOCK		0x04

#define	TSG_ACTION_NONE			0x00
#define	TSG_ACTION_MONITOR		0x01
#define	TSG_ACTION_INTERCEPT	0x02
#define	TSG_ACTION_DENY			0x10
#define	TSG_ACTION_MANIPULATE	0x30
#define	TSG_ACTION_BYPASS		0x80


#define	MAX_RESULT_NUM	8
#define	MAX_DOAMIN_LEN	2048

typedef	struct _policy_priority_label
{
	tsg_protocol_t proto;	//enum _tsg_protocol (tsg_types.h)
	int domain_len;
	int result_type;	//enum _PULL_RESULT_TYPE (tsg_rule.h)
	int result_num;
	char domain[MAX_DOAMIN_LEN];
	Maat_rule_t result[MAX_RESULT_NUM];
}policy_priority_label_t;


typedef	struct _tsg_para
{
	int ip_addr_table_id;
	int subscribe_id_table_id;
	int priority_project_id;
	void *logger;
}g_tsg_para_t;



extern g_tsg_para_t g_tsg_para;

#endif