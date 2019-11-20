#ifndef	__TSG_ENTRY_H__
#define	__TSG_ENTRY_H__

#include <MESA/Maat_rule.h>
#include <MESA/field_stat2.h>
#include "tsg_rule.h"

#define	TSG_ACTION_NONE			0x00
#define	TSG_ACTION_MONITOR		0x01
#define	TSG_ACTION_INTERCEPT	0x02
#define	TSG_ACTION_DENY			0x10
#define	TSG_ACTION_MANIPULATE	0x30
#define	TSG_ACTION_BYPASS		0x80

enum TSG_FS2_TYPE{
	TSG_FS2_LINKS=0,
	TSG_FS2_BYPASS,
	TSG_FS2_HIT_ADDR,
	TSG_FS2_HIT_SHARE,
	TSG_FS2_INTERCEPT,
	TSG_FS2_LOG,
	TSG_FS2_MAX
};

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
	int device_id;
	int ip_addr_table_id;
	int subscribe_id_table_id;
	int priority_project_id;
	int fs2_field_id[TSG_FS2_MAX];
	void *logger;
	screen_stat_handle_t fs2_handle;
}g_tsg_para_t;

extern g_tsg_para_t g_tsg_para;


#endif