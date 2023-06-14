#pragma once

#include "uthash.h"
#include "tsg_bridge.h"

#include <MESA/stream.h>
#include <ctemplate/template.h>

enum DEPLOY_MODE
{
	DEPLOY_MODE_MIRROR,
	DEPLOY_MODE_INLINE,
	DEPLOY_MODE_TRANSPARENT,
	DEPLOY_MODE_MAX
};

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef	MAX_MATCHED_RULES_NUM
#define	MAX_MATCHED_RULES_NUM	MAX_RESULT_NUM*4
#endif

#ifndef	MAX_STRING_LEN32
#define	MAX_STRING_LEN32	32
#endif

struct reset_argv
{
	int pkt_num;
	int seed1;
	int seed2;
	int th_flags;
	int dir;
	int remedy;
};

#ifndef	MAX_STRING_LEN128
#define	MAX_STRING_LEN128	128
#endif

struct id2field
{
	int type;
	int id;
	char name[MAX_STRING_LEN32];
};

struct id2field_tlv
{
	int type;
	int id;
	int len;
	char name[MAX_STRING_LEN32];
};

struct tsg_rt_para
{
	int level;
	short mirror_switch;
	unsigned short timeout;
	int dynamic_maat_switch;
	int device_seq_in_dc;
	int datacenter_id;
	int scan_signaling_switch;
	int hash_timeout;
	int hash_slot_size;
	int hash_thread_safe;
	int feature_tamper;
	int service_chaining_sid;
	int shaping_sid;
	int intercept_sid;
	int send_resetall;
	int app_metric_update_interval_ms;
	enum DEPLOY_MODE deploy_mode;
	int scan_time_interval;
	int identify_app_max_pkt_num;
	int unknown_app_id;
	int proto_flag; //enum TSG_PROTOCOL
	char device_sn[MAX_STRING_LEN128];
	char log_path[MAX_STRING_LEN128];
	char device_id_command[MAX_STRING_LEN128];
	void *logger;
	struct reset_argv reset;
	struct l7_protocol *name_by_id;
	struct l7_protocol *id_by_name;
	struct traffic_mirror *mirror_handle;
	ctemplate::Template *tpl_403,*tpl_404;
	ctemplate::Template *tpl_200,*tpl_204;
	ctemplate::Template *tpl_303;
};

extern struct tsg_rt_para g_tsg_para;;
extern struct id2field_tlv g_tsg_proto_name2id[PROTO_MAX];

struct l7_protocol 
{
	int id;				/* first key */
	char name[32];		/* second key */
	UT_hash_handle hh1;	/* handle for first hash table */
	UT_hash_handle hh2;	/* handle for second hash table */
};

long long tsg_get_current_time_ms(void);

