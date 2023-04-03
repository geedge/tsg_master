#pragma once

#include "uthash.h"
#include "tsg_bridge.h"

#include <MESA/stream.h>
#include <MESA/field_stat2.h>
#include <ctemplate/template.h>

enum TSG_FS2_TYPE
{
	TSG_FS2_TCP_LINKS=0,
	TSG_FS2_UDP_LINKS,
	TSG_FS2_BYPASS,
	TSG_FS2_HIT_ADDR,
	TSG_FS2_HIT_SHARE,
	TSG_FS2_INTERCEPT,
	TSG_FS2_SHAPING,
	TSG_FS2_S_CHAINING,
	TSG_FS2_CTRL_OPENING,
	TSG_FS2_CTRL_CLOSING,
	TSG_FS2_CTRL_ACTIVE,
	TSG_FS2_CTRL_RESETALL,
	TSG_FS2_EXCLUSION,
	TSG_FS2_APP_DPKT_RESULT,
	TSG_FS2_APP_Q_RESULT,
	TSG_FS2_APP_USER_RESULT,
	TSG_FS2_APP_BUILT_IN_RESULT,
	TSG_FS2_INJECT_PKT_SUCCESS,
	TSG_FS2_INJECT_PKT_FAILED,
	TSG_FS2_MIRRORED_PKT_SUCCESS,	
	TSG_FS2_MIRRORED_BYTE_SUCCESS,
	TSG_FS2_MIRRORED_PKT_FAILED,
	TSG_FS2_MIRRORED_BYTE_FAILED,
	TSG_FS2_SET_TIMOUT_SUCCESS,
	TSG_FS2_SET_TIMOUT_FAILED,
    TSG_FS2_SUCESS_TAMPER,
    TSG_FS2_TAMPER_FAILED_PLOAD_LESS_4,
    TSG_FS2_TAMPER_FAILED_NOSWAP,
	TSG_FS2_ASN_ADD,
	TSG_FS2_ASN_DEL,
	TSG_FS2_GTPC_ADD,
	TSG_FS2_GTPC_DEL,
	TSG_FS2_LOCATION_ADD,
	TSG_FS2_LOCATION_DEL,
	TSG_FS2_FQDN_ADD,
	TSG_FS2_FQDN_DEL,
	TSG_FS2_SUBSCRIBER_ADD,
	TSG_FS2_SUBSCRIBER_DEL,
	TSG_FS2_SECURIRY_ADD,
	TSG_FS2_SECURIRY_DEL,
	TSG_FS2_MIRRORED_ADD,
	TSG_FS2_MIRRORED_DEL,
	TSG_FS2_HTTP_RES_ADD,
	TSG_FS2_HTTP_RES_DEL,
	TSG_FS2_DNS_RES_ADD,
	TSG_FS2_DNS_RES_DEL,
	TSG_FS2_APP_ID_ADD,
	TSG_FS2_APP_ID_DEL,
	TSG_FS2_TUNNEL_CATALOG_ADD,
	TSG_FS2_TUNNEL_CATALOG_DEL,
	TSG_FS2_TUNNEL_ENDPOINT_ADD,
	TSG_FS2_TUNNEL_ENDPOINT_DEL,
	TSG_FS2_TUNNEL_LABEL_ADD,
	TSG_FS2_TUNNEL_LABEL_DEL,
	TSG_FS2_MAX
};


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

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

#ifndef	MAX_TSG_ALL_RESULT_NUM
#define	MAX_TSG_ALL_RESULT_NUM	MAX_RESULT_NUM*3
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
	int send_resetall;
	enum DEPLOY_MODE deploy_mode;
	int scan_time_interval;
	int identify_app_max_pkt_num;
	int unknown_app_id;
	int proto_flag; //enum TSG_PROTOCOL
	int fs2_field_id[TSG_FS2_MAX];
	char device_sn[MAX_STRING_LEN128];
	char log_path[MAX_STRING_LEN128];
	char device_id_command[MAX_STRING_LEN128];
	void *logger;
	struct reset_argv reset;
	screen_stat_handle_t fs2_handle;
	struct l7_protocol *name_by_id;
	struct l7_protocol *id_by_name;
	struct traffic_mirror *mirror_handle;
	ctemplate::Template *tpl_403,*tpl_404;
	ctemplate::Template *tpl_200,*tpl_204;
	ctemplate::Template *tpl_303;
};

extern struct tsg_rt_para g_tsg_para;;
extern struct id2field g_tsg_proto_name2id[PROTO_MAX];

struct l7_protocol 
{
	int id;				/* first key */
	char name[32];		/* second key */
	UT_hash_handle hh1;	/* handle for first hash table */
	UT_hash_handle hh2;	/* handle for second hash table */
};

long long tsg_get_current_time_ms(void);

