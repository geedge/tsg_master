#pragma once

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

enum MASTER_STATIC_TABLE
{
	TABLE_SECURITY_COMPILE=0,
	TABLE_IP_ADDR,
	TABLE_SUBSCRIBER_ID,
	TABLE_APP_ID,
	TABLE_HTTP_HOST,
	TABLE_SSL_SNI,
	TABLE_EXCLUSION_SSL_SNI,
	TABLE_SRC_ASN,
	TABLE_DST_ASN,
	TABLE_SRC_LOCATION,
	TABLE_DST_LOCATION,
	TABLE_ASN_USER_DEFINED,
	TABLE_ASN_BUILT_IN,
	TABLE_LOCATION_USER_DEFINED,
	TABLE_LOCATION_BUILT_IN,
	TABLE_QUIC_SNI,
	TABLE_FQDN_CAT_ID,
	TABLE_FQDN_CAT_USER_DEFINED,
	TABLE_FQDN_CAT_BUILT_IN,
	TABLE_APP_ID_DICT,
	TABLE_SELECTOR_ID,
	TABLE_SELECTOR_PROPERTIES,
	TABLE_GTP_APN,
	TABLE_GTP_IMSI,
	TABLE_GTP_PHONE_NUMBER,
	TABLE_RESPONSE_PAGES,
	TABLE_DNS_PROFILE_RECORD,
	TABLE_PROFILE_MIRROR,
	TABLE_HTTP_URL,
	TABLE_DTLS_SNI,
	TABLE_TUNNEL_ID,
	TABLE_TUNNEL_CATALOG,
	TABLE_TUNNEL_ENDPOINT,
	TABLE_TUNNEL_LABEL,
	TABLE_SESSION_FLAGS,
	TABLE_SESSION_LOG,
	TABLE_MAX
};

enum MASTER_DYNAMIC_TABLE
{
	DYN_TABLE_SUBSCRIBER_IP=0,
	DYN_TABLE_GTP_SIGNALING,
	DYN_TABLE_MAX
};

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

#ifndef	MAX_TSG_ALL_RESULT_NUM
#define	MAX_TSG_ALL_RESULT_NUM	MAX_RESULT_NUM*2
#endif

#ifndef	MAX_STRING_LEN32
#define	MAX_STRING_LEN32	32
#endif

struct id2field
{
	int type;
	int id;
	char name[MAX_STRING_LEN32];
};

struct reset_argv
{
	int pkt_num;
	int seed1;
	int seed2;
	int th_flags;
	int dir;
	int remedy;
};

#ifndef	MAX_TABLE_NAME_LEN
#define	MAX_TABLE_NAME_LEN	64
#endif

#ifndef	MAX_STRING_LEN128
#define	MAX_STRING_LEN128	128
#endif

typedef	struct tsg_para
{
	int level;
	short mirror_switch;
	unsigned short timeout;
	int dynamic_maat_switch;
	int location_field_num;
	int app_dict_field_num;
	int device_seq_in_dc;
	int datacenter_id;
	int scan_signaling_switch;
	int hash_timeout;
	int hash_slot_size;
	int hash_thread_safe;
	int feature_tamper;
	enum DEPLOY_MODE deploy_mode;
	int scan_time_interval;
	int identify_app_max_pkt_num;
	int unknown_app_id;
	int hit_path_switch;
	int session_record_switch;
	int default_compile_id;
	int table_id[TABLE_MAX];
	int dyn_table_id[DYN_TABLE_MAX];
	int session_attribute_project_id;
	int proto_flag; //tsg_protocol_t
	int fs2_field_id[TSG_FS2_MAX];
	char device_sn[MAX_STRING_LEN128];
	char log_path[MAX_STRING_LEN128];
	char device_id_command[MAX_STRING_LEN128];
	char data_center[MAX_STRING_LEN128];
	char device_tag[MAX_STRING_LEN128];
	char table_name[TABLE_MAX][MAX_TABLE_NAME_LEN];	
	char dyn_table_name[DYN_TABLE_MAX][MAX_TABLE_NAME_LEN];
	struct bridge_info bridge[BRIDGE_TYPE_MAX];
	void *logger;
	void *maat_logger;
	struct reset_argv reset;
	struct mirrored_vlan default_vlan;
	screen_stat_handle_t fs2_handle;
	struct l7_protocol *name_by_id;
	struct l7_protocol *id_by_name;
	struct traffic_mirror *mirror_handle;
	ctemplate::Template *tpl_403,*tpl_404;
	ctemplate::Template *tpl_200,*tpl_204;
	ctemplate::Template *tpl_303;
}g_tsg_para_t;

extern g_tsg_para_t g_tsg_para;
extern Maat_feather_t g_tsg_dynamic_maat_feather;
extern struct id2field g_tsg_proto_name2id[PROTO_MAX];

