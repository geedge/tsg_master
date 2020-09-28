#ifndef	__TSG_ENTRY_H__
#define	__TSG_ENTRY_H__

#include <MESA/Maat_rule.h>
#include <MESA/field_stat2.h>
#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_statistic.h"

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 411)
#define atomic_inc(x) __sync_add_and_fetch((x),1)
#define atomic_dec(x) __sync_sub_and_fetch((x),1)
#define atomic_add(x,y) __sync_add_and_fetch((x),(y))
#define atomic_sub(x,y) __sync_sub_and_fetch((x),(y))
typedef int atomic_t;
#define ATOMIC_INIT(i)  { (i) }
#define atomic_read(x) __sync_add_and_fetch((x),0)
#define atomic_set(x,y) __sync_lock_test_and_set((x),y)
#else 
#include <alsa/iatomic.h>
#endif 

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

enum MASTER_TABLE{
	TABLE_IP_ADDR=0,
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
	TABLE_MAX
};


enum TSG_FS2_TYPE{
	TSG_FS2_TCP_LINKS=0,
	TSG_FS2_UDP_LINKS,
	TSG_FS2_BYPASS,
	TSG_FS2_HIT_ADDR,
	TSG_FS2_HIT_SHARE,
	TSG_FS2_INTERCEPT,
	TSG_FS2_SUCCESS_LOG,
	TSG_FS2_FAILED_LOG,
	TSG_FS2_DROP_LOG,
	TSG_FS2_MAX
};

struct _str2index
{
	int index;
	int len;
	char *type;
};

struct _fqdn_category_t
{
	int ref_cnt;	
	unsigned int category_id;
	int match_method;
	char fqdn[MAX_DOAMIN_LEN/8];
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

struct _master_context
{
	tsg_protocol_t proto;
	int hit_cnt;
	int domain_len;
	char domain[MAX_DOAMIN_LEN];
	struct Maat_rule_t *result;
};

#define	_MAX_TABLE_NAME_LEN	64
typedef	struct _tsg_para
{
	int level;
	unsigned short timeout;
	int app_id_table_type;
	int device_id;	
	int table_id[TABLE_MAX];
	int dyn_subscribe_ip_table_id; //TSG_DYN_SUBSCRIBER_IP
	int priority_project_id;
	int internal_project_id;
	int proto_flag; //tsg_protocol_t
	int fs2_field_id[TSG_FS2_MAX];
	char device_sn[MAX_DOAMIN_LEN/8];
	char log_path[MAX_DOAMIN_LEN/8];
	char data_center[_MAX_TABLE_NAME_LEN];
	char table_name[TABLE_MAX][_MAX_TABLE_NAME_LEN];
	void *logger;
	screen_stat_handle_t fs2_handle;
}g_tsg_para_t;

extern g_tsg_para_t g_tsg_para;

typedef enum _tsg_statis_field_id
{
	STATIS_UNKNOWN=0,
	STATIS_ENTRANCE_ID=1,
	STATIS_TOTAL_CON_NUM,
	STATIS_NEW_CON_NUM,
	STATIS_ESTABLISHED_CON_NUM,
	STATIS_CLOSE_CON_NUM,
	STATIS_TOTAL_IN_BYTES,
	STATIS_TOTAL_OUT_BYTES,
	STATIS_TOTAL_IN_PACKETS,
	STATIS_TOTAL_OUT_PACKETS,
	STATIS_DEFAULT_CON_NUM,
	STATIS_DEFAULT_IN_BYTES,
	STATIS_DEFAULT_OUT_BYTES,
	STATIS_DEFAULT_IN_PACKETS,
	STATIS_DEFAULT_OUT_PACKETS,
	STATIS_ALLOW_CON_NUM,
	STATIS_ALLOW_IN_BYTES,
	STATIS_ALLOW_OUT_BYTES,
	STATIS_ALLOW_IN_PACKETS,
	STATIS_ALLOW_OUT_PACKETS,
	STATIS_DENY_CON_NUM,
	STATIS_DENY_IN_BYTES,
	STATIS_DENY_OUT_BYTES,
	STATIS_DENY_IN_PACKETS,
	STATIS_DENY_OUT_PACKETS,
	STATIS_MONITOR_CON_NUM,
	STATIS_MONITOR_IN_BYTES,
	STATIS_MONITOR_OUT_BYTES,
	STATIS_MONITOR_IN_PACKETS,
	STATIS_MONITOR_OUT_PACKETS,
	STATIS_INTERCEPT_CON_NUM,
	STATIS_INTERCEPT_IN_BYTES,
	STATIS_INTERCEPT_OUT_BYTES,
	STATIS_INTERCEPT_IN_PACKETS,
	STATIS_INTERCEPT_OUT_PACKETS,
	STATIS_ALERT_BYTES,
	STATIS_BLOCK_BYTES,
	STATIS_PINNING_NUM,
	STATIS_MAYBE_PINNING_NUM,
	STATIS_NOT_PINNING_NUM,
	STATIS_MAX
}tsg_statis_field_id_t;

enum TRAFFIC_INFO_IDX
{
	TRAFFIC_INFO_ALLOW=0,
	TRAFFIC_INFO_DENY,
	TRAFFIC_INFO_MONITOR,
	TRAFFIC_INFO_INTERCEPT,
	TRAFFIC_INFO_MAX
};

typedef	struct _tsg_statistic
{
	int cycle;
	int fs_line_id;
	int fs_field_id[STATIS_MAX];
	long long statistic_opt[_OPT_TYPE_MAX];
	struct _traffic_info *traffic_info[TSG_ACTION_MAX+1];
	struct _traffic_info default_total_info;
	screen_stat_handle_t fs2_handle;
}tsg_statis_para_t;

int tsg_statistic_init(const char *conffile, void *logger);

int tsg_scan_shared_policy(Maat_feather_t maat_feather, struct _identify_info *identify_info, Maat_rule_t *result, int result_num, scan_status_t *mid, int thread_seq);

void location_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void ASN_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void subscribe_id_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);


#endif
