#ifndef	__TSG_ENTRY_H__
#define	__TSG_ENTRY_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include <MESA/dns.h>

#include <MESA/Maat_rule.h>
#include <MESA/field_stat2.h>
#include <ctemplate/template.h>

#include "uthash.h"
#include "tsg_rule.h"
#include "app_label.h"
#include "tsg_label.h"
#include "tsg_statistic.h"
#include "tsg_leaky_bucket.h"
#include "tsg_protocol_common.h"
#include "tsg_send_log_internal.h"

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

#ifndef	PRINTADDR
#define	PRINTADDR(a, b)	((b)<RLOG_LV_FATAL ? printaddr(&(a->addr), a->threadnum) : "")
#endif

#ifndef	FLAG_FALSE
#define	FLAG_FALSE	0
#endif

#ifndef	FLAG_TRUE
#define FLAG_TRUE	1
#endif

#define	APP_SCAN_FLAG_STOP	0
#define	APP_SCAN_FLAG_CONTINUE	1

enum DEPLOY_MODE
{
	DEPLOY_MODE_MIRROR,
	DEPLOY_MODE_INLINE,
	DEPLOY_MODE_TRANSPARENT,
	DEPLOY_MODE_MAX
};

enum MASTER_STATIC_TABLE{
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
	TABLE_MAX
};

enum MASTER_DYNAMIC_TABLE{
	DYN_TABLE_SUBSCRIBER_IP=0,		
	DYN_TABLE_GTP_SIGNALING,
	DYN_TABLE_MAX
};

enum TSG_FS2_TYPE{
	TSG_FS2_TCP_LINKS=0,
	TSG_FS2_UDP_LINKS,
	TSG_FS2_BYPASS,
	TSG_FS2_HIT_ADDR,
	TSG_FS2_HIT_SHARE,
	TSG_FS2_INTERCEPT,
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

enum TSG_ATTRIBUTE_TYPE
{
	TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY=0,
	TSG_ATTRIBUTE_TYPE_PROTOCOL,
	TSG_ATTRIBUTE_TYPE_JA3_HASH,
	TSG_ATTRIBUTE_TYPE_MLTS_USER_INFO,
	TSG_ATTRIBUTE_TYPE_LOCATION,
	TSG_ATTRIBUTE_TYPE_ASN,
	TSG_ATTRIBUTE_TYPE_SUBSCRIBER_ID,
	TSG_ATTRIBUTE_TYPE_HTTP_ACTION_FILESIZE,
	TSG_ATTRIBUTE_TYPE_CATEGORY_ID,
	TSG_ATTRIBUTE_TYPE_SESSION_FLAGS,
	_MAX_TSG_ATTRIBUTE_TYPE
};

enum HTTP_RESPONSE_FORMAT
{
	HTTP_RESPONSE_FORMAT_TEMPLATE=0,
	HTTP_RESPONSE_FORMAT_HTML
};

enum BRIDGE_TYPE
{
	BRIDGE_TYPE_SEND_CONN_SKETCH_DATA=0,
	BRIDGE_TYPE_RECV_CONN_SKETCH_DATA,
	BRIDGE_TYPE_APP_IDENTIFY_RESULT,
	BRIDGE_TYPE_NOTIFY_FLAGS,
	BRIDGE_TYPE_MAX
};

struct _str2index
{
	int index;
	int len;
	char *type;
};

struct app_attributes
{
	unsigned int app_id;
	unsigned int surrogate_id;
	unsigned int packet_sequence;
};

struct gather_app_result
{
	int app_num;
	enum APP_IDENTIFY_ORIGIN origin;
	struct app_attributes attributes[MAX_APP_ID_NUM];
};

struct l7_protocol 
{
    int id;                    /* first key */
    char name[32];         		/* second key */
    UT_hash_handle hh1;        /* handle for first hash table */
    UT_hash_handle hh2;        /* handle for second hash table */
};

struct fqdn_category
{
	int ref_cnt;	
	unsigned int category_id;
};

struct http_response_pages
{
	int profile_id;
	int content_len;
	int ref_cnt;	
	enum HTTP_RESPONSE_FORMAT format;
	char *content;
};

struct app_id_dict
{
	int ref_cnt;
	int app_id;
	int parent_app_id;
	int continue_scanning;
	unsigned short tcp_timeout;
	unsigned short udp_timeout;
	int tcp_time_wait;
	int tcp_half_close;
	char *risk;
	char *app_name;
	char *parent_app_name;
	char *category;
	char *subcategroy;
	char *technology;
	char *characteristics;
	struct deny_user_region deny_app_para;
};

struct hited_app_para
{
	int hited_app_id;
	int after_n_packets;
};

struct master_context
{
	unsigned char is_esni;
	unsigned char is_log;
	unsigned char deal_pkt_num;
	unsigned char is_app_link;
	unsigned char sync_cb_state;
	unsigned short timeout;
	tsg_protocol_t proto;
	int hit_cnt;
	int hited_app_id;		// only app
	unsigned int quic_version;
	unsigned long session_flag;
	char *domain;
	union
	{
		char *http_url;
		char *quic_ua;
		void *para;
	};
	scan_status_t mid;	
	struct Maat_rule_t *result;
	struct hited_app_para hited_para;  // l7 protocol and app
	long long last_scan_time;
};

struct tcpall_context
{
	char udp_data_dropme;
	char set_latency_flag;
	char direction;
	char padding[5];
	enum TSG_METHOD_TYPE method_type; 
	tsg_protocol_t protocol;
	union
	{
		struct leaky_bucket *bucket;
		long tamper_count;		
		int default_policy_after_n_packets;		
		struct hited_app_para hited_para;
		void *para;
	};
};

struct udp_context
{
	struct master_context *data_entry;
	struct tcpall_context *all_entry;
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

#define	_MAX_TABLE_NAME_LEN	64
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
	int default_compile_id;
	int table_id[TABLE_MAX];	
	int dyn_table_id[DYN_TABLE_MAX];
	int priority_project_id;
	int session_attribute_project_id;
	int context_project_id;
	int tcpall_project_id;
	int gather_app_project_id;	
	int bridge_id[BRIDGE_TYPE_MAX];
	int proto_flag; //tsg_protocol_t
	int fs2_field_id[TSG_FS2_MAX];
	char device_sn[MAX_DOMAIN_LEN/8];
	char log_path[MAX_DOMAIN_LEN/8];
	char device_id_command[MAX_DOMAIN_LEN/8];
	char data_center[_MAX_TABLE_NAME_LEN];
	char device_tag[MAX_DOMAIN_LEN/2];
	char table_name[TABLE_MAX][_MAX_TABLE_NAME_LEN];	
	char dyn_table_name[DYN_TABLE_MAX][_MAX_TABLE_NAME_LEN];
	char bridge_name[BRIDGE_TYPE_MAX][_MAX_TABLE_NAME_LEN];
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
extern id2field_t g_tsg_proto_name2id[PROTO_MAX];

typedef enum tsg_statis_field_id
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
	STATIS_IPV4_IN_BYTES,
	STATIS_IPV4_OUT_BYTES,
	STATIS_IPV4_IN_PACKETS,
	STATIS_IPV4_OUT_PACKETS,
	STATIS_IPV6_IN_BYTES,
	STATIS_IPV6_OUT_BYTES,
	STATIS_IPV6_IN_PACKETS,
	STATIS_IPV6_OUT_PACKETS,
	STATIS_TCP_NEW_CON_NUM,
	STATIS_TCP_IN_BYTES,
	STATIS_TCP_OUT_BYTES,
	STATIS_TCP_IN_PACKETS,
	STATIS_TCP_OUT_PACKETS,
	STATIS_UDP_NEW_CON_NUM,
	STATIS_UDP_IN_BYTES,
	STATIS_UDP_OUT_BYTES,
	STATIS_UDP_IN_PACKETS,
	STATIS_UDP_OUT_PACKETS,
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

typedef	struct tsg_statistic
{
	int cycle;
	int fs_line_id;
	int thread_alive;
	pthread_t stat_thread_id;
	int fs_field_id[STATIS_MAX];
	long long statistic_opt[_OPT_TYPE_MAX];
	struct _traffic_info *traffic_info[TSG_ACTION_MAX+1];
	struct _traffic_info default_total_info;
	screen_stat_handle_t fs2_handle;
}tsg_statis_para_t;

int tsg_statistic_init(const char *conffile, void *logger);
void tsg_statistic_destroy(void);

int tsg_gtp_signaling_hash_init(const char* conffile, void *logger);

int set_struct_project(const struct streaminfo *a_stream, int project_id, void *data);
const void *get_struct_project(const struct streaminfo *a_stream, int project_id);

long long get_current_time_ms(void);

//parent_app_name.app_name
int tsg_app_id2name(int app_id, char *app_name, int app_name_len, int is_joint_parent);

//return 18 or 19: subdivision_addr
int tsg_get_location_type(void);
void location_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void ASN_number_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void subscriber_id_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void app_id_dict_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void gtp_c_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void tunnel_endpoint_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp);

void http_response_pages_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp);
void dns_profile_records_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp);
void set_session_attribute_label(const struct streaminfo *a_stream, enum TSG_ATTRIBUTE_TYPE type, void *value, int value_len, int thread_seq);
int set_method_to_tcpall(const struct streaminfo *a_stream, enum TSG_METHOD_TYPE method_type, int thread_seq);
int set_protocol_to_tcpall(const struct streaminfo *a_stream, tsg_protocol_t protocol, int thread_seq);
int set_bucket_to_tcpall(const struct streaminfo *a_stream, struct leaky_bucket *bucket, int thread_seq);
int set_after_n_packet_to_tcpall(const struct streaminfo *a_stream, int after_n_packets, int thread_seq);

char get_direction_from_tcpall(const struct streaminfo *a_stream);

void security_compile_free(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp);

struct Maat_rule_t *tsg_policy_decision_criteria(struct streaminfo *a_stream, Maat_rule_t *result, int result_num, int thread_seq);
int tsg_scan_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num);
int tsg_scan_shared_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, char *domain, Maat_rule_t *result, int result_num,  scan_status_t *mid, int table_id, int thread_seq);
int tsg_scan_app_properties_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *property, char *district, int thread_seq);
int tsg_scan_subscribe_id_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, struct subscribe_id_info *user_info, int thread_seq);

int tsg_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info);
struct umts_user_info *tsg_get_umts_user_info_form_redis(unsigned int teid);

void free_policy_label(int thread_seq, void *project_req_value);
int tsg_set_policy_result(const struct streaminfo *a_stream, PULL_RESULT_TYPE result_type, struct Maat_rule_t *p_result, tsg_protocol_t proto, int thread_seq);
int tsg_scan_gtp_apn_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *apn, int thread_seq);
int tsg_scan_gtp_imsi_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *imsi, int thread_seq);
int tsg_scan_gtp_phone_number_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *phone_number, int thread_seq);
int tsg_get_ip_location(const struct streaminfo *a_stream, int table_id, MAAT_PLUGIN_EX_DATA *client_location, MAAT_PLUGIN_EX_DATA *server_location);
int tsg_get_ip_asn(const struct streaminfo *a_stream, int table_id, MAAT_PLUGIN_EX_DATA* client_asn, MAAT_PLUGIN_EX_DATA* server_asn);
int tsg_get_subscribe_id(const struct streaminfo *a_stream, struct subscribe_id_info **source_subscribe_id, struct subscribe_id_info **dest_subscribe_id);
int tsg_send_raw_packet(const struct streaminfo *a_stream, struct mirrored_vlan *vlan, int vlan_num, int thread_seq);
int tsg_scan_session_flags(Maat_feather_t maat_feather, const struct streaminfo *a_stream, Maat_rule_t *result, int result_num,  scan_status_t *mid, int table_id, unsigned long flag, int thread_seq);

#endif
