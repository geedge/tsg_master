#pragma once

#include <MESA/stream.h>

#include "app_label.h"
#include "tsg_label.h"
#include "tsg_rule.h"
#include "tsg_leaky_bucket.h"

#ifndef	MAX_BRIDGE_NAME_LEN
#define	MAX_BRIDGE_NAME_LEN	64
#endif

enum BRIDGE_TYPE
{
	BRIDGE_TYPE_SEND_CONN_SKETCH_DATA=0,
	BRIDGE_TYPE_RECV_CONN_SKETCH_DATA,
	BRIDGE_TYPE_SYNC_APP_IDENTIFY_RESULT,
	BRIDGE_TYPE_SYNC_SESSION_FLAGS,
	BRIDGE_TYPE_SHAPING_RESULT,	//sync and async
	BRIDGE_TYPE_SESSION_PROCESS_CONTEXT,		//async
	BRIDGE_TYPE_SESSION_ACTION_CONTEXT,		//async
	BRIDGE_TYPE_GATHER_APP_RESULT,	//async
	BRIDGE_TYPE_SERVICE_CHAINING_RESULT,	//async
	BRIDGE_TYPE_SECURITY_RESULT,	//async
	BRIDGE_TYPE_SESSION_ATTRIBUTE,	//async
	BRIDGE_TYPE_MAC_LINKINFO,	//async
	BRIDGE_TYPE_NAT_C2S_LINKINFO,
	BRIDGE_TYPE_NAT_S2C_LINKINFO,
	BRIDGE_TYPE_APP_LUA_RESULT,
	BRIDGE_TYPE_BUSINESS_S3_FILENAME,
	BRIDGE_TYPE_APP_BEHAVIOR_RESULT,
	BRIDGE_TYPE_POLICY_ACTION_PARA_EXEC_RESULT,
	BRIDGE_TYPE_ASYNC_SESSION_FLAGS,
	BRIDGE_TYPE_APP_SIGNATURE_RESULT,
	BRIDGE_TYPE_INTERCEPT_RESULT,	//sync and async
	BRIDGE_TYPE_SEGMENT_IDS,	//async service_chaining or shping SID
	BRIDGE_TYPE_MAX
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

struct hited_app_para
{
	int hited_app_id;
	int after_n_packets;
};

struct session_runtime_process_context
{
	unsigned char is_esni;
	unsigned char is_hited_allow;
	unsigned char deal_pkt_num;
	unsigned char is_app_link;
	unsigned char sync_cb_state;
	unsigned short timeout;
	enum TSG_PROTOCOL proto;
	int hited_app_id;		// only app
	unsigned int quic_version;
	unsigned long session_flag;
	union
	{
		char *ssl_sni;
		char *quic_sni;
		char *dtls_sni;
		char *http_host;
		char *domain;
	};
	union
	{
		char *http_url;
		char *quic_ua;
		void *para;
	};
	struct maat_state *mid;
	struct hited_app_para hited_para;  // l7 protocol and app
	long long last_scan_time;
	struct maat_rule *hited_result;
};

struct session_runtime_action_context
{
	char udp_data_dropme;
	char set_latency_flag;
	char direction;
	char padding[5];
	enum TSG_METHOD_TYPE method_type; 
	enum TSG_PROTOCOL protocol;
	union
	{
		struct leaky_bucket *bucket;
		long tamper_count;
		int default_policy_after_n_packets;
		struct hited_app_para hited_para;
		void *para;
	};
};

struct udp_session_runtime_context
{
	struct session_runtime_process_context *srt_process_context;
	struct session_runtime_action_context *srt_action_context;
};

struct session_runtime_attribute
{
	int http_action_file_size;
	size_t n_fqdn_category_ids;
	enum TSG_PROTOCOL proto;
	long establish_latency_ms;
	struct asn_info *client_asn;
	struct asn_info *server_asn;
	struct location_info *client_location;
	struct location_info *server_location;
	struct subscribe_id_info *client_subscribe_id;
	struct subscribe_id_info *server_subscribe_id;
	const char *ja3_fingerprint;
	unsigned int fqdn_category_ids[MAX_CATEGORY_ID_NUM];
	struct umts_user_info *user_info;
	struct tunnel_endpoint *client_endpoint;
	struct tunnel_endpoint *server_endpoint;
	unsigned long session_flags;
	struct tsg_proxy_tcp_attribute *proxy_tcp_attr;
};


// init
int tsg_bridge_init(const char *conffile);

//send log
void *session_mac_linkinfo_get(const struct streaminfo * a_stream);
void *session_conn_sketch_notify_data_get(const struct streaminfo * a_stream);
void *session_business_data_get(const struct streaminfo * a_stream);
void *session_session_flags_get(const struct streaminfo * a_stream);
void *session_application_behavior_get(const struct streaminfo * a_stream);
void *session_mirrored_and_capture_packets_exec_result_get(const struct streaminfo * a_stream);
void *session_lua_user_defined_attribute_get(const struct streaminfo * a_stream);
void *session_nat_c2s_linkinfo_get(const struct streaminfo * a_stream);
void *session_nat_s2c_linkinfo_get(const struct streaminfo * a_stream);

void *session_control_segment_ids_get(const struct streaminfo *a_stream);
int session_control_segment_ids_async(const struct streaminfo *a_stream, void *data);

void session_matched_rules_free(const struct streaminfo * a_stream, TSG_SERVICE service, void * data);
int session_matched_rules_async(const struct streaminfo * a_stream, TSG_SERVICE service, void * data);
const struct matched_policy_rules *session_matched_rules_get(const struct streaminfo *a_stream, enum TSG_SERVICE service);
int session_capture_packets_sync(const struct streaminfo *a_stream, struct maat_rule *results, int depth);
int session_mirror_packets_sync(const struct streaminfo *a_stream, struct maat_rule *results, struct mirrored_vlan *vlan);

// security 
void session_matched_rules_notify(const struct streaminfo * a_stream, TSG_SERVICE service, struct maat_rule *results, size_t n_results, int thread_seq);

// session runtime attribute
int srt_attribute_set_protocol(const struct streaminfo * a_stream, TSG_PROTOCOL protocol);
int srt_attribute_set_flags(const struct streaminfo * a_stream, unsigned long s_flags);
int srt_attribute_set_establish_latecy(const struct streaminfo * a_stream);
int srt_attribute_set_ja3_fingprint(const struct streaminfo *a_stream, const char *ja3_fingerprint);
int srt_attribute_set_reponse_size(const struct streaminfo *a_stream, int http_action_file_size);

//gather app identify result
int session_gather_app_results_async(const struct streaminfo * a_stream, void * data);
void *session_gather_app_results_get(const struct streaminfo * a_stream);

// session runtime do action context
int session_runtime_action_context_async(const struct streaminfo *a_stream, void *data);
const struct session_runtime_action_context *session_runtime_action_context_get(const struct streaminfo *a_stream);
int srt_action_context_set_leaky_bucket(const struct streaminfo * a_stream, struct leaky_bucket * bucket, int thread_seq);
int srt_action_context_set_l7_protocol(const struct streaminfo * a_stream, TSG_PROTOCOL protocol, int thread_seq);
int srt_action_context_set_rule_method(const struct streaminfo * a_stream, enum TSG_METHOD_TYPE method_type, int thread_seq);
int srt_action_context_set_after_n_packet(const struct streaminfo * a_stream, int after_n_packets, int thread_seq);
int srt_action_context_set_hitted_app_id(const struct streaminfo * a_stream, int hited_app_id, int thread_seq);

char srt_action_context_get_direction(const struct streaminfo * a_stream);

