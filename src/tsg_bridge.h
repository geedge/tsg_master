#pragma once

#include <MESA/stream.h>
#include <MESA/Maat_rule.h>

#include "tsg_rule.h"
#include "app_label.h"
#include "tsg_leaky_bucket.h"

#ifndef	MAX_BRIDGE_NAME_LEN
#define	MAX_BRIDGE_NAME_LEN	64
#endif

enum BRIDGE_TYPE
{
	BRIDGE_TYPE_SEND_CONN_SKETCH_DATA=0,
	BRIDGE_TYPE_RECV_CONN_SKETCH_DATA,
	BRIDGE_TYPE_APP_IDENTIFY_RESULT,
	BRIDGE_TYPE_NOTIFY_FLAGS,
	BRIDGE_TYPE_NOTIFY_SHAPING_RESULT,	//sync and async
	BRIDGE_TYPE_DATA_CONTEXT,		//async
	BRIDGE_TYPE_ALL_CONTEXT,		//async
	BRIDGE_TYPE_GATHER_APP_RESULT,	//async
	BRIDGE_TYPE_POLICY_PRIORITY,	//async
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

struct policy_priority_label
{
	tsg_protocol_t proto;	//enum _tsg_protocol (tsg_types.h)
	int domain_len;
	int result_type;	//enum _PULL_RESULT_TYPE (tsg_rule.h)
	int security_result_num;
	union
	{
		char *http_url;
		char *quic_ua;
		void *para;
	};
	char domain[MAX_DOMAIN_LEN];
	struct Maat_rule_t security_result[MAX_RESULT_NUM];
};

struct hited_app_para
{
	int hited_app_id;
	int after_n_packets;
};

struct master_context
{
	unsigned char is_esni;
	unsigned char is_hited_allow;
	unsigned char deal_pkt_num;
	unsigned char is_app_link;
	unsigned char sync_cb_state;
	unsigned short timeout;
	tsg_protocol_t proto;
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
	struct hited_app_para hited_para;  // l7 protocol and app
	long long last_scan_time;
	struct Maat_rule_t *hited_result;
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

struct bridge_info
{
	int id;
	char name[MAX_BRIDGE_NAME_LEN];
	stream_bridge_free_cb_t *free_cb;
	stream_bridge_sync_cb_t *sync_cb;
};

int tsg_init_bridge(const char *conffile);

void free_context_label(const struct streaminfo *stream, int bridge_id, void *data);
void free_tcpall_label(const struct streaminfo *stream, int bridge_id, void *data);
void free_policy_label(const struct streaminfo *stream, int bridge_id, void *data);
void free_shaping_result(const struct streaminfo *stream, int bridge_id, void *data);
void free_gather_app_result(const struct streaminfo *stream, int bridge_id, void *data);

void *tsg_get_xxx_from_bridge(const struct streaminfo *a_stream, int bridge_id);
int tsg_set_xxx_to_bridge(const struct streaminfo *a_stream, int bridge_id, void *data);

