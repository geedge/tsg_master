#pragma once

#include <stddef.h>

#define	MAX_STR_FIELD_LEN	64

#define	MAX_VLAN_ID_NUM		32

#define	MAX_RESULT_NUM	8

enum TSG_PROTOCOL
{
	PROTO_UNKONWN=0,
	PROTO_IPv4=1,
	PROTO_IPv6,
	PROTO_TCP,
	PROTO_UDP,
	PROTO_HTTP,
	PROTO_MAIL,
	PROTO_DNS,
	PROTO_FTP,
	PROTO_SSL,
	PROTO_SIP,
	PROTO_BGP,
	PROTO_STREAMING_MEDIA,
	PROTO_QUIC,
	PROTO_SSH,
	PROTO_SMTP,
	PROTO_IMAP,
	PROTO_POP3,
	PROTO_RTP,
	PROTO_APP,
	PROTO_L2TP,
	PROTO_PPTP,
	PROTO_STRATUM,
	PROTO_RDP,
	PROTO_DTLS,
	PROTO_MAX
};

struct asn_info
{
	int ref_cnt;
	char *asn_id;
	char *organization;
};

struct location_info
{
	int ref_cnt;
	int full_location_len;
	char *full_location;
};

struct subscribe_id_info
{
	int ref_cnt;
	char *subscribe_id;
};

struct umts_user_info
{
	int ref_cnt;
	char *apn;
	char *imsi;
	char *imei;
	char *msisdn; //MSISDN: phone number
};

struct tunnel_catalog
{
	int id;
	char *name;
	char *type;
	char *composition;
};

struct tunnel_endpoint
{
	int id;
	int ref_cnt;
	char *description;
};

struct tsg_conn_sketch_notify_data
{
	enum TSG_PROTOCOL protocol;
	union
	{
		char *mail_eml_filename;
		struct TLD_handle_t *TLD_handle;
		void *value;
	}pdata;
};

enum NOTIFY_TYPE
{
	NOTIFY_TYPE_MIRRORED=0,
	NOTIFY_TYPE_CAPTURE,
	NOTIFY_TYPE_MAX
};

struct mirrored_vlan
{
	int num;
	int id[MAX_VLAN_ID_NUM];
};

struct mirrored_stat
{
	long bytes;
	long packets;
	long long compile_id;
};

struct policy_capture_result
{
	long long compile_id;
	char *packet_path;
};

struct tsg_notify_data
{
	long long compile_id;
	enum NOTIFY_TYPE type;
	union
	{		
		int capture_depth;
		struct mirrored_vlan *vlan;
	};
};

struct tsg_notify_execution_result
{	
	int stat_mirrored_cnt;
	int capture_result_cnt;
	struct policy_capture_result capture_result[MAX_RESULT_NUM];
	struct mirrored_stat stat_mirrored[MAX_RESULT_NUM];
};

struct application_behavior
{
	char *stream_behavior;
};

struct http_s3_file
{
	char *request_filename;
	char *response_filename;
};

struct business_notify_data
{
	enum TSG_PROTOCOL proto;	//enum _tsg_protocol (tsg_types.h)
	union
	{		
		struct http_s3_file *s3_http;
		void *pdata;
	};
};

struct session_runtime_attribute;
const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo *a_stream);
const char *srt_attribute_get_ja3_fingerprint(const struct session_runtime_attribute *srt_attribute);
const char *srt_attribute_get_client_subscriber_id(const struct session_runtime_attribute *srt_attribute);
const char *srt_attribute_get_server_subscriber_id(const struct session_runtime_attribute *srt_attribute);
const struct asn_info *srt_attribute_get_client_ip_asn(const struct session_runtime_attribute *srt_attribute);
const struct asn_info *srt_attribute_get_server_ip_asn(const struct session_runtime_attribute *srt_attribute);
const struct location_info *srt_attribute_get_client_ip_location(const struct session_runtime_attribute *srt_attribute);
const struct location_info *srt_attribute_get_server_ip_location(const struct session_runtime_attribute *srt_attribute);
size_t srt_attribute_get_category_ids(const struct session_runtime_attribute *srt_attribute, unsigned int *category_ids, size_t n_category_ids);

int srt_attribute_set_category_ids(const struct streaminfo *a_stream, unsigned int *category_ids, int n_category_ids);

struct session_runtime_process_context;
int session_runtime_process_context_async(const struct streaminfo *a_stream, void *data);
const struct session_runtime_process_context *session_runtime_process_context_get(const struct streaminfo *a_stream);
// return NULL; http host or ssl sni or quic sni or dtls sni
const char *srt_process_context_get_domain(const struct session_runtime_process_context *srt_process_context);
const char *srt_process_context_get_http_url(const struct session_runtime_process_context *srt_process_context);
const char *srt_process_context_get_quic_ua(const struct session_runtime_process_context *srt_process_context);
enum TSG_PROTOCOL srt_process_context_get_protocol(const struct session_runtime_process_context *srt_process_context);
unsigned char srt_process_context_get_hitted_allow_flag(const struct session_runtime_process_context *srt_process_context);

