#ifndef	__TSG_LABEL_H__
#define	__TSG_LABEL_H__

#define	MAX_CATEGORY_ID_NUM	8
#define	MAX_STR_FIELD_LEN	64

#define	MAX_VLAN_ID_NUM		32

#define	MAX_RESULT_NUM	8
#define	MAX_DOMAIN_LEN	2048

typedef enum _tsg_protocol
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
   PROTO_MAX
}tsg_protocol_t;


struct asn_info
{
	int ref_cnt;
	char *asn_id;
	char *organization;
};

struct location_info
{
	int ref_cnt;
	char *country_full;
	char *province_full;
	char *city_full;
	char *subdivision_addr;
};

struct subscribe_id_info
{
	int ref_cnt;
	char *subscribe_id;
};

struct umts_user_info
{
	char *apn;
	char *imsi;
	char *imei;
	char *msisdn; //MSISDN: phone number
};

struct session_attribute_label
{
	int http_action_file_size;
	int fqdn_category_id_num;
	tsg_protocol_t proto;
	long establish_latency_ms;
	struct asn_info *client_asn;
	struct asn_info *server_asn;
	struct location_info *client_location;
	struct location_info *server_location;
	struct subscribe_id_info *client_subscribe_id;
	struct subscribe_id_info *server_subscribe_id;
	char *ja3_fingerprint;
	unsigned int fqdn_category_id[MAX_CATEGORY_ID_NUM];
	struct umts_user_info *user_info;
};

struct policy_priority_label
{
	tsg_protocol_t proto;	//enum _tsg_protocol (tsg_types.h)
	int domain_len;
	int result_type;	//enum _PULL_RESULT_TYPE (tsg_rule.h)
	int result_num;
	union
	{
		char *http_url;
		char *quic_ua;
		void *para;
	};
	char domain[MAX_DOMAIN_LEN];
	Maat_rule_t result[MAX_RESULT_NUM];
};


struct tsg_conn_sketch_notify_data
{
	tsg_protocol_t protocol;
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
	int compile_id;
};

struct tsg_notify_data
{
	int compile_id;
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
	char *capture_packet_path;
	struct mirrored_stat stat_mirrored[MAX_RESULT_NUM];
};

struct application_behavior
{
	char *stream_behavior;
};

#endif
