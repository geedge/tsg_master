#ifndef	__TSG_LABEL_H__
#define	__TSG_LABEL_H__

#define	MAX_CATEGORY_ID_NUM	8
#define	MAX_STR_FIELD_LEN	64

#define	MAX_RESULT_NUM	8
#define	MAX_DOAMIN_LEN	2048

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
   PROTO_MAX
}tsg_protocol_t;


struct _asn_info_t
{
	int ref_cnt;
	int addr_type;
	int table_id;
	char start_ip[MAX_STR_FIELD_LEN];
	char end_ip[MAX_STR_FIELD_LEN];
	char asn[MAX_STR_FIELD_LEN];
	char organization[MAX_STR_FIELD_LEN*4];
};

struct _location_info_t
{
	int geoname_id;
	int table_id;
	int ref_cnt;
	int addr_type;
	double latitude;
	double longitude;
	double coords;
	char start_ip[MAX_STR_FIELD_LEN];
	char end_ip[MAX_STR_FIELD_LEN];
	char language[MAX_STR_FIELD_LEN];
	char continent_abbr[MAX_STR_FIELD_LEN*4];
	char continent_full[MAX_STR_FIELD_LEN*4];
	char country_abbr[MAX_STR_FIELD_LEN*4];
	char country_full[MAX_STR_FIELD_LEN*4];
	char province_abbr[MAX_STR_FIELD_LEN*4];
	char province_full[MAX_STR_FIELD_LEN*4];
	char city_full[MAX_STR_FIELD_LEN*4];
	char time_zone[MAX_STR_FIELD_LEN*4];
};

struct _subscribe_id_info_t
{
	int ref_cnt;
	int table_id;
	char subscribe_id[MAX_STR_FIELD_LEN*4];
};

struct umts_user_info
{
	char *apn;
	char *imsi;
	char *imei;
	char *msisdn; //MSISDN: phone number
};

struct _session_attribute_label_t
{
	int fqdn_category_id_num;
	tsg_protocol_t proto;
	long establish_latency_ms;
	struct _asn_info_t *client_asn;
	struct _asn_info_t *server_asn;
	struct _location_info_t *client_location;
	struct _location_info_t *server_location;
	struct _subscribe_id_info_t *client_subscribe_id;
	struct _subscribe_id_info_t *server_subscribe_id;
	char *ja3_fingerprint;
	unsigned int fqdn_category_id[MAX_CATEGORY_ID_NUM];
	struct umts_user_info *user_info;
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

#endif
