#ifndef	__APP_LABEL_H__
#define	__APP_LABEL_H__

#define	MAX_APP_ID_PROPERTY_LEN	128


struct _quic_attribute_t
{
	char *version;
	char *sni;
	char *user_agent;
};

struct _dns_attribute_t
{
	unsigned short id;
	unsigned short flag;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short aucount;//authority count
	unsigned short adcount;//additional count

	unsigned short qtype;
	unsigned short qclass;
	char *qname;
};

struct _http_attribute_t
{
	char *host;
	char *uri;
	char *user_agent;
	char *content_type;
	char *content_encoding;
	char *referer;
	char *cookie;
	char *set_cookie;
};

struct _ssl_attribute_t
{
	char *cn;
	char *sni;
	char *san;
	char *version;
	char *fingerprint;
	char *serial_number;
	char *issuer_common_name;
	char *issuer_organition_name;
	char *issuer_country_name;
	char *subject_common_name;
	char *subject_organition_name;
	char *subject_country_name;
	char *not_valid_before;
	char *not_valid_after;
	char *algotithm_id;
	char *ja3_fingerprint;
};

struct _app_id_dict_t
{
	int ref_cnt;
	int app_id;
	int deny_action;
	int continue_scanning;
	int tcp_timeout;
	int udp_timeout;
	int tcp_time_wait;
	int tcp_half_close;
	int is_valid;
	char risk[MAX_APP_ID_PROPERTY_LEN*4];
	char app_name[MAX_APP_ID_PROPERTY_LEN];
	char category[MAX_APP_ID_PROPERTY_LEN*4];
	char subcategroy[MAX_APP_ID_PROPERTY_LEN*4];
	char technology[MAX_APP_ID_PROPERTY_LEN*4];
	char characteristics[MAX_APP_ID_PROPERTY_LEN*4];
	char depends_on_app_ids[MAX_APP_ID_PROPERTY_LEN];
	char implicitly_uses_app_ids[MAX_APP_ID_PROPERTY_LEN];
};


#define	MAX_APP_ID_NUM	8

enum _APP_SESSION_PROTO
{
	SESSION_PROTO_HTTP=1,
	SESSION_PROTO_SSL,
	SESSION_PROTO_QUIC,
	SESSION_PROTO_DNS,
	_SESSION_PROTO_MAX
};

enum _APP_SESSION_FLAG
{
	SESSION_FLAG_TCP_CREATE_WITH_SYN=1,
	SESSION_FLAG_SSL_USE_SELFSIGNED_CERT=2,
	SESSION_FLAG_SSL_INCOMPLETE_CERT_CHAIN=4
};


typedef	struct _app_id_label_add_flag_t
{
	volatile char flag;
}APP_ADD_ID_LABEL_T;

struct _app_id_label_t
{
	char ref_cnt;
	char session_flag; // enum SESSION_FLAG
	char session_proto; //enum _APP_SESSION_PROTO
	char app_id_num;
	APP_ADD_ID_LABEL_T flag; //0: no; 1: yes
	char pad[3];
	int surrogate_id;
	int app_id;
	struct _app_id_dict_t *dict;
	union
	{
		struct _ssl_attribute_t *ssl_attribute;
		struct _dns_attribute_t *dns_attribute;
		struct _http_attribute_t *http_attribute;
		struct _quic_attribute_t *quic_attribute;
		void *attribute; //quic sni or dns query qname
	};
};

struct _basic_proto_label
{
	unsigned char continue_scan_flag;  //0: stop; 1: continue
	unsigned char pad;
	unsigned short proto_id;
};

enum _ATTRIBUTE_TYPE
{
	ATTRIBUTE_TYPE_UNKNOWN,
	ATTRIBUTE_TYPE_IP,
	ATTRIBUTE_TYPE_STRING,
	ATTRIBUTE_TYPE_NUMERIC,
	ATTRIBUTE_TYPE_BOOL,
	_ATTRIBUTE_TYPE_MAX
};

struct _attribute_kv_t
{
	enum _ATTRIBUTE_TYPE type;
	char *name;
	void *value;
};

struct _user_defined_attribute_label_t
{
	int attribute_num;
	struct _attribute_kv_t *attribute;
};

#endif
