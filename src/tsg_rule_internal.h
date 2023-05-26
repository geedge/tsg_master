#pragma once

#include <MESA/maat.h>

#include "tsg_rule.h"
#include "tsg_variable.h"

#ifndef	MAX_FILEPATH_LEN
#define	MAX_FILEPATH_LEN	128
#endif

#ifndef	MAX_IPV6_ADDR_LEN
#define	MAX_IPV6_ADDR_LEN	128
#endif

#ifndef	TUNNEL_BOOL_ID_MAX
#define	TUNNEL_BOOL_ID_MAX	128
#endif

#ifndef	TUNNEL_CATALOG_MAX
#define	TUNNEL_CATALOG_MAX	128
#endif

#ifndef	MAX_TABLE_NAME_LEN
#define	MAX_TABLE_NAME_LEN	64
#endif

enum MAAT_MODE
{
	MAAT_MODE_FILE=0,
	MAAT_MODE_JSON,
	MAAT_MODE_REDIS,
	MAAT_MODE_MAX
};

enum MAAT_PLUGIN_TB
{
	MAAT_PLUGIN_SECURITY_COMPILE=0,
	MAAT_PLUGIN_ASN_USER_DEFINED,
	MAAT_PLUGIN_ASN_BUILT_IN,
	MAAT_PLUGIN_LOCATION_USER_DEFINED,
	MAAT_PLUGIN_LOCATION_BUILT_IN,
	MAAT_PLUGIN_FQDN_CAT_USER_DEFINED,
	MAAT_PLUGIN_FQDN_CAT_BUILT_IN,
	MAAT_PLUGIN_APP_ID_DICT,
	MAAT_PLUGIN_RESPONSE_PAGES,
	MAAT_PLUGIN_DNS_PROFILE_RECORD,
	MAAT_PLUGIN_PROFILE_MIRROR,
	MAAT_PLUGIN_TUNNEL_CATALOG,
	MAAT_PLUGIN_TUNNEL_ENDPOINT,
	MAAT_PLUGIN_TUNNEL_LABEL,
	MAAT_PLUGIN_SESSION_LOG, //T_VSYS_INFO,
	MAAT_PLUGIN_SUBSCRIBER_IP2ID,
	MAAT_PLUGIN_GTP_IP2SIGNALING,
	MAAT_PLUGIN_MAX
};

struct maat_plugin_table
{
	int id;
	char name[MAX_TABLE_NAME_LEN];
	maat_ex_new_func_t *ex_new;
	maat_ex_free_func_t *ex_free;
	maat_ex_dup_func_t *ex_dup;
};

enum MAAT_SCAN_TB
{
	MAAT_SCAN_SRC_IP_ADDR=0,
	MAAT_SCAN_DST_IP_ADDR,
	MAAT_SCAN_SUBSCRIBER_ID,
	MAAT_SCAN_APP_ID,
	MAAT_SCAN_HTTP_HOST,
	MAAT_SCAN_HTTP_URL,
	MAAT_SCAN_SSL_SNI,
	MAAT_SCAN_EXCLUSION_SSL_SNI,
	MAAT_SCAN_SRC_ASN,
	MAAT_SCAN_DST_ASN,
	MAAT_SCAN_SRC_LOCATION,
	MAAT_SCAN_DST_LOCATION,
	MAAT_SCAN_QUIC_SNI,
	//MAAT_SCAN_FQDN_CAT_ID,
	MAAT_SCAN_SELECTOR_ID,
	MAAT_SCAN_SELECTOR_PROPERTIES,
	MAAT_SCAN_GTP_APN,
	MAAT_SCAN_GTP_IMSI,
	MAAT_SCAN_GTP_PHONE_NUMBER,
	MAAT_SCAN_DTLS_SNI,
	MAAT_SCAN_TUNNEL_ID,
	MAAT_SCAN_SESSION_FLAGS,
	MAAT_SCAN_HTTP_HOST_CAT,
	MAAT_SCAN_SSL_SNI_CAT,
	MAAT_SCAN_QUIC_SNI_CAT,
	MAAT_SCAN_DTLS_SNI_CAT,
	MAAT_SCAN_MAX
};

struct maat_scan_table
{
	int id;
	char name[MAX_TABLE_NAME_LEN];
};

struct maat_runtime_para
{
	int level;
	int default_compile_id;
	int location_field_num;
	int session_record_switch;
	char data_center[MAX_STRING_LEN128];
	char device_tag[MAX_STRING_LEN128];
	struct mirrored_vlan default_vlan;
	struct maat_scan_table scan_tb[MAAT_SCAN_MAX];
	struct maat_plugin_table plugin_tb[MAAT_PLUGIN_MAX];
	void *logger;
};

struct maat_compile
{
	int ref_cnt;
	struct maat_rule rule;
	char *p_user_region;
	struct compile_user_region *user_region;
};

int tsg_maat_rule_init(const char *conffile);

void plugin_ex_data_gtp_c_free(struct umts_user_info *user_info);
void plugin_ex_data_asn_number_free(struct asn_info *asn);
void plugin_ex_data_location_free(struct location_info *location);
void plugin_ex_data_subscriber_id_free(struct subscribe_id_info *subscriber);
void plugin_ex_data_tunnel_endpoint_free(struct tunnel_endpoint *t_enpoint);
void plugin_ex_data_http_response_pages_free(struct http_response_pages *response_pages);
void plugin_ex_data_app_id_dict_free(struct app_id_dict * dict);
void plugin_ex_data_security_compile_free(struct maat_compile *maat_compile);
void plugin_ex_data_dns_profile_record_free(struct dns_profile_records * records);

void tsg_maat_state_free(struct maat_state *state);
int srt_attribute_set_ip_asn(const struct streaminfo *a_stream, struct maat *feather, struct asn_info **client_asn, struct asn_info **server_asn);
int srt_attribute_set_ip_location(const struct streaminfo *a_stream, struct maat *feather, struct location_info **client_location, struct location_info **server_location);
int srt_attribute_set_subscriber_id(const struct streaminfo *a_stream, struct maat *feather, struct subscribe_id_info **client_subscriber_id, struct subscribe_id_info **server_subscriber_id);

int session_runtine_attribute_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info);
struct umts_user_info *tsg_get_umts_user_info_form_redis(unsigned int teid);

void *matched_rule_cites_http_response_pages(struct maat *feather, long long profile_id);
void *matched_rule_cites_app_id_dict(struct maat *feather, long long app_id);
void *matched_rule_cites_security_compile(struct maat *feather, long long compile_id);
void *matched_rule_cites_dns_profile_record(struct maat *feather, long long profile_id);

char *tsg_data_center_get(void);
char *tsg_device_tag_get(void);
int tsg_location_type_get(void);
int tsg_session_record_switch_get(void);
int tsg_domain_table_idx_get(enum TSG_PROTOCOL proto);
int tsg_fqdn_category_table_idx_get(enum TSG_PROTOCOL proto);
int tsg_http_url_table_idx_get(void);
long long tsg_default_compile_id_get(void);


//parent_app_name.app_name
int tsg_get_app_name_by_id(struct maat *feather, int app_id, char *app_name, int app_name_len, int is_joint_parent);

size_t tsg_scan_session_flags(const struct streaminfo *a_stream, struct maat *feather, unsigned long flag, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
size_t tsg_scan_app_id_policy(const struct streaminfo *a_stream, struct maat *feather, unsigned int app_id, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
size_t tsg_scan_shared_policy(const struct streaminfo *a_stream, struct maat *feather, char *domain, int idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
size_t tsg_scan_app_properties_policy(const struct streaminfo *a_stream, struct maat *feather, char *property, char *district, struct maat_state *s_mid, struct maat_rule *results, int n_results);
size_t tsg_scan_tunnel_id(const struct streaminfo *a_stream, struct maat *feather, struct maat_rule *results, size_t n_results, struct maat_state *s_mid, long long *bool_id_array, size_t n_bool_id_array);
size_t tsg_scan_fqdn_category_id(const struct streaminfo * a_stream, struct maat *feather, unsigned int *category_id, int category_id_num, int table_idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);

int tsg_scan_intercept_exclusion(const struct streaminfo *a_stream, struct maat *feather, struct maat_rule *p_result, char *domain, int thread_seq);

struct maat_rule *tsg_select_deny_rule(struct maat_rule *rules, size_t n_rules);

struct umts_user_info *tsg_get_umts_user_info_form_redis(struct maat *feather, long long teid);
