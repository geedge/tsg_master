#ifndef	__TSG_RULE_H__
#define	__TSG_RULE_H__

#include <MESA/Maat_rule.h>

#include "tsg_label.h"

#define TSG_DOMAIN_MAX 	256
#define	MAX_APP_ID_PROPERTY_LEN	128

#define	TSG_ACTION_NONE			0x00
#define	TSG_ACTION_MONITOR		0x01
#define	TSG_ACTION_INTERCEPT	0x02
#define	TSG_ACTION_DENY			0x10
#define	TSG_ACTION_MANIPULATE	0x30
#define	TSG_ACTION_BYPASS		0x80
#define	TSG_ACTION_MAX			0x80

enum TSG_METHOD_TYPE
{
	TSG_METHOD_TYPE_UNKNOWN=0,
	TSG_METHOD_TYPE_DROP,
	TSG_METHOD_TYPE_REDIRECTION,
	TSG_METHOD_TYPE_BLOCK,
	TSG_METHOD_TYPE_RESET,
	TSG_METHOD_TYPE_ALERT,
	TSG_METHOD_TYPE_RATE_LINIT,
	TSG_METHOD_TYPE_MIRRORED,
	TSG_METHOD_TYPE_MAX
};

enum TSG_DENY_TYPE
{
	TSG_DENY_TYPE_MESSAGE=0,
	TSG_DENY_TYPE_PROFILE,
	TSG_DENY_TYPE_REDIRECT_TO,
	TSG_DENY_TYPE_MAX
};
struct identify_info
{
	tsg_protocol_t proto;	//enum _tsg_protocol (tsg_types.h)
	int domain_len;
	char domain[MAX_DOAMIN_LEN];
};

struct deny_user_region
{
	int code;
	enum TSG_DENY_TYPE type;
	union
	{
		char *message;
		char *redirect_url_to;
		int profile_id;
		int bps;
		void *para;
	};
};

struct monitor_user_region
{
	int enabled;
	int vlan_id;
};

struct compile_user_region
{	
	int ref_cnt;
	enum TSG_METHOD_TYPE method_type;
	union	
	{
		struct deny_user_region *deny;		
		struct monitor_user_region *mirror;		
		struct Maat_rule_t *result;				//XJ default policy
		void *user_region_para;
	};
};

typedef	enum _PULL_RESULT_TYPE
{
	PULL_KNI_RESULT,
	PULL_FW_RESULT,
	PULL_ALL_RESULT
}PULL_RESULT_TYPE;

struct app_id_dict_table
{
	int ref_cnt;
	int app_id;
	int parent_app_id;
	int deny_action;
	int continue_scanning;
	int tcp_timeout;
	int udp_timeout;
	int tcp_time_wait;
	int tcp_half_close;
	int is_valid;
	char risk[MAX_APP_ID_PROPERTY_LEN*4];
	char app_name[MAX_APP_ID_PROPERTY_LEN];
	char parent_app_name[MAX_APP_ID_PROPERTY_LEN];
	char category[MAX_APP_ID_PROPERTY_LEN*4];
	char subcategroy[MAX_APP_ID_PROPERTY_LEN*4];
	char technology[MAX_APP_ID_PROPERTY_LEN*4];
	char characteristics[MAX_APP_ID_PROPERTY_LEN*4];
	char depends_on_app_ids[MAX_APP_ID_PROPERTY_LEN];
	char implicitly_uses_app_ids[MAX_APP_ID_PROPERTY_LEN];
};

extern Maat_feather_t g_tsg_maat_feather;

int tsg_rule_init(const char *conffile, void *logger);

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num);
int tsg_pull_policy_result(struct streaminfo *a_stream, PULL_RESULT_TYPE pull_result_type, Maat_rule_t*result, int result_num, struct identify_info *identify_info);

//return NULL if none exists, otherwise return one deny rule;
struct Maat_rule_t *tsg_fetch_deny_rule(Maat_rule_t *result, int result_num);

enum ACTION_RETURN_TYPE
{
	ACTION_RETURN_TYPE_PROT=0,
	ACTION_RETURN_TYPE_APP
};
unsigned char tsg_deal_deny_action(const struct streaminfo *a_stream, Maat_rule_t *p_result, tsg_protocol_t protocol, enum ACTION_RETURN_TYPE type, const void *a_packet);

int tsg_get_method_id(char *method);

int tsg_free_compile_user_region(const struct Maat_rule_t *rule, struct compile_user_region *user_region);
struct compile_user_region *tsg_get_compile_user_region(const Maat_feather_t maat_feather,	struct Maat_rule_t *result);

int tsg_get_fqdn_category_id(Maat_feather_t maat_feather, char *fqdn, unsigned int *category_id, int category_id_num, void *logger, int thread_seq);
int tsg_scan_app_id_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *name, unsigned int id, int thread_seq);
int tsg_scan_fqdn_category_id(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, int table_id, unsigned int *category_id, int category_id_num, int thread_seq);
int tsg_notify_hited_monitor_result(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, int thread_seq);

#endif
