#ifndef	__TSG_RULE_H__
#define	__TSG_RULE_H__

#include <MESA/Maat_rule.h>

#define	TSG_ACTION_NONE			0x00
#define	TSG_ACTION_MONITOR		0x01
#define	TSG_ACTION_INTERCEPT	0x02
#define	TSG_ACTION_DENY			0x10
#define	TSG_ACTION_MANIPULATE	0x30
#define	TSG_ACTION_BYPASS		0x80
#define	TSG_ACTION_MAX			0x80

enum TSG_ETHOD_TYPE
{
	TSG_METHOD_TYPE_UNKNOWN=0,
	TSG_METHOD_TYPE_DROP,
	TSG_METHOD_TYPE_REDIRECTION,
	TSG_METHOD_TYPE_BLOCK,
	TSG_METHOD_TYPE_RESET,
	TSG_METHOD_TYPE_MAX
};


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
   PROTO_MAX
}tsg_protocol_t;


#define	MAX_RESULT_NUM	8
#define	MAX_DOAMIN_LEN	2048

struct _identify_info
{
	tsg_protocol_t proto;	//enum _tsg_protocol (tsg_types.h)
	int domain_len;
	char domain[MAX_DOAMIN_LEN];
};

typedef	enum _PULL_RESULT_TYPE
{
	PULL_KNI_RESULT,
	PULL_FW_RESULT
}PULL_RESULT_TYPE;

#define TSG_DOMAIN_MAX 	256

extern Maat_feather_t g_tsg_maat_feather;

int tsg_rule_init(const char *conffile, void *logger);

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num);

//return NULL if none exists, otherwise return one deny rule;
struct Maat_rule_t *tsg_fetch_deny_rule(Maat_rule_t *result, int result_num);

int tsg_get_method_id(char *method);

#endif
