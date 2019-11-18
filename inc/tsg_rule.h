#ifndef	__TSG_RULE_H__
#define	__TSG_RULE_H__

#include <MESA/Maat_rule.h>

#ifdef __cplusplus
extern "C"
{
#endif

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

//return 0 if failed, return >0 on success;
int tsg_pull_policy_result(struct streaminfo *a_stream, PULL_RESULT_TYPE pull_result_type, Maat_rule_t *result, int result_num, struct _identify_info *identify_info);

//return -1 if failed, return 0 on success;
int tsg_shared_table_init(const char *conffile, Maat_feather_t maat_feather, void *logger);

//return value: -1: failed, 0: not hit, >0: hit count 
int tsg_scan_shared_policy(Maat_feather_t maat_feather, void *pkt, int pkt_len, Maat_rule_t *result, int result_num, struct _identify_info *identify_info, scan_status_t *mid, void *logger, int thread_seq);

#ifdef __cplusplus
}
#endif

#endif
