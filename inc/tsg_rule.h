#ifndef	__TSG_RULE_H__
#define	__TSG_RULE_H__

#include <MESA/Maat_rule.h>
#include "tsg_types.h"

#ifdef __cplusplus
extern "C"
{
#endif


typedef	enum _PULL_RESULT_TYPE
{
	PULL_KNI_RESULT,
	PULL_FW_RESULT
}PULL_RESULT_TYPE;

extern Maat_feather_t g_tsg_maat_feather;


int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num);

//return 0 if failed, return >0 on success;
int tsg_pull_policy_result(PULL_RESULT_TYPE pull_result_type, Maat_rule_t *result, int result_num);

//return -1 if failed, return 0 on success;
int tsg_shared_table_init(const char *conffile, Maat_feather_t maat_feather, void *logger);

//return -1 if failed, return 0 on success;
int tsg_scan_shared_policy(Maat_feather_t maat_feather, void *pkt, int pkt_len, Maat_rule_t *result, int result_num, scan_status_t *mid, void *logger, int thread_seq);


#ifdef __cplusplus
}
#endif

#endif
