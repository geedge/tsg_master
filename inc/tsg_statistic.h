#ifndef	__TSG_STATISTIC_H__
#define	__TSG_STATISTIC_H__

struct _traffic_info
{
	long long con_num;
	long long in_bytes;
	long long out_bytes;
	long long in_packets;
	long long out_packets;
};

int tsg_set_policy_flow(struct streaminfo *a_stream, Maat_rule_t *p_result, int thread_seq);
int tsg_set_intercept_flow(Maat_rule_t *p_result, struct _traffic_info *traffic_info, int thread_seq);

#endif
