#ifndef	__TSG_STATISTIC_H__
#define	__TSG_STATISTIC_H__

enum _STATISTIC_OPT_TYPE
{
	OPT_TYPE_ALERT_BYTES,
	OPT_TYPE_BLOCK_BYTES,
	OPT_TYPE_PINNING_YES,
	OPT_TYPE_PINNING_MAYBE,
	OPT_TYPE_PINNING_NOT,
	_OPT_TYPE_MAX
};

struct _traffic_info
{
	long long con_num;
	long long in_bytes;
	long long out_bytes;
	long long in_packets;
	long long out_packets;
};

int tsg_set_policy_flow(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_intercept_flow(struct maat_rule *p_result, struct _traffic_info *traffic_info, int thread_seq);
int tsg_set_statistic_opt(int value, enum _STATISTIC_OPT_TYPE type, int thread_seq);

#endif
