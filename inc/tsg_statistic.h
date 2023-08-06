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

struct traffic_info
{
	long long con_num;
	long long in_bytes;
	long long out_bytes;
	long long in_packets;
	long long out_packets;
};

struct traffic_packet_info
{
	uint64_t sessions;
	uint64_t in_pkts;
	uint64_t out_pkts;
	uint64_t c2s_pkts;
	uint64_t s2c_pkts;
	uint64_t c2s_fragments;
	uint64_t s2c_fragments;	
	uint64_t c2s_tcp_ooorder_pkts;
	uint64_t s2c_tcp_ooorder_pkts;
	uint64_t c2s_tcp_retransmitted_pkts;
	uint64_t s2c_tcp_retransmitted_pkts;
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint64_t c2s_bytes;
	uint64_t s2c_bytes;
	uint64_t c2s_tcp_lost_bytes;
	uint64_t s2c_tcp_lost_bytes;
	uint64_t c2s_tcp_retransmitted_bytes;
	uint64_t s2c_tcp_retransmitted_bytes;
};

int tsg_set_policy_flow(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_intercept_flow(struct maat_rule *p_result, struct traffic_info *traffic_info, int thread_seq);
int tsg_set_statistic_opt(int value, enum _STATISTIC_OPT_TYPE type, int thread_seq);

int tsg_set_application_metrics(const struct streaminfo *a_stream, const char *l4_protocol, const char *app_full_path, struct traffic_packet_info *app_statis, int thread_seq);

//statistics policy
int tsg_set_statistics_policy(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);

int tsg_set_statistics_fqdn(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_statistics_fqdn_category(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_statistics_client_object(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_statistics_server_object(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);
int tsg_set_statistics_application(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq);

// statistics object
int tsg_set_statistics_object(const struct streaminfo *a_stream, struct maat_hit_group *group, long long *item_id, int n_item_id, int thread_seq);


#endif
