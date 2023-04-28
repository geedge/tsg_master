#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <MESA/field_stat2.h>
#include <MESA/fieldstat.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"

struct tsg_statistic g_tsg_statis_para;

enum metric_columns_index
{
	COLUMN_HIT_COUNT = 0,
	COLUMN_IN_BYTES,
	COLUMN_OUT_BYTES,
	COLUMN_IN_PKTS,
	COLUMN_OUT_PKTS,
	COLUMN_MAX
};

enum metric_tags_index
{
	TAG_RULE_ID = 0,
	TAG_ACTION,
	TAG_VSYS_ID,
	TAG_MAX
};

enum field_type metric_column_type[COLUMN_MAX] = {FIELD_TYPE_COUNTER, FIELD_TYPE_COUNTER, FIELD_TYPE_COUNTER, FIELD_TYPE_COUNTER, FIELD_TYPE_COUNTER};
const char *metric_column_field[COLUMN_MAX] = {"hit_count", "in_bytes", "out_bytes", "in_pkts", "out_pkts"};
unsigned int metric_column_array[COLUMN_MAX] = {0};
struct fieldstat_tag g_metric_tags[TAG_MAX] = {{"rule_id", 0, -1}, {"action", 0, -1}, {"vsys_id", 0, -1}};

struct fieldstat_tag *tsg_set_metric_tags(struct maat_rule *p_result, int thread_seq)
{
	g_tsg_statis_para.metric_tags[thread_seq][TAG_RULE_ID].value_int = p_result->rule_id;
	g_tsg_statis_para.metric_tags[thread_seq][TAG_ACTION].value_int = p_result->action;
	g_tsg_statis_para.metric_tags[thread_seq][TAG_VSYS_ID].value_int = p_result->vsys_id;

	return g_tsg_statis_para.metric_tags[thread_seq];
}

int tsg_metric_tsgs_init(int thread_num)
{
	g_tsg_statis_para.metric_tags = (struct fieldstat_tag **)calloc(thread_num, sizeof(struct fieldstat_tag *));
	for (int i = 0; i < thread_num; i++)
	{
		g_tsg_statis_para.metric_tags[i] = (struct fieldstat_tag *)calloc((size_t)TAG_MAX, sizeof(struct fieldstat_tag));
		memcpy(g_tsg_statis_para.metric_tags[i], g_metric_tags, sizeof(struct fieldstat_tag) * (size_t)TAG_MAX);
	}

	return 0;
}

int tsg_metric_tsgs_free(int thread_num)
{
	for (int i = 0; i < thread_num; i++)
	{
		if (g_tsg_statis_para.metric_tags[i])
		{
			free(g_tsg_statis_para.metric_tags[i]);
			g_tsg_statis_para.metric_tags[i] = NULL;
		}
	}

	free(g_tsg_statis_para.metric_tags);
	g_tsg_statis_para.metric_tags = NULL;

	return 0;
}

int tsg_set_statistic_opt(int value, enum _STATISTIC_OPT_TYPE type, int thread_seq)
{
	switch(type)
	{
		case	OPT_TYPE_ALERT_BYTES:
		case	OPT_TYPE_BLOCK_BYTES:
		case	OPT_TYPE_PINNING_YES:
		case	OPT_TYPE_PINNING_NOT:
		case	OPT_TYPE_PINNING_MAYBE:
			atomic_add(&(g_tsg_statis_para.statistic_opt[type]), value);
			break;
		default:
			break;
	}

	return 0;
}

int tsg_set_intercept_flow(struct maat_rule *p_result, struct _traffic_info *traffic_info, int thread_seq)
{
	if (p_result == NULL || traffic_info == NULL || thread_seq < 0 || thread_seq >= get_thread_count() || p_result->action != TSG_ACTION_INTERCEPT)
	{
		return -1;
	}

	struct _traffic_info *_info = NULL;
	struct fieldstat_tag *metric_tags = tsg_set_metric_tags(p_result, thread_seq);
	if (metric_tags == NULL)
	{
		return -1;
	}

	_info = &(g_tsg_statis_para.traffic_info[(unsigned char)p_result->action][thread_seq]);

	_info->con_num += traffic_info->con_num;
	_info->in_bytes += traffic_info->in_bytes;
	_info->in_packets += traffic_info->in_packets;
	_info->out_bytes += traffic_info->out_bytes;
	_info->out_packets += traffic_info->out_packets;

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_HIT_COUNT], "security_rule_hits", traffic_info->con_num, metric_tags, (size_t)TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_IN_BYTES], "security_rule_hits", traffic_info->in_bytes, metric_tags, (size_t)TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_OUT_BYTES], "security_rule_hits", traffic_info->out_bytes, metric_tags, (size_t)TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_IN_PKTS], "security_rule_hits", traffic_info->in_packets, metric_tags, (size_t)TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_OUT_PKTS], "security_rule_hits", traffic_info->out_packets, metric_tags, (size_t)TAG_MAX, thread_seq);

	return 0;
}

int tsg_set_policy_flow(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq)
{
	if (a_stream == NULL || p_result == NULL || thread_seq < 0 || thread_seq >= get_thread_count())
	{
		return -1;
	}

	unsigned long long value = 0;
	int value_len = sizeof(unsigned long long);
	struct _traffic_info *traffic_info = NULL;

	traffic_info=&(g_tsg_statis_para.traffic_info[(unsigned char)p_result->action][thread_seq]);

	struct fieldstat_tag *metric_tags = tsg_set_metric_tags(p_result, thread_seq);
	if (metric_tags == NULL)
	{
		return -1;
	}

	traffic_info->con_num++;
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_HIT_COUNT], "security_rule_hits", 1, metric_tags, (size_t)TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_BYTE_RAW, (void *)&value, &value_len);
	traffic_info->in_bytes+=value;
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_IN_BYTES], "security_rule_hits", value, metric_tags, (size_t)TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
	traffic_info->in_packets+=value;
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_IN_PKTS], "security_rule_hits", value, metric_tags, (size_t)TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_BYTE_RAW, (void *)&value, &value_len);	
	traffic_info->out_bytes+=value;
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_OUT_BYTES], "security_rule_hits", value, metric_tags, (size_t)TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
	traffic_info->out_packets+=value;
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_table_id, metric_column_array[COLUMN_OUT_PKTS], "security_rule_hits", value, metric_tags, (size_t)TAG_MAX, thread_seq);

	return 0;
}

static int _get_traffic_info(struct _traffic_info *total, struct _traffic_info *policy, struct _traffic_info *out)
{
	struct _traffic_info *acc=NULL;
	
	if(total!=NULL && policy!=NULL && out!=NULL)
	{
		out->con_num=total->con_num-policy->con_num;
		out->in_bytes=total->in_bytes-policy->in_bytes;
		out->in_packets=total->in_packets-policy->in_packets;
		out->out_bytes=total->out_bytes-policy->out_bytes;
		out->out_packets=total->out_packets-policy->out_packets;

		acc=&g_tsg_statis_para.default_total_info;

		out->con_num=(out->con_num-acc->con_num)>0 ? out->con_num : acc->con_num;
		out->in_bytes=(out->in_bytes-acc->in_bytes)>0 ? out->in_bytes: acc->in_bytes;
		out->in_packets=(out->in_packets-acc->in_packets)>0 ? out->in_packets: acc->in_packets;
		out->out_bytes=(out->out_bytes-acc->out_bytes)>0 ? out->out_bytes: acc->out_bytes;
		out->out_packets=(out->out_packets-acc->out_packets)>0 ? out->out_packets: acc->out_packets;

		memcpy(acc, out, sizeof(struct _traffic_info));
	}
	
	return 0;
}

static int _set_traffic_info(struct _traffic_info *from, struct _traffic_info *to, int action, int thread_num)
{
	tsg_statis_field_id_t con_num_id=STATIS_UNKNOWN;
	tsg_statis_field_id_t in_bytes_id=STATIS_UNKNOWN;
	tsg_statis_field_id_t in_packets_id=STATIS_UNKNOWN;
	tsg_statis_field_id_t out_bytes_id=STATIS_UNKNOWN;
	tsg_statis_field_id_t out_packets_id=STATIS_UNKNOWN;

	long long con_num_sum=0;
	long long in_bytes_sum=0,in_packets_sum=0;
	long long out_bytes_sum=0,out_packets_sum=0;

	for(int i=0; i<thread_num; i++)
	{
		con_num_sum+=from[i].con_num;
		in_bytes_sum+=from[i].in_bytes;
		in_packets_sum+=from[i].in_packets;
		out_bytes_sum+=from[i].out_bytes;
		out_packets_sum+=from[i].out_packets;
	}

	if(to!=NULL)
	{
		to->con_num+=con_num_sum;
		to->in_bytes+=in_bytes_sum;
		to->in_packets+=in_packets_sum;
		to->out_bytes+=out_bytes_sum;
		to->out_packets+=out_packets_sum;
	}

	switch(action)
	{
		case	TSG_ACTION_BYPASS:
			con_num_id=STATIS_ALLOW_CON_NUM;
			in_bytes_id=STATIS_ALLOW_IN_BYTES;
			in_packets_id=STATIS_ALLOW_IN_PACKETS;
			out_bytes_id=STATIS_ALLOW_OUT_BYTES;
			out_packets_id=STATIS_ALLOW_OUT_PACKETS;
			break;
		case	TSG_ACTION_DENY:
			con_num_id=STATIS_DENY_CON_NUM;
			in_bytes_id=STATIS_DENY_IN_BYTES;
			in_packets_id=STATIS_DENY_IN_PACKETS;
			out_bytes_id=STATIS_DENY_OUT_BYTES;
			out_packets_id=STATIS_DENY_OUT_PACKETS;
			break;
		case	TSG_ACTION_MONITOR:
			con_num_id=STATIS_MONITOR_CON_NUM;
			in_bytes_id=STATIS_MONITOR_IN_BYTES;
			in_packets_id=STATIS_MONITOR_IN_PACKETS;
			out_bytes_id=STATIS_MONITOR_OUT_BYTES;
			out_packets_id=STATIS_MONITOR_OUT_PACKETS;
			break;
		case	TSG_ACTION_INTERCEPT:
			con_num_id=STATIS_INTERCEPT_CON_NUM;
			in_bytes_id=STATIS_INTERCEPT_IN_BYTES;
			in_packets_id=STATIS_INTERCEPT_IN_PACKETS;
			out_bytes_id=STATIS_INTERCEPT_OUT_BYTES;
			out_packets_id=STATIS_INTERCEPT_OUT_PACKETS;
			break;
		case	TSG_ACTION_NONE:
			con_num_id=STATIS_DEFAULT_CON_NUM;
			in_bytes_id=STATIS_DEFAULT_IN_BYTES;
			in_packets_id=STATIS_DEFAULT_IN_PACKETS;
			out_bytes_id=STATIS_DEFAULT_OUT_BYTES;
			out_packets_id=STATIS_DEFAULT_OUT_PACKETS;
			break;
		case	-1:
			con_num_id=STATIS_NEW_CON_NUM;
			in_bytes_id=STATIS_TOTAL_IN_BYTES;
			in_packets_id=STATIS_TOTAL_IN_PACKETS;
			out_bytes_id=STATIS_TOTAL_OUT_BYTES;
			out_packets_id=STATIS_TOTAL_OUT_PACKETS;
			break;
		default:
			return 0;
			break;
	}

	fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[con_num_id], con_num_sum);
	fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[in_bytes_id], in_bytes_sum);
	fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[in_packets_id], in_packets_sum);
	fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[out_bytes_id], out_bytes_sum);
	fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[out_packets_id], out_packets_sum);

	return 0;
}
static void *tsg_statistic_thread(void *arg)
{
	int thread_num=get_thread_count();
	struct _traffic_info policy_traffic_info;
	struct _traffic_info total_traffic_info;
	struct _traffic_info default_traffic_info;

	fieldstat_instance_start(g_tsg_statis_para.statistic_handle);

	while(g_tsg_statis_para.thread_alive)
	{
		long long value=0;
		long long total_value=0;
		int value_len=sizeof(long long);

		memset(&policy_traffic_info, 0, sizeof(policy_traffic_info));
		memset(&total_traffic_info, 0, sizeof(total_traffic_info));
		memset(&default_traffic_info, 0, sizeof(default_traffic_info));

		_set_traffic_info(g_tsg_statis_para.traffic_info[TSG_ACTION_BYPASS], &policy_traffic_info, TSG_ACTION_BYPASS, thread_num);
		_set_traffic_info(g_tsg_statis_para.traffic_info[TSG_ACTION_DENY], &policy_traffic_info, TSG_ACTION_DENY, thread_num);
		_set_traffic_info(g_tsg_statis_para.traffic_info[TSG_ACTION_MONITOR], &policy_traffic_info, TSG_ACTION_MONITOR, thread_num);
		_set_traffic_info(g_tsg_statis_para.traffic_info[TSG_ACTION_INTERCEPT], &policy_traffic_info, TSG_ACTION_INTERCEPT, thread_num);
		
		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_ESTAB, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CONCURRENT, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_ESTABLISHED_CON_NUM], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_CLOSE_CON_NUM], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_NEW, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_TCP_NEW_CON_NUM], total_value);

		total_value+=value;
		
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_TCP_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_TCP_IN_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_TCP_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_TCP_IN_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_TCP_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_TCP_OUT_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_TCP_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_TCP_OUT_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_NEW, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_UDP_NEW_CON_NUM], value);

		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_NEW_CON_NUM], total_value);
		total_traffic_info.con_num+=total_value;

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_UDP_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_UDP_IN_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_UDP_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_UDP_IN_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_UDP_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_UDP_OUT_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_UDP_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_UDP_OUT_BYTES], value);

		value_len=sizeof(total_traffic_info.in_bytes);
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, (void *)&total_traffic_info.in_bytes, &value_len);
		value_len=sizeof(total_traffic_info.in_packets);
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, (void *)&total_traffic_info.in_packets, &value_len);

		value_len=sizeof(total_traffic_info.out_bytes);
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, (void *)&total_traffic_info.out_bytes, &value_len);
		value_len=sizeof(total_traffic_info.out_packets);
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, (void *)&total_traffic_info.out_packets, &value_len);

		_set_traffic_info(&total_traffic_info, NULL, -1, 1);
		
		_get_traffic_info(&total_traffic_info, &policy_traffic_info, &default_traffic_info);
		_set_traffic_info(&default_traffic_info, NULL, TSG_ACTION_NONE, 1);

		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_ALERT_BYTES], g_tsg_statis_para.statistic_opt[OPT_TYPE_ALERT_BYTES]);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_BLOCK_BYTES], g_tsg_statis_para.statistic_opt[OPT_TYPE_BLOCK_BYTES]);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_PINNING_NUM], g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_YES]);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_MAYBE_PINNING_NUM], g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_MAYBE]);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_NOT_PINNING_NUM], g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_NOT]);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV4_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV4_IN_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV4_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV4_IN_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV4_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV4_OUT_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV4_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV4_OUT_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV6_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV6_IN_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV6_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV6_IN_BYTES], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV6_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV6_OUT_PACKETS], value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV6_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IPV6_OUT_BYTES], value);

		fieldstat_passive_output(g_tsg_statis_para.statistic_handle);

		sleep(g_tsg_statis_para.cycle);
	}

	return NULL;
}

int tsg_statistic_metric_init(const char *conffile, void *logger)
{
	if (conffile == NULL || logger == NULL)
	{
		return -1;
	}

	unsigned short fs_server_port=0;
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char app_name[128]={0};
	int thread_num = get_thread_count();

	MESA_load_profile_short_nodef(conffile, "SECURITY_HITS", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"SECURITY_HITS", "TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"SECURITY_HITS", "APP_NAME", app_name, sizeof(app_name), "metric");
	MESA_load_profile_int_def(conffile, "SECURITY_HITS", "CYCLE", &g_tsg_statis_para.metric_cycle, 1000);
	if(g_tsg_statis_para.metric_cycle<=0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "SECURITY_HITS", "g_tsg_statis_para.metric_cycle error");
		return -1;
	}

	g_tsg_statis_para.metric_handle = fieldstat_dynamic_instance_new(app_name, thread_num);
	if(g_tsg_statis_para.metric_handle==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "SECURITY_HITS", "g_tsg_statis_para.metric_handle error");
		return -1;
	}

	fieldstat_dynamic_set_output_interval(g_tsg_statis_para.metric_handle, g_tsg_statis_para.metric_cycle);
	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_dynamic_set_line_protocol_server(g_tsg_statis_para.metric_handle, fs_server_ip, fs_server_port);
	}

	g_tsg_statis_para.metric_table_id = fieldstat_register_dynamic_table(g_tsg_statis_para.metric_handle, "security_rule_hits", metric_column_field, metric_column_type, (size_t)COLUMN_MAX, metric_column_array);
	if(g_tsg_statis_para.metric_table_id<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "SECURITY_HITS", "g_tsg_statis_para.metric_table_id error");
		return -1;
	}

	tsg_metric_tsgs_init(thread_num);

	fieldstat_dynamic_instance_start(g_tsg_statis_para.metric_handle);

	return 0;
}

int tsg_statistic_init(const char *conffile, void *logger)
{
	// int output_prometheus=0;
	// unsigned short prometheus_port = 8093;
	int i = 0, thread_num = 0;
	unsigned short fs_server_port = 0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	memset(&g_tsg_statis_para, 0, sizeof(g_tsg_statis_para));

	thread_num=get_thread_count();
	for(i=0; i<TSG_ACTION_MAX+1; i++)
	{
		g_tsg_statis_para.traffic_info[i]=(struct _traffic_info *)calloc(1, sizeof(struct _traffic_info)*thread_num);
	}

	MESA_load_profile_int_def(conffile, "STATISTIC", "CYCLE", &g_tsg_statis_para.cycle, 1);
	if(g_tsg_statis_para.cycle<=0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "STATISTIC", "Disabale traffic statistic");
		return 0;
	}

	MESA_load_profile_short_nodef(conffile, "STATISTIC", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"STATISTIC", "TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"STATISTIC", "OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "statistic.log");
	MESA_load_profile_string_def(conffile, "STATISTIC", "APP_NAME", app_name, sizeof(app_name), "network_activity");
	// MESA_load_profile_int_def(conffile, "STATISTIC", "PROMETHEUS", &output_prometheus, 1);
	// MESA_load_profile_short_nodef(conffile, "STATISTIC", "PROMETHEUS_PORT", (short *)&(prometheus_port));

	g_tsg_statis_para.statistic_handle = fieldstat_instance_new(app_name);
	g_tsg_statis_para.thread_alive=1;

	fieldstat_disable_background_thread(g_tsg_statis_para.statistic_handle);

	fieldstat_set_output_interval(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.cycle * 1000);
	fieldstat_set_local_output(g_tsg_statis_para.statistic_handle, fs_output_path, "default");

	// if (output_prometheus == 1)
	// {
	// 	fieldstat_enable_prometheus_output(g_tsg_statis_para.statistic_handle);
	// 	fieldstat_global_enable_prometheus_endpoint(prometheus_port, "/metrics");
	// }

	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_set_line_protocol_server(g_tsg_statis_para.statistic_handle, fs_server_ip, fs_server_port);
	}

	const char *static_column_name[STATIS_MAX] = {"", "", "", "new_conn_num", "established_conn_num", "close_conn_num", "total_in_bytes", "total_out_bytes", "total_in_packets", "total_out_packets",
												  "default_conn_num", "default_in_bytes", "default_out_bytes", "default_in_packets", "default_out_packets",
												  "allow_conn_num", "allow_in_bytes", "allow_out_bytes", "allow_in_packets", "allow_out_packets",
												  "deny_conn_num", "deny_in_bytes", "deny_out_bytes", "deny_in_packets", "deny_out_packets",
												  "monitor_conn_num", "monitor_in_bytes", "monitor_out_bytes", "monitor_in_packets", "monitor_out_packets",
												  "intercept_conn_num", "intercept_in_bytes", "intercept_out_bytes", "intercept_in_packets", "intercept_out_packets",
												  "ipv4_in_packets", "ipv4_in_bytes", "ipv4_out_packets", "ipv4_out_bytes",
												  "ipv6_in_packets", "ipv6_in_bytes", "ipv6_out_packets", "ipv6_out_bytes",
												  "tcp_conn_num", "tcp_in_packets", "tcp_in_bytes", "tcp_out_packets", "tcp_out_bytes",
												  "udp_conn_num", "udp_in_packets", "udp_in_bytes", "udp_out_packets", "udp_out_bytes",
												  "alert_bytes", "block_bytes", "pinning_num", "maybe_pinning_num", "not_pinning_num"};

	enum field_type static_column_type[STATIS_MAX] = {FIELD_TYPE_COUNTER};
	static_column_type[STATIS_ESTABLISHED_CON_NUM] = FIELD_TYPE_GAUGE;

	g_tsg_statis_para.static_table_id = fieldstat_register_table(g_tsg_statis_para.statistic_handle, app_name, static_column_name + STATIS_NEW_CON_NUM, static_column_type + STATIS_NEW_CON_NUM, (size_t)(STATIS_MAX - STATIS_NEW_CON_NUM));
	fieldstat_register_table_row(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_table_id, (const char *)"TRAFFIC", NULL, 0, g_tsg_statis_para.static_column_id + STATIS_NEW_CON_NUM);

	int ret=tsg_statistic_metric_init(conffile, logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "INIT_METRIC", "tsg_statistic_metric_init failed ...");
		return -1;
	}

	pthread_create(&g_tsg_statis_para.stat_thread_id, NULL, tsg_statistic_thread, NULL);
	
	return 0;
}

void tsg_statistic_metric_destroy(void)
{
	tsg_metric_tsgs_free(get_thread_count());
	return;
}

void tsg_statistic_destroy(void)
{
	pthread_cancel(g_tsg_statis_para.stat_thread_id);
	g_tsg_statis_para.thread_alive=0;
	sleep(g_tsg_statis_para.cycle);
	fieldstat_instance_free(g_tsg_statis_para.statistic_handle);

	tsg_statistic_metric_destroy();
	return ;
}

