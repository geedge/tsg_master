#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <MESA/fieldstat.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"

struct tsg_statistic g_tsg_statis_para;

enum security_metric_tags
{
	SECURITY_TAG_RULE_ID = 0,
	SECURITY_TAG_ACTION,
	SECURITY_TAG_VSYS_ID,
	SECURITY_TAG_MAX
};

enum traffic_metric_tags
{
	TRAFFIC_TAG_VSYS_ID = 0,
	TRAFFIC_TAG_MAX
};

enum app_metric_tags
{
	APP_TAG_VSYS_ID = 0,
	APP_TAG_PROTOCOL_LABEL,
	APP_TAG_APP_FULL_PATH,
	APP_TAG_MAX
};

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

int tsg_set_intercept_flow(struct maat_rule *p_result, struct traffic_info *traffic_info, int thread_seq)
{
	if (p_result == NULL || traffic_info == NULL || thread_seq < 0 || thread_seq >= get_thread_count() || p_result->service_id != TSG_SERVICE_INTERCEPT)
	{
		return -1;
	}

	struct fieldstat_tag security_tags[SECURITY_TAG_MAX] = {{"rule_id", 0, -1}, {"action", 0, -1}, {"vsys_id", 0, -1}};
	security_tags[SECURITY_TAG_RULE_ID].value_int = p_result->rule_id;
	security_tags[SECURITY_TAG_ACTION].value_int = p_result->action;
	security_tags[SECURITY_TAG_VSYS_ID].value_int = p_result->vsys_id;

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_HIT_COUNT], "security_rule_hits", traffic_info->con_num, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_IN_BYTES], "security_rule_hits", traffic_info->in_bytes, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_OUT_BYTES], "security_rule_hits", traffic_info->out_bytes, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_IN_PKTS], "security_rule_hits", traffic_info->in_packets, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_OUT_PKTS], "security_rule_hits", traffic_info->out_packets, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

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

	struct fieldstat_tag security_tags[SECURITY_TAG_MAX] = {{"rule_id", 0, -1}, {"action", 0, -1}, {"vsys_id", 0, -1}};
	security_tags[SECURITY_TAG_RULE_ID].value_int = p_result->rule_id;
	security_tags[SECURITY_TAG_ACTION].value_int = p_result->action;
	security_tags[SECURITY_TAG_VSYS_ID].value_int = p_result->vsys_id;

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_HIT_COUNT], "security_rule_hits", 1, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_BYTE_RAW, (void *)&value, &value_len);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_IN_BYTES], "security_rule_hits", value, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_IN_PKTS], "security_rule_hits", value, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_BYTE_RAW, (void *)&value, &value_len);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_OUT_BYTES], "security_rule_hits", value, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_table_id, g_tsg_statis_para.security_column_ids[COLUMN_OUT_PKTS], "security_rule_hits", value, security_tags, (size_t)SECURITY_TAG_MAX, thread_seq);

	return 0;
}

static void *tsg_statistic_thread(void *arg)
{
	fieldstat_instance_start(g_tsg_statis_para.statistic_handle);

	while(g_tsg_statis_para.thread_alive)
	{
		long long value=0;
		long long total_value=0;
		int value_len=sizeof(long long);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_ESTAB, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CONCURRENT, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_ACTIVE_SESSIONS], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_CLOSE_SESSIONS], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_NEW, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_NEW, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_SESSIONS], total_value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IN_BYTES], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_IN_PACKETS], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_OUT_BYTES], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIS_OUT_PACKETS], value);

		value = 0;
		total_value = 0;
		sapp_get_platform_opt(SPO_TCP_STREAM_C2S, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_C2S, (void *)&value, &value_len);
		total_value += value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIC_ASYMMETRIC_C2S_FLOWS], total_value);

		value = 0;
		total_value = 0;
		sapp_get_platform_opt(SPO_TCP_STREAM_S2C, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_S2C, (void *)&value, &value_len);
		total_value += value;
		fieldstat_value_set(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_column_id[STATIC_ASYMMETRIC_S2C_FLOWS], total_value);

		fieldstat_passive_output(g_tsg_statis_para.statistic_handle);

		sleep(g_tsg_statis_para.cycle);
	}

	return NULL;
}

int tsg_set_application_metrics(const struct streaminfo *a_stream, const char *l4_protocol, const char *app_full_path, struct traffic_packet_info *app_statis, int thread_seq)
{
	if (a_stream == NULL || l4_protocol == NULL || app_full_path == NULL || app_statis == NULL)
	{
			return -1;
	}

	struct fieldstat_tag app_tags[APP_TAG_MAX] = {{"vsys_id", 0, -1}, {"protocol_label", 2, 0}, {"app_full_path", 2, 0}};
	app_tags[APP_TAG_VSYS_ID].value_int = g_tsg_statis_para.vsystem_id;
	app_tags[APP_TAG_PROTOCOL_LABEL].value_str = l4_protocol;
	app_tags[APP_TAG_APP_FULL_PATH].value_str = app_full_path;

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_SESSIONS], "traffic_application_protocol_stat",
												app_statis->sessions, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_IN_BYTES], "traffic_application_protocol_stat",
												app_statis->in_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_IN_PKTS], "traffic_application_protocol_stat",
												app_statis->in_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_OUT_BYTES], "traffic_application_protocol_stat",
												app_statis->out_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_OUT_PKTS], "traffic_application_protocol_stat",
												app_statis->out_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_PKTS], "traffic_application_protocol_stat",
												app_statis->c2s_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_PKTS], "traffic_application_protocol_stat",
												app_statis->s2c_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_BYTES], "traffic_application_protocol_stat",
												app_statis->c2s_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_BYTES], "traffic_application_protocol_stat",
												app_statis->s2c_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_FRAGMENTS], "traffic_application_protocol_stat",
												app_statis->c2s_fragments, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_FRAGMENTS], "traffic_application_protocol_stat",
												app_statis->s2c_fragments, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_LOST_BYTES], "traffic_application_protocol_stat",
												app_statis->c2s_tcp_lost_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_LOST_BYTES], "traffic_application_protocol_stat",
												app_statis->s2c_tcp_lost_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_ORDER_PKTS], "traffic_application_protocol_stat",
												app_statis->c2s_tcp_ooorder_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_ORDER_PKTS], "traffic_application_protocol_stat",
												app_statis->s2c_tcp_ooorder_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_RETRANSMITTED_PKTS], "traffic_application_protocol_stat",
												app_statis->c2s_tcp_retransmitted_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_RETRANSMITTED_PKTS], "traffic_application_protocol_stat",
												app_statis->s2c_tcp_retransmitted_pkts, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_C2S_RETRANSMITTED_BYTES], "traffic_application_protocol_stat",
												app_statis->c2s_tcp_retransmitted_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	fieldstat_dynamic_table_metric_value_incrby(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_table_id, g_tsg_statis_para.app_column_ids[TRAFFIC_APP_S2C_RETRANSMITTED_BYTES], "traffic_application_protocol_stat",
												app_statis->s2c_tcp_retransmitted_bytes, app_tags, (size_t)APP_TAG_MAX, thread_seq);

	return 0;
}

int tsg_security_metric_init(const char *conffile, void *logger)
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

	g_tsg_statis_para.security_metric_handle = fieldstat_dynamic_instance_new(app_name, thread_num);
	if (g_tsg_statis_para.security_metric_handle == NULL)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "SECURITY_HITS", "g_tsg_statis_para.security_metric_handle error");
			return -1;
	}

	fieldstat_dynamic_set_output_interval(g_tsg_statis_para.security_metric_handle, g_tsg_statis_para.metric_cycle);
	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
			fieldstat_dynamic_set_line_protocol_server(g_tsg_statis_para.security_metric_handle, fs_server_ip, fs_server_port);
	}

	enum field_type security_metric_type[COLUMN_MAX] = {FIELD_TYPE_COUNTER};
	const char *security_metric_field[COLUMN_MAX] = {"hit_count", "in_bytes", "out_bytes", "in_pkts", "out_pkts"};
	g_tsg_statis_para.metric_table_id = fieldstat_register_dynamic_table(g_tsg_statis_para.security_metric_handle, "security_rule_hits", security_metric_field, security_metric_type, (size_t)COLUMN_MAX, g_tsg_statis_para.security_column_ids);
	if(g_tsg_statis_para.metric_table_id<0)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "SECURITY_HITS", "g_tsg_statis_para.metric_table_id error");
			return -1;
	}

	fieldstat_dynamic_instance_start(g_tsg_statis_para.security_metric_handle);

	return 0;
}

int tsg_traffic_metric_init(const char *conffile, void *logger)
{
	if (conffile == NULL || logger == NULL)
	{
			return -1;
	}

	unsigned short fs_server_port = 0;
	char fs_server_ip[MAX_IPV4_LEN] = {0};
	char app_name[128] = {0};
	int thread_num = get_thread_count();

	MESA_load_profile_short_nodef(conffile, "APP_METRIC", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile, "APP_METRIC", "TELEGRAF_IP", fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile, "APP_METRIC", "APP_NAME", app_name, sizeof(app_name), "app_metric");
	MESA_load_profile_int_def(conffile, "APP_METRIC", "CYCLE", &g_tsg_statis_para.app_metric_cycle, 1000);

	if (g_tsg_statis_para.app_metric_cycle <= 0)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "APP_METRIC", "g_tsg_statis_para.app_metric_cycle error");
			return -1;
	}

	g_tsg_statis_para.app_metric_handle = fieldstat_dynamic_instance_new(app_name, thread_num);
	if (g_tsg_statis_para.app_metric_handle == NULL)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "APP_METRIC", "g_tsg_statis_para.app_metric_handle error");
			return -1;
	}

	fieldstat_dynamic_set_output_interval(g_tsg_statis_para.app_metric_handle, g_tsg_statis_para.app_metric_cycle);
	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
			fieldstat_dynamic_set_line_protocol_server(g_tsg_statis_para.app_metric_handle, fs_server_ip, fs_server_port);
	}

	enum field_type app_metric_type[TRAFFIC_APP_MAX] = {FIELD_TYPE_COUNTER};
	const char *app_metric_field[TRAFFIC_APP_MAX] = {"sessions", "in_bytes", "out_bytes", "in_pkts", "out_pkts", "c2s_pkts", "s2c_pkts", "c2s_bytes", "s2c_bytes", "c2s_fragments", "s2c_fragments",
													 "c2s_tcp_lost_bytes", "s2c_tcp_lost_bytes", "c2s_tcp_ooorder_pkts", "s2c_tcp_ooorder_pkts", "c2s_tcp_retransmitted_pkts", "s2c_tcp_retransmitted_pkts",
													 "c2s_tcp_retransmitted_bytes", "s2c_tcp_retransmitted_bytes"};
	g_tsg_statis_para.app_metric_table_id = fieldstat_register_dynamic_table(g_tsg_statis_para.app_metric_handle, "traffic_application_protocol_stat", app_metric_field, app_metric_type, (size_t)TRAFFIC_APP_MAX, g_tsg_statis_para.app_column_ids);
	if (g_tsg_statis_para.app_metric_table_id < 0)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "APP_METRIC", "g_tsg_statis_para.app_metric_table_id error");
			return -1;
	}

	fieldstat_dynamic_instance_start(g_tsg_statis_para.app_metric_handle);
	return 0;
}

int tsg_metric_init(const char *conffile, void *logger)
{
	unsigned short fs_server_port = 0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	memset(&g_tsg_statis_para, 0, sizeof(g_tsg_statis_para));

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
	MESA_load_profile_int_def(conffile, "TSG_LOG", "VSYSTEM_ID", &(g_tsg_statis_para.vsystem_id), 1);

	g_tsg_statis_para.statistic_handle = fieldstat_instance_new(app_name);
	g_tsg_statis_para.thread_alive=1;

	fieldstat_disable_background_thread(g_tsg_statis_para.statistic_handle);

	fieldstat_set_output_interval(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.cycle * 1000);
	fieldstat_set_local_output(g_tsg_statis_para.statistic_handle, fs_output_path, "default");

	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
			fieldstat_set_line_protocol_server(g_tsg_statis_para.statistic_handle, fs_server_ip, fs_server_port);
	}

	const char *static_column_name[STATIS_MAX] = {"sessions", "active_sessions", "closed_sessions", "in_bytes", "out_bytes", "in_pkts", "out_pkts", "asymmetric_c2s_flows", "asymmetric_s2c_flows"};

	enum field_type static_column_type[STATIS_MAX] = {FIELD_TYPE_COUNTER};
	static_column_type[STATIS_ACTIVE_SESSIONS] = FIELD_TYPE_GAUGE;
	struct fieldstat_tag traffic_tags[TRAFFIC_TAG_MAX] = {{"vsys_id", 0, -1}};
	traffic_tags[TRAFFIC_TAG_VSYS_ID].value_int = g_tsg_statis_para.vsystem_id;

	g_tsg_statis_para.static_table_id = fieldstat_register_table(g_tsg_statis_para.statistic_handle, app_name, static_column_name, static_column_type, (size_t)(STATIS_MAX));
	fieldstat_register_table_row(g_tsg_statis_para.statistic_handle, g_tsg_statis_para.static_table_id, (const char *)"traffic_general_stat", traffic_tags, (size_t)TRAFFIC_TAG_MAX, g_tsg_statis_para.static_column_id);

	int ret = tsg_security_metric_init(conffile, logger);
	if(ret<0)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "INIT_METRIC", "tsg_security_metric_init failed ...");
			return -1;
	}

	ret = tsg_traffic_metric_init(conffile, logger);
	if (ret < 0)
	{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "INIT_METRIC", "tsg_traffic_metric_init failed ...");
			return -1;
	}

	pthread_create(&g_tsg_statis_para.stat_thread_id, NULL, tsg_statistic_thread, NULL);

	return 0;
}

void tsg_metric_destroy(void)
{
	pthread_cancel(g_tsg_statis_para.stat_thread_id);
	g_tsg_statis_para.thread_alive = 0;
	sleep(g_tsg_statis_para.cycle);
	fieldstat_instance_free(g_tsg_statis_para.statistic_handle);

	return;
}
