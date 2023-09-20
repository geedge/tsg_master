#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <MESA/fieldstat.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_stat.h"
#include "tsg_log.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"

enum NETWORK_TAGS
{
	NETWORK_TAG_VSYS_ID=0,
	NETWORK_TAG_MAX
};

enum NETWORK_METRICS
{
	NETWORK_SESSIONS=0,
	NETWORK_ACTIVE_SESSIONS,
	NETWORK_CLOSE_SESSIONS,
	NETWORK_IN_BYTES,
	NETWORK_OUT_BYTES,
	NETWORK_IN_PACKETS,
	NETWORK_OUT_PACKETS,
	NETWORK_ASYM_C2S_FLOWS,
	NETWORK_ASYM_S2C_FLOWS,
	NETWORK_METRIC_MAX
};

enum SECURYTY_METRICS_COLUMS
{
	SECURITY_COLUMN_HIT_COUNT=0,
	SECURITY_COLUMN_IN_BYTES,
	SECURITY_COLUMN_OUT_BYTES,
	SECURITY_COLUMN_IN_PKTS,
	SECURITY_COLUMN_OUT_PKTS,
	SECURITY_COLUMN_MAX
};

enum APPLICATION_TAGS
{
	APPLICATION_TAG_VSYS_ID=0,
	APPLICATION_TAG_PROTOCOL_LABEL,
	APPLICATION_TAG_FULL_PATH,
	APPLICATION_MAX
};
enum APPLICATION_METRICS
{
	APPLICATION_SESSIONS=0,
	APPLICATION_IN_BYTES,
	APPLICATION_OUT_BYTES,
	APPLICATION_IN_PKTS,
	APPLICATION_OUT_PKTS,
	APPLICATION_C2S_PKTS,
	APPLICATION_S2C_PKTS,
	APPLICATION_C2S_BYTES,
	APPLICATION_S2C_BYTES,
	APPLICATION_C2S_FRAGMENTS,
	APPLICATION_S2C_FRAGMENTS,
	APPLICATION_C2S_LOST_BYTES,
	APPLICATION_S2C_LOST_BYTES,
	APPLICATION_C2S_ORDER_PKTS,
	APPLICATION_S2C_ORDER_PKTS,
	APPLICATION_C2S_RETRANSMITTED_PKTS,
	APPLICATION_S2C_RETRANSMITTED_PKTS,
	APPLICATION_C2S_RETRANSMITTED_BYTES,
	APPLICATION_S2C_RETRANSMITTED_BYTES,
	APPLICATION_METRICS_MAX
};


struct network_metrics
{
	int thread_alive;
	int cycle_interval_ms;
	pthread_t stat_thread_id;
	long long statistic_opt[_OPT_TYPE_MAX];

	int metrics_table_id;
	int metrics_column_id[NETWORK_METRIC_MAX];
	struct fieldstat_instance *metrics_handle;
};

struct security_metrics
{
	int cycle_interval_ms;
	int metrics_table_id;
	unsigned int metrics_column_id[SECURITY_COLUMN_MAX];
	struct fieldstat_dynamic_instance *metrics_handle;
};

struct application_metrics
{
	int cycle_interval_ms;
	int metrics_table_id;
	unsigned int metrics_column_id[APPLICATION_METRICS_MAX];
	struct fieldstat_dynamic_instance *metrics_handle;
};
struct tsg_statistic_metrics
{
	int vsystem_id;
	struct network_metrics fs_network;
	struct security_metrics fs_security;
	struct application_metrics fs_application;
};

struct tsg_statistic_metrics g_tsg_statis_para;

enum security_metric_tags
{
	SECURITY_TAG_RULE_ID = 0,
	SECURITY_TAG_ACTION,
	SECURITY_TAG_VSYS_ID,
	SECURITY_TAG_MAX
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
		atomic_add(&(g_tsg_statis_para.fs_network.statistic_opt[type]), value);
		break;
	default:
		break;
	}

	return 0;
}

int tsg_set_intercept_flow(struct maat_rule *p_result, struct traffic_info *traffic_info, int thread_seq)
{
	if (p_result == NULL || traffic_info == NULL || thread_seq < 0 || g_tsg_statis_para.fs_security.metrics_handle==NULL || p_result->service_id != TSG_SERVICE_INTERCEPT)
	{
		return -1;
	}

	struct fieldstat_tag security_tags[SECURITY_TAG_MAX] = {{"rule_id", 0, -1}, {"action", 0, -1}, {"vsys_id", 0, -1}};
	security_tags[SECURITY_TAG_RULE_ID].value_int = p_result->rule_id;
	security_tags[SECURITY_TAG_ACTION].value_int = p_result->action;
	security_tags[SECURITY_TAG_VSYS_ID].value_int = p_result->vsys_id;

	long long column[SECURITY_COLUMN_MAX];
	size_t n_column_num=SECURITY_COLUMN_MAX;
	column[SECURITY_COLUMN_HIT_COUNT]=traffic_info->con_num;
	column[SECURITY_COLUMN_IN_BYTES]=traffic_info->in_bytes;
	column[SECURITY_COLUMN_OUT_BYTES]=traffic_info->out_bytes;
	column[SECURITY_COLUMN_IN_PKTS]=traffic_info->in_packets;
	column[SECURITY_COLUMN_OUT_PKTS]=traffic_info->out_packets;

	fieldstat_dynamic_table_row_metric_values_incrby(g_tsg_statis_para.fs_security.metrics_handle, 
														g_tsg_statis_para.fs_security.metrics_table_id,
														"security_rule_hits",
														column,
														n_column_num,
														security_tags,
														SECURITY_TAG_MAX,
														thread_seq
													);

	return 0;
}

int tsg_set_policy_flow(const struct streaminfo *a_stream, struct maat_rule *p_result, int thread_seq)
{
	if (a_stream == NULL || p_result == NULL || thread_seq < 0 || g_tsg_statis_para.fs_security.metrics_handle==NULL)
	{
		return -1;
	}
	
	struct fieldstat_tag security_tags[SECURITY_TAG_MAX] = {{"rule_id", 0, -1}, {"action", 0, -1}, {"vsys_id", 0, -1}};
	security_tags[SECURITY_TAG_RULE_ID].value_int = p_result->rule_id;
	security_tags[SECURITY_TAG_ACTION].value_int = p_result->action;
	security_tags[SECURITY_TAG_VSYS_ID].value_int = p_result->vsys_id;

	long long column[SECURITY_COLUMN_MAX];
	size_t n_column_num=SECURITY_COLUMN_MAX;
	
	column[SECURITY_COLUMN_HIT_COUNT]=1;
	
	int value_len = sizeof(unsigned long long);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_BYTE_RAW, (void *)&(column[SECURITY_COLUMN_IN_BYTES]), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&(column[SECURITY_COLUMN_IN_PKTS]), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_BYTE_RAW, (void *)&(column[SECURITY_COLUMN_OUT_BYTES]), &value_len);
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&(column[SECURITY_COLUMN_OUT_PKTS]), &value_len);

	fieldstat_dynamic_table_row_metric_values_incrby(g_tsg_statis_para.fs_security.metrics_handle, 
														g_tsg_statis_para.fs_security.metrics_table_id,
														"security_rule_hits",
														column,
														n_column_num,
														security_tags,
														SECURITY_TAG_MAX,
														thread_seq
													 );

	return 0;
}

static void *tsg_statistic_thread(void *arg)
{
	fieldstat_instance_start(g_tsg_statis_para.fs_network.metrics_handle);

	while(g_tsg_statis_para.fs_network.thread_alive)
	{
		long long value=0;
		long long total_value=0;
		int value_len=sizeof(long long);


		int state=0;
		int state_len=sizeof(int);
		sapp_get_platform_opt(SPO_CURRENT_STATE, (void *)&state, &state_len);
		if(state > SAPP_STATE_PROCESSING)
		{
			break;
		}

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_ESTAB, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CONCURRENT, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_ACTIVE_SESSIONS], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_CLOSE_SESSIONS], total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_NEW, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_NEW, (void *)&value, &value_len);
		total_value+=value;
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_SESSIONS], total_value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_IN_BYTES], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_IN_PACKETS], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_BYTE, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_OUT_BYTES], value);

		value = 0;
		sapp_get_platform_opt(SPO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_OUT_PACKETS], value);

		value = 0;
		total_value = 0;
		sapp_get_platform_opt(SPO_TCP_STREAM_C2S, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_C2S, (void *)&value, &value_len);
		total_value += value;
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_ASYM_C2S_FLOWS], total_value);

		value = 0;
		total_value = 0;
		sapp_get_platform_opt(SPO_TCP_STREAM_S2C, (void *)&value, &value_len);
		total_value += value;
		value = 0;
		sapp_get_platform_opt(SPO_UDP_STREAM_S2C, (void *)&value, &value_len);
		total_value += value;
		fieldstat_value_set(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.metrics_column_id[NETWORK_ASYM_S2C_FLOWS], total_value);

		fieldstat_passive_output(g_tsg_statis_para.fs_network.metrics_handle);

		sleep(g_tsg_statis_para.fs_network.cycle_interval_ms/1000);
	}

	pthread_exit(NULL);
	return NULL;
}

int tsg_set_application_metrics(const struct streaminfo *a_stream, const char *l4_protocol, const char *app_full_path, struct traffic_packet_info *app_statis, int thread_seq)
{
	if (a_stream == NULL || l4_protocol == NULL || app_full_path == NULL || app_statis == NULL || g_tsg_statis_para.fs_application.metrics_handle==NULL)
	{
			return -1;
	}

	struct fieldstat_tag app_tags[APPLICATION_MAX] = {{"vsys_id", 0, -1}, {"protocol_label", 2, 0}, {"app_full_path", 2, 0}};
	app_tags[APPLICATION_TAG_VSYS_ID].value_int = g_tsg_statis_para.vsystem_id;
	app_tags[APPLICATION_TAG_PROTOCOL_LABEL].value_str = l4_protocol;
	app_tags[APPLICATION_TAG_FULL_PATH].value_str = app_full_path;

	long long column[APPLICATION_METRICS_MAX];
	size_t n_column_num=APPLICATION_METRICS_MAX;

	column[APPLICATION_SESSIONS]=app_statis->sessions;
	column[APPLICATION_IN_BYTES]=app_statis->in_bytes;
	column[APPLICATION_OUT_BYTES]=app_statis->out_bytes;
	column[APPLICATION_IN_PKTS]=app_statis->in_pkts;
	column[APPLICATION_OUT_PKTS]=app_statis->out_pkts;
	column[APPLICATION_C2S_PKTS]=app_statis->c2s_pkts;
	column[APPLICATION_S2C_PKTS]=app_statis->s2c_pkts;
	column[APPLICATION_C2S_BYTES]=app_statis->c2s_bytes;
	column[APPLICATION_S2C_BYTES]=app_statis->s2c_bytes;
	column[APPLICATION_C2S_FRAGMENTS]=app_statis->c2s_fragments;
	column[APPLICATION_S2C_FRAGMENTS]=app_statis->s2c_fragments;
	column[APPLICATION_C2S_LOST_BYTES]=app_statis->c2s_tcp_lost_bytes;
	column[APPLICATION_S2C_LOST_BYTES]=app_statis->s2c_tcp_lost_bytes;
	column[APPLICATION_C2S_ORDER_PKTS]=app_statis->c2s_tcp_ooorder_pkts;
	column[APPLICATION_S2C_ORDER_PKTS]=app_statis->s2c_tcp_ooorder_pkts;
	column[APPLICATION_C2S_RETRANSMITTED_PKTS]=app_statis->c2s_tcp_retransmitted_pkts;
	column[APPLICATION_S2C_RETRANSMITTED_PKTS]=app_statis->s2c_tcp_retransmitted_pkts;
	column[APPLICATION_C2S_RETRANSMITTED_BYTES]=app_statis->c2s_tcp_retransmitted_bytes;
	column[APPLICATION_S2C_RETRANSMITTED_BYTES]=app_statis->s2c_tcp_retransmitted_bytes;

	fieldstat_dynamic_table_row_metric_values_incrby(g_tsg_statis_para.fs_application.metrics_handle, 
														g_tsg_statis_para.fs_application.metrics_table_id,
														"traffic_application_protocol_stat",
														column,
														n_column_num,
														app_tags,
														APPLICATION_MAX,
														thread_seq
													);

	tsg_stat_application_metrics_count_set(thread_seq, fieldstat_dynamic_read_htable_item_cnt(g_tsg_statis_para.fs_application.metrics_handle, thread_seq));

	return 0;
}

int tsg_security_metric_init(const char *conffile, void *logger)
{
	if(conffile == NULL || logger == NULL)
	{
			return -1;
	}

	unsigned short fs_server_port=0;
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char app_name[128]={0};
	int thread_num = get_thread_count();

	MESA_load_profile_short_nodef(conffile, "SECURITY_HITS_METRICS", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"SECURITY_HITS_METRICS", "TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"SECURITY_HITS_METRICS", "APP_NAME", app_name, sizeof(app_name), "metric");
	MESA_load_profile_int_def(conffile, "SECURITY_HITS_METRICS", "CYCLE_INTERVAL_MS", &g_tsg_statis_para.fs_security.cycle_interval_ms, 1000);
	if(g_tsg_statis_para.fs_security.cycle_interval_ms<=0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "Disabale secutiry metrics");
		return 0;
	}

	g_tsg_statis_para.fs_security.metrics_handle = fieldstat_dynamic_instance_new(app_name, thread_num);
	if (g_tsg_statis_para.fs_security.metrics_handle == NULL)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "SECURITY_HITS_METRICS g_tsg_statis_para.fs_security.metrics_handle error");
		return -1;
	}

	fieldstat_dynamic_set_output_interval(g_tsg_statis_para.fs_security.metrics_handle, g_tsg_statis_para.fs_security.cycle_interval_ms);
	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_dynamic_set_line_protocol_server(g_tsg_statis_para.fs_security.metrics_handle, fs_server_ip, fs_server_port);
	}

	enum field_type security_metric_type[SECURITY_COLUMN_MAX] = {FIELD_TYPE_COUNTER};
	const char *security_metric_field[SECURITY_COLUMN_MAX] = {"hit_count", "in_bytes", "out_bytes", "in_pkts", "out_pkts"};
	g_tsg_statis_para.fs_security.metrics_table_id = fieldstat_register_dynamic_table(g_tsg_statis_para.fs_security.metrics_handle,
																						"security_rule_hits",
																						security_metric_field,
																						security_metric_type,
																						SECURITY_COLUMN_MAX,
																						g_tsg_statis_para.fs_security.metrics_column_id
																					);
	if(g_tsg_statis_para.fs_security.metrics_table_id<0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "SECURITY_HITS_METRICS g_tsg_statis_para.metric_table_id error");
		return -1;
	}

	fieldstat_dynamic_instance_start(g_tsg_statis_para.fs_security.metrics_handle);

	return 0;
}

int tsg_application_metric_init(const char *conffile, void *logger)
{
	if(conffile == NULL || logger == NULL)
	{
			return -1;
	}

	unsigned short fs_server_port = 0;
	char fs_server_ip[MAX_IPV4_LEN] = {0};
	char app_name[128] = {0};
	int thread_num = get_thread_count();

	MESA_load_profile_short_nodef(conffile, "APPLICATION_METRICS", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile, "APPLICATION_METRICS", "TELEGRAF_IP", fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile, "APPLICATION_METRICS", "APP_NAME", app_name, sizeof(app_name), "app_metric");
	MESA_load_profile_int_def(conffile, "APPLICATION_METRICS", "CYCLE_INTERVAL_MS", &g_tsg_statis_para.fs_application.cycle_interval_ms, 1000);

	if (g_tsg_statis_para.fs_application.cycle_interval_ms <= 0)
	{
			MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "Disabale application metrics");
			return 0;
	}

	g_tsg_statis_para.fs_application.metrics_handle = fieldstat_dynamic_instance_new(app_name, thread_num);
	if(g_tsg_statis_para.fs_application.metrics_handle == NULL)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "APPLICATION_METRICS g_tsg_statis_para.fs_application.metrics_handle error");
		return -1;
	}

	fieldstat_dynamic_set_output_interval(g_tsg_statis_para.fs_application.metrics_handle, g_tsg_statis_para.fs_application.cycle_interval_ms);
	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_dynamic_set_line_protocol_server(g_tsg_statis_para.fs_application.metrics_handle, fs_server_ip, fs_server_port);
	}

	enum field_type app_metric_type[APPLICATION_METRICS_MAX] = {FIELD_TYPE_COUNTER};
	const char *app_metric_field[APPLICATION_METRICS_MAX] = {"sessions", "in_bytes", "out_bytes", "in_pkts", "out_pkts", "c2s_pkts", "s2c_pkts", "c2s_bytes", "s2c_bytes", "c2s_fragments", "s2c_fragments",
													 "c2s_tcp_lost_bytes", "s2c_tcp_lost_bytes", "c2s_tcp_ooorder_pkts", "s2c_tcp_ooorder_pkts", "c2s_tcp_retransmitted_pkts", "s2c_tcp_retransmitted_pkts",
													 "c2s_tcp_retransmitted_bytes", "s2c_tcp_retransmitted_bytes"};
	g_tsg_statis_para.fs_application.metrics_table_id = fieldstat_register_dynamic_table(g_tsg_statis_para.fs_application.metrics_handle, 
																							"traffic_application_protocol_stat",
																							app_metric_field,
																							app_metric_type,
																							APPLICATION_METRICS_MAX,
																							g_tsg_statis_para.fs_application.metrics_column_id
																						);
	if (g_tsg_statis_para.fs_application.metrics_table_id < 0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "APP_METRIC g_tsg_statis_para.app_metric_table_id error");
		return -1;
	}

	fieldstat_dynamic_instance_start(g_tsg_statis_para.fs_application.metrics_handle);
	return 0;
}

int tsg_network_traffic_metrics_init(const char *conffile, void *logger)
{
	if(conffile == NULL || logger == NULL)
	{
			return -1;
	}

	unsigned short fs_server_port = 0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	MESA_load_profile_int_def(conffile, "NETWORK_METRICS", "CYCLE_INTERVAL_MS", &g_tsg_statis_para.fs_network.cycle_interval_ms, 5000);
	if(g_tsg_statis_para.fs_network.cycle_interval_ms<=0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "Disabale traffic statistic");
		return 0;
	}

	MESA_load_profile_short_nodef(conffile, "NETWORK_METRICS", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"NETWORK_METRICS", "TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"NETWORK_METRICS", "OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "statistic.log");
	MESA_load_profile_string_def(conffile, "NETWORK_METRICS", "APP_NAME", app_name, sizeof(app_name), "network_activity");

	g_tsg_statis_para.fs_network.metrics_handle=fieldstat_instance_new(app_name);
	g_tsg_statis_para.fs_network.thread_alive=1;

	fieldstat_disable_background_thread(g_tsg_statis_para.fs_network.metrics_handle);

	fieldstat_set_output_interval(g_tsg_statis_para.fs_network.metrics_handle, g_tsg_statis_para.fs_network.cycle_interval_ms);
	fieldstat_set_local_output(g_tsg_statis_para.fs_network.metrics_handle, fs_output_path, "default");

	if (fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_set_line_protocol_server(g_tsg_statis_para.fs_network.metrics_handle, fs_server_ip, fs_server_port);
	}

	const char *network_column_name[NETWORK_METRIC_MAX] = {"sessions", "active_sessions", "closed_sessions", "in_bytes", "out_bytes", "in_pkts", "out_pkts", "asymmetric_c2s_flows", "asymmetric_s2c_flows"};

	enum field_type network_column_type[NETWORK_METRIC_MAX]={FIELD_TYPE_COUNTER};
	network_column_type[NETWORK_ACTIVE_SESSIONS]=FIELD_TYPE_GAUGE;
	struct fieldstat_tag traffic_tags[NETWORK_TAG_MAX]={{"vsys_id", 0, -1}};
	traffic_tags[NETWORK_TAG_VSYS_ID].value_int = g_tsg_statis_para.vsystem_id;

	g_tsg_statis_para.fs_network.metrics_table_id = fieldstat_register_table(g_tsg_statis_para.fs_network.metrics_handle, app_name, network_column_name, network_column_type, (size_t)(NETWORK_METRIC_MAX));
	fieldstat_register_table_row(g_tsg_statis_para.fs_network.metrics_handle, 
									g_tsg_statis_para.fs_network.metrics_table_id,
									(const char *)"traffic_general_stat",
									traffic_tags,
									NETWORK_TAG_MAX, 
									g_tsg_statis_para.fs_network.metrics_column_id
								);

	pthread_create(&g_tsg_statis_para.fs_network.stat_thread_id, NULL, tsg_statistic_thread, NULL);

	return 0;
}

int tsg_metric_init(const char *conffile, void *logger)
{
	memset(&g_tsg_statis_para, 0, sizeof(g_tsg_statis_para));
	MESA_load_profile_int_def(conffile, "TSG_LOG", "VSYSTEM_ID", &(g_tsg_statis_para.vsystem_id), 1);

	int ret=tsg_network_traffic_metrics_init(conffile, logger);
	if(ret<0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "tsg_network_traffic_metrics_init failed ...");
		return -1;
	}

	ret=tsg_security_metric_init(conffile, logger);
	if(ret<0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "tsg_security_metric_init failed ...");
		return -1;
	}

	ret=tsg_application_metric_init(conffile, logger);
	if(ret<0)
	{
		MASTER_LOG(logger, RLOG_LV_FATAL, LOG_MODULE_METRICS, "tsg_application_metric_init failed ...");
		return -1;
	}

	return 0;
}

void tsg_metric_destroy(void)
{
	if(g_tsg_statis_para.fs_network.metrics_handle!=NULL)
	{
		g_tsg_statis_para.fs_network.thread_alive = 0;
		sleep((g_tsg_statis_para.fs_network.cycle_interval_ms/1000));
		pthread_join(g_tsg_statis_para.fs_network.stat_thread_id, NULL);
		fieldstat_instance_free(g_tsg_statis_para.fs_network.metrics_handle);
	}

	if(g_tsg_statis_para.fs_security.metrics_handle!=NULL)
	{
		fieldstat_dynamic_instance_free(g_tsg_statis_para.fs_security.metrics_handle);
	}

	if(g_tsg_statis_para.fs_application.metrics_handle!=NULL)
	{
		fieldstat_dynamic_instance_free(g_tsg_statis_para.fs_application.metrics_handle);
	}

	return;
}
