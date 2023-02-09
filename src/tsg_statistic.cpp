#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#include <MESA/field_stat2.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"

tsg_statis_para_t g_tsg_statis_para;

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

int tsg_set_intercept_flow(Maat_rule_t *p_result, struct _traffic_info *traffic_info, int thread_seq)
{
	struct _traffic_info *_info=NULL;

	if(p_result!=NULL && traffic_info!=NULL && thread_seq>=0)
	{
		_info=&(g_tsg_statis_para.traffic_info[(unsigned char)p_result->action][thread_seq]);
		
		_info->con_num+=traffic_info->con_num;
		_info->in_bytes+=traffic_info->in_bytes;
		_info->in_packets+=traffic_info->in_packets;
		_info->out_bytes+=traffic_info->out_bytes;
		_info->out_packets+=traffic_info->out_packets;
	}
	
	return 0;
}

int tsg_set_policy_flow(struct streaminfo *a_stream, Maat_rule_t *p_result, int thread_seq)
{
	unsigned long long value=0;
	int value_len=sizeof(unsigned long long);
	struct _traffic_info *traffic_info=NULL;

	if(g_tsg_statis_para.cycle<=0)
	{
		return 0;
	}
	
	if(a_stream==NULL || p_result==NULL)
	{
		return -1;
	}
	
	traffic_info=&(g_tsg_statis_para.traffic_info[(unsigned char)p_result->action][thread_seq]);

	traffic_info->con_num++;

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_BYTE_RAW, (void *)&value, &value_len);
	traffic_info->in_bytes+=value;

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_INBOUND_PKT, (void *)&value, &value_len);
	traffic_info->in_packets+=value;

	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_BYTE_RAW, (void *)&value, &value_len);	
	traffic_info->out_bytes+=value;
	
	value=0;
	MESA_get_stream_opt(a_stream, MSO_TOTAL_OUTBOUND_PKT, (void *)&value, &value_len);
	traffic_info->out_packets+=value;
	
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

	FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[con_num_id], FS_OP_SET, con_num_sum);
	FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[in_bytes_id], FS_OP_SET, in_bytes_sum);
	FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[in_packets_id], FS_OP_SET, in_packets_sum);
	FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[out_bytes_id], FS_OP_SET, out_bytes_sum);
	FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[out_packets_id], FS_OP_SET, out_packets_sum);

	return 0;
}
static void *tsg_statistic_thread(void *arg)
{
	int thread_num=get_thread_count();
	struct _traffic_info policy_traffic_info;
	struct _traffic_info total_traffic_info;
	struct _traffic_info default_traffic_info;

	FS_start(g_tsg_statis_para.fs2_handle);

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
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_ESTABLISHED_CON_NUM], FS_OP_SET, total_value);
		
		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_CLOSE, (void *)&value, &value_len);
		total_value+=value;
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_CLOSE_CON_NUM], FS_OP_SET, total_value);

		value=0;
		total_value=0;
		sapp_get_platform_opt(SPO_TCP_STREAM_NEW, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_TCP_NEW_CON_NUM], FS_OP_SET, value);
		
		total_value+=value;
		
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_TCP_PKT, (void *)&value, &value_len);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_TCP_IN_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_TCP_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_TCP_IN_BYTES], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_TCP_PKT, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_TCP_OUT_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_TCP_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_TCP_OUT_BYTES], FS_OP_SET, value);

		value=0;
		sapp_get_platform_opt(SPO_UDP_STREAM_NEW, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_UDP_NEW_CON_NUM], FS_OP_SET, value);

		total_value+=value;
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_NEW_CON_NUM], FS_OP_SET, total_value);
		total_traffic_info.con_num+=total_value;

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_UDP_PKT, (void *)&value, &value_len);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_UDP_IN_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_UDP_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_UDP_IN_BYTES], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_UDP_PKT, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_UDP_OUT_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_UDP_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_UDP_OUT_BYTES], FS_OP_SET, value);

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

		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_ALERT_BYTES], FS_OP_SET, g_tsg_statis_para.statistic_opt[OPT_TYPE_ALERT_BYTES]);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_BLOCK_BYTES], FS_OP_SET, g_tsg_statis_para.statistic_opt[OPT_TYPE_BLOCK_BYTES]);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_PINNING_NUM], FS_OP_SET, g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_YES]);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_MAYBE_PINNING_NUM], FS_OP_SET, g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_MAYBE]);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_NOT_PINNING_NUM], FS_OP_SET, g_tsg_statis_para.statistic_opt[OPT_TYPE_PINNING_NOT]);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV4_PKT, (void *)&value, &value_len);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV4_IN_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV4_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV4_IN_BYTES], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV4_PKT, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV4_OUT_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV4_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV4_OUT_BYTES], FS_OP_SET, value);

		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV6_PKT, (void *)&value, &value_len);
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV6_IN_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_INBOUND_IPV6_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV6_IN_BYTES], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV6_PKT, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV6_OUT_PACKETS], FS_OP_SET, value);
		value=0;
		sapp_get_platform_opt(SPO_TOTAL_RCV_OUTBOUND_IPV6_BYTE, (void *)&value, &value_len);		
		FS_operate(g_tsg_statis_para.fs2_handle, g_tsg_statis_para.fs_line_id, g_tsg_statis_para.fs_field_id[STATIS_IPV6_OUT_BYTES], FS_OP_SET, value);

		FS_passive_output(g_tsg_statis_para.fs2_handle);
		
		sleep(g_tsg_statis_para.cycle);
	}

	return NULL;
}


int tsg_statistic_init(const char *conffile, void *logger)
{
	int output_prometheus=0;
	int i=0,value=0,thread_num=0;
	unsigned short fs_server_port=0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	memset(&g_tsg_statis_para, 0, sizeof(g_tsg_statis_para));

	thread_num=get_thread_count();
	for(i=0; i<TSG_ACTION_MAX+1; i++)
	{
		g_tsg_statis_para.traffic_info[i]=(struct _traffic_info *)calloc(1, sizeof(struct _traffic_info)*thread_num);
	}
	
	MESA_load_profile_int_def(conffile, "STATISTIC", "CYCLE", &g_tsg_statis_para.cycle, 30);
	if(g_tsg_statis_para.cycle<=0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "STATISTIC", "Disabale traffic statistic");
		return 0;
	}

	MESA_load_profile_short_nodef(conffile, "STATISTIC", "TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"STATISTIC", "TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"STATISTIC", "OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "statistic.log");
	MESA_load_profile_string_def(conffile,"STATISTIC", "APP_NAME", app_name, sizeof(app_name), "statistic");
	MESA_load_profile_int_def(conffile, "STATISTIC", "PROMETHEUS", &output_prometheus, 1);

	g_tsg_statis_para.fs2_handle=FS_create_handle();
	g_tsg_statis_para.thread_alive=1;

	value=1;//Rewrite
	FS_set_para(g_tsg_statis_para.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=0;//Do not create stat thread
	FS_set_para(g_tsg_statis_para.fs2_handle, CREATE_THREAD, &value, sizeof(value));

	FS_set_para(g_tsg_statis_para.fs2_handle, STAT_CYCLE, &g_tsg_statis_para.cycle, sizeof(g_tsg_statis_para.cycle));
    FS_set_para(g_tsg_statis_para.fs2_handle, APP_NAME, app_name, strlen(app_name)+1);
	FS_set_para(g_tsg_statis_para.fs2_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);

	FS_set_para(g_tsg_statis_para.fs2_handle, OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));

    if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
    {
        FS_set_para(g_tsg_statis_para.fs2_handle, STATS_SERVER_IP,fs_server_ip, strlen(fs_server_ip)+1);
        FS_set_para(g_tsg_statis_para.fs2_handle, STATS_SERVER_PORT,&(fs_server_port), sizeof(fs_server_port));
    }

	int output_influx_line=FS_OUTPUT_INFLUX_LINE;
	FS_set_para(g_tsg_statis_para.fs2_handle, STATS_FORMAT, &output_influx_line, sizeof(output_influx_line));

	g_tsg_statis_para.fs_field_id[STATIS_NEW_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"new_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_ESTABLISHED_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, (char *)"established_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_CLOSE_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"close_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_TOTAL_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"total_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_TOTAL_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"total_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_TOTAL_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"total_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_TOTAL_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"total_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_DEFAULT_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"default_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_DEFAULT_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"default_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_DEFAULT_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"default_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_DEFAULT_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"default_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_DEFAULT_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"default_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_ALLOW_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"allow_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_ALLOW_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"allow_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_ALLOW_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"allow_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_ALLOW_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"allow_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_ALLOW_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"allow_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_DENY_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"deny_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_DENY_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"deny_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_DENY_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"deny_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_DENY_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"deny_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_DENY_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"deny_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_MONITOR_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"monitor_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_MONITOR_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"monitor_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_MONITOR_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"monitor_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_MONITOR_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"monitor_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_MONITOR_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"monitor_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_INTERCEPT_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"intercept_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_INTERCEPT_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"intercept_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_INTERCEPT_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"intercept_out_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_INTERCEPT_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"intercept_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_INTERCEPT_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"intercept_out_packets");

	g_tsg_statis_para.fs_field_id[STATIS_IPV4_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv4_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_IPV4_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv4_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_IPV4_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv4_out_packets");
	g_tsg_statis_para.fs_field_id[STATIS_IPV4_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv4_out_bytes");

	g_tsg_statis_para.fs_field_id[STATIS_IPV6_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv6_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_IPV6_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv6_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_IPV6_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv6_out_packets");
	g_tsg_statis_para.fs_field_id[STATIS_IPV6_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"ipv6_out_bytes");

	g_tsg_statis_para.fs_field_id[STATIS_TCP_NEW_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"tcp_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_TCP_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"tcp_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_TCP_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"tcp_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_TCP_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"tcp_out_packets");
	g_tsg_statis_para.fs_field_id[STATIS_TCP_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"tcp_out_bytes");

	g_tsg_statis_para.fs_field_id[STATIS_UDP_NEW_CON_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"udp_conn_num");
	g_tsg_statis_para.fs_field_id[STATIS_UDP_IN_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"udp_in_packets");
	g_tsg_statis_para.fs_field_id[STATIS_UDP_IN_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"udp_in_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_UDP_OUT_PACKETS]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"udp_out_packets");
	g_tsg_statis_para.fs_field_id[STATIS_UDP_OUT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"udp_out_bytes");

	g_tsg_statis_para.fs_field_id[STATIS_ALERT_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"alert_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_BLOCK_BYTES]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"block_bytes");
	g_tsg_statis_para.fs_field_id[STATIS_PINNING_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"pinning_num");
	g_tsg_statis_para.fs_field_id[STATIS_MAYBE_PINNING_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"maybe_pinning_num");
	g_tsg_statis_para.fs_field_id[STATIS_NOT_PINNING_NUM]=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_COLUMN, FS_CALC_SPEED, (char *)"not_pinning_num");

	g_tsg_statis_para.fs_line_id=FS_register(g_tsg_statis_para.fs2_handle, FS_STYLE_LINE, FS_CALC_CURRENT, (const char *)"TRAFFIC");

	pthread_create(&g_tsg_statis_para.stat_thread_id, NULL, tsg_statistic_thread, NULL);
	
	return 0;
}

void tsg_statistic_destroy(void)
{
	pthread_cancel(g_tsg_statis_para.stat_thread_id);
	g_tsg_statis_para.thread_alive=0;
	sleep(g_tsg_statis_para.cycle);
	FS_stop(&(g_tsg_statis_para.fs2_handle));

	return ;
}

