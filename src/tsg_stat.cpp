#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stream.h>

#include "tsg_stat.h"
#include <MESA/fieldstat.h>
#include <MESA/MESA_prof_load.h>

enum OP_EXDATA
{
	OP_EXDATA_ADD=0,
	OP_EXDATA_DEL,
	OP_EXDATA_MAX
};

enum APP_METRICS
{
	APP_METRICS_COUNT=0,
	APP_METRICS_MAX	
};

struct fs3_rule_stat
{
	int table_id;
	int abort_column_id[RULE_TYPE_MAX];
	int send_column_id[RULE_TYPE_MAX];
};

struct fs3_tld_stat
{
	int table_id;
	int column_id[LOG_HANDLE_MAX];
};

struct fs3_sendlog_stat
{
	int table_id;
	int max_row_idx;
	int (*column_id)[LOG_STATUS_MAX];
};

struct fs3_sync_ctrl_stat
{
	int table_id;
	int success_column_id[CTRL_SYNC_MAX];
	int fail_column_id[CTRL_SYNC_MAX];
};

struct ctrl_service_status
{
	int activing_column_id[CTRL_SERVICE_MAX];
	int updating_column_id[CTRL_SERVICE_MAX];
};

struct fs3_sync_ctrl_service
{
	int table_id;
	struct ctrl_service_status fail;
	struct ctrl_service_status success;
};

struct fs3_sync_application
{
	int table_id;
	int column_id[SYNC_APP_MAX];
};

struct fs3_application_metrics
{
	int table_id;
	int *column_id;
};

struct fs3_sync_exdata
{
	int table_id;
	int column_id[SYNC_EXDATA_ROW_MAX][OP_EXDATA_MAX];
};

struct fs3_flow
{
	int table_id;
	int fail_column_id[FLOW_STAT_MAX];
	int success_column_id[FLOW_STAT_MAX];
};

struct runtime_stat_para
{
	//struct fieldstat_tag tags;
	struct fs3_flow flow;
	struct fs3_tld_stat tld;
	struct fs3_rule_stat rule;
	struct fs3_sync_exdata exdata;
	struct fs3_sendlog_stat sendlog;
	struct fs3_sync_application sync_app;
	struct fs3_application_metrics app_metrics;
	struct fs3_sync_ctrl_stat ctrl_sync;
	struct fs3_sync_ctrl_service ctrl_service;
	struct fieldstat_instance *fs_instance;
};

struct runtime_stat_para g_rt_stat_para={0};

static void stat_update(int column_id, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		fieldstat_value_incrby(g_rt_stat_para.fs_instance, column_id, increase);
	}
}

void tsg_stat_abort_rule_update(enum RULE_TYPE column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.rule.abort_column_id[column_idx], increase);
	}
}

void tsg_stat_send_rule_update(enum RULE_TYPE column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.rule.send_column_id[column_idx], increase);
	}
}

void tsg_stat_sendlog_update(int row_idx, enum LOG_STATUS column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.sendlog.column_id[row_idx][column_idx], increase);
	}
}

void tsg_stat_log_handle_update(enum LOG_HANDLE column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.tld.column_id[column_idx], increase);
	}
}

void tsg_stat_flow_update(enum STAT_STATUS status, enum FLOW_STAT column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return ;
	}

	switch(status)
	{
		case	STAT_STATUS_FAIL:
			stat_update(g_rt_stat_para.flow.fail_column_id[column_idx], increase);
			break;
		case	STAT_STATUS_SUCCESS:
			stat_update(g_rt_stat_para.flow.success_column_id[column_idx], increase);
			break;
		default:
			break;
	}
}

void tsg_stat_sync_ctrl_update(enum STAT_STATUS status, enum CTRL_SYNC column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return ;
	}

	switch(status)
	{
		case	STAT_STATUS_FAIL:
			stat_update(g_rt_stat_para.ctrl_sync.fail_column_id[column_idx], increase);
			break;
		case	STAT_STATUS_SUCCESS:
			stat_update(g_rt_stat_para.ctrl_sync.success_column_id[column_idx], increase);
			break;
		default:
			break;
	}
}

void tsg_stat_sync_exdata_add_update(enum SYNC_EXDATA_ROW row_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.exdata.column_id[row_idx][OP_EXDATA_ADD], increase);
	}
}

void tsg_stat_sync_exdata_del_update(enum SYNC_EXDATA_ROW row_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.exdata.column_id[row_idx][OP_EXDATA_DEL], increase);
	}
}

void tsg_stat_sync_application_update(enum SYNC_APP column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		stat_update(g_rt_stat_para.sync_app.column_id[column_idx], increase);
	}
}

void tsg_stat_application_metrics_count_set(int row_idx, long long current)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		fieldstat_value_set(g_rt_stat_para.fs_instance, g_rt_stat_para.app_metrics.column_id[row_idx], current);
	}
}

void tsg_stat_ctrl_service_activing_update(enum STAT_STATUS status, enum CTRL_SERVICE column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return ;
	}

	switch(status)
	{
		case	STAT_STATUS_FAIL:
			stat_update(g_rt_stat_para.ctrl_service.fail.activing_column_id[column_idx], increase);
			break;
		case	STAT_STATUS_SUCCESS:
			stat_update(g_rt_stat_para.ctrl_service.success.activing_column_id[column_idx], increase);
			break;
		default:
			break;
	}
}

void tsg_stat_ctrl_service_updating_update(enum STAT_STATUS status, enum CTRL_SERVICE column_idx, long long increase)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return ;
	}

	switch(status)
	{
		case	STAT_STATUS_FAIL:
			stat_update(g_rt_stat_para.ctrl_service.fail.updating_column_id[column_idx], increase);
			break;
		case	STAT_STATUS_SUCCESS:
			stat_update(g_rt_stat_para.ctrl_service.success.updating_column_id[column_idx], increase);
			break;
		default:
			break;
	}
}

int tsg_stat_create(const char *conffile)
{
	int cycle_interval_ms=0,vsystem_id=0;
	unsigned short fs_server_port=0;
	char instance_name[128]={0};
	char fs_server_ip[32]={0};
	char fs_output_path[128]={0};

	MESA_load_profile_int_def(conffile, "MASTER_STATUS", "CYCLE_INTERVAL_MS", &cycle_interval_ms, 30000);
	if(cycle_interval_ms<=0)
	{
		return 0;
	}

	MESA_load_profile_int_def(conffile, "TSG_LOG", "VSYSTEM_ID", &vsystem_id, 1);
	MESA_load_profile_short_nodef(conffile, "MASTER_STATUS","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"MASTER_STATUS","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"MASTER_STATUS","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "master.status");
	MESA_load_profile_string_def(conffile,"MASTER_STATUS","INSTANCE_NAME", instance_name, sizeof(instance_name), "tsg_master");
	

	//memset(&(g_rt_stat_para), 0, sizeof(struct runtime_stat_para));

	g_rt_stat_para.fs_instance=fieldstat_instance_new(instance_name);
	fieldstat_set_output_interval(g_rt_stat_para.fs_instance, cycle_interval_ms);
	fieldstat_enable_prometheus_output(g_rt_stat_para.fs_instance);
	fieldstat_set_local_output(g_rt_stat_para.fs_instance, fs_output_path, "default");

	if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
	{
		fieldstat_set_line_protocol_server(g_rt_stat_para.fs_instance, fs_server_ip, fs_server_port);
	}

	return 0;
}

int tsg_stat_init(void)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return 0;
	}

	enum field_type exdata_column_type[OP_EXDATA_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *exdata_column_name[OP_EXDATA_MAX]={"add", "del"};
	g_rt_stat_para.exdata.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "sync_exdata", exdata_column_name, exdata_column_type, OP_EXDATA_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "asn", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_ASN]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "gtpc", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_GTPC]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "location", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_LOCATION]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "fqdn_category", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_FQDN_CATEGORY]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "subscriber", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_SUBSCRIBER]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "compile", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_COMPILE]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "http_response", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_HTTP_RESPONSE]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "dns_response", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_DNS_RESPONSE]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "app_id_dict", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_APP_ID_DICT]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "tunnel_catalog", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_TUNNEL_CATALOG]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "tunnel_endpoint", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_TUNNEL_ENDPOINT]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "tunnel_label", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_TUNNEL_LABEL]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "statistics_template", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_STATISTICS_TEMPLATE]);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.exdata.table_id, "statistics_chart", NULL, 0, g_rt_stat_para.exdata.column_id[SYNC_EXDATA_ROW_STATISTICS_CHART]);

	enum field_type flow_column_type[FLOW_STAT_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *flow_column_name[FLOW_STAT_MAX]={"inject", "mirror_pkts", "mirror_bytes", "set_timeout", "tamper"};
	g_rt_stat_para.flow.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "flow", flow_column_name, flow_column_type, FLOW_STAT_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.flow.table_id, "success", NULL, 0, g_rt_stat_para.flow.success_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.flow.table_id, "fail", NULL, 0, g_rt_stat_para.flow.fail_column_id);

	enum field_type app_sync_column_type[SYNC_APP_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *app_sync_column_name[SYNC_APP_MAX]={"lpi", "dpkt", "thrid", "user_define", "built_in"};
	g_rt_stat_para.sync_app.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "sync_application", app_sync_column_name, app_sync_column_type, SYNC_APP_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.sync_app.table_id, "sum", NULL, 0, g_rt_stat_para.sync_app.column_id);

	enum field_type ctrl_sync_column_type[CTRL_SYNC_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *ctrl_sync_column_name[CTRL_SYNC_MAX]={"unknown", "rstall", "opening", "activing", "updating", "closing"};
	g_rt_stat_para.ctrl_sync.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "ctrl_stat", ctrl_sync_column_name, ctrl_sync_column_type, CTRL_SYNC_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_sync.table_id, "success", NULL, 0, g_rt_stat_para.ctrl_sync.success_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_sync.table_id, "fail", NULL, 0, g_rt_stat_para.ctrl_sync.fail_column_id);

	enum field_type ctrl_service_column_type[CTRL_SERVICE_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *ctrl_service_column_name[CTRL_SERVICE_MAX]={"unknown", "sce", "shaping", "intercept"};
	g_rt_stat_para.ctrl_service.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "ctrl_service", ctrl_service_column_name, ctrl_service_column_type, CTRL_SERVICE_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_service.table_id, "activing_success", NULL, 0, g_rt_stat_para.ctrl_service.success.activing_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_service.table_id, "activing_fail", NULL, 0, g_rt_stat_para.ctrl_service.fail.activing_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_service.table_id, "updating_success", NULL, 0, g_rt_stat_para.ctrl_service.success.updating_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.ctrl_service.table_id, "updating_fail", NULL, 0, g_rt_stat_para.ctrl_service.fail.updating_column_id);

	enum field_type rule_column_type[RULE_TYPE_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *rule_column_name[RULE_TYPE_MAX]={"unknown", "shunt", "allow", "deny", "shaping", "intercept", "no_intercept", "service_chaining", "monitor"};
	g_rt_stat_para.rule.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "matched_rule", rule_column_name, rule_column_type, RULE_TYPE_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.rule.table_id, "abort", NULL, 0, g_rt_stat_para.rule.abort_column_id);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.rule.table_id, "send", NULL, 0, g_rt_stat_para.rule.send_column_id);

	enum field_type handle_column_type[LOG_HANDLE_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *handle_column_name[LOG_HANDLE_MAX]={"create", "dup", "append", "free_cnt", "free_size", "free_capacity"};
	g_rt_stat_para.tld.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "tld_handle", handle_column_name, handle_column_type, LOG_HANDLE_MAX);
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.tld.table_id, "handle", NULL, 0, g_rt_stat_para.tld.column_id);
	
	enum field_type sendlog_column_type[LOG_STATUS_MAX]={FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE, FIELD_TYPE_GAUGE};
	const char *sendlog_column_name[LOG_STATUS_MAX]={"T_success_log", "T_fail_log", "T_drop_log", "success_log/s", "fail_log/s", "drop_log/s"};
	g_rt_stat_para.sendlog.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "sendlog", sendlog_column_name, sendlog_column_type, LOG_STATUS_MAX);

	char fs3_table_name[128]={0};
	enum field_type app_metrics_column_type[APP_METRICS_MAX]={FIELD_TYPE_GAUGE};
	const char *app_metrics_column_name[APP_METRICS_MAX]={"metric_cnt"};
	g_rt_stat_para.app_metrics.table_id=fieldstat_register_table(g_rt_stat_para.fs_instance, "application", app_metrics_column_name, app_metrics_column_type, APP_METRICS_MAX);
	
	int thread_count=get_thread_count();
	g_rt_stat_para.app_metrics.column_id=(int *)calloc(thread_count, sizeof(int));
	for(int i=0; i<thread_count; i++)
	{
		snprintf(fs3_table_name, sizeof(fs3_table_name), "thread_%d", i);
		fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.app_metrics.table_id, fs3_table_name, NULL, 0, &(g_rt_stat_para.app_metrics.column_id[i]));
	}

	return 0;
}

int tsg_stat_sendlog_row_init(const char *row_name)
{
	if(g_rt_stat_para.fs_instance==NULL)
	{
		return 0;
	}

	int row_idx=g_rt_stat_para.sendlog.max_row_idx;
	if(row_idx==0)
	{
		g_rt_stat_para.sendlog.column_id=(int (*)[LOG_STATUS_MAX])calloc(row_idx+1, sizeof(int[LOG_STATUS_MAX]));
	}
	else
	{
		g_rt_stat_para.sendlog.column_id=(int (*)[LOG_STATUS_MAX])realloc(g_rt_stat_para.sendlog.column_id, (row_idx+1)*sizeof(int[LOG_STATUS_MAX]));
	}
	
	fieldstat_register_table_row(g_rt_stat_para.fs_instance, g_rt_stat_para.sendlog.table_id, row_name, NULL, 0, g_rt_stat_para.sendlog.column_id[row_idx]);

	g_rt_stat_para.sendlog.max_row_idx++;

	return row_idx;
}


void tsg_stat_start(void)
{
	if(g_rt_stat_para.fs_instance!=NULL)
	{
		fieldstat_instance_start(g_rt_stat_para.fs_instance);
	}
}

