#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"



char TSG_MASTER_VERSION_20191119=0;
const char *tsg_conffile="tsgconf/main.conf";
g_tsg_para_t g_tsg_para;

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{TLD_TYPE_UNKNOWN, TSG_FS2_LINKS, "links"}, 
										 {TLD_TYPE_UNKNOWN, TSG_FS2_BYPASS, "bypass"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_SHARE, "hit_share"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_INTERCEPT, "intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_LOG, "log"}
	};
static void free_policy_label(int thread_seq, void *project_req_value)
{
	dictator_free(thread_seq, project_req_value);
	project_req_value=NULL;
}

#if 0
static int is_ip_policy(Maat_rule_t *p_result, char *protocol, int len, int thread_seq)
{
	int ret=0;
	cJSON *item=NULL;
	char *service_defined=NULL;
	cJSON *user_define_object=NULL;	

	if(p_result->serv_def_len>MAX_SERVICE_DEFINE_LEN)
	{
		service_defined=dictator_malloc(thread_seq, p_result->serv_def_len+1);
		ret=Maat_read_rule(g_tsg_maat_feather, p_result, MAAT_RULE_SERV_DEFINE, service_defined, p_result->serv_def_len+1);
		assert(ret==p_result->serv_def_len+1);
		
		user_define_object=cJSON_Parse(service_defined);
	}
	else
	{
		user_define_object=cJSON_Parse(p_result->service_defined);
	}

	if(user_define_object!=NULL)
	{
		item=cJSON_GetObjectItem(user_define_object, "protocol");
		if(item!=NULL && item->valuestring!=NULL)
		{
			memcpy(protocol, item->valuestring, (len>strlen(item->valuestring)) ? strlen(item->valuestring): len);
		}
		
		item=cJSON_GetObjectItem(user_define_object, "method");
		if((item==NULL) || ((strncasecmp(item->valuestring, "http", strlen(item->valuestring)))!=0 && (strncasecmp(item->valuestring, "ssl", strlen(item->valuestring)))!=0))
		{
			ret=1;
		}

		cJSON_Delete(user_define_object);
		user_define_object=NULL;
	}

	if(service_defined!=NULL)
	{
		dictator_free(thread_seq, service_defined);
		service_defined=NULL;
	}
	
	return ret;
}
#endif
static Maat_rule_t *tsg_policy_decision_criteria(Maat_rule_t *result, int result_num)
{
	int i=0;
	Maat_rule_t *p_result=NULL;
	if(result==NULL || result_num<=0)
	{
		return NULL;
	}
	
	p_result=&result[0];
	
	for(i=1; i<result_num; i++)
	{
		if((unsigned char)result[i].action>(unsigned char)p_result->action)
		{
			p_result=&result[i];
			continue;
		}
		
		if(result[i].action==p_result->action)
		{
			if(result[i].config_id<p_result->config_id)
			{
				p_result=&result[i];
			}
		}	
	}

	return p_result;
}

extern "C" char TSG_MASTER_TCPALL_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{
	int send_log=0,identify_flag=0;
	int ret=0,hit_num=0,ip_policy=0;
	int state=APP_STATE_DROPME;
	scan_status_t mid=NULL;
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	Maat_rule_t *p_result=NULL;
	Maat_rule_t *q_result=NULL;
	tsg_log_t log_msg;
	TLD_handle_t TLD_handle=NULL;
	struct _identify_info identify_info;
	Maat_rule_t all_result[MAX_RESULT_NUM];
	policy_priority_label_t *priority_label=NULL;
	
	switch(a_tcp->pktstate)
	{
		case	OP_STATE_PENDING:
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_LINKS], 0, FS_OP_ADD, 1);
		case	OP_STATE_DATA:
			if((a_tcp->ptcpdetail->pdata==NULL) || (a_tcp->ptcpdetail->datalen<=0) || (a_tcp->dir==DIR_DOUBLE && a_tcp->curdir==DIR_S2C))
			{
				return APP_STATE_GIVEME;
			}
			
			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_tcp, PROTO_MAX, &mid, all_result+hit_num, MAX_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
				q_result=tsg_policy_decision_criteria(all_result, hit_num);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);
			}


			if(a_tcp->curdir==DIR_C2S)
			{
				memset(&identify_info, 0, sizeof(identify_info));
				
				ret=tsg_scan_shared_policy(g_tsg_maat_feather, 
											a_tcp->ptcpdetail->pdata,
											a_tcp->ptcpdetail->datalen,
											all_result+hit_num,
											MAX_RESULT_NUM-hit_num,
											&identify_info,
											&mid,
											g_tsg_para.logger,
											thread_seq);
				if(ret>0)
				{
					hit_num+=ret;
					identify_flag=1;
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_SHARE], 0, FS_OP_ADD, 1);
				}
			}
			
			p_result=tsg_policy_decision_criteria(all_result, hit_num);
			
			if(p_result!=NULL)
			{
				if(q_result!=NULL && (p_result==q_result))
				{
					ip_policy=1;
					send_log=1;
				}
				
				switch((unsigned char)p_result->action)
				{
					case	TSG_ACTION_DENY:
						if(ip_policy==1)
						{
							MESA_kill_tcp(a_tcp, a_packet);
							state|=APP_STATE_DROPPKT;
						}
						break;
					case	TSG_ACTION_MONITOR:
						break;
					case	TSG_ACTION_BYPASS:
						send_log=1;
						state|=APP_STATE_DROPPKT; //TODO
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
						break;
					case	TSG_ACTION_INTERCEPT:
						send_log=0;
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
						priority_label=(policy_priority_label_t *)dictator_malloc(thread_seq, sizeof(policy_priority_label_t));
						
						priority_label->result_num=1;
						priority_label->result_type=PULL_KNI_RESULT;
						priority_label->domain_len=identify_info.domain_len;
						memcpy(priority_label->domain, identify_info.domain, identify_info.domain_len);
						memcpy(priority_label->result, p_result, sizeof(struct Maat_rule_t));
						
						ret=project_req_add_struct(a_tcp, g_tsg_para.priority_project_id, (void *)priority_label);
						if(ret<0)
						{
							free_policy_label(thread_seq, (void *)priority_label);
							MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_ADD", "Add policy_priority_label failed ...");
						}
						
						MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "INTERCEPT", "Hit intercept policy, policy_id: %d action: %d addr: %s",
															priority_label->result[0].config_id, priority_label->result[0].action, printaddr(&a_tcp->addr, thread_seq));
						break;
					case	TSG_ACTION_NONE:
					default:
						assert(0);
						break;
				}

				if(send_log==1 && p_result->do_log>0)
				{
					TLD_handle=TLD_create(thread_seq);
					if(identify_flag==1)
					{
						schema_field_name=log_field_id2name(g_tsg_log_instance, LOG_COMMON_SCHAME_TYPE);
						TLD_append(TLD_handle, schema_field_name, (void *)((identify_info.proto==PROTO_HTTP) ? "HTTP" : "SSL"), TLD_TYPE_STRING);
						
						domain_field_name=log_field_id2name(g_tsg_log_instance, ((identify_info.proto==PROTO_HTTP) ? LOG_HTTP_HOST : LOG_SSL_SNI));
						TLD_append(TLD_handle, domain_field_name, (void *)identify_info.domain, TLD_TYPE_STRING);
					}
					
					log_msg.a_stream=a_tcp;
					log_msg.result=p_result;
					log_msg.result_num=1;
					tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
				}
			}
		break;
		case	OP_STATE_CLOSE:
		default:
			break;
	}

	return state;
}



extern "C" int TSG_MASTER_INIT()
{
	int i=0,ret=0,cycle=0;
	int value=0,level=30;
	unsigned short fs_server_port=0;
	char app_name[MAX_STRING_LEN]={0};
	char log_path[MAX_STRING_LEN*4]={0};
	char label_buff[MAX_STRING_LEN*4]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[MAX_STRING_LEN*4]={0};

	memset(&g_tsg_para, 0, sizeof(g_tsg_para));
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","LOG_LEVEL", &level, 30);
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM","LOG_PATH", log_path, sizeof(log_path), NULL);

	g_tsg_para.logger=MESA_create_runtime_log_handle(log_path, level);
	if(g_tsg_para.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}


	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "POLICY_PRIORITY_LABEL", label_buff, sizeof(label_buff), "POLICY_PRIORITY");
	g_tsg_para.priority_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_policy_label);
	if(g_tsg_para.priority_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed ...", label_buff);
		return -1;
	}

	ret=tsg_rule_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_MAAT", "tsg_rule_init failed ...");
		return -1;
	}

	g_tsg_log_instance=tsg_sendlog_init(tsg_conffile);
	if(g_tsg_log_instance==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_SENDLOG", "tsg_sendlog_init failed ...");
		return -1;
	}

	MESA_load_profile_int_def(tsg_conffile, "FIELD_STAT", "CYCLE", &cycle, 30);
	MESA_load_profile_short_nodef(tsg_conffile, "FIELD_STAT","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(tsg_conffile,"FIELD_STAT","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "tsg_stat.log");
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","APP_NAME", app_name, sizeof(app_name), "tsg_master");

	g_tsg_para.fs2_handle=FS_create_handle();

	value=1;//Rewrite
	FS_set_para(g_tsg_para.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(g_tsg_para.fs2_handle, CREATE_THREAD, &value, sizeof(value));
	
    FS_set_para(g_tsg_para.fs2_handle, STAT_CYCLE, &cycle, sizeof(cycle));
    FS_set_para(g_tsg_para.fs2_handle, APP_NAME, app_name, strlen(app_name)+1);
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);

    if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
    {
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_IP,fs_server_ip, strlen(fs_server_ip)+1);
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_PORT,&(fs_server_port), sizeof(fs_server_port));
    }

	for(i=0; i<TSG_FS2_MAX; i++)
	{
		g_tsg_para.fs2_field_id[g_tsg_fs2_field[i].id]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, g_tsg_fs2_field[i].name);
	}

	
	FS_start(g_tsg_para.fs2_handle);
	
	return 0;
}



extern "C" int TSG_MASTER_UNLOAD()
{
	return 0;
}

