#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <MESA/http.h>
#include <MESA/ftp.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"
#include "tsg_ssl_utils.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define GIT_VERSION_CATTER(v) __attribute__((__used__)) const char * GIT_VERSION_##v = NULL
#define GIT_VERSION_EXPEND(v) GIT_VERSION_CATTER(v)

/* VERSION TAG */
#ifdef GIT_VERSION
GIT_VERSION_EXPEND(GIT_VERSION);
#else
static __attribute__((__used__)) const char * GIT_VERSION_UNKNOWN = NULL;
#endif
#undef GIT_VERSION_CATTER
#undef GIT_VERSION_EXPEND

#ifdef __cplusplus
}
#endif


char TSG_MASTER_VERSION_20200113=0;
const char *tsg_conffile="tsgconf/main.conf";
g_tsg_para_t g_tsg_para;

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{TLD_TYPE_UNKNOWN, TSG_FS2_LINKS, "links"}, 
										 {TLD_TYPE_UNKNOWN, TSG_FS2_BYPASS, "bypass"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_SHARE, "hit_share"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_INTERCEPT, "intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_LOG, "log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_DENY, "deny"}
	};

static void free_policy_label(int thread_seq, void *project_req_value)
{
	dictator_free(thread_seq, project_req_value);
	project_req_value=NULL;
}

static char *schema_index2string(tsg_protocol_t proto)
{
	char *schema_field_value=NULL;

	switch(proto)
	{
		case	PROTO_HTTP:
			schema_field_value=(char *)"HTTP";
			break;
		case	PROTO_SSL:
			schema_field_value=(char *)"SSL";
			break;
		case	PROTO_DNS:
			schema_field_value=(char *)"DNS";
			break;
		case	PROTO_FTP:
			schema_field_value=(char *)"FTP";
			break;
		case	PROTO_BGP:
			schema_field_value=(char *)"BGP";
			break;
		case	PROTO_SIP:
			schema_field_value=(char *)"SIP";
			break;
		case	PROTO_MAIL:
			schema_field_value=(char *)"MAIL";
			break;
		case	PROTO_STREAMING_MEDIA:
			schema_field_value=(char *)"STREAMING_MEDIA";
			break;
		default:
			break;
	}

	return schema_field_value;
}

static int master_send_log(struct streaminfo *a_stream, struct Maat_rule_t *p_result, int result_num, struct _identify_info *identify_info, int thread_seq)
{
	tsg_log_t log_msg;	
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	char *schema_field_value=NULL;
	struct TLD_handle_t *TLD_handle=NULL;

	TLD_handle=TLD_create(thread_seq);
	if(identify_info!=NULL && (identify_info->proto>PROTO_UNKONWN) && (identify_info->proto<PROTO_MAX))
	{
		schema_field_name=log_field_id2name(g_tsg_log_instance, LOG_COMMON_SCHAME_TYPE);

		schema_field_value=schema_index2string(identify_info->proto);
		if(schema_field_value!=NULL)
		{
			TLD_append(TLD_handle, schema_field_name, (void *)schema_field_value, TLD_TYPE_STRING);
		}

		if(identify_info->proto==PROTO_HTTP || identify_info->proto==PROTO_SSL)
		{
			domain_field_name=log_field_id2name(g_tsg_log_instance, ((identify_info->proto==PROTO_HTTP) ? LOG_HTTP_HOST : LOG_SSL_SNI));
			TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
		}
	}
	
	log_msg.a_stream=a_stream;
	log_msg.result=p_result;
	log_msg.result_num=result_num;
	tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
	tsg_set_policy_flow(a_stream, p_result, thread_seq);
	
	return 1;
}

static struct Maat_rule_t *tsg_policy_decision_criteria(Maat_rule_t *result, int result_num)
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
			if(result[i].config_id>p_result->config_id)
			{
				p_result=&result[i];
			}
		}	
	}

	return p_result;
}

static int identify_application_protocol(struct streaminfo *a_stream, struct _identify_info *identify_info)
{
	int ret=0;

	identify_info->proto = PROTO_UNKONWN;
	//http
	char *host = NULL;
	ret=http_host_parser((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, DIR_C2S, &host);
	if(ret>=0)
	{
		identify_info->proto=PROTO_HTTP;
		if(ret==0)
		{
			identify_info->domain_len=0;
		}
		else
		{
			identify_info->domain_len=MIN(ret, (int)sizeof(identify_info->domain) - 1);
			strncpy(identify_info->domain, host, identify_info->domain_len);
		}
		return 1;
	}
	
	//ssl
	enum chello_parse_result chello_status = CHELLO_PARSE_INVALID_FORMAT;
	struct ssl_chello *chello = NULL;

	chello=ssl_chello_parse((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, &chello_status);
	if(chello_status==CHELLO_PARSE_SUCCESS)
	{
		identify_info->proto=PROTO_SSL;
		if(chello->sni==NULL)
		{
			identify_info->domain_len = 0;
		}
		else
		{
			identify_info->domain_len = strnlen(chello->sni, sizeof(identify_info->domain) - 1);
			strncpy(identify_info->domain, chello->sni, identify_info->domain_len);
		}
		
		ssl_chello_free(chello);
		return 1;
	}
	
    ssl_chello_free(chello);

	//dns
	struct stream_tuple4_v4 *tpl4 = NULL;
	struct stream_tuple4_v6 *tpl6 = NULL;

	switch(a_stream->addr.addrtype)
	{
		case ADDR_TYPE_IPV4:
			tpl4=a_stream->addr.tuple4_v4;
			if((ntohs(tpl4->source)==53) || (ntohs(tpl4->dest)==53))
			{
				identify_info->proto=PROTO_DNS;
				return 1;
			}
			break;
		case ADDR_TYPE_IPV6:
			tpl6=a_stream->addr.tuple4_v6;
			if((ntohs(tpl6->source)==53) || (ntohs(tpl6->dest)==53))
			{
				identify_info->proto=PROTO_DNS;
				return 1;
			}
			break;
		default:
			break;
	}

	//ftp
	ret=ftp_control_identify(a_stream);
	if(ret>0)
	{
		identify_info->proto=PROTO_FTP;
		return 1;
	}

	//mail
	
	return ret;
}

extern "C" char TSG_MASTER_TCP_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{
	int ret=0,hit_num=0;
	int state=APP_STATE_DROPME;
	scan_status_t mid=NULL;
	Maat_rule_t *p_result=NULL;
	Maat_rule_t *q_result=NULL;
	struct _identify_info identify_info;
	Maat_rule_t all_result[MAX_RESULT_NUM];
	policy_priority_label_t *priority_label=NULL;
	struct _master_context *_context=(struct _master_context *)*pme;
	
	switch(a_tcp->opstate)
	{
		case	OP_STATE_PENDING:
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_LINKS], 0, FS_OP_ADD, 1);
			
			memset(&identify_info, 0, sizeof(identify_info));
			identify_application_protocol(a_tcp, &identify_info);
			
			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_tcp, identify_info.proto, &mid, all_result+hit_num, MAX_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
				q_result=tsg_policy_decision_criteria(all_result, hit_num);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
			}
			
			ret=tsg_scan_shared_policy(g_tsg_maat_feather, &identify_info, all_result+hit_num, MAX_RESULT_NUM-hit_num, &mid, thread_seq);

			if(ret>0)
			{
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_SHARE], 0, FS_OP_ADD, 1);
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_FQDN",
											"Hit %s: %s policy_id: %d service: %d action: %d addr: %s",

											(identify_info.proto==PROTO_HTTP) ? "host" : "sni",
											identify_info.domain,
											all_result[hit_num].config_id,
											all_result[hit_num].service_id,
											all_result[hit_num].action,
											printaddr(&a_tcp->addr, thread_seq)
										);

				hit_num+=ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_FQDN",
											"Not hit %s: %s stream_dir: %d addr: %s",

											(ret==-1) ?  "NULL" : ((identify_info.proto==PROTO_HTTP) ? "host" : "sni"),
											(ret==-1) ? "NULL" : identify_info.domain,
											a_tcp->dir,
											printaddr(&a_tcp->addr, thread_seq)
										);
			}
			
			p_result=tsg_policy_decision_criteria(all_result, hit_num);
			
			if(p_result!=NULL)
			{	
				switch((unsigned char)p_result->action)
				{
					case	TSG_ACTION_DENY:
						MESA_kill_tcp(a_tcp, a_packet);
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_DENY], 0, FS_OP_ADD, 1);

						master_send_log(a_tcp, p_result, 1, &identify_info, thread_seq);
						state|=APP_STATE_DROPPKT|APP_STATE_KILL_OTHER;

						MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"DENY",
												"Hit deny policy, policy_id: %d action: %d addr: %s",
												p_result[0].config_id,
												p_result[0].action,
												printaddr(&a_tcp->addr, thread_seq)
												);
						break;
					case	TSG_ACTION_MONITOR:
						if(q_result!=NULL && (p_result==q_result))
						{
							*pme=dictator_malloc(thread_seq, sizeof(struct _master_context));
							_context=(struct _master_context *)*pme;
							_context->hit_cnt=1;
							_context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t));
							memcpy(_context->result, p_result, sizeof(struct Maat_rule_t));

							state=APP_STATE_GIVEME;
						}
						break;
					case	TSG_ACTION_BYPASS:
						*pme=dictator_malloc(thread_seq, sizeof(struct _master_context));
						_context=(struct _master_context *)*pme;
						_context->hit_cnt=1;
						_context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t));
						memcpy(_context->result, p_result, sizeof(struct Maat_rule_t));
							
						state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
						break;
					case	TSG_ACTION_INTERCEPT:
						FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);

						tsg_set_policy_flow(a_tcp, p_result, thread_seq);
						
						priority_label=(policy_priority_label_t *)dictator_malloc(thread_seq, sizeof(policy_priority_label_t));
						
						priority_label->result_num=1;
						priority_label->result_type=PULL_KNI_RESULT;
						priority_label->proto=identify_info.proto;
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
			}

			if(mid!=NULL)
			{
				Maat_clean_status(&mid);
				mid=NULL;
			}
		break;
		case	OP_STATE_DATA:
		case	OP_STATE_CLOSE:
			if(_context!=NULL)
			{
				if(_context->hit_cnt>0 && _context->result!=NULL)
				{
					master_send_log(a_tcp, _context->result, _context->hit_cnt, NULL, thread_seq);
					dictator_free(thread_seq, (void *)_context->result);
					_context->result=NULL;
				}
			}
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

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "DEVICE_ID", &g_tsg_para.device_id, 0);

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

	ret=tsg_statistic_init(tsg_conffile, g_tsg_para.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_STATISTIC", "tsg_statistic_init failed ...");
		return -1;
	}
	
	return 0;
}



extern "C" int TSG_MASTER_UNLOAD()
{
	return 0;
}

