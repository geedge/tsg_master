#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <MESA/http.h>
#include <MESA/ftp.h>
#include <MESA/ssl.h>
#include <MESA/mail.h>
#include "MESA/gquic.h"
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "app_label.h"
#include "tsg_rule.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_statistic.h"
#include "tsg_send_log_internal.h"
#include "tsg_ssl_utils.h"
#include "tsg_ssh_utils.h"

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


char TSG_MASTER_VERSION_20200805=0;
const char *tsg_conffile="tsgconf/main.conf";
g_tsg_para_t g_tsg_para;

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{TLD_TYPE_UNKNOWN, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {TLD_TYPE_UNKNOWN, TSG_FS2_BYPASS, "bypass"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_HIT_SHARE, "hit_share"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_INTERCEPT, "intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_EXCLUSION, "exclusion"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_SUCCESS_LOG, "success_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_FAILED_LOG, "failed_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_DROP_LOG, "drop_log"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_ALLOW, "abort_allow"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_DENY, "abort_deny"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_MONITOR, "abort_monitor"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_INTERCEPT, "abort_intercept"},
										 {TLD_TYPE_UNKNOWN, TSG_FS2_ABORT_UNKNOWN, "abort_unknown"}
										};

id2field_t g_tsg_proto_name2id[PROTO_MAX]={{TLD_TYPE_UNKNOWN, PROTO_UNKONWN, "unknown"}, 
										 {TLD_TYPE_UNKNOWN, PROTO_IPv4, "IPV4"},
										 {TLD_TYPE_UNKNOWN, PROTO_IPv6, "IPV6"},
										 {TLD_TYPE_UNKNOWN, PROTO_TCP, "TCP"},
										 {TLD_TYPE_UNKNOWN, PROTO_UDP, "UDP"},
										 {TLD_TYPE_UNKNOWN, PROTO_HTTP, "HTTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_MAIL, "MAIL"},
										 {TLD_TYPE_UNKNOWN, PROTO_DNS, "DNS"},
										 {TLD_TYPE_UNKNOWN, PROTO_FTP, "FTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_SSL, "SSL"},
										 {TLD_TYPE_UNKNOWN, PROTO_SIP, "SIP"},
										 {TLD_TYPE_UNKNOWN, PROTO_BGP, "BGP"},
										 {TLD_TYPE_UNKNOWN, PROTO_STREAMING_MEDIA, "STREAMING_MEDIA"},
										 {TLD_TYPE_UNKNOWN, PROTO_QUIC, "QUIC"},
										 {TLD_TYPE_UNKNOWN, PROTO_SSH, "SSH"},
										 {TLD_TYPE_UNKNOWN, PROTO_SMTP, "SMTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_IMAP, "IMAP"},
										 {TLD_TYPE_UNKNOWN, PROTO_POP3, "POP3"},
										 {TLD_TYPE_UNKNOWN, PROTO_RTP, "RTP"},
										 {TLD_TYPE_UNKNOWN, PROTO_APP, "APP"}
										};

#define	DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID	1


static int init_context(void **pme, int thread_seq)
{	
	struct master_context *context=(struct master_context *)*pme;

	*pme=dictator_malloc(thread_seq, sizeof(struct master_context));
	memset(*pme, 0, sizeof(struct master_context));
	context=(struct master_context *)*pme;
	context->domain_len=0;
	memset(context->domain, 0, sizeof(context->domain));
	
	context->continue_scan_app_id=APP_SCAN_FLAG_CONTINUE;
	context->continue_scan_proto_id=APP_SCAN_FLAG_CONTINUE;

	return 0;
}

static int tsg_get_sn(char *filename, char *device_sn, int device_sn_len)
{
	int ret=0,flags=0;
	char buff[4096]={0};
	cJSON *object=NULL;
	
	FILE *fp=fopen(filename, "rb");
	if(fp)
	{
		ret=fread(buff, sizeof(buff), 1, fp);
		if(ret<(int)sizeof(buff))
		{
			object=cJSON_Parse(buff);
			if(object)
			{
				cJSON *item=cJSON_GetObjectItem(object, "sn");
				if(item && item->valuestring!=NULL && device_sn_len>(int)strlen(item->valuestring))
				{
					flags=1;
					memcpy(device_sn, item->valuestring, strlen(item->valuestring));
				}
				cJSON_Delete(object);
				object=NULL;
			}
		}

		fclose(fp);
		fp=NULL;
	}

	return flags;
}

static int get_device_id(char *command, int entrance_id)
{
	FILE *fp=NULL; 
	char buffer[128]={0};

	fp=popen(command, "r"); 
	if(fp)
	{
		fgets(buffer,sizeof(buffer),fp); 
    	pclose(fp);
	}
	
	return (entrance_id<<7)+(atoi(buffer)%128);
}

static int is_repetitive_protocol_id(unsigned short proto_id)
{
	switch(proto_id)
	{
		case	DNS_PROTO_ID:
		case	FTP_PROTO_ID:
		case	HTTP_PROTO_ID:
		case	MAIL_PROTO_ID:
		case	QUIC_PROTO_ID:
		case	SIP_PROTO_ID:
		case	SSL_PROTO_ID:
		case	RTP_PROTO_ID:
			return 1;
		default:
			break;
	}

	return 0;
}

static int is_only_monitor(struct Maat_rule_t *result, int hit_cnt)
{
	int i=0;

	for(i=0; i<hit_cnt; i++)
	{
		if(result[i].action==TSG_ACTION_BYPASS || result[i].action==TSG_ACTION_INTERCEPT || result[i].action==TSG_ACTION_DENY)
		{
			return 0;
		}
	}

	return 1;
}

static int get_default_policy(int compile_id, struct Maat_rule_t *result)
{
	struct Maat_rule_t p_result={0};
	struct compile_user_region *user_region=NULL;

	p_result.config_id=compile_id;
	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, &p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region!=NULL)
	{
		if(user_region->result!=NULL)
		{
			memcpy(result, user_region->result, sizeof(struct Maat_rule_t));
			if(result->action==TSG_ACTION_BYPASS)
			{
				result->action=TSG_ACTION_NONE;
			}
		}
		
		security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], &p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
		return 1;
	}

	return 0;
}

static struct app_id_label *get_app_id_label(struct streaminfo *a_stream, struct master_context *context, int thread_seq)
{
	struct app_id_label *app_id_label=NULL;
	
	if(context->continue_scan_app_id==APP_SCAN_FLAG_CONTINUE && g_tsg_para.app_id_project_id>=0)
	{	
		app_id_label=(struct app_id_label *)project_req_get_struct(a_stream, g_tsg_para.app_id_project_id);
		if(app_id_label==NULL)
		{
			return NULL;
		}

		if(context->app_id!=app_id_label->app_id)
		{
			MESA_handle_runtime_log(g_tsg_para.logger, 
									RLOG_LV_DEBUG,
									"READ_APP_ID_FLAG",
									"Get app id label, app_id: %d addr: %s",
									app_id_label->app_id,
									PRINTADDR(a_stream, g_tsg_para.level)
								);
			context->app_id=app_id_label->app_id;
			return app_id_label;
		}

		
	}
	
	return NULL;
}

static int get_basic_proto_id(struct streaminfo *a_stream, struct master_context *context, int thread_seq)
{
	struct basic_proto_label *proto_label=NULL;

	if(context->continue_scan_proto_id==APP_SCAN_FLAG_CONTINUE && g_tsg_para.l7_proto_project_id>=0)
	{
		proto_label=(struct basic_proto_label *)project_req_get_struct(a_stream, g_tsg_para.l7_proto_project_id);
		if(proto_label!=NULL)
		{
			if(proto_label->continue_scan_flag==APP_SCAN_FLAG_STOP)
			{
				context->continue_scan_proto_id=APP_SCAN_FLAG_STOP;
			}

			return proto_label->proto_id;
		}
	}

	return 0;
}

static int master_send_log(struct streaminfo *a_stream, struct Maat_rule_t *p_result, int result_num, struct identify_info *identify_info, int thread_seq)
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

		if(identify_info->proto==PROTO_IMAP || identify_info->proto==PROTO_SMTP || identify_info->proto==PROTO_POP3)
		{
			schema_field_value=tsg_schema_index2string(PROTO_MAIL);
		}
		else
		{
			schema_field_value=tsg_schema_index2string(identify_info->proto);
		}
		
		if(schema_field_value!=NULL)
		{
			TLD_append(TLD_handle, schema_field_name, (void *)schema_field_value, TLD_TYPE_STRING);
		}

		switch(identify_info->proto)
		{
			case	PROTO_HTTP:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_HOST);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			case	PROTO_SSL:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_SSL_SNI);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			case	PROTO_QUIC:
				domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_SNI);
				TLD_append(TLD_handle, domain_field_name, (void *)identify_info->domain, TLD_TYPE_STRING);
				break;
			default:
				break;
		}
	}
	
	log_msg.a_stream=a_stream;
	log_msg.result=p_result;
	log_msg.result_num=result_num;
	tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
	
	if(p_result->config_id!=DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID)
	{
		tsg_set_policy_flow(a_stream, p_result, thread_seq);
	}
	
	return 1;
}


static int tsg_proto_name2flag(char *proto_list, int *flag)
{
	int i=0;
	char *s=NULL,*e=NULL;

	s=proto_list;
	while(s)
	{
		e=index(s, ';');
		if(!e)
		{
			break;
		}

		for(i=0; i< PROTO_MAX; i++)
		{
			if((memcmp(s, g_tsg_proto_name2id[i].name, e-s))==0)
			{
				*flag|=(1<<g_tsg_proto_name2id[i].id);
				break;
			}
		}
		
		s=e+1;	
	}

	return 0;
}

int get_depolyment_mode(void)
{
	int ret=0, len=0;
	char buff[32]={0};

	len=sizeof(buff);
	ret=sapp_get_platform_opt(SPO_DEPLOYMENT_MODE_STR, buff, &len);
	if(ret>=0)
	{
		if((memcmp(buff, "mirror", strlen(buff)))==0)
		{
			g_tsg_para.depolyment_mode=0;
		}
		else
		{
			g_tsg_para.depolyment_mode=1;
		}
	}

	return 0;
}

void free_app_id_label(int thread_seq, void *project_req_value)
{
	if(project_req_value!=NULL)
	{
		dictator_free(thread_seq, project_req_value);
	}
}

static void free_policy_label(int thread_seq, void *project_req_value)
{
	dictator_free(thread_seq, project_req_value);
	project_req_value=NULL;
}

static void copy_identify_info(struct master_context *context, struct identify_info *identify_info, int thread_seq)
{
	if(identify_info->proto>PROTO_UNKONWN && identify_info->proto<PROTO_MAX && identify_info->domain_len>0 && strlen(identify_info->domain)>0)
	{
		memcpy(context->domain, identify_info->domain, identify_info->domain_len);
		context->domain_len=identify_info->domain_len;
	}
}

static void copy_monitor_result(struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int result_num, int thread_seq)
{
	int i=0;
	
	if(context->result==NULL)
	{
		context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t)*MAX_RESULT_NUM);

		for(i=0; i<result_num && p_result[i].action!=TSG_ACTION_INTERCEPT && context->hit_cnt<MAX_RESULT_NUM; i++) // SSL Decryption Exclusion
		{
			memcpy(context->result+context->hit_cnt, &p_result[i], sizeof(struct Maat_rule_t));
			context->hit_cnt+=1;
		}
	}
	else
	{
		if(context->result[0].action==TSG_ACTION_MONITOR)
		{
			for(i=0; i<result_num && p_result[i].action!=TSG_ACTION_INTERCEPT && context->hit_cnt<MAX_RESULT_NUM; i++) // SSL Decryption Exclusion
			{
				memcpy(context->result+context->hit_cnt, &p_result[i], sizeof(struct Maat_rule_t));
				context->hit_cnt+=1;
			}
		}
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"MONITOR",
								"Hit monitor policy, policy_id: %d service: %d action: %d addr: %s",
								p_result[0].config_id,
								p_result[0].service_id,
								(unsigned char)p_result[0].action,
								PRINTADDR(a_stream, g_tsg_para.level)
							);

}

static void copy_intercept_result(struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, struct identify_info *identify_info, int thread_seq)
{
	int ret=0;
	policy_priority_label_t *priority_label=NULL;	

	priority_label=(policy_priority_label_t *)dictator_malloc(thread_seq, sizeof(policy_priority_label_t));
	
	priority_label->result_num=1;
	priority_label->result_type=PULL_KNI_RESULT;
	priority_label->proto=identify_info->proto;
	priority_label->domain_len=identify_info->domain_len;
	memcpy(priority_label->domain, identify_info->domain, identify_info->domain_len);
	memcpy(priority_label->result, p_result, sizeof(struct Maat_rule_t));
	
	ret=project_req_add_struct(a_stream, g_tsg_para.priority_project_id, (void *)priority_label);
	if(ret<0)
	{
		free_policy_label(thread_seq, (void *)priority_label);
		MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_FATAL,
								"PROJECT_ADD",
								"Add policy_priority_label failed, intercept policy, policy_id: %d action: %d addr: %s",
								priority_label->result[0].config_id,
								(unsigned char)priority_label->result[0].action,
								PRINTADDR(a_stream, g_tsg_para.level)
							);
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, 
							RLOG_LV_DEBUG,
							"INTERCEPT",
							"Hit intercept policy, policy_id: %d action: %d addr: %s",
							priority_label->result[0].config_id,
							(unsigned char)priority_label->result[0].action,
							PRINTADDR(a_stream, g_tsg_para.level)
						);

	return ;
}

static void copy_deny_result(struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int thread_seq)
{
	if(context->result==NULL)
	{
		context->hit_cnt=1;
		context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t));
			
		memcpy(context->result, p_result, sizeof(struct Maat_rule_t));
	}
	else
	{
		context->hit_cnt=1;
		memcpy(context->result, p_result, sizeof(struct Maat_rule_t));
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"DENY",
								"Hit deny policy, policy_id: %d service: %d action: %d addr: %s",
								p_result[0].config_id,
								p_result[0].service_id,
								(unsigned char)p_result[0].action,
								PRINTADDR(a_stream, g_tsg_para.level)
							);

	return ;
}

static void copy_bypass_result(struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int thread_seq)
{
	if(context->result==NULL)
	{
		context->hit_cnt=1;
		context->result=(struct Maat_rule_t *)dictator_malloc(thread_seq, sizeof(struct Maat_rule_t));
			
		memcpy(context->result, p_result, sizeof(struct Maat_rule_t));
	}
	else
	{
		if(context->result[0].action==TSG_ACTION_BYPASS)
		{
			if(p_result->config_id>context->result[0].config_id)
			{
				context->hit_cnt=1;
				memcpy(&(context->result[0]), p_result, sizeof(struct Maat_rule_t));
			}
		}
		else   // hit monitor
		{
			context->hit_cnt=1;
			memcpy(context->result, p_result, sizeof(struct Maat_rule_t));
		}
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"ALLOW",
								"Hit allow policy, policy_id: %d service: %d action: %d addr: %s",
								p_result[0].config_id,
								p_result[0].service_id,
								(unsigned char)p_result[0].action,
								PRINTADDR(a_stream, g_tsg_para.level)
							);

	return ;
}

int is_intercept_exclusion(struct streaminfo *a_stream, Maat_rule_t *p_result, struct identify_info *identify_info, int thread_seq)
{
	int ret=0;	
	scan_status_t mid=NULL;
	Maat_rule_t tmp_result;

	if(identify_info!=NULL && identify_info->domain_len>0)
	{
		ret=Maat_full_scan_string(g_tsg_maat_feather,
									g_tsg_para.table_id[TABLE_EXCLUSION_SSL_SNI],
									CHARSET_UTF8,
									identify_info->domain,
									identify_info->domain_len,
									&tmp_result,
									NULL,
									1,
									&mid,
									thread_seq);

		if(mid!=NULL)
		{
			Maat_clean_status(&mid);
			mid=NULL;
		}

		if(ret>0)
		{	
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"EXCLUSION_SSL_SNI",
										"Hit %s policy_id: %d service: %d action: %d Decryption Exclusion: [ policy_id: %d service: %d action: %d ] addr: %s",
										identify_info->domain,
										tmp_result.config_id,
										tmp_result.service_id,
										(unsigned char)tmp_result.action,
										p_result->config_id,
										p_result->service_id,
										(unsigned char)p_result->action,
										PRINTADDR(a_stream, g_tsg_para.level)
									);
						
			return 1;
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"EXCLUSION_SSL_SNI",
										"Not hit %s stream_dir: %d addr: %s  scan ret: %d",
										identify_info->domain,
										a_stream->dir,
										PRINTADDR(a_stream, g_tsg_para.level),
										ret
									);
		}
	}

	return 0;
}

void close_stream_free_context(struct streaminfo *a_stream, struct master_context *context, int thread_seq)
{
	struct identify_info identify_info;

	if(context!=NULL)
	{
		if(context->hit_cnt>0 && context->result!=NULL)
		{
			memset(&identify_info, 0, sizeof(identify_info));
			if(context->proto==PROTO_UNKONWN || context->proto>PROTO_APP)
			{
				identify_info.proto=PROTO_APP;
			}
			else
			{
				identify_info.proto=context->proto;
			}

			if(context->domain_len>0)
			{
				memcpy(identify_info.domain, context->domain, context->domain_len);
				identify_info.domain_len=context->domain_len;
			}
			master_send_log(a_stream, context->result, context->hit_cnt, &identify_info, thread_seq);
		}

		if(context->result!=NULL)
		{
			dictator_free(thread_seq, (void *)context->result);
			context->result=NULL;
		}

		if(context->mid!=NULL)
		{
			Maat_clean_status(&context->mid);
			context->mid=NULL;
		}

		dictator_free(thread_seq, (void *)context);
		context=NULL;
	}

	return ;
}

void set_session_attribute_label(struct streaminfo *a_stream, enum TSG_ATTRIBUTE_TYPE type, void *value, int thread_seq)
{
	struct timespec tv;
	unsigned long long create_time=0;	
	int ret=0,size=sizeof(create_time);
	struct _ssl_ja3_info_t *ja3_info=NULL;
	struct _session_attribute_label_t *attribute_label=NULL;

	attribute_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, g_tsg_para.internal_project_id);
	if(attribute_label==NULL)
	{
		attribute_label=(struct _session_attribute_label_t *)dictator_malloc(thread_seq, sizeof(struct _session_attribute_label_t));
		memset(attribute_label, 0, sizeof(struct _session_attribute_label_t));

		ret=project_req_add_struct(a_stream, g_tsg_para.internal_project_id, (const void *)attribute_label);
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"PROJECT_ADD",
									"Add internal_label failed, establish latency ms: %llu proto: %d addr: %s",
									attribute_label->establish_latency_ms,
									attribute_label->proto,
									PRINTADDR(a_stream, g_tsg_para.level)
									);
		}
	}

	switch(type)
	{
		case	TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY:
			ret=MESA_get_stream_opt(a_stream, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
			if(ret>=0)
			{
				clock_gettime(CLOCK_REALTIME, &tv);
				attribute_label->establish_latency_ms=tv.tv_sec*1000+tv.tv_nsec/1000/1000 - create_time;
			}
			break;
		case	TSG_ATTRIBUTE_TYPE_PROTOCOL:
			attribute_label->proto=(tsg_protocol_t)(*(int *)value);
			break;
		case	TSG_ATTRIBUTE_TYPE_JA3_HASH:
			ja3_info=ssl_get_ja3_fingerprint(a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
			if(ja3_info!=NULL)
			{
				if(attribute_label!=NULL && ja3_info->fp!=NULL && ja3_info->fp_len>0)
				{
					attribute_label->ja3_fingerprint=(char *)dictator_malloc(a_stream->threadnum, ja3_info->fp_len+1);
					memcpy(attribute_label->ja3_fingerprint, ja3_info->fp, ja3_info->fp_len);
					attribute_label->ja3_fingerprint[ja3_info->fp_len]='\0';
				}			
			}
			break;
		default:
			break;
	}

	return ;
}

char *tsg_schema_index2string(tsg_protocol_t proto)
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
		case	PROTO_QUIC:
			schema_field_value=(char *)"QUIC";
			break;
		case	PROTO_SSH:
			schema_field_value=(char *)"SSH";
			break;
		case	PROTO_IMAP:
			schema_field_value=(char *)"IMAP";
			break;
		case	PROTO_POP3:
			schema_field_value=(char *)"POP3";
			break;
		case	PROTO_SMTP:
			schema_field_value=(char *)"SMTP";
			break;
		case	PROTO_RTP:
			schema_field_value=(char *)"RTP";
			break;
		case	PROTO_APP:
			schema_field_value=(char *)"APP";
			break;
		default:
			break;
	}

	return schema_field_value;
}

int tsg_set_device_id_to_telegraf(char *device_sn)
{
	char buff[128]={0};
	FILE *fp=NULL;

	if(device_sn)
	{
		fp=fopen("/etc/default/telegraf", "wb");
		if(fp)
		{
			snprintf(buff, sizeof(buff), "device_id=\"%s\"\n", device_sn);
			fwrite(buff, strlen(buff), 1, fp);
			fclose(fp);
			fp=NULL;
			return 0;
		}
	}

	return -1;
}

static void free_session_attribute_label(int thread_seq, void *project_req_value)
{
	struct _session_attribute_label_t *label=(struct _session_attribute_label_t *)project_req_value;

	if(label!=NULL)
	{
		if(label->client_asn!=NULL)
		{
			ASN_free_data(label->client_asn->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->client_asn), 0, g_tsg_para.logger);
			label->client_asn=NULL;
		}

		if(label->server_asn!=NULL)
		{
			ASN_free_data(label->server_asn->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->server_asn), 0, g_tsg_para.logger);
			label->server_asn=NULL;
		}

		if(label->client_location!=NULL)
		{
			location_free_data(label->client_location->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->client_location), 0, g_tsg_para.logger);
			label->client_location=NULL;
		}

		if(label->server_location!=NULL)
		{
			location_free_data(label->server_location->table_id, (MAAT_PLUGIN_EX_DATA *)&(label->server_location), 0, g_tsg_para.logger);
			label->server_location=NULL;
		}

		if(label->client_subscribe_id!=NULL)
		{
			subscribe_id_free_data(label->client_subscribe_id->table_id, (MAAT_PLUGIN_EX_DATA *)&label->client_subscribe_id, 0, g_tsg_para.logger);
			label->client_subscribe_id=NULL;
		}

		if(label->server_subscribe_id!=NULL)
		{
			subscribe_id_free_data(label->server_subscribe_id->table_id, (MAAT_PLUGIN_EX_DATA *)&label->server_subscribe_id, 0, g_tsg_para.logger);
			label->server_subscribe_id=NULL;
		}

		if(label->ja3_fingerprint!=NULL)
		{
			dictator_free(thread_seq, (void *)label->ja3_fingerprint);
			label->ja3_fingerprint=NULL;
		}
		
		dictator_free(thread_seq, project_req_value);
		project_req_value=NULL;
	}
}

struct Maat_rule_t *tsg_policy_decision_criteria(struct streaminfo *a_stream, Maat_rule_t *result, int result_num, struct identify_info *identify_info, int thread_seq)
{
	int i=0;
	Maat_rule_t *p_result=NULL;

	for(i=0; i<result_num; i++)
	{
		if(p_result==NULL)
		{
			p_result=&result[i];
			continue;
		}
		
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

static int identify_application_protocol(struct streaminfo *a_stream, struct identify_info *identify_info, void *a_packet)
{
	int ret=0;                            
	identify_info->proto = PROTO_UNKONWN;

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if(g_tsg_para.proto_flag&(1<<PROTO_HTTP))  //http
			{
				char *host=NULL;
				ret=http_host_parser((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->curdir, &host);
				if(ret>=0)
				{
					identify_info->proto=PROTO_HTTP;
					if(ret>0 && host!=NULL)
					{
						identify_info->domain_len=MIN(ret, (int)sizeof(identify_info->domain) - 1);
						strncpy(identify_info->domain, host, identify_info->domain_len);
					}
					else
					{
						identify_info->domain_len=0;
					}
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_SSL))  //ssl
			{
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
			}
	
			if(g_tsg_para.proto_flag&(1<<PROTO_FTP))  //ftp
			{
				ret=ftp_control_identify(a_stream);
				if(ret>0)
				{
					identify_info->proto=PROTO_FTP;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_MAIL))  //mail
			{
				ret=mail_protocol_identify_by_first_payload(a_stream,(char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, a_stream->threadnum);
				if(ret>0)
				{
					switch(ret)
					{
						case	SMTP_PROTOCOL:
							identify_info->proto=PROTO_SMTP;
							return 1;
							break;
						case	POP3_PROTOCOL:
							identify_info->proto=PROTO_POP3;
							return 1;
							break;
						case	IMAP_PROTOCOL:
							identify_info->proto=PROTO_IMAP;
							return 1;
							break;
						default:
							break;
					}
				}
			}

			break;
		case	STREAM_TYPE_UDP:
			if(g_tsg_para.proto_flag&(1<<PROTO_DNS))  //dns
			{
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
			}
				
			if(g_tsg_para.proto_flag&(1<<PROTO_SSH))  //ssh
			{
				ret = ssh_protocol_identify((unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen,g_tsg_para.logger);
				if(ret > 0)
				{
					identify_info->proto=PROTO_SSH;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_QUIC))  //quic
			{
				ret=quic_protocol_identify(a_stream, a_packet, identify_info->domain, sizeof(identify_info->domain));
				if(ret>=0)
				{
					identify_info->proto=PROTO_QUIC;
					identify_info->domain_len=ret;
					return 1;
				}
			}
			break;
		default:
			break;
	}
	
	return ret;
}

int scan_application_id_and_properties(struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *result, int result_num, scan_status_t *mid, int thread_seq)
{
	int hit_num=0;
	char app_id_buff[32]={0};
	struct app_id_label *app_id_label=NULL;
	struct app_id_dict_table *dict=NULL;

	app_id_label=get_app_id_label(a_stream, context, thread_seq);
	if(app_id_label!=NULL)
	{
		snprintf(app_id_buff, sizeof(app_id_buff), "%d", app_id_label->app_id);
		dict=(struct app_id_dict_table *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
		if(dict!=NULL)
		{
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->risk, (char *)"risk", thread_seq);
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->category, (char *)"category", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->technology, (char *)"technology", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->subcategroy, (char *)"subcategroy", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->characteristics, (char *)"characteristics", thread_seq);
		
			if(dict->continue_scanning==APP_SCAN_FLAG_STOP)
			{
				context->continue_scan_app_id=APP_SCAN_FLAG_STOP;
			}

			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->app_name, app_id_label->app_id, thread_seq);
		}
		else
		{			
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, (char *)"", app_id_label->app_id, thread_seq);
		}
	}

	return hit_num;
}

extern "C" char TSG_MASTER_TCP_ENTRY(struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{	
	int opt_value=0;
	int proto_id=0;
	char *l7_protocol=NULL;
	int ret=0,hit_num=0;	
	int state=APP_STATE_GIVEME;
	Maat_rule_t *p_result=NULL;
	struct identify_info identify_info;
	Maat_rule_t result[MAX_RESULT_NUM];
	struct rst_tcp_para rst_paras;
	struct compile_user_region *user_region=NULL;
	int method_type=TSG_METHOD_TYPE_UNKNOWN;
	struct master_context *context=(struct master_context *)*pme;

	if(*pme==NULL)
	{		
		init_context(pme, thread_seq);
		context=(struct master_context *)*pme;
	}
	
	switch(a_tcp->opstate)
	{
		case	OP_STATE_PENDING:
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TCP_LINKS], 0, FS_OP_ADD, 1);			
			set_session_attribute_label(a_tcp, TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY, NULL, thread_seq);
			
			memset(&identify_info, 0, sizeof(identify_info));
			ret=identify_application_protocol(a_tcp, &identify_info, a_packet);
			if(ret==1)
			{
				copy_identify_info(context, &identify_info, thread_seq);				
				set_session_attribute_label(a_tcp, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)(&identify_info.proto), thread_seq);
				
				context->proto=identify_info.proto;

				if(identify_info.proto==PROTO_SSL)
				{
					set_session_attribute_label(a_tcp, TSG_ATTRIBUTE_TYPE_JA3_HASH, NULL, thread_seq);				
				}
				else
				{
					context->continue_scan_proto_id=APP_SCAN_FLAG_STOP;
				}
				
				hit_num+=tsg_scan_shared_policy(g_tsg_maat_feather, a_tcp, &identify_info, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, thread_seq);
			}

			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_tcp, identify_info.proto, &context->mid, result+hit_num, MAX_RESULT_NUM-hit_num);
			if(ret>0)
			{
				hit_num+=ret;
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
			}
			if((is_only_monitor(result, hit_num)) && identify_info.proto!=PROTO_UNKONWN)	// business deal action of monitor 
			{
				hit_num=0;
			}
			break;
		default:
			break;
	}

	if(context->proto==PROTO_UNKONWN || context->proto==PROTO_SSL || context->proto>PROTO_APP || context->continue_scan_proto_id==APP_SCAN_FLAG_CONTINUE) /* support block/alert(deny), Do action in fw_http_plug */
	{
		proto_id=get_basic_proto_id(a_tcp, context, thread_seq);
		if(proto_id>0 && proto_id!=context->basic_proto_id)
		{
			context->proto=((context->proto==PROTO_SSL) ? PROTO_SSL : PROTO_APP);
			context->basic_proto_id=proto_id;
			l7_protocol=tsg_l7_protocol_id2name(g_tsg_log_instance, proto_id);
			if(l7_protocol==NULL && proto_id==g_tsg_para.mail_proto_id)
			{
				l7_protocol=(char *)"MAIL";
			}
			
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_tcp, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, l7_protocol, proto_id, thread_seq);
		}
	}
	
	hit_num+=scan_application_id_and_properties(a_tcp, context, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, thread_seq);
	p_result=tsg_policy_decision_criteria(a_tcp, result, hit_num, &identify_info, thread_seq);
	if(g_tsg_para.default_compile_switch==1 && p_result==NULL)
	{
		if(get_default_policy(g_tsg_para.default_compile_id, &result[0]))
		{
			p_result=&result[0];			
			context->is_default_policy=1;
		}
	}

	if(p_result!=NULL)
	{		
		switch((unsigned char)p_result->action)
		{
			case	TSG_ACTION_DENY:
				user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
				if(user_region!=NULL)
				{
					method_type=tsg_get_method_id(user_region->method);
					switch(method_type)
					{
						case	TSG_METHOD_TYPE_DROP:
							opt_value=1;
							MESA_set_stream_opt(a_tcp, MSO_DROP_STREAM, (void *)&opt_value, sizeof(opt_value));
							MESA_set_stream_opt(a_tcp, MSO_TIMEOUT, (void *)&g_tsg_para.timeout, sizeof(g_tsg_para.timeout));
							copy_deny_result(a_tcp, context, p_result, thread_seq);
							state=APP_STATE_DROPPKT|APP_STATE_DROPME;
							break;
						case	TSG_METHOD_TYPE_RESET:
							rst_paras.rst_pkt_num=1;
							rst_paras.signature_seed1=65535;
							rst_paras.signature_seed2=13;
							rst_paras.th_flags=4;
							rst_paras.__pad_no_use=0;
							rst_paras.dir=DIR_DOUBLE;
							ret=MESA_rst_tcp(a_tcp, &rst_paras, sizeof(rst_paras));			

							opt_value=1;
							MESA_set_stream_opt(a_tcp, MSO_TCP_RST_REMEDY, (void *)&opt_value, sizeof(opt_value));

							if(g_tsg_para.depolyment_mode>0)
							{
								opt_value=1;
								MESA_set_stream_opt(a_tcp, MSO_DROP_STREAM, (void *)&opt_value, sizeof(opt_value));
								MESA_set_stream_opt(a_tcp, MSO_TIMEOUT, (void *)&g_tsg_para.timeout, sizeof(g_tsg_para.timeout));
							}
							copy_deny_result(a_tcp, context, p_result, thread_seq);
							state=APP_STATE_DROPPKT|APP_STATE_DROPME;
							break;
						case	TSG_METHOD_TYPE_BLOCK:
						case	TSG_METHOD_TYPE_ALERT:
						case	TSG_METHOD_TYPE_REDIRECTION:
							break;
						default:
							break;
					}
					
					security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
				}
				break;
			case	TSG_ACTION_MONITOR:
				copy_monitor_result(a_tcp, context, result, hit_num, thread_seq);
				break;
			case	TSG_ACTION_BYPASS:
				copy_bypass_result(a_tcp, context, p_result, thread_seq);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
				state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
				break;
			case	TSG_ACTION_INTERCEPT:
				if(is_intercept_exclusion(a_tcp, p_result, &identify_info, thread_seq))
				{					
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_EXCLUSION], 0, FS_OP_ADD, 1);
					break;
				}
				
				copy_intercept_result(a_tcp, context, p_result, &identify_info, thread_seq);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
				state=APP_STATE_DROPME|APP_STATE_KILL_OTHER;
				break;
			default:
				break;
		}
	}

	if((a_tcp->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		close_stream_free_context(a_tcp, context, thread_seq);
		*pme=NULL;
	}

	return state;
}

extern "C" char TSG_MASTER_UDP_ENTRY(struct streaminfo *a_udp, void **pme, int thread_seq,void *a_packet)
{
	int ret=0,hit_num=0;	
	int opt_value=0,proto_id=0;
	char *l7_protocol=NULL;
	int state=APP_STATE_GIVEME;
	Maat_rule_t *p_result=NULL;
	Maat_rule_t result[MAX_RESULT_NUM]={0};
	struct identify_info identify_info;
	struct compile_user_region *user_region=NULL;
	int method_type=TSG_METHOD_TYPE_UNKNOWN;
	struct master_context *context=(struct master_context *)*pme;

	if(*pme==NULL)
	{
		init_context(pme, thread_seq);
		context=(struct master_context *)*pme;
	}
	switch(a_udp->opstate)
	{
		case	OP_STATE_PENDING:			
			FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_UDP_LINKS], 0, FS_OP_ADD, 1);			

			memset(&identify_info, 0, sizeof(identify_info));
			ret=identify_application_protocol(a_udp, &identify_info, a_packet);
			if(ret==1)
			{
				copy_identify_info(context, &identify_info, thread_seq);
				set_session_attribute_label(a_udp, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)&(identify_info.proto), thread_seq);

				context->proto=identify_info.proto;
				context->continue_scan_proto_id=APP_SCAN_FLAG_STOP;
				hit_num+=tsg_scan_shared_policy(g_tsg_maat_feather, a_udp, &identify_info, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, thread_seq);
			}

			ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_udp, identify_info.proto, &context->mid, result, MAX_RESULT_NUM);
			if(ret>0)
			{
				hit_num+=ret;
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
			}

			if((is_only_monitor(result, hit_num)) && identify_info.proto!=PROTO_UNKONWN)	// business deal action of deny and monitor 
			{
				hit_num=0;
			}

			break;
		default:
			break;
	}

	if(context->proto==PROTO_UNKONWN || context->proto>PROTO_APP || context->continue_scan_proto_id==APP_SCAN_FLAG_CONTINUE)
	{
		proto_id=get_basic_proto_id(a_udp, context, thread_seq);
		if(proto_id>0 && context->basic_proto_id!=proto_id)
		{
			if(is_repetitive_protocol_id(proto_id))
			{
				context->continue_scan_proto_id=APP_SCAN_FLAG_STOP;
				switch(proto_id)
				{
					case	SIP_PROTO_ID:					
						context->proto=PROTO_SIP;
						set_session_attribute_label(a_udp, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)&(context->proto), thread_seq);
						break;
					case	RTP_PROTO_ID:					
						context->proto=PROTO_RTP;
						set_session_attribute_label(a_udp, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)&(context->proto), thread_seq);
						break;
					default:
						break;
				}
			}
			else
			{
				context->proto=PROTO_APP;
			}
			
			context->basic_proto_id=proto_id;
			l7_protocol=tsg_l7_protocol_id2name(g_tsg_log_instance, proto_id);
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_udp, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, l7_protocol, proto_id, thread_seq);
		}
	}
	
	hit_num+=scan_application_id_and_properties(a_udp, context, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, thread_seq);
	p_result=tsg_policy_decision_criteria(a_udp, result, hit_num, &identify_info, thread_seq);
	if(g_tsg_para.default_compile_switch==1 && p_result==NULL)
	{
		if(get_default_policy(g_tsg_para.default_compile_id, &result[0]))
		{
			p_result=&result[0];
			context->is_default_policy=1;
		}
	}

	if(p_result!=NULL)
	{
		switch((unsigned char)p_result->action)
		{
			case	TSG_ACTION_DENY:
				user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
				if(user_region!=NULL)
				{
					method_type=tsg_get_method_id(user_region->method);
					switch(method_type)
					{
						case	TSG_METHOD_TYPE_RESET:
						case	TSG_METHOD_TYPE_DROP:
							opt_value=1;
							MESA_set_stream_opt(a_udp, MSO_DROP_STREAM, (void *)&opt_value, sizeof(opt_value));
							MESA_set_stream_opt(a_udp, MSO_TIMEOUT, (void *)&g_tsg_para.timeout, sizeof(g_tsg_para.timeout));		
							break;
						default:
							break;
					}
					security_compile_free(g_tsg_para.table_id[TABLE_SECURITY_COMPILE], p_result, NULL, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
				}
				copy_deny_result(a_udp, context, p_result, thread_seq);
				state=APP_STATE_DROPPKT|APP_STATE_DROPME;
				break;
			case	TSG_ACTION_MONITOR:				
				copy_monitor_result(a_udp, context, result, hit_num, thread_seq);
				break;
			case	TSG_ACTION_BYPASS:
				copy_bypass_result(a_udp, context, p_result, thread_seq);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
				state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
				break;
			case	TSG_ACTION_INTERCEPT:
				break;
			default:
				break;
		}
	}

	if((a_udp->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		close_stream_free_context(a_udp, context, thread_seq);
		*pme=NULL;
	}
	return state;
}

extern "C" int TSG_MASTER_INIT()
{
	int i=0,ret=0;
	int value=0,cycle=0;
	int output_prometheus=0;
	unsigned short fs_server_port=0;
	char app_name[MAX_STRING_LEN]={0};
	char label_buff[MAX_STRING_LEN*4]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[MAX_STRING_LEN*4]={0};
	char device_sn_filename[MAX_STRING_LEN]={0};
	char identify_proto_name[MAX_STRING_LEN*4]={0};
	
	memset(&g_tsg_para, 0, sizeof(g_tsg_para));

	get_depolyment_mode();
	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","LOG_LEVEL", &g_tsg_para.level, RLOG_LV_FATAL);
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM","LOG_PATH", g_tsg_para.log_path, sizeof(g_tsg_para.log_path), "tsglog/tsg_master");

	g_tsg_para.logger=MESA_create_runtime_log_handle(g_tsg_para.log_path, g_tsg_para.level);
	if(g_tsg_para.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}

	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","DEFAULT_POLICY_ID", &g_tsg_para.default_compile_id, 0);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM","DEFAULT_POLICY_SWITCH", &g_tsg_para.default_compile_switch, 0);

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "IDENTIFY_PROTO_NAME", identify_proto_name, sizeof(identify_proto_name), "HTTP;SSL;DNS;FTP;BGP;SIP;MAIL;STREAMING_MEDIA;QUIC;");
	tsg_proto_name2flag(identify_proto_name, &g_tsg_para.proto_flag);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "ENTRANCE_ID", &g_tsg_para.entrance_id, 0);
	MESA_load_profile_short_def(tsg_conffile, "SYSTEM", "TIMEOUT", (short *)&g_tsg_para.timeout, 300);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "MAIL_PROTOCOL_ID",&(g_tsg_para.mail_proto_id), 110);	

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "DEVICE_ID_COMMAND", g_tsg_para.device_id_command, sizeof(g_tsg_para.device_id_command), NULL);
	g_tsg_para.device_id=get_device_id(g_tsg_para.device_id_command, g_tsg_para.entrance_id);
		
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "DEVICE_SN_FILENAME", device_sn_filename, sizeof(device_sn_filename), "/opt/tsg/etc/tsg_sn.json");
	ret=tsg_get_sn(device_sn_filename, g_tsg_para.device_sn, sizeof(g_tsg_para.device_sn));
	if(ret==0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "GET_DEVICE_SN", "Get device SN failed; please check :%s", device_sn_filename);
	}

	ret=tsg_set_device_id_to_telegraf(g_tsg_para.device_sn);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "SET_DEVICE_SN_TO_TELEGRAF", "Set device SN(%s) failed; please check :%s", g_tsg_para.device_sn, "/etc/default/telegraf");
	}
	
	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "POLICY_PRIORITY_LABEL", label_buff, sizeof(label_buff), "POLICY_PRIORITY");
	g_tsg_para.priority_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_policy_label);
	if(g_tsg_para.priority_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"PROJECT_REGISTER",
									"Register %s failed; please check :%s and add <POLICY_PRIORITY	struct>",
									label_buff,
									"etc/project_list.conf"
								);
		return -1;
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "TSG_MASTER_INTERNAL_LABEL", label_buff, sizeof(label_buff), "TSG_MASTER_INTERNAL_LABEL");
	g_tsg_para.internal_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_session_attribute_label);
	if(g_tsg_para.internal_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, 
									RLOG_LV_FATAL,
									"PROJECT_REGISTER",
									"Register %s failed; please check :%s and add <TSG_MASTER_INTERNAL_LABEL	struct>",
									label_buff,
									"etc/project_list.conf"
								);
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "APP_ID_LABEL", label_buff, sizeof(label_buff), "APP_ID_LABEL");	
	g_tsg_para.app_id_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_app_id_label);
	if(g_tsg_para.app_id_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"APP_ID_LABEL",
									"project_customer_register is error, app_id_label: %s, please check etc/project.conf",
									label_buff
								);	
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "L7_PROTO_LABEL", label_buff, sizeof(label_buff), "BASIC_PROTO_LABEL");
	g_tsg_para.l7_proto_project_id=project_customer_register(label_buff, "struct");
	if(g_tsg_para.l7_proto_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"L7_PROTO_LABEL",
									"project_customer_register is error, l7_proto_label: %s, please check etc/project.conf",
									label_buff
								);	
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
	g_tsg_log_instance->internal_project_id=g_tsg_para.internal_project_id;

	MESA_load_profile_int_def(tsg_conffile, "FIELD_STAT", "CYCLE", &cycle, 30);
	MESA_load_profile_short_nodef(tsg_conffile, "FIELD_STAT","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(tsg_conffile,"FIELD_STAT","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "tsg_stat.log");
	MESA_load_profile_string_def(tsg_conffile,"FIELD_STAT","APP_NAME", app_name, sizeof(app_name), "tsg_master");
	MESA_load_profile_int_def(tsg_conffile, "FIELD_STAT", "PROMETHEUS", &output_prometheus, 1);

	g_tsg_para.fs2_handle=FS_create_handle();

	value=1;//Rewrite
	FS_set_para(g_tsg_para.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(g_tsg_para.fs2_handle, CREATE_THREAD, &value, sizeof(value));
	
    FS_set_para(g_tsg_para.fs2_handle, STAT_CYCLE, &cycle, sizeof(cycle));
    FS_set_para(g_tsg_para.fs2_handle, APP_NAME, app_name, strlen(app_name)+1);
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);

	value=1;
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));

    if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
    {
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_IP,fs_server_ip, strlen(fs_server_ip)+1);
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_PORT,&(fs_server_port), sizeof(fs_server_port));
    }

	value=FS_OUTPUT_INFLUX_LINE;
	FS_set_para(g_tsg_para.fs2_handle, STATS_FORMAT, &value, sizeof(value));

	for(i=0; i<TSG_FS2_MAX; i++)
	{
		g_tsg_para.fs2_field_id[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_FIELD, FS_CALC_SPEED, g_tsg_fs2_field[i].name);
	}

	char buff[32]={0};
	int thread_num=get_thread_count();
	for(i=0; i<thread_num && g_tsg_log_instance!=NULL; i++)
	{
		snprintf(buff, sizeof(buff), "send_log_percent_%02d", i);
		g_tsg_log_instance->fs_status_ids[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_STATUS, FS_CALC_CURRENT, buff);
	}
	
	FS_start(g_tsg_para.fs2_handle);

	for(i=0; i<thread_num; i++)
	{
		FS_operate(g_tsg_para.fs2_handle,g_tsg_log_instance ->fs_status_ids[i], 0, FS_OP_SET, g_tsg_log_instance->send_log_percent[i]);
	}
	
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
	sleep(5);
	return 0;
}

