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
#include <MESA/gquic.h>
#include "MESA/mesa_sip.h"
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

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{0, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {0, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {0, TSG_FS2_BYPASS, "bypass"},
										 {0, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {0, TSG_FS2_HIT_SHARE, "hit_share"},
										 {0, TSG_FS2_INTERCEPT, "intercept"},
										 {0, TSG_FS2_EXCLUSION, "exclusion"},
										 {0, TSG_FS2_SUCCESS_LOG, "success_log"},
										 {0, TSG_FS2_FAILED_LOG, "failed_log"},
										 {0, TSG_FS2_DROP_LOG, "drop_log"},
										 {0, TSG_FS2_ABORT_ALLOW, "abort_allow"},
										 {0, TSG_FS2_ABORT_DENY, "abort_deny"},
										 {0, TSG_FS2_ABORT_MONITOR, "abort_monitor"},
										 {0, TSG_FS2_ABORT_INTERCEPT, "abort_intercept"},
										 {0, TSG_FS2_ABORT_UNKNOWN, "abort_unknown"}
										};

id2field_t g_tsg_proto_name2id[PROTO_MAX]={{PROTO_UNKONWN, 0, "unknown"}, 
										 {PROTO_IPv4, 	0,	"IPV4"},
										 {PROTO_IPv6, 	0,	"IPV6"},
										 {PROTO_TCP, 	0, 	"TCP"},
										 {PROTO_UDP, 	0, 	"UDP"},
										 {PROTO_HTTP, 	0, 	"HTTP"},
										 {PROTO_MAIL, 	0, 	"MAIL"},
										 {PROTO_DNS, 	0, 	"DNS"},
										 {PROTO_FTP, 	0, 	"FTP"},
										 {PROTO_SSL, 	0, 	"SSL"},
										 {PROTO_SIP, 	0, 	"SIP"},
										 {PROTO_BGP, 	0, 	"BGP"},
										 {PROTO_STREAMING_MEDIA, 0, "STREAMING_MEDIA"},
										 {PROTO_QUIC, 	0,	 "QUIC"},
										 {PROTO_SSH, 	0, 	"SSH"},
										 {PROTO_SMTP, 	0, 	"SMTP"},
										 {PROTO_IMAP, 	0, 	"IMAP"},
										 {PROTO_POP3, 	0, 	"POP3"},
										 {PROTO_RTP, 	0, 	"RTP"},
										 {PROTO_APP, 	0,"APP"}
										};

#define	DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID	1


static int init_context(void **pme, int thread_seq)
{
	*pme=dictator_malloc(thread_seq, sizeof(struct master_context));
	memset(*pme, 0, sizeof(struct master_context));
	
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

static int is_hited_allow(struct Maat_rule_t *result, int hit_cnt)
{
	int i=0;

	for(i=0; i<hit_cnt; i++)
	{
		if(result[i].action==TSG_ACTION_BYPASS)
		{
			return 1;
		}
	}

	return 0;
}


static int set_drop_stream(const struct streaminfo *a_stream)
{
	int opt_value=1;
	MESA_set_stream_opt(a_stream, MSO_DROP_STREAM, (void *)&opt_value, sizeof(opt_value));
	MESA_set_stream_opt(a_stream, MSO_TIMEOUT, (void *)&g_tsg_para.timeout, sizeof(g_tsg_para.timeout));

	return 0;
				
}

static int set_struct_project(const struct streaminfo *a_stream, int project_id, void *data)
{
	if(a_stream==NULL || project_id<0 || data==NULL)
	{
		return 0;
	}
	
	int ret=project_req_add_struct((struct streaminfo *)a_stream, project_id, data);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, 
									RLOG_LV_FATAL,
									"PROJECT",
									"Add project failed, project_id: %d addr: %s", 
									project_id,
									PRINTADDR(a_stream, g_tsg_para.level)
								);
		return 0;
	}

	return 1;
}

static const void *get_struct_project(const struct streaminfo *a_stream, int project_id)
{
	if(a_stream==NULL || project_id<0)
	{
		return NULL;
	}
	
	return project_req_get_struct(a_stream, project_id);
}
static int get_table_id(tsg_protocol_t protocol)
{
	switch(protocol)
	{
		case	PROTO_HTTP:
			return g_tsg_para.table_id[TABLE_HTTP_HOST];
		case	PROTO_SSL:
			return g_tsg_para.table_id[TABLE_SSL_SNI];
		case	PROTO_QUIC:
			return g_tsg_para.table_id[TABLE_QUIC_SNI];
		default:
			break;
	}

	return -1;
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

static int master_send_log(const struct streaminfo *a_stream, struct Maat_rule_t *p_result, int result_num, char *domain, tsg_protocol_t proto, int thread_seq)
{
	tsg_log_t log_msg;	
	char *domain_field_name=NULL;
	char *schema_field_name=NULL;
	struct TLD_handle_t *TLD_handle=NULL;

	TLD_handle=TLD_create(thread_seq);
	if(proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		schema_field_name=log_field_id2name(g_tsg_log_instance, LOG_COMMON_SCHAME_TYPE);

		if(proto==PROTO_IMAP || proto==PROTO_SMTP || proto==PROTO_POP3)
		{
			TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[PROTO_MAIL].name, TLD_TYPE_STRING);
			TLD_append(TLD_handle, (char *)"mail_protocol_type", (void *)g_tsg_proto_name2id[proto].name, TLD_TYPE_STRING);
		}
		else
		{			
			TLD_append(TLD_handle, schema_field_name, (void *)g_tsg_proto_name2id[proto].name, TLD_TYPE_STRING);
		}

		if(domain!=NULL)
		{
			switch(proto)
			{
				case	PROTO_HTTP:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_HTTP_HOST);
					TLD_append(TLD_handle, domain_field_name, (void *)domain, TLD_TYPE_STRING);
					break;
				case	PROTO_SSL:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_SSL_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)domain, TLD_TYPE_STRING);
					break;
				case	PROTO_QUIC:
					domain_field_name=log_field_id2name(g_tsg_log_instance, LOG_QUIC_SNI);
					TLD_append(TLD_handle, domain_field_name, (void *)domain, TLD_TYPE_STRING);
					break;
				default:
					break;
			}
		}
	}
	
	log_msg.a_stream=(struct streaminfo *)a_stream;
	log_msg.result=p_result;
	log_msg.result_num=result_num;
	tsg_send_log(g_tsg_log_instance, TLD_handle, &log_msg, thread_seq);
	
	if(p_result->config_id!=DECCRYPTION_EXCLUSION_ALLOW_POLICY_ID)
	{
		tsg_set_policy_flow((struct streaminfo *)a_stream, p_result, thread_seq);
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
				*flag|=(1<<g_tsg_proto_name2id[i].type);
				break;
			}
		}
		
		s=e+1;	
	}

	return 0;
}

static void free_context_label(int thread_seq, void *project_req_value)
{
	project_req_value=NULL;

	return ;
}

static void free_policy_label(int thread_seq, void *project_req_value)
{
	if(project_req_value!=NULL)
	{
		dictator_free(thread_seq, project_req_value);
		project_req_value=NULL;
	}
}

void free_gather_app_result(int thread_seq, void *project_req_value)
{
	if(project_req_value!=NULL)
	{
		dictator_free(thread_seq, project_req_value);
		project_req_value=NULL;
	}
}

static void copy_monitor_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int result_num, int thread_seq)
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

static void copy_intercept_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, char *domain, tsg_protocol_t proto, int thread_seq)
{
	int ret=0;
	policy_priority_label_t *priority_label=NULL;	

	priority_label=(policy_priority_label_t *)dictator_malloc(thread_seq, sizeof(policy_priority_label_t));
	memset(priority_label, 0, sizeof(policy_priority_label_t));

	priority_label->proto=proto;
	priority_label->domain_len=MIN(sizeof(priority_label->domain)-1 ,strlen(domain));
	memcpy(priority_label->domain, domain, priority_label->domain_len);

	priority_label->result_num=1;
	priority_label->result_type=PULL_KNI_RESULT;
	memcpy(priority_label->result, p_result, sizeof(struct Maat_rule_t));
	
	ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.priority_project_id, (void *)priority_label);
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

static void copy_deny_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int thread_seq)
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

static void copy_bypass_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *p_result, int thread_seq)
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

static unsigned char deal_deny_action(const struct streaminfo *a_stream, struct master_context *context, Maat_rule_t *p_result)
{
	int ret=0,opt_value=0;
	struct rst_tcp_para rst_paras;
	unsigned char state=APP_STATE_GIVEME;
	int method_type=TSG_METHOD_TYPE_UNKNOWN;
	struct compile_user_region *user_region=NULL;

	user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, p_result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	if(user_region!=NULL)
	{
		method_type=tsg_get_method_id(user_region->method);
		switch(method_type)
		{
			case	TSG_METHOD_TYPE_DROP:
				set_drop_stream(a_stream);
				//copy_deny_result(a_stream, context, p_result, a_stream->threadnum);
				state=APP_STATE_DROPPKT|APP_STATE_DROPME;
				break;
			case	TSG_METHOD_TYPE_RESET:
				if(a_stream->type==STREAM_TYPE_TCP)
				{
					rst_paras.rst_pkt_num=1;
					rst_paras.signature_seed1=65535;
					rst_paras.signature_seed2=13;
					rst_paras.th_flags=4;
					rst_paras.__pad_no_use=0;
					rst_paras.dir=DIR_DOUBLE;
					ret=MESA_rst_tcp((struct streaminfo *)a_stream, &rst_paras, sizeof(rst_paras));
					if(ret<0)
					{
						MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_FATAL,
										"RST_TCP",
										"Send RST failed policy_id: %d service: %d action: %d addr: %s",
										p_result->config_id,
										p_result->service_id,
										(unsigned char)p_result->action,
										PRINTADDR(a_stream, g_tsg_para.level)
									);
					}

					opt_value=1;
					MESA_set_stream_opt(a_stream, MSO_TCP_RST_REMEDY, (void *)&opt_value, sizeof(opt_value));
				}

				set_drop_stream(a_stream);
				//copy_deny_result(a_stream, context, p_result, a_stream->threadnum);
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

	return state;
}

static int l7_protocol_mapper(const char *filename)
{
	int ret=0;
	FILE *fp=NULL;
	char line[1024]={0};
	char type_name[32]={0};
	struct l7_protocol *protocol=NULL;
	
	fp=fopen(filename, "r");
	if(fp==NULL)
	{
		printf("Open %s failed ...", filename);
		return -1;
	}
	
	memset(line, 0, sizeof(line));

	while((fgets(line, sizeof(line), fp))!=NULL)
	{
		if(line[0]=='#' || line[0]=='\n' || line[0]=='\r' ||line[0]=='\0')
		{
			continue;
		}
		
	    protocol=(struct l7_protocol *)calloc(1, sizeof(struct l7_protocol));
		ret=sscanf(line, "%s %s %d", type_name, protocol->name, &protocol->id);
		assert(ret==3);

	    HASH_ADD(hh1, g_tsg_para.name_by_id, id, sizeof(int), protocol);
	    HASH_ADD(hh2, g_tsg_para.id_by_name, name, strlen(protocol->name), protocol);
		
		memset(line, 0, sizeof(line));
	}

	fclose(fp);
	fp=NULL;

	return 1;
}

char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id)
{	
	struct l7_protocol *l7_proto=NULL;
	HASH_FIND(hh1, g_tsg_para.name_by_id, &l7_protocol_id, sizeof(l7_protocol_id), l7_proto);
	if(l7_proto!=NULL)
	{
		return l7_proto->name;
	}

	return NULL;
}

unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name)
{
	struct l7_protocol *l7_proto=NULL;

	HASH_FIND(hh2, g_tsg_para.id_by_name, l7_protocol_name, strlen(l7_protocol_name), l7_proto);
	if(l7_proto!=NULL)
	{
		return l7_proto->id;
	}

	return 0;
}


int is_intercept_exclusion(const struct streaminfo *a_stream, Maat_rule_t *p_result, char *domain, int thread_seq)
{
	int ret=0;	
	scan_status_t mid=NULL;
	Maat_rule_t tmp_result;

	if(domain!=NULL)
	{
		ret=Maat_full_scan_string(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_EXCLUSION_SSL_SNI], CHARSET_UTF8, domain, strlen(domain), &tmp_result, NULL, 1, &mid,thread_seq);
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
										domain,
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
	
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"EXCLUSION_SSL_SNI",
									"Not hit %s stream_dir: %d addr: %s  scan ret: %d",
									domain,
									a_stream->dir,
									PRINTADDR(a_stream, g_tsg_para.level),
									ret
								);
	}

	return 0;
}

static int scan_fqdn_category_id(Maat_feather_t maat_feather, const struct streaminfo *a_stream, char *domain, Maat_rule_t *result, int result_num,  scan_status_t *mid, int table_id, int thread_seq)
{
	int scan_ret=0;
	struct _session_attribute_label_t *attribute_label=NULL;
	
	attribute_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, g_tsg_para.internal_project_id);
	if(attribute_label!=NULL && domain!=NULL && table_id>=0)
	{
		attribute_label->fqdn_category_id_num=tsg_get_fqdn_category_id(g_tsg_maat_feather, domain, attribute_label->fqdn_category_id, MAX_CATEGORY_ID_NUM, g_tsg_para.logger, thread_seq);
		scan_ret=tsg_scan_fqdn_category_id(g_tsg_maat_feather, a_stream, result, result_num, mid, table_id, attribute_label->fqdn_category_id, attribute_label->fqdn_category_id_num, thread_seq);
	}

	return scan_ret;
}

void close_stream_free_context(const struct streaminfo *a_stream, struct master_context *context, int thread_seq)
{
	if(context!=NULL)
	{
		if(context->hit_cnt>0 && context->result!=NULL)
		{
			master_send_log(a_stream, context->result, context->hit_cnt, context->domain, context->proto, thread_seq);
		}

		if(context->domain!=NULL)
		{
			dictator_free(thread_seq, (void *)context->domain);
			context->domain=NULL;
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

void set_session_attribute_label(const struct streaminfo *a_stream, enum TSG_ATTRIBUTE_TYPE type, void *value, int thread_seq)
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

		ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.internal_project_id, (const void *)attribute_label);
		if(ret<0)
		{
			dictator_free(thread_seq, (void *)attribute_label);
			attribute_label=NULL;
			
			MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_FATAL,
									"PROJECT_ADD",
									"Add internal_label failed, establish latency ms: %llu proto: %d addr: %s",
									attribute_label->establish_latency_ms,
									attribute_label->proto,
									PRINTADDR(a_stream, g_tsg_para.level)
									);
			return ;
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
			ja3_info=ssl_get_ja3_fingerprint((struct streaminfo *)a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
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

struct Maat_rule_t *tsg_policy_decision_criteria(Maat_rule_t *result, int result_num)
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

static int identify_application_protocol(const struct streaminfo *a_stream, struct master_context *context, void *a_packet)
{
	int ret=0, length=0;
	char buff[4096]={0};
	context->proto = PROTO_UNKONWN;

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			if(g_tsg_para.proto_flag&(1<<PROTO_HTTP))  //http
			{
				char *host=NULL;
				length=http_host_parser((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->curdir, &host);
				if(length>=0)
				{
					context->proto=PROTO_HTTP;
					if(length>0 && host!=NULL)
					{
						context->domain=(char *)dictator_malloc(a_stream->threadnum, length+1);
						memset(context->domain, 0, length+1);
						memcpy(context->domain, host, length);
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
					context->proto=PROTO_SSL;
					if(chello->sni!=NULL)
					{
						length=strlen(chello->sni);
						context->domain=(char *)dictator_malloc(a_stream->threadnum, length+1);
						memset(context->domain, 0, length+1);
						memcpy(context->domain, chello->sni, length);
					}

					context->is_esni=(int)chello->is_encrypt_sni;
					
					ssl_chello_free(chello);
					return 1;
				}
				
			    ssl_chello_free(chello);
			}
	
			if(g_tsg_para.proto_flag&(1<<PROTO_FTP))  //ftp
			{
				ret=ftp_control_identify((struct streaminfo *)a_stream);
				if(ret>0)
				{
					context->proto=PROTO_FTP;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_MAIL))  //mail
			{
				ret=mail_protocol_identify_by_first_payload((struct streaminfo *)a_stream,(char *)a_stream->ptcpdetail->pdata, a_stream->ptcpdetail->datalen, a_stream->threadnum);
				if(ret>0)
				{
					switch(ret)
					{
						case	SMTP_PROTOCOL:
							context->proto=PROTO_SMTP;
							return 1;
							break;
						case	POP3_PROTOCOL:
							context->proto=PROTO_POP3;
							return 1;
							break;
						case	IMAP_PROTOCOL:
							context->proto=PROTO_IMAP;
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
							context->proto=PROTO_DNS;
							return 1;
						}
						break;
					case ADDR_TYPE_IPV6:
						tpl6=a_stream->addr.tuple4_v6;
						if((ntohs(tpl6->source)==53) || (ntohs(tpl6->dest)==53))
						{
							context->proto=PROTO_DNS;
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
					context->proto=PROTO_SSH;
					return 1;
				}
			}
			
			if(g_tsg_para.proto_flag&(1<<PROTO_QUIC))  //quic
			{
				length=quic_protocol_identify((struct streaminfo *)a_stream, a_packet, buff, sizeof(buff));
				if(length>=0)
				{
					context->proto=PROTO_QUIC;
					if(length>0 && strlen(buff)>0)
					{
						context->domain=(char *)dictator_malloc(a_stream->threadnum, length+1);
						memset(context->domain, 0, length+1);
						memcpy(context->domain, buff, length);
					}
					return 1;
				}
			}

			if(g_tsg_para.proto_flag&(1<<PROTO_SIP))
			{
				unsigned char sip_ret=0;
				char *from=NULL, *to=NULL;
				unsigned int from_len=0, to_len=0;
				sip_ret=sip_identify_from_to((char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, &from, &from_len, &to, &to_len);
				if(sip_ret==SIP_TRUE)
				{
					context->proto=PROTO_SIP;
				}
			}
			break;
		default:
			break;
	}
	
	return ret;
}

int scan_application_id_and_properties(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, struct app_identify_result *identify_result, int thread_seq)
{
	int i=0,hit_num=0;
	char *name=NULL;
	char app_id_buff[32]={0};
	struct app_id_dict_table *dict=NULL;

	for(i=0; i< identify_result->app_id_num; i++)
	{
		snprintf(app_id_buff, sizeof(app_id_buff), "%d", identify_result->app_id[i]);
		dict=(struct app_id_dict_table *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
		if(dict!=NULL)
		{
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->risk, (char *)"risk", thread_seq);
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->category, (char *)"category", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->technology, (char *)"technology", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->subcategroy, (char *)"subcategroy", thread_seq);	
			hit_num+=tsg_scan_app_properties_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->characteristics, (char *)"characteristics", thread_seq);

			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, dict->app_name, identify_result->app_id[i], thread_seq);
			app_id_dict_free_data(g_tsg_para.table_id[TABLE_APP_ID_DICT], (MAAT_PLUGIN_EX_DATA *)&dict, 0, NULL);
		}
		else
		{
			name=tsg_l7_protocol_id2name(identify_result->app_id[i]);
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, ((name==NULL) ? (char *)"" : name), identify_result->app_id[i], thread_seq);
		}
	}

	return hit_num;
}

static unsigned char master_deal_scan_result(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *result, int hit_num, void *a_packet)
{
	Maat_rule_t *p_result=NULL;
	unsigned char state=APP_STATE_GIVEME;

	p_result=tsg_policy_decision_criteria(result, hit_num);
	if(p_result!=NULL)
	{	
		switch((unsigned char)p_result->action)
		{
			case	TSG_ACTION_DENY:
				state=deal_deny_action(a_stream, context, p_result);
				if((state&APP_STATE_DROPPKT)==APP_STATE_DROPPKT)
				{
					context->hit_cnt=0;
					master_send_log(a_stream, p_result, 1, context->domain, context->proto, a_stream->threadnum);
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"DENY",
												"Hit deny policy, policy_id: %d service: %d action: %d addr: %s",
												p_result->config_id,
												p_result->service_id,
												(unsigned char)p_result->action,
												PRINTADDR(a_stream, g_tsg_para.level)
											);
				}
				break;
			case	TSG_ACTION_MONITOR:
				copy_monitor_result(a_stream, context, result, hit_num, a_stream->threadnum);
				break;
			case	TSG_ACTION_BYPASS:
				copy_bypass_result(a_stream, context, p_result, a_stream->threadnum);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_BYPASS], 0, FS_OP_ADD, 1);
				state=APP_STATE_GIVEME|APP_STATE_KILL_OTHER;
				break;
			case	TSG_ACTION_INTERCEPT:
				if(is_intercept_exclusion(a_stream, p_result, context->domain, a_stream->threadnum))
				{					
					FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_EXCLUSION], 0, FS_OP_ADD, 1);
					break;
				}
				
				copy_intercept_result(a_stream, context, p_result, context->domain, context->proto, a_stream->threadnum);
				FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INTERCEPT], 0, FS_OP_ADD, 1);
				state=APP_STATE_DROPME|APP_STATE_KILL_OTHER;
				break;
			default:
				break;
		}
	}

	return state;
}

static int app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	int hit_num=0;	
	struct master_context *context=NULL;
	struct Maat_rule_t scan_result[MAX_RESULT_NUM];
	struct gather_app_result *gather_result=NULL;
	struct app_identify_result *identify_result=(struct app_identify_result *)data;

	if(data==NULL)
	{
		return 0;
	}

	gather_result=(struct gather_app_result *)get_struct_project(a_stream, g_tsg_para.gather_app_project_id);
	if(gather_result==NULL)
	{
		gather_result=(struct gather_app_result *)dictator_malloc(a_stream->threadnum, sizeof(struct gather_app_result));
		memset(gather_result, 0, sizeof(struct gather_app_result));
		set_struct_project(a_stream, g_tsg_para.gather_app_project_id, (void *)gather_result);
	}
	
	switch(identify_result->origin)
	{
		case	ORIGIN_DKPT:
		case	ORIGIN_QM_ENGINE:
		case	ORIGIN_USER_DEFINE:
		case	ORIGIN_BASIC_PROTOCOL:
			memcpy(&(gather_result->result[identify_result->origin]), identify_result, sizeof(struct app_identify_result));
			break;
		default:
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_BRIDGE_CB", "Unknown type: %d addr: %s", identify_result->origin, PRINTADDR(a_stream, g_tsg_para.level));
			return 0;
	}

	context=(struct master_context *)get_struct_project(a_stream, g_tsg_para.context_project_id);
	if(context==NULL)
	{
		init_context((void **)(&context), a_stream->threadnum);
		set_struct_project(a_stream, g_tsg_para.context_project_id, (void *)context);
	}
	
	record_time_start(&(context->last_scan_time));
	
	hit_num=scan_application_id_and_properties((struct streaminfo *)a_stream, scan_result, MAX_RESULT_NUM, &(context->mid), identify_result, a_stream->threadnum);
	master_deal_scan_result(a_stream, context, scan_result, hit_num, NULL);

	return 0;
}


static int master_deal_pending_state(const struct streaminfo *a_stream, struct master_context *context, struct Maat_rule_t *result, int result_num, void *a_packet)
{
	int table_id=0;
	int ret=0,hit_num=0;
	unsigned int protocol_id=0;
	
	ret=identify_application_protocol(a_stream, context, a_packet);
	if(ret==1)
	{				
		set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_ESTABLISH_LATECY, NULL, a_stream->threadnum);
		set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_PROTOCOL, (void *)&(context->proto), a_stream->threadnum);

		if(context->proto==PROTO_SSL)
		{
			set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_JA3_HASH, NULL, a_stream->threadnum);
		}
		
		table_id=get_table_id(context->proto);	
		hit_num+=tsg_scan_shared_policy(g_tsg_maat_feather, a_stream, context->domain, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, table_id, a_stream->threadnum);
		hit_num+=scan_fqdn_category_id(g_tsg_maat_feather, a_stream, context->domain, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, table_id, a_stream->threadnum);
		if(context->is_esni)
		{
			protocol_id=tsg_l7_protocol_name2id("ESNI");
			hit_num+=tsg_scan_app_id_policy(g_tsg_maat_feather, a_stream, result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, (char *)"ESNI", protocol_id, a_stream->threadnum);
		}
	}

	ret=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, context->proto, &context->mid, result+hit_num, MAX_RESULT_NUM-hit_num);
	if(ret>0)
	{
		hit_num+=ret;
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_ADDR], 0, FS_OP_ADD, 1);		
	}
	
	if((is_only_monitor(result, hit_num)) && context->proto!=PROTO_UNKONWN)	// business deal action of monitor 
	{
		hit_num=0;
	}

	return hit_num;
}


static unsigned char tsg_master_entry(const struct streaminfo *a_stream, void **pme, int thread_seq,void *a_packet)
{
	int i=0, hit_num=0;	
	unsigned char state=APP_STATE_GIVEME;
	Maat_rule_t scan_result[MAX_RESULT_NUM];
	Maat_rule_t *p_result=NULL;
	struct gather_app_result *identify_result=NULL;
	struct master_context *context=(struct master_context *)*pme;

	if(*pme==NULL)
	{
		context=(struct master_context *)get_struct_project(a_stream, g_tsg_para.context_project_id);
		if(context==NULL)
		{
			init_context(pme, thread_seq);
			context=(struct master_context *)*pme;
			set_struct_project(a_stream, g_tsg_para.context_project_id, *pme);
		}
		else
		{
			*pme=(void *)context;
		}
		record_time_start(&context->last_scan_time);
	}
	
	switch(a_stream->opstate)
	{
		case	OP_STATE_PENDING:
			hit_num+=master_deal_pending_state(a_stream, context, scan_result+hit_num, MAX_RESULT_NUM-hit_num, a_packet);
			p_result=tsg_policy_decision_criteria(scan_result, hit_num);
			if(g_tsg_para.default_compile_switch==1 && p_result==NULL)
			{
				if(get_default_policy(g_tsg_para.default_compile_id, &scan_result[0]))
				{
					p_result=&scan_result[0];			
				}
			}
			
			state=master_deal_scan_result(a_stream, context, scan_result, hit_num, a_packet);
			break;
		case	OP_STATE_DATA:
		case	OP_STATE_CLOSE:
			if(is_hited_allow(context->result, context->hit_cnt))
			{
				break;
			}
			
			if(record_time_elapse_us(&context->last_scan_time) < (g_tsg_para.scan_time_interval*1000000))
			{
				break;
			}
			
			record_time_start(&context->last_scan_time);
			hit_num+=tsg_scan_nesting_addr(g_tsg_maat_feather, a_stream, context->proto, &context->mid, scan_result+hit_num, MAX_RESULT_NUM-hit_num);
			
			identify_result=(struct gather_app_result *)get_struct_project(a_stream, g_tsg_para.gather_app_project_id);
			for(i=0; i<ORIGIN_MAX && identify_result!=NULL; i++)
			{
				hit_num+=scan_application_id_and_properties(a_stream, scan_result+hit_num, MAX_RESULT_NUM-hit_num, &context->mid, &(identify_result->result[i]), thread_seq);
			}

			p_result=tsg_policy_decision_criteria(scan_result, hit_num);
			if(p_result!=NULL && p_result->action!=TSG_ACTION_MONITOR)
			{
				state=master_deal_scan_result(a_stream, context, scan_result, hit_num, a_packet);
			}
			break;
		default:
			break;
	}
	
	if((a_stream->opstate==OP_STATE_CLOSE) || (state&APP_STATE_DROPME)==APP_STATE_DROPME)
	{
		close_stream_free_context(a_stream, context, thread_seq);
		*pme=NULL;
		set_struct_project(a_stream, g_tsg_para.context_project_id, NULL);	//
	}

	return state;
}

extern "C" unsigned char TSG_MASTER_TCP_ENTRY(const struct streaminfo *a_tcp, void **pme, int thread_seq,void *a_packet)
{
	if(a_tcp->type==STREAM_TYPE_TCP)
	{		
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TCP_LINKS], 0, FS_OP_ADD, 1); 		
	}
	
	return tsg_master_entry(a_tcp, pme, thread_seq, a_packet);
}

extern "C" unsigned char TSG_MASTER_UDP_ENTRY(const struct streaminfo *a_udp, void **pme, int thread_seq,void *a_packet)
{
	if(a_udp->type==STREAM_TYPE_UDP)
	{		
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_UDP_LINKS], 0, FS_OP_ADD, 1); 		
	}

	return tsg_master_entry(a_udp, pme, thread_seq, a_packet);
}

extern "C" int TSG_MASTER_INIT()
{
	int i=0,ret=0;
	char buff[128]={0};
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

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "IDENTIFY_PROTO_NAME", identify_proto_name, sizeof(identify_proto_name), "HTTP;SSL;DNS;FTP;BGP;SIP;MAIL;STREAMING_MEDIA;QUIC;SIP;");
	tsg_proto_name2flag(identify_proto_name, &g_tsg_para.proto_flag);

	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "ENTRANCE_ID", &g_tsg_para.entrance_id, 0);
	MESA_load_profile_short_def(tsg_conffile, "SYSTEM", "TIMEOUT", (short *)&g_tsg_para.timeout, 300);
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "MAIL_PROTOCOL_ID",&(g_tsg_para.mail_proto_id), 110);	
	MESA_load_profile_int_def(tsg_conffile, "SYSTEM", "SCAN_TIME_INTERVAL", &g_tsg_para.scan_time_interval, 5);

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
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
		return -1;
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "TSG_MASTER_INTERNAL_LABEL", label_buff, sizeof(label_buff), "TSG_MASTER_INTERNAL_LABEL");
	g_tsg_para.internal_project_id=project_producer_register(label_buff, PROJECT_VAL_TYPE_STRUCT, free_session_attribute_label);
	if(g_tsg_para.internal_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "PROJECT_REGISTER", "Register %s failed.", label_buff);
	}

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "APP_BRIDGE_NAME", label_buff, sizeof(label_buff), "APP_BRIDGE");
	g_tsg_para.app_bridge_id=stream_bridge_build(label_buff, "w");
	if(g_tsg_para.app_bridge_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_BRIDGE", "stream_bridge_build is error, app_bridge_name: %s", label_buff);	
	}

	ret=stream_bridge_register_data_sync_cb(g_tsg_para.app_bridge_id, app_identify_result_cb);
	if(ret<0)
	{		
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_BRIDGE", "Register callback failed, app_bridge_id: %d", g_tsg_para.app_bridge_id);	
		return -1;
	}

	g_tsg_para.context_project_id=project_producer_register("TSG_MASTER_CONTEXT", PROJECT_VAL_TYPE_STRUCT, free_context_label);
	if(g_tsg_para.context_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "CONTEXT_LABEL", "project_customer_register is error, context label: %s","TSG_MASTER_CONTEXT");
		return -1;
	}

	g_tsg_para.gather_app_project_id=project_producer_register("APP_IDENTIFY_RESULT", PROJECT_VAL_TYPE_STRUCT, free_gather_app_result);
	if(g_tsg_para.gather_app_project_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "APP_IDENTIFY_RESULT", "project_customer_register is error, context label: %s","APP_IDENTIFY_RESULT");
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

	MESA_load_profile_string_def(tsg_conffile, "SYSTEM", "L7_RPTOCOL_FILE", buff, sizeof(buff), "./tsgconf/tsg_l7_protocol.conf");
	l7_protocol_mapper(buff);
	
	return 0;
}



extern "C" int TSG_MASTER_UNLOAD()
{
	sleep(5);
	return 0;
}

