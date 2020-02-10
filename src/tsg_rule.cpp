#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>

#include "MESA/MESA_handle_logger.h"
#include "Maat_rule.h"
#include "Maat_command.h"
#include "MESA/http.h"
#include "tsg_rule.h"
#include "tsg_entry.h"

Maat_feather_t g_tsg_maat_feather;
Maat_feather_t g_tsg_dynamic_maat_feather;

#define	MAX_PATH_LEN	1024
#define	MAX_IPV6_ADDR_LEN	128

enum kni_scan_table{
    TSG_FIELD_SSL_SNI,
	TSG_FIELD_HTTP_HOST,
	SCAN_TABLE_MAX
};

const char *g_kni_scan_table_name[SCAN_TABLE_MAX];
int g_kni_scan_tableid[SCAN_TABLE_MAX] = {0};


const struct _str2index method2index[TSG_METHOD_TYPE_MAX]={	{TSG_METHOD_TYPE_UNKNOWN, 7, (char *)"unknown"},
													{TSG_METHOD_TYPE_DROP, 4, (char *)"drop"},
													{TSG_METHOD_TYPE_REDIRECTION, 8, (char *)"redirect"},
													{TSG_METHOD_TYPE_BLOCK, 5, (char *)"block"},
													{TSG_METHOD_TYPE_RESET, 3, (char *)"rst"}
	};

const struct _str2index g_tsg_proto_string[PROTO_MAX+1]={{PROTO_UNKONWN, 0, (char *)""}, 
										 {PROTO_IPv4, 5, (char *)"IPv4."},
										 {PROTO_IPv6, 5, (char *)"IPv6."},
										 {PROTO_TCP, 4, (char *)"TCP."},
										 {PROTO_UDP, 4, (char *)"UDP."},
										 {PROTO_HTTP, 5, (char *)"HTTP."},
										 {PROTO_MAIL, 5, (char *)"MAIL."},
										 {PROTO_DNS, 4, (char *)"DNS."},
										 {PROTO_FTP, 4, (char *)"FTP."},
										 {PROTO_SSL, 4, (char *)"SSL."},
										 {PROTO_SIP, 4, (char *)"SIP."},
										 {PROTO_BGP, 4, (char *)"BGP."},
										 {PROTO_STREAMING_MEDIA, 16, (char *)"STREAMING_MEDIA."},
										 {PROTO_MAX, 0, (char *)""}
};

void subscribe_id_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	void *logger=argp;
	
	*to=calloc(1, strlen((char *)*from)+1);
	memcpy(*to, *from, strlen((char *)*from));
	
	MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, "SUBSCRIBE_ID", "Dup subscribe_id: %s table_id: %d", (char *)*to, table_id);
	return;
}

void subscribe_id_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	int ret=0,id=0,type=0,is_valid=0;
	char subscribe_id[256]={0};
	char ip_addr[MAX_IPV6_ADDR_LEN]={0};
	
	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%d", &id, &type, ip_addr, subscribe_id, &is_valid);
	if(ret!=5)
	{
		MESA_handle_runtime_log(logger, 
								RLOG_LV_FATAL,
								"SUBSCRIBE_ID",
								"Parse subscribe_id failed, ret: %d table_id: %d key: %s table_line: %s",
								ret,
								table_id,
								key,
								table_line
								);
		return;
	}
	
	*ad=calloc(1, strlen(subscribe_id)+1);
	
	memcpy(*ad, subscribe_id, strlen(subscribe_id));
	MESA_handle_runtime_log(logger, 
								RLOG_LV_DEBUG,
								"SUBSCRIBE_ID",
								"Add subscribe_id: %s table_id: %d key: %s table_line: %s",
								*ad,
								table_id,
								key,
								table_line
								);
	return;
}

void subscribe_id_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	MESA_handle_runtime_log(logger, RLOG_LV_DEBUG, "SUBSCRIBE_ID", "Delete subscribe_id: %s table_id: %d", (char *)*ad, table_id);
	free(*ad);
	*ad=NULL;

	return;
}


static Maat_feather_t init_maat_feather(const char* conffile, char* instance_name, char *module, void *logger)
{
	unsigned short redis_port = 0;
	int ret=0,scan_detail=0,effect_interval=60;
	Maat_feather_t _maat_feather=NULL;
	int factor=0, redis_port_num=0,redis_index=0;
	char redis_ip[16]={0}, effective_flag[1024]={0};
	int maat_mode=0,maat_stat_on=0,maat_perf_on=0,thread_max=0;
	char json_cfg_file[MAX_PATH_LEN]={0},maat_stat_file[MAX_PATH_LEN]={0};
	char table_info[MAX_PATH_LEN]={0},inc_cfg_dir[MAX_PATH_LEN]={0},ful_cfg_dir[MAX_PATH_LEN]={0};

	memset(effective_flag, 0, sizeof(effective_flag));
	MESA_load_profile_string_def(conffile,module,"EFFECTIVE_FLAG",effective_flag, sizeof(effective_flag),"");

	MESA_load_profile_int_def(conffile, module,"MAAT_MODE", &(maat_mode),0);
	MESA_load_profile_int_def(conffile, module,"STAT_SWITCH", &(maat_stat_on),1);
	MESA_load_profile_int_def(conffile, module,"PERF_SWITCH", &(maat_perf_on),1);

	MESA_load_profile_string_def(conffile,module,"TABLE_INFO",table_info, sizeof(table_info), "");
	MESA_load_profile_string_def(conffile,module,"STAT_FILE",maat_stat_file, sizeof(maat_stat_file), "");
	MESA_load_profile_int_def(conffile, module,"EFFECT_INTERVAL_S", &(effect_interval), 60);
	effect_interval*=1000;//convert s to ms

	thread_max=get_thread_count();
	_maat_feather=Maat_feather(thread_max, table_info, logger);
	
	if(maat_mode==2)
	{
		MESA_load_profile_string_def(conffile,module,"REDIS_IP", redis_ip, sizeof(redis_ip),"");
		MESA_load_profile_int_def(conffile, module,"REDIS_PORT_NUM", &(redis_port_num), 1);
		MESA_load_profile_short_def(conffile, module,"REDIS_PORT", (short*)&(redis_port), 6379);
		MESA_load_profile_int_def(conffile, module,"REDIS_INDEX", &redis_index, 0);
		
		if(strlen(effective_flag)!=0)
		{
			Maat_set_feather_opt(_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
		}
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));

		srand((unsigned int)time(NULL));
		factor = rand()%redis_port_num;
		redis_port = redis_port+factor;
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_IP, redis_ip, strlen(redis_ip)+1);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_PORT, (void *)&redis_port, sizeof(redis_port));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_FILE_PATH, maat_stat_file, strlen(maat_stat_file)+1);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_ON, NULL, 0);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_PERF_ON, NULL, 0);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_INDEX, &redis_index, sizeof(redis_index));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
		//Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_DEFERRED_LOAD, NULL,0);
	}
	else
	{
		if(strlen(effective_flag)!=0)
		{
			ret=Maat_set_feather_opt(_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
			assert(ret>=0);
		}
		Maat_set_feather_opt(_maat_feather,MAAT_OPT_INSTANCE_NAME,instance_name, strlen(instance_name)+1);
		if(maat_mode==1)
		{
			MESA_load_profile_string_def(conffile,module,"JSON_CFG_FILE",json_cfg_file, sizeof(json_cfg_file),"");
			Maat_set_feather_opt(_maat_feather, MAAT_OPT_JSON_FILE_PATH, json_cfg_file, strlen(json_cfg_file)+1);
		}
		else
		{
			MESA_load_profile_string_def(conffile,module,"INC_CFG_DIR",inc_cfg_dir, sizeof(inc_cfg_dir),"");
			MESA_load_profile_string_def(conffile,module,"FULL_CFG_DIR",ful_cfg_dir, sizeof(ful_cfg_dir),"");	
			assert(strlen(inc_cfg_dir)!=0&&strlen(ful_cfg_dir)!=0);
			
			Maat_set_feather_opt(_maat_feather, MAAT_OPT_FULL_CFG_DIR, ful_cfg_dir, strlen(ful_cfg_dir)+1);
			Maat_set_feather_opt(_maat_feather, MAAT_OPT_INC_CFG_DIR, inc_cfg_dir, strlen(inc_cfg_dir)+1);
		}
		if(maat_stat_on)
		{
			Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_FILE_PATH, maat_stat_file, strlen(maat_stat_file)+1);
			Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_ON, NULL, 0);
			if(maat_perf_on)
			{
				Maat_set_feather_opt(_maat_feather, MAAT_OPT_PERF_ON, NULL, 0);
			}
		}

		Maat_set_feather_opt(_maat_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	}
	
	ret=Maat_initiate_feather(_maat_feather);
	if(ret<0)
	{
		return NULL;
	}

	return _maat_feather;
}

int tsg_rule_init(const char* conffile, void *logger)
{
	int i=0,ret=0;
	char maat_conffile[256]={0};
	char cb_subscriber_ip_table[32]={0};
	
	MESA_load_profile_string_def(conffile, "MAAT", "PROFILE", maat_conffile, sizeof(maat_conffile), "./tsgconf/maat_profile.conf");	
	MESA_load_profile_string_def(conffile, "MAAT", "IP_ADDR_TABLE", g_tsg_para.table_name[TABLE_IP_ADDR], _MAX_TABLE_NAME_LEN, "TSG_OBJ_IP_ADDR");
	MESA_load_profile_string_def(conffile, "MAAT", "SUBSCRIBER_ID_TABLE", g_tsg_para.table_name[TABLE_SUBSCRIBER_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_SUBSCRIBER_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_TABLE", g_tsg_para.table_name[TABLE_APP_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_APP_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "HTTP_HOST_TABLE", g_tsg_para.table_name[TABLE_HTTP_HOST], _MAX_TABLE_NAME_LEN, "TSG_FIELD_HTTP_HOST");
	MESA_load_profile_string_def(conffile, "MAAT", "SSL_SNI_TABLE", g_tsg_para.table_name[TABLE_SSL_SNI], _MAX_TABLE_NAME_LEN, "TSG_FIELD_SSL_SNI");

	//init dynamic maat feather
	g_tsg_maat_feather=init_maat_feather(maat_conffile, (char *)"TSG_STATIC", (char *)"STATIC", logger);
	if(g_tsg_maat_feather==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "init_maat_feather failed, instance_name: %s module: %s", "TSG_STATIC", "STATIC"); 
		return -1;
	}

	for(i=0; i<TABLE_MAX; i++)
	{
		g_tsg_para.table_id[i]=Maat_table_register(g_tsg_maat_feather, g_tsg_para.table_name[i]);
		if(g_tsg_para.table_id[i]<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "Maat_table_register %s failed, Please check tsgconf/tsg_static_tableinfo.conf", g_tsg_para.table_name[i]); 
			return -1;
		}
	}	

	//init dynamic maat feather
	g_tsg_dynamic_maat_feather=init_maat_feather(maat_conffile, (char *)"TSG_DYNAMIC", (char *)"DYNAMIC", logger);
	if(g_tsg_maat_feather==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "init_maat_feather failed, instance_name: %s module: %s", "TSG_DYNAMIC", "DYNAMIC"); 
		return -1;
	}

	MESA_load_profile_string_def(conffile, "MAAT", "CB_SUBSCRIBER_IP_TABLE", cb_subscriber_ip_table, sizeof(cb_subscriber_ip_table), "TSG_DYN_SUBSCRIBER_IP");

	g_tsg_para.dyn_subscribe_ip_table_id=Maat_table_register(g_tsg_dynamic_maat_feather, cb_subscriber_ip_table);
	if(g_tsg_para.dyn_subscribe_ip_table_id<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "RULE_INIT", "Maat_table_register %s failed", cb_subscriber_ip_table); 
		return -1;
	}
	ret=Maat_plugin_EX_register(g_tsg_dynamic_maat_feather,
							g_tsg_para.dyn_subscribe_ip_table_id,
							subscribe_id_new_data,
							subscribe_id_free_data,
							subscribe_id_dup_data,
							NULL,
							0,
							logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "RULE_INIT", "Maat_plugin_EX_register failed, table_name: %s table_id: %d", cb_subscriber_ip_table, g_tsg_para.dyn_subscribe_ip_table_id); 
		return -1;		
	}

	return 0;
}

int tsg_pull_policy_result(struct streaminfo *a_stream, PULL_RESULT_TYPE pull_result_type, Maat_rule_t*result, int result_num, struct _identify_info *identify_info)
{
	int num=0;
	policy_priority_label_t *label=NULL;

	label=(policy_priority_label_t *)project_req_get_struct(a_stream, g_tsg_para.priority_project_id);
	if(label!=NULL && result!=NULL && result_num>0 && identify_info!=NULL)
	{
		if(label->result_type==pull_result_type)
		{
			num=(label->result_num>result_num) ? result_num : label->result_num;
			memcpy(result, label->result, num*sizeof(Maat_rule_t));
			
			memcpy(identify_info->domain, label->domain, label->domain_len);
			identify_info->domain_len=label->domain_len;

			identify_info->proto = label->proto;
			
			return num;
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PULL_RESULT", 
														"pull policy failed, hit: %s %s: %s policy_id: %d service: %d action: %d addr: %s",
														(label->result_type==PULL_KNI_RESULT) ? "KNI" : "FW",
														label->proto==PROTO_HTTP ? "host" : "sni",
														label->domain,
														label->result->config_id,
														label->result->service_id,
														label->result->action,
														printaddr(&a_stream->addr, a_stream->threadnum));
		}
	}
	else
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PULL_RESULT",
														"pull policy failed, Not hit, label is %s addr: %s",
														(label==NULL) ? "NULL" : label->domain,
														printaddr(&a_stream->addr, a_stream->threadnum));
	}
	
	return 0;
}


int tsg_get_subscribe_id(const struct streaminfo *a_stream, char **source_subscribe_id, char **dest_subscribe_id)
{
	char source_ip[MAX_IPV6_ADDR_LEN]={0};
	char dest_ip[MAX_IPV6_ADDR_LEN]={0};
	struct stream_tuple4_v4 *v4=NULL;
	struct stream_tuple4_v6 *v6=NULL;
	
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
			v4=a_stream->addr.tuple4_v4;
			inet_ntop(AF_INET, &(v4->saddr), source_ip, MAX_IPV6_ADDR_LEN);
			inet_ntop(AF_INET, &(v4->daddr), dest_ip, MAX_IPV6_ADDR_LEN);
			break;
		case	ADDR_TYPE_IPV6:
			v6=a_stream->addr.tuple4_v6;
			inet_ntop(AF_INET6, v6->saddr, source_ip, MAX_IPV6_ADDR_LEN);
			inet_ntop(AF_INET6, v6->daddr, dest_ip, MAX_IPV6_ADDR_LEN);
			break;
		default:
			break;
	}

	if(strlen(dest_ip)>0)
	{
		*dest_subscribe_id = (char*)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, dest_ip);
	}

	if(strlen(source_ip)>0)
	{
		*source_subscribe_id = (char*)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, source_ip);
	}

	return 0;
}

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	struct ipaddr t_addr;
	struct ipaddr* p_addr=NULL;
	int hit_num=0,tans_proto=0;
	char *source_subscribe_id=NULL;
	char *dest_subscribe_id=NULL;
	int is_scan_addr=1, maat_ret=0,found_pos=0;
	const struct streaminfo *cur_stream = a_stream;


	if(result==NULL || result_num<=0 || a_stream==NULL || maat_feather==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_FATAL,
								"SCAN_NESTING_ADDR",
								"result==NULL || result_num<=0 || maat_feather==NULL || a_stream==%s",
								(a_stream!=NULL) ? printaddr(&a_stream->addr, a_stream->threadnum) : "NULL");
		return -1;
	}
	
	do
	{
		if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 || cur_stream->addr.addrtype == ADDR_TYPE_IPV4 || cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6 || cur_stream->addr.addrtype == ADDR_TYPE_IPV6)
		{
			is_scan_addr = 1;
			if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 || cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
			{
				memcpy(&t_addr, &cur_stream->addr, sizeof(t_addr));
				if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
					t_addr.addrtype = ADDR_TYPE_IPV4;
				else
					t_addr.addrtype = ADDR_TYPE_IPV6;
				p_addr = &t_addr;
			}
			else
			{
				p_addr = (struct ipaddr *)&cur_stream->addr;
			}
		}
		else
		{
			is_scan_addr = 0;
			p_addr = NULL;
		}
		
		if(is_scan_addr==1 && p_addr!=NULL)
		{
			switch(cur_stream->type)
			{
				case	STREAM_TYPE_TCP:
					tans_proto=6;
					break;
				case	STREAM_TYPE_UDP:
					tans_proto=17;
					break;
				default:
					tans_proto=255;
					break;
			}
			
 			maat_ret=Maat_scan_proto_addr(maat_feather,
 											g_tsg_para.table_id[TABLE_IP_ADDR],
 											p_addr,
 											tans_proto,
 											result+hit_num,
 											result_num-hit_num,
 											mid,
 											cur_stream->threadnum);
			if(maat_ret>0)
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_IP",
											"Hit addr: %s scan ret: %d policy_id: %d service: %d action: %d",
											printaddr(&cur_stream->addr, cur_stream->threadnum),
											maat_ret,
											result[hit_num].config_id,
											result[hit_num].service_id,
											(unsigned char)result[hit_num].action
										);

				hit_num+=maat_ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_IP",
											"No hit addr: %s scan ret: %d",
											printaddr(&cur_stream->addr, cur_stream->threadnum),
											maat_ret
										);	
			}
		}
		
		cur_stream = cur_stream->pfather;
		
	}while(cur_stream != NULL && hit_num < result_num);


	if(hit_num<result_num && proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		maat_ret=Maat_full_scan_string(maat_feather,
									g_tsg_para.table_id[TABLE_APP_ID],
									CHARSET_GBK,
									g_tsg_proto_string[proto].type,
									strlen(g_tsg_proto_string[proto].type),
									result+hit_num,
									&found_pos,
									result_num-hit_num,
									mid,
									a_stream->threadnum);
		if(maat_ret > 0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_PROTO",
									"Hit PROTO: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
									g_tsg_proto_string[proto].type,
									maat_ret,
									result[hit_num].config_id,
									result[hit_num].service_id,
									(unsigned char)result[hit_num].action,
									printaddr(&a_stream->addr, a_stream->threadnum)
									);

			hit_num+=maat_ret;
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_PROTO",
									"No hit PROTO: %s scan ret: %d addr: %s",
									g_tsg_proto_string[proto].type,
									maat_ret,
									printaddr(&a_stream->addr, a_stream->threadnum)
									);
		}
	}


	if(hit_num<result_num)
	{
		tsg_get_subscribe_id(a_stream, &source_subscribe_id, &dest_subscribe_id);
		
		if(source_subscribe_id!=NULL)
		{
			maat_ret=Maat_full_scan_string(maat_feather,
										g_tsg_para.table_id[TABLE_SUBSCRIBER_ID],
										CHARSET_GBK,
										source_subscribe_id,
										strlen(source_subscribe_id),
										result+hit_num,
										&found_pos,
										result_num-hit_num,
										mid,
										a_stream->threadnum);
			if(maat_ret > 0)
			{				
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"Hit source subscribe id: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
											source_subscribe_id,
											maat_ret,
											result[hit_num].config_id,
											result[hit_num].service_id,
											(unsigned char)result[hit_num].action,
											printaddr(&a_stream->addr, a_stream->threadnum)
										);

				hit_num+=maat_ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"No hit source subscribe id: %s scan ret: %d addr: %s",
											source_subscribe_id,
											maat_ret,
											printaddr(&a_stream->addr, a_stream->threadnum)
										);
			}
			
			subscribe_id_free_data(g_tsg_para.dyn_subscribe_ip_table_id,(MAAT_PLUGIN_EX_DATA *)&source_subscribe_id, 0, g_tsg_para.logger);
		}
		
		if(dest_subscribe_id!=NULL)
		{
			maat_ret=Maat_full_scan_string(maat_feather,
										g_tsg_para.table_id[TABLE_SUBSCRIBER_ID],
										CHARSET_GBK,
										dest_subscribe_id,
										strlen(dest_subscribe_id),
										result+hit_num,
										&found_pos,
										result_num-hit_num,
										mid,
										a_stream->threadnum);
			if(maat_ret > 0)
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"Hit dest subscribe id: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
											dest_subscribe_id,
											maat_ret,
											result[hit_num].config_id,
											result[hit_num].service_id,
											(unsigned char)result[hit_num].action,
											printaddr(&a_stream->addr, a_stream->threadnum)
										);

				hit_num+=maat_ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"No hit dest subscribe id: %s scan ret: %d addr: %s",
											dest_subscribe_id,
											maat_ret,
											printaddr(&a_stream->addr, a_stream->threadnum)
										);
			}
			
			subscribe_id_free_data(g_tsg_para.dyn_subscribe_ip_table_id,(MAAT_PLUGIN_EX_DATA *)&dest_subscribe_id, 0, g_tsg_para.logger);
		}
	}

	return hit_num;
}


//return value: -1: failed, 0: not hit, >0: hit count 
int tsg_scan_shared_policy(Maat_feather_t maat_feather, struct _identify_info *identify_info, Maat_rule_t *result, int result_num,  scan_status_t *mid, int thread_seq)
{
	int ret=0,idx=0;
	
	if(identify_info->proto!=PROTO_UNKONWN && identify_info->domain_len>0)
	{
		switch(identify_info->proto)
		{
			case	PROTO_HTTP:
				idx=TABLE_HTTP_HOST;
				break;
			case	PROTO_SSL:
				idx=TABLE_SSL_SNI;
				break;
			default:
				return 0;
				break;
		}
		
		ret=Maat_full_scan_string(g_tsg_maat_feather,
									g_tsg_para.table_id[idx],
									CHARSET_UTF8,
									identify_info->domain,
									identify_info->domain_len,
									result,
									NULL,
									result_num,
									mid,
									thread_seq
								);
	}

	return ret;
}


struct Maat_rule_t *tsg_fetch_deny_rule(Maat_rule_t *result, int result_num)
{
	int i=0;
	Maat_rule_t *p_result=NULL; 

	for(i=0; i< result_num; i++)
	{
		if(result[i].action==TSG_ACTION_DENY || result[i].action==TSG_ACTION_BYPASS)
		{
			if(p_result==NULL)
			{
				p_result=&result[i];
				continue;
			}

			if(result[i].action > p_result->action)
			{
				p_result=&result[i];
				continue;
			}

			if((result[i].action==p_result->action) && (result[i].config_id > p_result->config_id))
			{
				p_result=&result[i];
			}
		}
	}

	return p_result;
}

int tsg_get_method_id(char *method)
{
	int i=0;

	for(i=0; i<TSG_METHOD_TYPE_MAX; i++)
	{
		if(method2index[i].len==(int)strlen(method) && (strncasecmp(method2index[i].type, method, method2index[i].len))==0)
		{
			return method2index[i].index;
		}
	}

	return -1;
}

