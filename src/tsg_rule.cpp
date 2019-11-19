#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>

#include "MESA/MESA_handle_logger.h"
#include "Maat_rule.h"
#include "Maat_command.h"
#include "tsg_ssl_utils.h"
#include "tsg_rule.h"
#include "tsg_entry.h"

Maat_feather_t g_tsg_maat_feather;

#define	MAX_PATH_LEN	1024

enum kni_scan_table{
    TSG_FIELD_SSL_SNI,
	TSG_FIELD_HTTP_HOST,
	SCAN_TABLE_MAX
};

const char *g_kni_scan_table_name[SCAN_TABLE_MAX];
int g_kni_scan_tableid[SCAN_TABLE_MAX] = {0};

int tsg_rule_init(const char* conffile, void *logger)
{
	unsigned short redis_port = 0;
	int ret=0,scan_detail=0,effect_interval=60;
	const char* instance_name="TSG",*module="MAAT";
	int factor=0, redis_port_num=0,redis_index=0;
	char redis_ip[16]={0}, effective_flag[1024]={0};
	int maat_mode=0,maat_stat_on=0,maat_perf_on=0,thread_max=0;
	char ip_addr_table[32]={0},subscriber_id_table[32]={0};
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
	g_tsg_maat_feather=Maat_feather(thread_max, table_info, logger);
	
	if(maat_mode==2)
	{
		MESA_load_profile_string_def(conffile,module,"REDIS_IP", redis_ip, sizeof(redis_ip),"");
		MESA_load_profile_int_def(conffile, module,"REDIS_PORT_NUM", &(redis_port_num), 1);
		MESA_load_profile_short_def(conffile, module,"REDIS_PORT", (short*)&(redis_port), 6379);
		MESA_load_profile_int_def(conffile, module,"REDIS_INDEX", &redis_index, 0);
		
		if(strlen(effective_flag)!=0)
		{
			Maat_set_feather_opt(g_tsg_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
		}
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));

		srand((unsigned int)time(NULL));
		factor = rand()%redis_port_num;
		redis_port = redis_port+factor;
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_REDIS_IP, redis_ip, strlen(redis_ip)+1);
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_REDIS_PORT, (void *)&redis_port, sizeof(redis_port));
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_STAT_FILE_PATH, maat_stat_file, strlen(maat_stat_file)+1);
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_STAT_ON, NULL, 0);
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_PERF_ON, NULL, 0);
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_REDIS_INDEX, &redis_index, sizeof(redis_index));
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_DEFERRED_LOAD, NULL,0);
	}
	else
	{
		if(strlen(effective_flag)!=0)
		{
			ret=Maat_set_feather_opt(g_tsg_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
			assert(ret>=0);
		}
		Maat_set_feather_opt(g_tsg_maat_feather,MAAT_OPT_INSTANCE_NAME,instance_name, strlen(instance_name)+1);
		if(maat_mode==1)
		{
			MESA_load_profile_string_def(conffile,module,"JSON_CFG_FILE",json_cfg_file, sizeof(json_cfg_file),"");
			Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_JSON_FILE_PATH, json_cfg_file, strlen(json_cfg_file)+1);
		}
		else
		{
			MESA_load_profile_string_def(conffile,module,"INC_CFG_DIR",inc_cfg_dir, sizeof(inc_cfg_dir),"");
			MESA_load_profile_string_def(conffile,module,"FULL_CFG_DIR",ful_cfg_dir, sizeof(ful_cfg_dir),"");	
			assert(strlen(inc_cfg_dir)!=0&&strlen(ful_cfg_dir)!=0);
			
			Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_FULL_CFG_DIR, ful_cfg_dir, strlen(ful_cfg_dir)+1);
			Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_INC_CFG_DIR, inc_cfg_dir, strlen(inc_cfg_dir)+1);
		}
		if(maat_stat_on)
		{
			Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_STAT_FILE_PATH, maat_stat_file, strlen(maat_stat_file)+1);
			Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_STAT_ON, NULL, 0);
			if(maat_perf_on)
			{
				Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_PERF_ON, NULL, 0);
			}
		}

		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));
		Maat_set_feather_opt(g_tsg_maat_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
	}
	
	ret=Maat_initiate_feather(g_tsg_maat_feather);
	if(ret<0)
	{
		return -1;
	}

	MESA_load_profile_string_def(conffile, module, "IP_ADDR_TABLE", ip_addr_table, sizeof(ip_addr_table), "TSG_OBJ_IP_ADDR");
	MESA_load_profile_string_def(conffile, module, "SUBSCRIBER_ID_TABLE", subscriber_id_table, sizeof(subscriber_id_table), "TSG_OBJ_SUBSCRIBER_ID");

	g_tsg_para.ip_addr_table_id=Maat_table_register(g_tsg_maat_feather, ip_addr_table);
	if(g_tsg_para.ip_addr_table_id<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "Maat_table_register %s failed", ip_addr_table); 
		return -1;
	}
	
	g_tsg_para.subscribe_id_table_id=Maat_table_register(g_tsg_maat_feather, subscriber_id_table);
	if(g_tsg_para.subscribe_id_table_id<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "RULE_INIT", "Maat_table_register %s failed", subscriber_id_table); 
		return -1;
	}

	ret=tsg_shared_table_init(conffile, g_tsg_maat_feather, logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "RULE_INIT", "tsg_shared_table_init %s failed"); 
		return -1;	
	}
	
	return 0;
}

static void protocol_identify(char *buff, int buff_len, struct _identify_info *result){
    result->proto = PROTO_MAX;
	//TODO:  http: get from http protocol plugin
	/*
	if(is_http){
		result->protocol = PROTO_HTTP;
		return;
	}
	*/
	//ssl
	enum chello_parse_result chello_status = CHELLO_PARSE_INVALID_FORMAT;
	struct ssl_chello *chello = NULL;
	chello = ssl_chello_parse((const unsigned char*)buff, buff_len, &chello_status);
	if(chello_status == CHELLO_PARSE_SUCCESS){
		result->proto = PROTO_SSL;
		if(chello->sni == NULL){
			result->domain_len = 0;
		}
		else{
			result->domain_len = strnlen(chello->sni, sizeof(result->domain) - 1);
			strncpy(result->domain, chello->sni, result->domain_len);
		}
		result->domain[result->domain_len] = '\0';
	}
    ssl_chello_free(chello);
	return;
}

//return -1 if failed, return 0 on success;
int tsg_shared_table_init(const char *conffile, Maat_feather_t maat_feather, void *logger){
    g_tsg_maat_feather = maat_feather;
    g_kni_scan_table_name[TSG_FIELD_HTTP_HOST] = "TSG_FIELD_HTTP_HOST";
    g_kni_scan_table_name[TSG_FIELD_SSL_SNI] = "TSG_FIELD_SSL_SNI";
    int i;
    for(i = 0; i < SCAN_TABLE_MAX; i++){
		g_kni_scan_tableid[i] = Maat_table_register(maat_feather, g_kni_scan_table_name[i]);
		if(g_kni_scan_tableid[i] < 0){
            MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "Failed at Maat_table_register, tablename = %s, ret = %d", 
				g_kni_scan_table_name[i], g_kni_scan_tableid[i]);
			return -1;
		}
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
	}
	
	return 0;
}

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	struct ipaddr t_addr;
	struct ipaddr* p_addr = NULL;
	char subscribe_id[64]={0};
	int hit_num=0,tans_proto=0;
	int is_scan_addr=1, maat_ret=0,found_pos=0;
	const struct streaminfo *cur_stream = a_stream;

	if(result == NULL || result_num <= 0 || a_stream == NULL || maat_feather == NULL)
	{
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
 											g_tsg_para.ip_addr_table_id,
 											p_addr,
 											tans_proto,
 											result+hit_num,
 											result_num-hit_num,
 											mid,
 											cur_stream->threadnum);
			if(maat_ret > 0)
			{
				hit_num+=maat_ret;
			}
		}
		
		cur_stream = cur_stream->pfather;
		
	}while(cur_stream != NULL && hit_num < result_num);


	if(hit_num < result_num)
	{
		maat_ret=Maat_full_scan_string(maat_feather,
										g_tsg_para.subscribe_id_table_id,
										CHARSET_GBK,
										subscribe_id,
										strlen(subscribe_id),
										result+hit_num,
										&found_pos,
										result_num-hit_num,
										mid,
										a_stream->threadnum);
		if(maat_ret > 0)
		{
			hit_num+=maat_ret;
		}
	}

	return hit_num;
}


//return value: -1: failed, 0: not hit, >0: hit count 
int tsg_scan_shared_policy(Maat_feather_t maat_feather, void *pkt, int pkt_len, Maat_rule_t *result, int result_num, 
			struct _identify_info *identify_info, scan_status_t *mid, void *logger, int thread_seq)
{
    memset(identify_info, 0, sizeof(*identify_info));
    protocol_identify((char*)pkt, pkt_len, identify_info);
	if(identify_info->proto != PROTO_SSL && identify_info->proto != PROTO_HTTP){
		return -1;
	}
	int tableid;
	if(identify_info->proto == PROTO_SSL){
		tableid = g_kni_scan_tableid[TSG_FIELD_SSL_SNI];
	}
	else{
		tableid = g_kni_scan_tableid[TSG_FIELD_HTTP_HOST];
	}
	return Maat_full_scan_string(g_tsg_maat_feather, tableid, CHARSET_UTF8, identify_info->domain, identify_info->domain_len,
									result, NULL, result_num, mid, thread_seq);
}


Maat_rule_t *tsg_fetch_deny_rule(Maat_rule_t *result, int result_num)
{
	int i=0;
	Maat_rule_t *p_result=NULL; 

	for(i=0; i< result_num; i++)
	{
		if(result[i].action==TSG_ACTION_DENY)
		{
			if(p_result==NULL)
			{
				p_result=&result[i];
				continue;
			}

			if(result[i].action > p_result->action)
			{
				p_result=&result[i];
			}
		}
	}

	return p_result;
}

