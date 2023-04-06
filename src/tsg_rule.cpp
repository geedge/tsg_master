#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>

#include "MESA/http.h"
#include "MESA/cJSON.h"
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include "MESA/MESA_handle_logger.h"

#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

struct str2index
{
	int index;
	int len;
	char *type;
};

struct maat *g_tsg_maat_feather;
struct maat_runtime_para g_tsg_maat_rt_para;

const struct str2index method2index[TSG_METHOD_TYPE_MAX]={	{TSG_METHOD_TYPE_UNKNOWN, 7, (char *)"unknown"},
													{TSG_METHOD_TYPE_DROP, 4, (char *)"drop"},
													{TSG_METHOD_TYPE_REDIRECTION, 8, (char *)"redirect"},
													{TSG_METHOD_TYPE_BLOCK, 5, (char *)"block"},
													{TSG_METHOD_TYPE_RESET, 5, (char *)"reset"},
													{TSG_METHOD_TYPE_RESET, 3, (char *)"rst"},
													{TSG_METHOD_TYPE_ALERT, 5, (char *)"alert"},
													{TSG_METHOD_TYPE_RATE_LIMIT, 10, (char *)"rate_limit"}, 
													{TSG_METHOD_TYPE_MIRRORED, 8, (char *)"mirrored"},
													{TSG_METHOD_TYPE_TAMPER, 6, (char *)"tamper"},
													{TSG_METHOD_TYPE_DEFAULT, 14, (char *)"default_policy"}, // policy id=0, default policy 
													{TSG_METHOD_TYPE_APP_DROP, 7, (char *)"default"},	 // use action of app_id_dict 
													{TSG_METHOD_TYPE_ALLOW, 7, (char *)"allow"},	 // use action of app_id_dict
													{TSG_METHOD_TYPE_SHUNT, 7, (char *)"shunt"}	 // use action of app_id_dict
												};

extern const char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id);
extern unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name);

static char* tm_strdup(const char* s)
{
	char*d=NULL;
	if(s==NULL)
	{
		return NULL;
	}
	d=(char*)malloc(strlen(s)+1);
	memcpy(d,s,strlen(s)+1);
	return d;
}

enum MAAT_MODE get_maat_mode(char *maat_mode)
{
	if(strcasecmp(maat_mode, "redis")==0)
	{
		return MAAT_MODE_REDIS;
	}

	if(strcasecmp(maat_mode, "json")==0)
	{
		return MAAT_MODE_JSON;
	}

	if(strcasecmp(maat_mode, "file")==0)
	{
		return MAAT_MODE_FILE;
	}

	return MAAT_MODE_MAX;
}

unsigned short get_redis_port(char *redis_port_range)
{
	int port_num=0;
	int range_len=0,used_len=0;
	char buf[256]={0};
	unsigned short s_port=0,e_port=0;
	unsigned short redis_port[32]={0};
	char *begin=NULL,*end=NULL,*pchr=NULL;

	if(redis_port_range==NULL)
	{
		return 0;
	}
	
	begin=redis_port_range;
	end=NULL;
	range_len=strlen(redis_port_range);
	
	while(range_len>used_len)
	{
		end=index(begin, ';');
		if(end==NULL)
		{
			end=begin+range_len-used_len;
		}

		if(end==begin)
		{
			break;
		}
		
		memset(buf, 0, sizeof(buf));
		strncpy(buf, begin, end-begin);
		used_len+=end-begin+1;
		if(range_len>used_len)
		{			
			begin=end+1;
		}
		
		pchr=strchr(buf, '-');
		if(pchr == NULL)
		{
			s_port=(unsigned short)atoi(buf);
			e_port=s_port;
		}
		else
		{
			int ret=sscanf(buf, "%hu-%hu", &s_port, &e_port);
			assert(ret==2);
		}
		
		for(int i=s_port; i<=e_port && port_num<32; i++)
		{
			redis_port[port_num++]=i;
		}
	}

	if(port_num==0)
	{
		return 0;
	}
	
	srand((unsigned int)time(NULL));
	int idx=rand()%port_num;

	return redis_port[idx];
}

static int get_column_pos(const char* line, int column_seq, size_t *offset, size_t *len)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	char* dup_line=tm_strdup(line);
	int i=0, ret=-1;
	for (str = dup_line; ; str = NULL)
	{
		subtoken = strtok_r(str, seps, &saveptr);
		if (subtoken == NULL)
			break;
		if(i==column_seq-1)
		{
			*offset=subtoken-dup_line;
			*len=strlen(subtoken);
			ret=0;
			break;
		}
		i++;
	}
	free(dup_line);
	return ret;
}

static char* tm_str_unescape(char* s)
{
	if(s==NULL)
	{
		return NULL;
	}
	
	int i=0,j=0;
	int len=strlen(s);
	for(i=0,j=0;i<len;i++)
	{
		if(s[i]=='\\')
		{
			switch(s[i+1])
			{
				case '&':
					s[j]='&';
					break;
				case 'b':
					s[j]=' ';//space,0x20;
					break;
				case '\\':
					s[j]='\\';
					break;
				default:
					s[j]=s[i];
					i--;	//undo the followed i++
					break;
			}
			i++;
			j++;
		}
		else
		{
			s[j]=s[i];
			j++;
		}
	}
	s[j]='\0';
	return s;
}

static int get_dns_qtype(char *qtype, int qtype_len)
{
	switch(qtype_len)
	{
		case	1:
			if(qtype[0]=='A')
			{
				return DNS_TYPE_A;
			}
			break;
		case	4:
			if((strcasecmp(qtype, "AAAA"))==0)
			{
				return DNS_TYPE_AAAA;
			}
			break;
		case	5:
			if((strcasecmp(qtype, "CNAME"))==0)
			{
				return DNS_TYPE_CNAME;
			}
			break;
		default:
			break;
	}
	
	return -1;
}

static int get_fqdn_len(char *domain)
{
	char *p=NULL;
	int fqdn_len=0;
	
	p=index(domain, ':');
	if(p==NULL)
	{
		fqdn_len=strlen(domain);
	}
	else
	{
		fqdn_len=p-domain;
	}

	return fqdn_len;
}

static int get_data_center(char *accept_tag, char *effective_tag_key, char *data_center, int data_center_len)
{
	cJSON *object=cJSON_Parse(accept_tag);
	if(object!=NULL)
	{
		cJSON *array=cJSON_GetObjectItem(object, "tags");
		if(array!=NULL)
		{
			for(int i=0; i<cJSON_GetArraySize(array); i++)
			{
				cJSON *item=cJSON_GetArrayItem(array, i);
				if(item!=NULL)
				{
					cJSON *tag_item=cJSON_GetObjectItem(item, "tag");
					if(tag_item!=NULL && tag_item->valuestring!=NULL && (memcmp(effective_tag_key, tag_item->valuestring, strlen(effective_tag_key)))==0)
					{
						cJSON *v_item=cJSON_GetObjectItem(item, "value");
						if(v_item!=NULL && v_item->valuestring!=NULL)
						{
							int len=strlen(v_item->valuestring);
							memcpy(data_center, v_item->valuestring, (len>data_center_len-1 ? data_center_len-1 : len));
						}

						cJSON_Delete(object);
						object=NULL;
						return 1;
					}
				}
			}
		}

		cJSON_Delete(object);
		object=NULL;
	}

	return 0;
}

static void tsg_free_field(char *field)
{
	if(field!=NULL)
	{
		free(field);
		field=NULL;
	}
}

static char *tsg_malloc_field(const char *field_start, size_t field_len)
{
	if(field_start==NULL || field_len==0)
	{
		return NULL;
	}

	if(field_len==4 && (memcmp(field_start, "null", 4))==0)
	{
		return NULL;
	}

	char *field=(char *)malloc(field_len+1);
	memcpy(field, field_start, field_len);
	field[field_len]='\0';

	return field;
}

void tsg_maat_state_free(struct maat_state *state)
{
	if(state)
	{
		maat_state_free(state);
	}
}

static int get_string_from_json(cJSON *object, const char *key, char **value)
{
	if(object==NULL || key==NULL)
	{
		return 0;
	}
	cJSON *item=cJSON_GetObjectItem(object, key);
	if(item!=NULL)
	{
		int len=strlen(item->valuestring);
		(*value)=(char *)malloc(len+1);
		memcpy((*value), item->valuestring, len);
		(*value)[len]='\0';

		return 1;
	}

	return 0;
}

static int get_integer_from_json(cJSON *object, const char *key, int *value)
{
	if(object==NULL || key==NULL || (value)==NULL)
	{
		return 0;
	}
	
	cJSON *item=cJSON_GetObjectItem(object, key);
	if(item!=NULL)
	{
		(*value)=item->valueint;
		return 1;
	}

	return 0;
}

int tsg_get_method_id(char *method)
{
	for(int i=0; i<TSG_METHOD_TYPE_MAX; i++)
	{
		if(method2index[i].len==(int)strlen(method) && (strncasecmp(method2index[i].type, method, method2index[i].len))==0)
		{
			return method2index[i].index;
		}
	}

	return -1;
}

char *column_string_get_value(const char* line, int column_seq)
{
	int ret=0;
	size_t offset=0;
	size_t length=0;

	ret=get_column_pos(line, column_seq, &offset, &length);
	if(ret>=0)
	{
		return tsg_malloc_field(line+offset, length);
	}

	return NULL;
}

int column_integer_get_value(const char* line, int column_seq)
{
	int ret=0;
	size_t offset=0;
	size_t length=0;

	ret=get_column_pos(line, column_seq, &offset, &length);
	if(ret>=0)
	{
		return atoi(line+offset);
	}

	return -1;
}

void ex_data_gtp_c_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct umts_user_info *user_info=(struct umts_user_info *)(*from);
		atomic_inc(&user_info->ref_cnt);
		*to=*from;
	}
	
	return;
}

void ex_data_gtp_c_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int imsi=3,msisdn=4,apn=5,imei=6;
	struct umts_user_info *user_info=(struct umts_user_info *)calloc(1, sizeof(struct umts_user_info));

	user_info->imsi=column_string_get_value(table_line, imsi);
	user_info->msisdn=column_string_get_value(table_line, msisdn);	
	user_info->apn=column_string_get_value(table_line, apn);
	user_info->imei=column_string_get_value(table_line, imei);
	
	tm_str_unescape(user_info->imsi);
	tm_str_unescape(user_info->msisdn);
	tm_str_unescape(user_info->apn);
	tm_str_unescape(user_info->imei);
	
	atomic_inc(&user_info->ref_cnt);
	*ad=(void *)user_info;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_GTPC_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_gtp_c_free(int table_id, void **ad, long argl, void* argp)
{
	if(*ad!=NULL)
	{
		struct umts_user_info *user_info=(struct umts_user_info *)(*ad);
		if((__sync_sub_and_fetch(&user_info->ref_cnt, 1) == 0))	
		{
			tsg_free_field(user_info->imsi);
			tsg_free_field(user_info->msisdn);
			tsg_free_field(user_info->apn);
			tsg_free_field(user_info->imei);	

			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_GTPC_DEL], 0, FS_OP_ADD, 1);
		}
	}
	
	return;
}

void plugin_ex_data_gtp_c_free(struct umts_user_info *user_info)
{
	ex_data_gtp_c_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (void **)&user_info, 0, NULL);
}

void ex_data_asn_number_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct asn_info *asn=(struct asn_info *)(*from);
		atomic_inc(&asn->ref_cnt);
		*to=*from;
	}

	return;
}

void ex_data_asn_number_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int asn_field=5;
	int organization_field=6;

	struct asn_info *asn=(struct asn_info *)calloc(1, sizeof(struct asn_info));

	asn->asn_id=column_string_get_value(table_line, asn_field);
	asn->organization=column_string_get_value(table_line, organization_field);
	
	if(asn->asn_id==NULL && asn->organization==NULL)
	{
		tsg_free_field((char *)asn);
		asn=NULL;
		return ;
	}

	tm_str_unescape(asn->asn_id);
	tm_str_unescape(asn->organization);

	atomic_inc(&asn->ref_cnt);
	*ad=(void *)asn;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_ASN_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_asn_number_free(int table_id, void **ad, long argl, void* argp)
{
	if(*ad!=NULL)
	{
		struct asn_info *asn=(struct asn_info *)(*ad);
		if((__sync_sub_and_fetch(&asn->ref_cnt, 1) == 0))	
		{
			tsg_free_field(asn->asn_id);
			tsg_free_field(asn->organization);
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_ASN_DEL], 0, FS_OP_ADD, 1);
		}
	}
	
	return;
}

void plugin_ex_data_asn_number_free(struct asn_info *asn)
{
	ex_data_asn_number_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_USER_DEFINED].id, (void **)&asn, 0, NULL);
}

void ex_data_location_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct location_info *location=(struct location_info *)(*from);
		atomic_inc(&location->ref_cnt);
		*to=*from;
	}
	
	return;
}

void ex_data_location_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	struct location_info *location=(struct location_info *)calloc(1, sizeof(struct location_info));

	location->country_full=column_string_get_value(table_line, 13);	// country_full
	location->province_full=column_string_get_value(table_line, 15);	// province_full
	location->city_full=column_string_get_value(table_line, 16);	// city_full
	tm_str_unescape(location->country_full);
	tm_str_unescape(location->province_full);
	tm_str_unescape(location->city_full);
			
	if(g_tsg_maat_rt_para.location_field_num==19)
	{
		location->subdivision_addr=column_string_get_value(table_line, 17);	// subdivision_addr
		tm_str_unescape(location->subdivision_addr);
	}
	
	atomic_inc(&location->ref_cnt);
	*ad=(void *)location;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_LOCATION_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_location_free(int table_id, void **ad, long argl, void* argp)
{
	if(*ad!=NULL)
	{
		struct location_info *location=(struct location_info *)(*ad);
		if((__sync_sub_and_fetch(&location->ref_cnt, 1) == 0))	
		{
			tsg_free_field(location->country_full);
			tsg_free_field(location->province_full);
			tsg_free_field(location->city_full);
			tsg_free_field(location->subdivision_addr);

			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_LOCATION_DEL], 0, FS_OP_ADD, 1);
		}
	}
	
	return;
}

void plugin_ex_data_location_free(struct location_info *location)
{
	ex_data_location_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, (void **)&location, 0, NULL);
}

void ex_data_fqdn_category_id_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct fqdn_category *fqdn_cat=(struct fqdn_category *)(*from);
		atomic_inc(&fqdn_cat->ref_cnt);
		*to=*from;
	}
	return;
}

void ex_data_fqdn_category_id_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int category_id=2;

	struct fqdn_category * fqdn_cat=(struct fqdn_category *)calloc(1, sizeof(struct fqdn_category));
	fqdn_cat->category_id=(unsigned int)column_integer_get_value(table_line, category_id);
	if(fqdn_cat->category_id==((unsigned int)-1))
	{
		tsg_free_field((char *)fqdn_cat);
		fqdn_cat=NULL;
		return ;
	}
	
	atomic_inc(&fqdn_cat->ref_cnt);
	*ad=(void *)fqdn_cat;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_FQDN_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_fqdn_category_id_free(int table_id, void **ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct fqdn_category *fqdn_cat=(struct fqdn_category *)(*ad);
		if((__sync_sub_and_fetch(&fqdn_cat->ref_cnt, 1) == 0))	
		{
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_FQDN_DEL], 0, FS_OP_ADD, 1);
		}
	}
	
	return;
}

void ex_data_subscriber_id_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct subscribe_id_info *subscribe_id=(struct subscribe_id_info *)(*from);
		atomic_inc(&subscribe_id->ref_cnt);
		*to=*from;
	}
	
	return;
}

void ex_data_subscriber_id_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	int subscribe_id=4;
	struct subscribe_id_info *subscriber=(struct subscribe_id_info *)calloc(1, sizeof(struct subscribe_id_info));
	subscriber->subscribe_id=column_string_get_value(table_line, subscribe_id);

	if(subscriber->subscribe_id==NULL)
	{
		tsg_free_field((char *)subscriber);
		subscriber=NULL;
		
		return;
	}
	
	atomic_inc(&subscriber->ref_cnt);
	*ad=(void *)subscriber;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SUBSCRIBER_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_subscriber_id_free(int table_id, void **ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct subscribe_id_info *subscriber=(struct subscribe_id_info *)(*ad);			
		if((__sync_sub_and_fetch(&subscriber->ref_cnt, 1) == 0))	
		{
			tsg_free_field(subscriber->subscribe_id);
			tsg_free_field((char *)(*ad));
			*ad=NULL;
				
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SUBSCRIBER_DEL], 0, FS_OP_ADD, 1);
		}
	}
	
	return;
}

void plugin_ex_data_subscriber_id_free(struct subscribe_id_info *subscriber)
{
	ex_data_subscriber_id_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, (void **)&subscriber, 0, NULL);
}

static int parse_security_deny_action(char *deny_action_str, struct deny_user_region *deny_app_para)
{
	if(deny_action_str==NULL)
	{
		return 0;
	}

	cJSON *app_para=cJSON_Parse(deny_action_str);
	if(app_para==NULL)
	{
		return 0;
	}

	char *method=NULL;	
	int ret=get_string_from_json(app_para, "method", &method);	
	if(ret==1)
	{
		int method_type=tsg_get_method_id(method);
		switch(method_type)
		{
			case	TSG_METHOD_TYPE_DROP:
				deny_app_para->type=TSG_DENY_TYPE_APP_DROP;
				get_integer_from_json(app_para, "send_tcp_reset", &(deny_app_para->drop_para.send_reset_enable));	
				get_integer_from_json(app_para, "after_n_packets", &(deny_app_para->after_n_packets));	
				get_integer_from_json(app_para, "send_icmp_unreachable", &(deny_app_para->drop_para.send_icmp_enable));
				break;
			case	TSG_METHOD_TYPE_RATE_LIMIT:
				deny_app_para->type=TSG_DENY_TYPE_APP_RATELIMIT;
				get_integer_from_json(app_para, "bps", &(deny_app_para->bps)); 
				break;
			default:
				break;
		}

		free(method);
		method=NULL;
	}
	cJSON_Delete(app_para);
	app_para=NULL;

	return 1;
}

void ex_data_app_id_dict_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct app_id_dict *dict=(struct app_id_dict *)(*from);
		atomic_inc(&dict->ref_cnt);
		*to=*from;
	}
	
	return;
}

void ex_data_app_id_dict_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	char *deny_action_str=NULL;
	struct app_id_dict *dict=NULL;

	dict=(struct app_id_dict *)calloc(1, sizeof(struct app_id_dict));
	
	dict->app_id=column_integer_get_value(table_line, 1);
	dict->app_name=column_string_get_value(table_line, 2);
	dict->parent_app_id=column_integer_get_value(table_line, 3); 
	dict->parent_app_name=column_string_get_value(table_line, 4);
	dict->category=column_string_get_value(table_line, 5);
	dict->subcategory=column_string_get_value(table_line, 6);
	dict->technology=column_string_get_value(table_line, 7);
	dict->risk=column_string_get_value(table_line, 8); 
	dict->characteristics=column_string_get_value(table_line, 9);
	dict->continue_scanning=column_integer_get_value(table_line, 13); 
	dict->tcp_timeout=column_integer_get_value(table_line, 14);
	dict->udp_timeout=column_integer_get_value(table_line, 15); 
	dict->tcp_half_close=column_integer_get_value(table_line, 16);
	dict->tcp_time_wait=column_integer_get_value(table_line, 17);
	deny_action_str=column_string_get_value(table_line, 12);

	parse_security_deny_action(deny_action_str, &(dict->deny_app_para));
	tsg_free_field(deny_action_str);
	deny_action_str=NULL;
	
	tm_str_unescape(dict->risk);
	tm_str_unescape(dict->app_name);
	tm_str_unescape(dict->parent_app_name);
	tm_str_unescape(dict->category);
	tm_str_unescape(dict->subcategory);
	tm_str_unescape(dict->technology);
	tm_str_unescape(dict->characteristics);

	atomic_inc(&dict->ref_cnt);
	*ad=(void *)dict;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_ID_ADD], 0, FS_OP_ADD, 1);
	return;
}

void ex_data_app_id_dict_free(int table_id, void **ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct app_id_dict *dict=(struct app_id_dict *)(*ad);
		if((__sync_sub_and_fetch(&dict->ref_cnt, 1) == 0))
		{
			tsg_free_field(dict->app_name);
			tsg_free_field(dict->parent_app_name);
			tsg_free_field(dict->category);
			tsg_free_field(dict->subcategory);
			tsg_free_field(dict->technology);
			tsg_free_field(dict->risk);
			tsg_free_field(dict->characteristics);
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_APP_ID_DEL], 0, FS_OP_ADD, 1);
		}
	}
	return;
}

static int parse_dns_answer_ttl(struct dns_user_region *user_region_records, cJSON *one_record, int answer_type)
{
	if(one_record==NULL || user_region_records==NULL)
	{
		return 0;
	}
	
	cJSON *ttl=cJSON_GetObjectItem(one_record, "ttl");
	if(ttl==NULL)
	{
		return 0;
	}

	struct dns_answer_records *answer_record_tmp=NULL;

	switch(answer_type)
	{
		case	DNS_TYPE_A:
			answer_record_tmp=user_region_records->a;
			break;
		case	DNS_TYPE_AAAA:
			answer_record_tmp=user_region_records->aaaa;
			break;
	case	DNS_TYPE_CNAME:
			answer_record_tmp=user_region_records->cname;
			break;
		default:
			return 0;
	}
		
	get_integer_from_json(ttl, "min", &(answer_record_tmp->min_ttl));
	get_integer_from_json(ttl, "max", &(answer_record_tmp->max_ttl));

	return 1;
}

static int parse_dns_answer_profile(struct dns_user_region *user_region_records, cJSON *record_profile, int answer_type)
{
	struct dns_answer_records *answer_records=(struct dns_answer_records *)calloc(1, sizeof(struct dns_answer_records));
	answer_records->record_val.answer_type=answer_type;
	
	get_integer_from_json(record_profile, "record_id", &(answer_records->record_val.selected.profile_id));
	get_integer_from_json(record_profile, "selected_num", &(answer_records->record_val.selected.selected_num));

	answer_records->record_val.selected_flag=1;

	switch(answer_type)
	{
		case	DNS_TYPE_A:
			user_region_records->a=answer_records;
			break;
		case	DNS_TYPE_AAAA:
			user_region_records->aaaa=answer_records;
			break;
	case	DNS_TYPE_CNAME:
			user_region_records->cname=answer_records;
			break;
		default:
			return 0;
	}

	return 1;
}

static int parse_dns_answer_value(struct dns_user_region *user_region_records, cJSON *record_value, int answer_type)
{
	switch(answer_type)
	{
		case	DNS_TYPE_A:
			user_region_records->a=(struct dns_answer_records *)calloc(1, sizeof(struct dns_answer_records));
			user_region_records->a->record_val.answer_type=answer_type;
			user_region_records->a->record_val.len=sizeof(struct in_addr);
			inet_pton(AF_INET, record_value->valuestring, (void *)&(user_region_records->a->record_val.v4_addr.s_addr));
			break;
		case	DNS_TYPE_AAAA:
			user_region_records->aaaa=(struct dns_answer_records *)calloc(1, sizeof(struct dns_answer_records));
			user_region_records->aaaa->record_val.answer_type=answer_type;
			user_region_records->aaaa->record_val.len=sizeof(struct in6_addr);
			inet_pton(AF_INET6, record_value->valuestring, (void *)(user_region_records->aaaa->record_val.v6_addr.s6_addr));
			break;
	case	DNS_TYPE_CNAME:
			user_region_records->cname=(struct dns_answer_records *)calloc(1, sizeof(struct dns_answer_records));
			user_region_records->cname->record_val.answer_type=answer_type;
			user_region_records->cname->record_val.len=strlen(record_value->valuestring);
			user_region_records->cname->record_val.cname=(char *)calloc(1, user_region_records->cname->record_val.len+1);
			memcpy(user_region_records->cname->record_val.cname, record_value->valuestring, user_region_records->cname->record_val.len);
			break;
		default:
			return -1;
	}

	return 1;
}

static int parse_dns_answer_records(struct dns_user_region *user_region_records, cJSON *answer_array)
{
	int answer_type=-1;
	int i=0,ret=0,answer_size=0;	
	cJSON *a_item=NULL, *one_record=NULL;

	if(answer_array==NULL || user_region_records==NULL)
	{
		return -1;
	}
	
	answer_size=cJSON_GetArraySize(answer_array);
	for(i=0; i<answer_size; i++)
	{
		one_record=cJSON_GetArrayItem(answer_array, i);
		a_item=cJSON_GetObjectItem(one_record, "atype");
		if(a_item==NULL || a_item->valuestring==NULL)
		{
			continue;
		}

		answer_type=get_dns_qtype(a_item->valuestring, strlen(a_item->valuestring));
		if(answer_type==-1)
		{
			continue;
		}

		a_item=cJSON_GetObjectItem(one_record, "value");
		if(a_item!=NULL)
		{
			ret=parse_dns_answer_value(user_region_records, a_item, answer_type);
		}
		else
		{
			ret=parse_dns_answer_profile(user_region_records, one_record, answer_type);
		}

		if(ret>0)
		{
			parse_dns_answer_ttl(user_region_records, one_record, answer_type);
		}
	}

	return 0;
}

static struct dns_user_region *parse_dns_user_region(cJSON *resolution_array, int arrary_num)
{
	int i=0;
	cJSON *resolution=NULL,*qtype=NULL;
	cJSON *answer_array=NULL;
	struct dns_user_region *records=NULL;
	
	records=(struct dns_user_region *)calloc(1, sizeof(struct dns_user_region)*arrary_num);
	for(i=0; i<arrary_num; i++)
	{
		resolution=cJSON_GetArrayItem(resolution_array, i);
		if(resolution==NULL)
		{
			continue;
		}
		
		qtype=cJSON_GetObjectItem(resolution, "qtype");
		if(qtype==NULL || qtype->valuestring==NULL)
		{
			continue;
		}
		
		records[i].query_type=get_dns_qtype(qtype->valuestring, strlen(qtype->valuestring));
		if(records[i].query_type==-1)
		{
			continue;
		}

		answer_array=cJSON_GetObjectItem(resolution, "answer");
		if(answer_array==NULL)
		{
			continue;
		}
		
		parse_dns_answer_records(&(records[i]), answer_array);
	}

	return records;
}

static int parse_default_policy_para(cJSON *deny_user_region_object, struct compile_user_region *user_region)
{	
	cJSON *method_item=NULL;
	cJSON *tcp_session_item=cJSON_GetObjectItem(deny_user_region_object, "tcp_session");
	cJSON *udp_session_item=cJSON_GetObjectItem(deny_user_region_object, "udp_session");
	if(tcp_session_item==NULL || udp_session_item==NULL)
	{
		return 0;
	}

	user_region->method_type=TSG_METHOD_TYPE_DEFAULT;
	user_region->session_para=(struct default_session_para *)calloc(1, sizeof(struct default_session_para));
	
	method_item=cJSON_GetObjectItem(tcp_session_item, "method");
	if(method_item!=NULL)
	{		
		int method_type=tsg_get_method_id(method_item->valuestring);
		switch(method_type)
		{
			case	TSG_METHOD_TYPE_RST:
			case	TSG_METHOD_TYPE_RESET:
				user_region->session_para->tcp.type=TSG_DENY_TYPE_DEFAULT_RST;
				get_integer_from_json(tcp_session_item, "after_n_packets", &(user_region->session_para->tcp.after_n_packets));
				break;
			case	TSG_METHOD_TYPE_DROP:
				user_region->session_para->tcp.type=TSG_DENY_TYPE_DROP;
				get_integer_from_json(tcp_session_item, "after_n_packets", &(user_region->session_para->tcp.after_n_packets));
				get_integer_from_json(tcp_session_item, "send_icmp_unreachable", &(user_region->session_para->tcp.drop_para.send_icmp_enable));
				get_integer_from_json(tcp_session_item, "send_tcp_reset", &(user_region->session_para->tcp.drop_para.send_reset_enable));
				break;
			default:
				break;
		}

	}

	method_item=cJSON_GetObjectItem(udp_session_item, "method");
	if(method_item!=NULL)
	{
		user_region->session_para->udp.type=TSG_DENY_TYPE_DROP;
		get_integer_from_json(udp_session_item, "after_n_packets", &(user_region->session_para->udp.after_n_packets));
		get_integer_from_json(udp_session_item, "send_icmp_unreachable", &(user_region->session_para->udp.drop_para.send_icmp_enable));
	}

	return 1;
}


static int parse_policy_packet_capture(cJSON *packet_capture_object, struct compile_user_region *user_region)
{
	if(packet_capture_object==NULL || user_region==NULL)
	{
		return 0;
	}

	int ret=get_integer_from_json(packet_capture_object, "enable", &(user_region->capture.enabled));
	if(ret!=1 || user_region->capture.enabled!=1)
	{
		return 0;
	}

	ret=get_integer_from_json(packet_capture_object, "capture_depth", &(user_region->capture.depth));
	if(ret==1)
	{
		return 1;
	}
	
	return 0;
}

static int parse_policy_packet_mirrored(cJSON *user_region_object, struct compile_user_region *user_region)
{
	if(user_region_object==NULL || user_region==NULL)
	{
		return 0;
	}
		
	cJSON *mirror_item=NULL;
	mirror_item=cJSON_GetObjectItem(user_region_object, "traffic_mirror");
	if(mirror_item==NULL)
	{		
		return 0;
	}
	
	user_region->mirror=(struct monitor_user_region *)calloc(1, sizeof(struct monitor_user_region));
	int ret=get_integer_from_json(mirror_item, "enable", &(user_region->mirror->enabled));		
	if(ret!=1)
	{
		return 0;
	}
	
	user_region->method_type=TSG_METHOD_TYPE_MIRRORED;
	get_integer_from_json(mirror_item, "mirror_profile", &(user_region->mirror->profile_id));	

	return 1;
}

static struct compile_user_region *parse_deny_user_region(cJSON *deny_user_region_object)
{
	int ret=0;
	cJSON *item=NULL;
	cJSON *resolution_array=NULL;
	struct compile_user_region *user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));
	
	item=cJSON_GetObjectItem(deny_user_region_object, "method");
	if(item!=NULL)
	{
		user_region->method_type=(TSG_METHOD_TYPE)tsg_get_method_id(item->valuestring);
	}

	switch(user_region->method_type)
	{
		case	TSG_METHOD_TYPE_ALERT:
		case	TSG_METHOD_TYPE_BLOCK:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			get_integer_from_json(deny_user_region_object, "code", &(user_region->deny->code));
			ret=get_integer_from_json(deny_user_region_object, "html_profile", &(user_region->deny->profile_id));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_PROFILE;
				break;
			}
			
			ret=get_string_from_json(deny_user_region_object, "message", &(user_region->deny->message));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_MESSAGE;
				break;
			}
			
			user_region->deny->type=TSG_DENY_TYPE_MAX;
			break;
		case	TSG_METHOD_TYPE_REDIRECTION:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			get_integer_from_json(deny_user_region_object, "code", &(user_region->deny->code));
			ret=get_string_from_json(deny_user_region_object, "redirect_url", &(user_region->deny->redirect_url_to));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_REDIRECT_TO;
				break;
			}

			ret=get_string_from_json(deny_user_region_object, "to", &(user_region->deny->redirect_url_to));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_REDIRECT_TO;
				break;
			}

			resolution_array=cJSON_GetObjectItem(deny_user_region_object, "resolution");
			if(resolution_array!=NULL)
			{				
				user_region->deny->records_num=cJSON_GetArraySize(resolution_array);
				if(user_region->deny->records_num<=0)
				{
					break;
				}
				user_region->deny->records=parse_dns_user_region(resolution_array, user_region->deny->records_num);
				if(user_region->deny->records!=NULL)
				{
					user_region->deny->type=TSG_DENY_TYPE_REDIRECT_RECORD;
					break;
				}
			}
			break;
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			user_region->deny->type=TSG_DENY_TYPE_MAX;
			get_integer_from_json(deny_user_region_object, "bps", &(user_region->deny->bps));
			break;
		case	TSG_METHOD_TYPE_DROP:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			user_region->deny->type=TSG_DENY_TYPE_DROP;
			get_integer_from_json(deny_user_region_object, "send_icmp_unreachable", &(user_region->deny->drop_para.send_icmp_enable));
			get_integer_from_json(deny_user_region_object, "send_tcp_reset", &(user_region->deny->drop_para.send_reset_enable));
			get_integer_from_json(deny_user_region_object, "after_n_packets", &(user_region->deny->after_n_packets));
			break;
		case	TSG_METHOD_TYPE_APP_DROP:
			break;
		case	TSG_METHOD_TYPE_RST:
		case	TSG_METHOD_TYPE_RESET:
			break;
		case	TSG_METHOD_TYPE_TAMPER:
			break;
		default:
			parse_default_policy_para(deny_user_region_object, user_region);
			break;
	}
	
	return user_region;
}

void ex_data_security_compile_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{	
	cJSON *user_region_object=NULL;	
	cJSON *packet_capture_object=NULL;
	//struct compile_user_region *user_region=NULL;

	struct maat_compile *compile=(struct maat_compile *)calloc(1, sizeof(struct maat_compile));
	
	compile->rule.rule_id=column_integer_get_value(table_line, 1);	//policy id
	compile->rule.service_id = column_integer_get_value(table_line, 2); // service id
	compile->rule.action = column_integer_get_value(table_line, 3);	   // action
	compile->rule.do_log = column_integer_get_value(table_line, 5);	   // do_log
	compile->p_user_region=column_string_get_value(table_line, 7);

	if(compile->p_user_region!=NULL && strlen(compile->p_user_region)>2)
	{
		user_region_object=cJSON_Parse(compile->p_user_region);
		if(user_region_object!=NULL)
		{			
			packet_capture_object=cJSON_GetObjectItem(user_region_object, "packet_capture");

			switch(compile->rule.action)
			{
				case	TSG_ACTION_DENY:
					compile->user_region=parse_deny_user_region(user_region_object);
					parse_policy_packet_capture(packet_capture_object, compile->user_region);
					parse_policy_packet_mirrored(user_region_object,compile->user_region);
					break;
				case	TSG_ACTION_MONITOR:
					compile->user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));
					parse_policy_packet_capture(packet_capture_object, compile->user_region);
					parse_policy_packet_mirrored(user_region_object,compile->user_region);
					break; 
				default:
					break;
			}

			cJSON_Delete(user_region_object);
			user_region_object=NULL;
		}
	}

	if(g_tsg_maat_rt_para.default_compile_id==compile->rule.rule_id && compile->user_region!=NULL)
	{
		if(compile->user_region->method_type==TSG_METHOD_TYPE_DEFAULT && compile->user_region->session_para!=NULL)
		{
			memcpy(&(compile->user_region->session_para->result), &(compile->rule), sizeof(struct maat_rule));
		}
	}
	
	atomic_inc(&compile->ref_cnt);
	*ad=(void *)compile;
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SECURIRY_ADD], 0, FS_OP_ADD, 1);

	return ;
}

void ex_data_security_compile_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	struct maat_compile *compile=(struct maat_compile *)(*from);
	if(compile!=NULL)
	{
		atomic_inc(&compile->ref_cnt);
		*to=*from;
	}
}

static void free_dns_records_val(struct dns_record_val *record_val, int record_val_num)
{
	int i=0;
	for(i=0; i<record_val_num; i++)
	{
		tsg_free_field(record_val[i].cname);
		record_val[i].cname=NULL;
	}
}

static void free_dns_answer_records(struct dns_answer_records *answer_records)
{
	if(answer_records!=NULL)
	{
		if(answer_records->record_val.answer_type==DNS_TYPE_CNAME && answer_records->record_val.selected_flag==0)
		{
			free_dns_records_val(&(answer_records->record_val), 1);
		}

		tsg_free_field((char *)answer_records);
		answer_records=NULL;
	}
}

static void free_deny_user_region(struct deny_user_region *deny)
{
	if(deny==NULL || deny->para==NULL)
	{
		return ;
	}

	switch(deny->type)
	{
		case	TSG_DENY_TYPE_MESSAGE:
		case	TSG_DENY_TYPE_REDIRECT_TO:
		case	TSG_DENY_TYPE_REDIRECT_URL:
			tsg_free_field(deny->message);
			deny->message=NULL;
			break;
		case	TSG_DENY_TYPE_REDIRECT_RECORD:
			free_dns_answer_records(deny->records->a);
			free_dns_answer_records(deny->records->aaaa);
			free_dns_answer_records(deny->records->cname);
			tsg_free_field(deny->message);
			deny->message=NULL;
			break;
		default:
			break;
	}

}

void ex_data_security_compile_free(int table_id, void **ad, long argl, void *argp)
{
	struct maat_compile *compile=(struct maat_compile *)(*ad);
	if(compile==NULL)
	{
		return ;
	}
	
	if((__sync_sub_and_fetch(&compile->ref_cnt, 1) == 0))
	{
		if (compile->user_region != NULL) 
		{
			switch(compile->user_region->method_type)
			{
				case	TSG_METHOD_TYPE_ALERT:
				case	TSG_METHOD_TYPE_BLOCK:
				case	TSG_METHOD_TYPE_RATE_LIMIT:
				case	TSG_METHOD_TYPE_REDIRECTION:
					free_deny_user_region(compile->user_region->deny);
					break;
				default:
					break;
			}
			
			if(compile->user_region->user_region_para!=NULL)
			{
				tsg_free_field((char *)(compile->user_region->user_region_para));
				compile->user_region->user_region_para=NULL;
			}
		}

		tsg_free_field(compile->p_user_region);
		
		tsg_free_field((char *)(*ad));
		*ad=NULL;
		
		//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_SECURIRY_DEL], 0, FS_OP_ADD, 1);
	}
		
}

static char *get_http_pages_content(const char *filename, int *filelen)
{
	FILE *file = NULL;
	long length = 0;
	char *content = NULL;
	size_t read_chars = 0;
	file = fopen(filename, "rb");
	if(file == NULL)
	{
		goto cleanup;
	}
	if(fseek(file, 0, SEEK_END) != 0)
	{
		goto cleanup;
	}
	length = ftell(file);
	if(length < 0)
	{
		goto cleanup;
	}
	if(fseek(file, 0, SEEK_SET) != 0) 
	{
		goto cleanup;
	} 
	content = (char*)malloc((size_t)length + sizeof("")); 
	if(content == NULL)
	{
		goto cleanup;
	}
	read_chars = fread(content, sizeof(char), (size_t)length, file);
	if ((long)read_chars != length)
	{
		free(content);
		content = NULL;
		goto cleanup;
	}
	*filelen = read_chars;
	content[read_chars] = '\0';
cleanup:
	if (file != NULL)
	{
		fclose(file);
	}

	return content;
}


void ex_data_http_response_pages_dup(int table_id, void **to, void **from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct http_response_pages *res_pages=(struct http_response_pages *)(*from);
		*to=*from;
		atomic_inc(&res_pages->ref_cnt);
	}
}

void ex_data_http_response_pages_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void* argp)
{
	char *path=NULL, *format=NULL;
	struct http_response_pages *res_pages=(struct http_response_pages *)calloc(1, sizeof(struct http_response_pages));
	res_pages->profile_id=column_integer_get_value(table_line, 1);

	format=column_string_get_value(table_line, 3);
	path=column_string_get_value(table_line, 4);

	if(format==NULL && path==NULL)
	{
		tsg_free_field((char *)res_pages);
		res_pages=NULL;
		return;
	}
	
	if((strncasecmp(format, "template", strlen(format)))==0)
	{
		res_pages->format=HTTP_RESPONSE_FORMAT_TEMPLATE;
	}
	else
	{
		res_pages->format=HTTP_RESPONSE_FORMAT_HTML;
	}

	tsg_free_field(format);
	format=NULL;
	
	res_pages->content=get_http_pages_content(path, &res_pages->content_len);
	tsg_free_field(path);
	path=NULL;
	
	if(res_pages->content!=NULL && res_pages->content_len>0)
	{		
		atomic_inc(&res_pages->ref_cnt);
		*ad=(void *)res_pages;
	}
	else
	{
		tsg_free_field(res_pages->content);
		tsg_free_field((char *)res_pages);
		res_pages=NULL;
	}

	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HTTP_RES_ADD], 0, FS_OP_ADD, 1);
}

void ex_data_http_response_pages_free(int table_id, void **ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct http_response_pages *res_pages=(struct http_response_pages *)(*ad);
		if((__sync_sub_and_fetch(&res_pages->ref_cnt, 1) == 0))
		{
			tsg_free_field(res_pages->content);
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HTTP_RES_DEL], 0, FS_OP_ADD, 1);
		}
	}
}

void ex_data_dns_profile_records_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{
	struct dns_profile_records *profile_records=(struct dns_profile_records *)calloc(1, sizeof(struct dns_profile_records));
	profile_records->record_id=column_integer_get_value(table_line, 1);
	char *answer_type=column_string_get_value(table_line, 3);
	char *json_record=column_string_get_value(table_line, 4);

	cJSON *records_array=cJSON_Parse(json_record);
	if(records_array!=NULL)
	{
		profile_records->record_num=cJSON_GetArraySize(records_array);
		profile_records->record_val=(struct dns_record_val *)calloc(1, profile_records->record_num*sizeof(struct dns_record_val));		
		profile_records->answer_type=get_dns_qtype(answer_type, strlen(answer_type));

		for(int i=0; i<profile_records->record_num; i++)
		{
			cJSON *one_record=cJSON_GetArrayItem(records_array, i);
			if(one_record==NULL)
			{
				continue;
			}
			
			cJSON *pSub=cJSON_GetObjectItem(one_record, "value");
			if(NULL==pSub )
			{
				continue; 
			}

			switch(profile_records->answer_type)
			{
				case	DNS_TYPE_A:
					profile_records->record_val[i].answer_type=profile_records->answer_type;
					profile_records->record_val[i].len=sizeof(struct in_addr);
					inet_pton(AF_INET, pSub->valuestring, &(profile_records->record_val[i].v4_addr.s_addr));
					break;
				case	DNS_TYPE_AAAA:
					profile_records->record_val[i].answer_type=profile_records->answer_type;
					profile_records->record_val[i].len=sizeof(struct in6_addr);
					inet_pton(AF_INET6, pSub->valuestring, (profile_records->record_val[i].v6_addr.s6_addr));
					break;
				case	DNS_TYPE_CNAME:
					profile_records->record_val[i].answer_type=profile_records->answer_type;
					profile_records->record_val[i].len=strlen(pSub->valuestring);
					profile_records->record_val[i].cname=(char *)calloc(1, profile_records->record_val[i].len+1);
					memcpy(profile_records->record_val[i].cname, pSub->valuestring, profile_records->record_val[i].len);
					break;
				default:
					continue;	
			}
		}

		atomic_inc(&profile_records->ref_cnt);
		(*ad)=(void *)profile_records;

		cJSON_Delete(records_array);
		records_array=NULL;

		tsg_free_field(json_record);
		json_record=NULL;

		tsg_free_field(answer_type);
		answer_type=NULL;
	}
	else
	{		
		tsg_free_field((char *)profile_records);
		profile_records=NULL;
	}

	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_DNS_RES_ADD], 0, FS_OP_ADD, 1);

	return ;
}

void ex_data_dns_profile_records_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct dns_profile_records *profile_records=(struct dns_profile_records *)(*from);
		atomic_inc(&profile_records->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

void ex_data_dns_profile_records_free(int table_id, void **ad, long argl, void *argp)
{
	if((*ad)!=NULL)
	{
		struct dns_profile_records *profile_records=(struct dns_profile_records *)*ad;
		if((__sync_sub_and_fetch(&profile_records->ref_cnt, 1) == 0))
		{
			if(profile_records->answer_type==DNS_TYPE_CNAME)
			{
				free_dns_records_val(profile_records->record_val, profile_records->record_num);
			}
			
			tsg_free_field((char *)(profile_records->record_val));
			profile_records->record_val=NULL;
			
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_DNS_RES_DEL], 0, FS_OP_ADD, 1);
		}
	}
}

void ex_data_mirrored_profile_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{
	struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)calloc(1, sizeof(struct traffic_mirror_profile));
	
	mirror_profile->profile_id=column_integer_get_value(table_line, 1);
	char *vlan_ids_str=column_string_get_value(table_line, 3);
	
	cJSON *vlan_ids_object=cJSON_Parse(vlan_ids_str);	
	if(vlan_ids_object!=NULL)
	{
		int vlan_id_num=cJSON_GetArraySize(vlan_ids_object);
		for(int i=0; i<vlan_id_num; i++)
		{
			cJSON *one_vlan=cJSON_GetArrayItem(vlan_ids_object, i);
			if(one_vlan==NULL)
			{
				continue;
			}

			mirror_profile->vlan.id[mirror_profile->vlan.num++]=one_vlan->valueint;
		}
	}

	atomic_inc(&mirror_profile->ref_cnt);

	*ad=(void *)mirror_profile;
	
	cJSON_Delete(vlan_ids_object);
	vlan_ids_object=NULL;

	tsg_free_field(vlan_ids_str);
	vlan_ids_str=NULL;

	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_ADD], 0, FS_OP_ADD, 1);

	return ;
}

void ex_data_mirrored_profile_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)(*from);
		atomic_inc(&mirror_profile->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

void ex_data_mirrored_profile_free(int table_id, void **ad, long argl, void *argp)
{
	if((*ad)!=NULL)
	{
		struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)*ad;
		if((__sync_sub_and_fetch(&mirror_profile->ref_cnt, 1) == 0))
		{	
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_MIRRORED_DEL], 0, FS_OP_ADD, 1);
		}
	}
}

void ex_data_session_log_profile_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{
	g_tsg_maat_rt_para.session_record_switch=column_integer_get_value(table_line, 2);
}

void ex_data_session_log_profile_dup(int table_id, void **to, void **from, long argl, void *argp)
{
}

void ex_data_session_log_profile_free(int table_id, void **ad, long argl, void *argp)
{
}

void ex_data_tunnel_catalog_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{
	struct tunnel_catalog *t_catalog=(struct tunnel_catalog *)calloc(sizeof(struct tunnel_catalog), 1);

	t_catalog->id=column_integer_get_value(table_line, 1);
	t_catalog->name=column_string_get_value(table_line, 2);	
	t_catalog->type=column_string_get_value(table_line, 3);
	t_catalog->composition=column_string_get_value(table_line, 4);

	atomic_inc(&t_catalog->ref_cnt);
	*ad=(void *)t_catalog;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_CATALOG_ADD], 0, FS_OP_ADD, 1);
	return;
}
void ex_data_tunnel_catalog_free(int table_id, void **ad, long argl, void *argp)
{
	if(*ad==NULL)
	{
		return ;
	}
	
	struct tunnel_catalog *t_catalog=(struct tunnel_catalog *)(*ad);
	if ((__sync_sub_and_fetch(&t_catalog->ref_cnt, 1) == 0))
	{
		tsg_free_field(t_catalog->name);
		tsg_free_field(t_catalog->type);		
		tsg_free_field(t_catalog->composition);
		tsg_free_field((char *)(*ad));
		*ad=NULL;
		//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_CATALOG_DEL], 0, FS_OP_ADD, 1);
	}
}
void ex_data_tunnel_catalog_dup(int table_id,	void **to, void **from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct tunnel_catalog *t_catalog=(struct tunnel_catalog *)(*from);
		__sync_add_and_fetch(&(t_catalog->ref_cnt), 1);
		*to=*from;
	}
}

void ex_data_tunnel_endpoint_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{
	struct tunnel_endpoint *t_endpoint=(struct tunnel_endpoint *)calloc(1, sizeof(struct tunnel_endpoint));
	
	t_endpoint->id=column_integer_get_value(table_line, 1);
	t_endpoint->description=column_string_get_value(table_line, 5);
	
	atomic_inc(&t_endpoint->ref_cnt);
	*ad=(void *)t_endpoint;
	
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_ENDPOINT_ADD], 0, FS_OP_ADD, 1);

	return ;
}

void ex_data_tunnel_endpoint_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct tunnel_endpoint *t_endpoint=(struct tunnel_endpoint *)(*from);
		atomic_inc(&t_endpoint->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

void ex_data_tunnel_endpoint_free(int table_id, void **ad, long argl, void *argp)
{
	if((*ad)!=NULL)
	{
		struct tunnel_endpoint *t_endpoint=(struct tunnel_endpoint *)*ad;
		if((__sync_sub_and_fetch(&t_endpoint->ref_cnt, 1) == 0))
		{
			tsg_free_field(t_endpoint->description);
			tsg_free_field((char *)(*ad));
			*ad=NULL;
			//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_ENDPOINT_DEL], 0, FS_OP_ADD, 1);
		}
	}
}

void plugin_ex_data_tunnel_endpoint_free(struct tunnel_endpoint *t_enpoint)
{
	ex_data_tunnel_endpoint_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (void **)&t_enpoint, 0, NULL);
}

void ex_data_tunnel_label_new(const char *table_name, int table_id, const char* key, const char* table_line, void **ad, long argl, void *argp)
{	
	int label_id=column_integer_get_value(table_line, 1);
	*ad=(void *)(long)label_id;
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_LABEL_ADD], 0, FS_OP_ADD, 1);

	return ;
}

void ex_data_tunnel_label_dup(int table_id, void **to, void **from, long argl, void *argp)
{
	(*to)=(*from);
	return ;
}

void ex_data_tunnel_label_free(int table_id, void **ad, long argl, void *argp)
{
	//FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_TUNNEL_LABEL_DEL], 0, FS_OP_ADD, 1);
}

int init_scan_table(struct maat *feather, const char *conffile)
{
	MESA_load_profile_string_def(conffile, "MAAT", "IP_SRC_ADDR_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SRC_IP_ADDR].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_SOURCE_ADDR");
	MESA_load_profile_string_def(conffile, "MAAT", "IP_DST_ADDR_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_DST_IP_ADDR].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_DESTINATION_ADDR");
	MESA_load_profile_string_def(conffile, "MAAT", "SUBSCRIBER_ID_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SUBSCRIBER_ID].name, MAX_TABLE_NAME_LEN, "TSG_OBJ_SUBSCRIBER_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_APP_ID].name, MAX_TABLE_NAME_LEN, "TSG_OBJ_APP_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "HTTP_HOST_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_HTTP_HOST].name, MAX_TABLE_NAME_LEN, "TSG_FIELD_HTTP_HOST");
	MESA_load_profile_string_def(conffile, "MAAT", "HTTP_URL_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_HTTP_URL].name, MAX_TABLE_NAME_LEN, "TSG_FIELD_HTTP_URL");
	MESA_load_profile_string_def(conffile, "MAAT", "SSL_SNI_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SSL_SNI].name, MAX_TABLE_NAME_LEN, "TSG_FIELD_SSL_SNI");
	MESA_load_profile_string_def(conffile, "MAAT", "DECYPTION_EXCLUSION_SSL_SNI", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_EXCLUSION_SSL_SNI].name, MAX_TABLE_NAME_LEN, "TSG_DECYPTION_EXCLUSION_SSL_SNI");
	MESA_load_profile_string_def(conffile, "MAAT", "SRC_ASN_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SRC_ASN].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_SOURCE_ASN");
	MESA_load_profile_string_def(conffile, "MAAT", "DST_ASN_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_DST_ASN].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_DESTINATION_ASN");
	MESA_load_profile_string_def(conffile, "MAAT", "SRC_LOCATION_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SRC_LOCATION].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_SOURCE_LOCATION");
	MESA_load_profile_string_def(conffile, "MAAT", "DST_LOCATION_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_DST_LOCATION].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_DESTINATION_LOCATION");
	MESA_load_profile_string_def(conffile, "MAAT", "QUIC_SNI_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_QUIC_SNI].name, MAX_TABLE_NAME_LEN, "TSG_FIELD_QUIC_SNI");
	//MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_ID_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_FQDN_CAT_ID].name, MAX_TABLE_NAME_LEN, "TSG_OBJ_FQDN_CAT");
	MESA_load_profile_string_def(conffile, "MAAT", "SELECTOR_ID_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SELECTOR_ID].name, MAX_TABLE_NAME_LEN, "APP_SELECTOR_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "SELECTOR_PROPERTIES_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SELECTOR_PROPERTIES].name, MAX_TABLE_NAME_LEN, "APP_SELECTOR_PROPERTIES");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_APN", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_GTP_APN].name, MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_APN");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_IMSI", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_GTP_IMSI].name, MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_IMSI");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_PHONE_NUMBER", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_GTP_PHONE_NUMBER].name, MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_PHONE_NUMBER");
	MESA_load_profile_string_def(conffile, "MAAT", "DTLS_SNI_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_DTLS_SNI].name, MAX_TABLE_NAME_LEN, "TSG_FIELD_DTLS_SNI");
	MESA_load_profile_string_def(conffile, "MAAT", "TUNNEL_ID_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_TUNNEL_ID].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_TUNNEL");
	MESA_load_profile_string_def(conffile, "MAAT", "SESSION_FLAG_TABLE", g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SESSION_FLAGS].name, MAX_TABLE_NAME_LEN, "TSG_SECURITY_FLAG");

	for(int i=0; i<MAAT_SCAN_MAX; i++)
	{
		g_tsg_maat_rt_para.scan_tb[i].id=maat_get_table_id(feather, g_tsg_maat_rt_para.scan_tb[i].name);
		if(g_tsg_maat_rt_para.scan_tb[i].id<0)
		{
			MESA_handle_runtime_log(g_tsg_maat_rt_para.logger, RLOG_LV_FATAL, "maat_table_get_id failed, table_name: %s", g_tsg_maat_rt_para.scan_tb[i].name); 
			return -1;
		}
	}

	return 0;
}

int init_plugin_table(struct maat *feather, const char *conffile)
{
	struct maat_plugin_table p_table[MAAT_PLUGIN_MAX]={
													{-1, "TSG_COMPILE", ex_data_security_compile_new, ex_data_security_compile_free, ex_data_security_compile_dup},
													{-1, "TSG_IP_ASN_BUILT_IN", ex_data_asn_number_new, ex_data_asn_number_free, ex_data_asn_number_dup},
													{-1, "TSG_IP_ASN_USER_DEFINED", ex_data_asn_number_new, ex_data_asn_number_free, ex_data_asn_number_dup},
													{-1, "TSG_IP_LOCATION_BUILT_IN", ex_data_location_new, ex_data_location_free, ex_data_location_dup},
													{-1, "TSG_IP_LOCATION_USER_DEFINED", ex_data_location_new, ex_data_location_free, ex_data_location_dup},
													{-1, "TSG_FQDN_CATEGORY_BUILT_IN", ex_data_fqdn_category_id_new, ex_data_fqdn_category_id_free, ex_data_fqdn_category_id_dup},
													{-1, "TSG_FQDN_CATEGORY_USER_DEFINED", ex_data_fqdn_category_id_new, ex_data_fqdn_category_id_free, ex_data_fqdn_category_id_dup},
													{-1, "APP_ID_DICT", ex_data_app_id_dict_new, ex_data_app_id_dict_free, ex_data_app_id_dict_dup},
													{-1, "TSG_PROFILE_RESPONSE_PAGES", ex_data_http_response_pages_new, ex_data_http_response_pages_free, ex_data_http_response_pages_dup},
													{-1, "TSG_PROFILE_DNS_RECORDS", ex_data_dns_profile_records_new, ex_data_dns_profile_records_free, ex_data_dns_profile_records_dup},
													{-1, "TSG_PROFILE_TRAFFIC_MIRROR", ex_data_mirrored_profile_new, ex_data_mirrored_profile_free, ex_data_mirrored_profile_dup},
													{-1, "TSG_TUNNEL_CATALOG", ex_data_tunnel_catalog_new, ex_data_tunnel_catalog_free, ex_data_tunnel_catalog_dup},
													{-1, "TSG_TUNNEL_ENDPOINT", ex_data_tunnel_endpoint_new, ex_data_tunnel_endpoint_free, ex_data_tunnel_endpoint_dup},
													{-1, "TSG_TUNNEL_LABEL", ex_data_tunnel_label_new, ex_data_tunnel_label_free, ex_data_tunnel_label_dup},
													{-1, "T_VSYS_INFO", ex_data_session_log_profile_new, ex_data_session_log_profile_free, ex_data_session_log_profile_dup},
													{-1, "TSG_DYN_SUBSCRIBER_IP", ex_data_subscriber_id_new, ex_data_subscriber_id_free, ex_data_subscriber_id_dup},
													{-1, "TSG_DYN_MOBILE_IDENTITY_APN_TEID", ex_data_gtp_c_new, ex_data_gtp_c_free, ex_data_gtp_c_dup}
												};
	
	memcpy(g_tsg_maat_rt_para.plugin_tb, p_table, MAAT_PLUGIN_MAX*sizeof(struct maat_plugin_table));

	MESA_load_profile_string_def(conffile, "MAAT", "SECURITY_COMPILE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].name, MAX_TABLE_NAME_LEN, "TSG_COMPILE");
	MESA_load_profile_string_def(conffile, "MAAT", "ASN_BUILT_IN_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_BUILT_IN].name, MAX_TABLE_NAME_LEN, "TSG_IP_ASN_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "ASN_USER_DEFINED_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_USER_DEFINED].name, MAX_TABLE_NAME_LEN, "TSG_IP_ASN_USER_DEFINED");
	MESA_load_profile_string_def(conffile, "MAAT", "LOCATION_BUILT_IN_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].name, MAX_TABLE_NAME_LEN, "TSG_IP_LOCATION_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "LOCATION_USER_DEFINED_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].name, MAX_TABLE_NAME_LEN, "TSG_IP_LOCATION_USER_DEFINED");
	MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_BUILT_IN_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_BUILT_IN].name, MAX_TABLE_NAME_LEN, "TSG_FQDN_CATEGORY_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_USER_DEFINED_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_USER_DEFINED].name, MAX_TABLE_NAME_LEN, "TSG_FQDN_CATEGORY_USER_DEFINED");
	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_DICT_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].name, MAX_TABLE_NAME_LEN, "APP_ID_DICT");
	MESA_load_profile_string_def(conffile, "MAAT", "RESPONSE_PAGES_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].name, MAX_TABLE_NAME_LEN, "TSG_PROFILE_RESPONSE_PAGES");
	MESA_load_profile_string_def(conffile, "MAAT", "DNS_PROFILE_RECORDS", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].name, MAX_TABLE_NAME_LEN, (char *)"TSG_PROFILE_DNS_RECORDS");
	MESA_load_profile_string_def(conffile, "MAAT", "TRAFFIC_MIRROR_PROFILE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_PROFILE_MIRROR].name, MAX_TABLE_NAME_LEN, (char *)"TSG_PROFILE_TRAFFIC_MIRROR");
	MESA_load_profile_string_def(conffile, "MAAT", "TUNNEL_CATALOG_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_CATALOG].name, MAX_TABLE_NAME_LEN, "TSG_TUNNEL_CATALOG");
	MESA_load_profile_string_def(conffile, "MAAT", "TUNNEL_ENDPOINT_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].name, MAX_TABLE_NAME_LEN, "TSG_TUNNEL_ENDPOINT");
	MESA_load_profile_string_def(conffile, "MAAT", "TUNNEL_LABEL_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_LABEL].name, MAX_TABLE_NAME_LEN, "TSG_TUNNEL_LABEL");
	MESA_load_profile_string_def(conffile, "MAAT", "SESSION_RECORD_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SESSION_LOG].name, MAX_TABLE_NAME_LEN, "T_VSYS_INFO");
	MESA_load_profile_string_def(conffile, "MAAT", "CB_SUBSCRIBER_IP_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].name, MAX_TABLE_NAME_LEN, "TSG_DYN_SUBSCRIBER_IP");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_SIGNALING_TABLE", g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].name, MAX_TABLE_NAME_LEN, (char *)"TSG_DYN_MOBILE_IDENTITY_APN_TEID");

	for(int i=0; i<MAAT_PLUGIN_MAX; i++)
	{
		g_tsg_maat_rt_para.plugin_tb[i].id=maat_get_table_id(feather, g_tsg_maat_rt_para.plugin_tb[i].name);
		if(g_tsg_maat_rt_para.plugin_tb[i].id<0)
		{
			return -1;
		}

		int ret=maat_plugin_table_ex_schema_register(feather,
														g_tsg_maat_rt_para.plugin_tb[i].name,
														g_tsg_maat_rt_para.plugin_tb[i].ex_new,
														g_tsg_maat_rt_para.plugin_tb[i].ex_free,
														g_tsg_maat_rt_para.plugin_tb[i].ex_dup,
														0,
														NULL
													);
		if(ret<0)
		{
			return -1;
		}
	}

	return 0;
}

struct maat *init_maat_feather(const char* conffile, char* instance_name, char *module)
{
	int deferred_load=0;
	char maat_mode[32]={0};
	int effect_interval=60;
	char effective_range_filename[1024]={0};
	char effective_flag[1024]={0};
	int output_prometheus=0;
	int maat_stat_on=0,maat_perf_on=0;
	char maat_stat_file[MAX_FILEPATH_LEN]={0};
	char table_info[MAX_FILEPATH_LEN]={0};

	memset(effective_flag, 0, sizeof(effective_flag));
	MESA_load_profile_string_def(conffile, module, "EFFECTIVE_RANGE_FILE", effective_range_filename, sizeof(effective_range_filename),"./tsgconf/maat.conf");

	if(strlen(effective_range_filename)>0)
	{
		MESA_load_profile_string_def(effective_range_filename, "MAAT", "ACCEPT_TAGS", effective_flag, sizeof(effective_flag),"");
	}

	if(strlen(effective_flag)==0)
	{
		MESA_load_profile_string_def(conffile, "MAAT", "ACCEPT_TAGS", effective_flag, sizeof(effective_flag),"");
	}

	if(strlen(g_tsg_maat_rt_para.device_tag)==0 && strlen(effective_flag)>0)
	{
		memcpy(g_tsg_maat_rt_para.device_tag, effective_flag, MIN(strlen(effective_flag), sizeof(g_tsg_maat_rt_para.device_tag)-1));
	}

	if(strlen(g_tsg_maat_rt_para.data_center)==0 && strlen(effective_flag)>0)
	{
		char effective_tag_key[128]={0};
		MESA_load_profile_string_def(conffile, module, "EFFECTIVE_TAG_KEY", effective_tag_key, sizeof(effective_tag_key),"data_center");
		get_data_center(effective_flag, effective_tag_key, g_tsg_maat_rt_para.data_center, sizeof(g_tsg_maat_rt_para.data_center));
	}

	int _log_level=LOG_LEVEL_FATAL;
	MESA_load_profile_int_def(conffile, module,"LOG_LEVEL", &(_log_level), LOG_LEVEL_FATAL);

	char log_path[128]={0};
	MESA_load_profile_string_def(conffile,module,"LOG_PATH", log_path, sizeof(log_path), "./log/maat.log");

	MESA_load_profile_int_def(conffile, module,"STAT_SWITCH", &(maat_stat_on),1);
	MESA_load_profile_int_def(conffile, module,"PERF_SWITCH", &(maat_perf_on),1);
	MESA_load_profile_int_def(conffile, module,"OUTPUT_PROMETHEUS", &(output_prometheus), 1);
	MESA_load_profile_int_def(conffile, module,"DEFERRED_LOAD", &(deferred_load), 0);
	MESA_load_profile_string_def(conffile,module,"TABLE_INFO",table_info, sizeof(table_info), "");
	MESA_load_profile_string_def(conffile,module,"STAT_FILE",maat_stat_file, sizeof(maat_stat_file), "");
	MESA_load_profile_int_def(conffile, module,"EFFECT_INTERVAL_S", &(effect_interval), 60);
	effect_interval*=1000;//convert s to ms

	struct maat_options *opts=maat_options_new();
	size_t thread_max=(size_t)get_thread_count();
	maat_options_set_logger(opts, log_path, (enum log_level)_log_level);
	maat_options_set_caller_thread_number(opts, thread_max);
	maat_options_set_accept_tags(opts, (const char *)effective_flag);
	maat_options_set_rule_effect_interval_ms(opts, effect_interval);
	maat_options_set_instance_name(opts, instance_name);
	if(deferred_load==1)
	{
		maat_options_set_deferred_load_on(opts);
	}

	MESA_load_profile_string_def(conffile, module, "MAAT_MODE", maat_mode, sizeof(maat_mode),"json");
	enum MAAT_MODE mode=get_maat_mode(maat_mode);
	switch(mode)
	{
		case	MAAT_MODE_FILE:
			{
				char inc_cfg_dir[MAX_FILEPATH_LEN]={0},ful_cfg_dir[MAX_FILEPATH_LEN]={0};
				MESA_load_profile_string_def(conffile,module,"INC_CFG_DIR",inc_cfg_dir, sizeof(inc_cfg_dir),"");
				MESA_load_profile_string_def(conffile,module,"FULL_CFG_DIR",ful_cfg_dir, sizeof(ful_cfg_dir),"");	
				assert(strlen(inc_cfg_dir)!=0&&strlen(ful_cfg_dir)!=0);
				maat_options_set_iris(opts, (const char *)ful_cfg_dir, (const char *)inc_cfg_dir);
			}
			break;
		case	MAAT_MODE_JSON:
			{
				char json_filename[MAX_FILEPATH_LEN]={0};
				MESA_load_profile_string_def(conffile,module,"JSON_CFG_FILE",json_filename, sizeof(json_filename),"");
				maat_options_set_json_file(opts, (const char *)json_filename);
			}
			break;
		case	MAAT_MODE_REDIS:
			{
				int redis_index=0;
				char redis_ip[16]={0};
				char redis_port_range[256]={0};
				MESA_load_profile_string_def(conffile,module,"REDIS_IP", redis_ip, sizeof(redis_ip),"");
				MESA_load_profile_int_def(conffile, module,"REDIS_INDEX", &redis_index, 0);
				MESA_load_profile_string_def(conffile,module,"REDIS_PORT", redis_port_range, sizeof(redis_port_range), "6379;");
				unsigned short redis_port=get_redis_port(redis_port_range);
				maat_options_set_redis(opts, redis_ip, redis_port, redis_index);
			}
			break;
		default:
			break;
	}

	return maat_new(opts, table_info);
}

int tsg_maat_rule_init(const char* conffile)
{
	int log_level=30;
	char log_path[128]={0};
	char maat_conffile[256]={0};

	memset(&g_tsg_maat_rt_para, 0, sizeof(struct maat_runtime_para));

	MESA_load_profile_int_def(conffile, "MAAT","LOG_LEVEL", &log_level, 30);
	MESA_load_profile_string_def(conffile, "MAAT", "LOG_PATH", log_path, sizeof(log_path), "./log/tsg_maat.log");
	g_tsg_maat_rt_para.logger=MESA_create_runtime_log_handle(log_path, log_level);
	if(g_tsg_maat_rt_para.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}

	MESA_load_profile_int_def(conffile, "MAAT","SESSION_RECORD_SWITCH", &g_tsg_maat_rt_para.session_record_switch, 0);
	
	MESA_load_profile_int_def(conffile, "MAAT","LOCATION_TABLE_TYPE", &g_tsg_maat_rt_para.location_field_num, 18);
	MESA_load_profile_string_def(conffile, "MAAT", "PROFILE", maat_conffile, sizeof(maat_conffile), "./tsgconf/maat.conf");
	g_tsg_maat_feather=init_maat_feather(maat_conffile, (char *)"STATIC", (char *)"STATIC");
	if(g_tsg_maat_feather==NULL)
	{
		return -1;
	}

	int ret=init_scan_table(g_tsg_maat_feather, conffile);
	if(ret<0)
	{
		return -1;
	}
	
	ret=init_plugin_table(g_tsg_maat_feather, conffile);
	if(ret<0)
	{
		return -1;
	}

	return 0;
}

static int sort_category_id(const void * a, const void * b)
{
	struct fqdn_category *x = (struct fqdn_category *) a;
	struct fqdn_category *y = (struct fqdn_category *) b;
	
	return (int)(x->category_id - y->category_id);
}

static int get_fqdn_category_id(struct maat *feather, int table_id, char *fqdn, unsigned int *category_id, int category_id_num)
{
	struct fqdn_category *ex_data_array[8]={0};
	int ret=maat_fqdn_plugin_table_get_ex_data(feather, table_id, fqdn, (void **)ex_data_array, 8);
	if(ret>0)
	{	
		int cnt=0;
		qsort(ex_data_array, ret, sizeof(struct fqdn_category *), sort_category_id);
		
		for(int i=0; i<ret; i++)
		{
			if(cnt==0)
			{
				category_id[cnt++]=ex_data_array[i]->category_id;
			}
			else
			{
				if(cnt<category_id_num && ex_data_array[i]->category_id!=category_id[cnt-1])
				{
					category_id[cnt++]=ex_data_array[i]->category_id;
				}
			}
			
			ex_data_fqdn_category_id_free(table_id, (void **)&(ex_data_array[i]), 0, NULL);
		}

		return cnt;
	}

	return 0;
}

int ip_int2string(const struct streaminfo *a_stream, char *s_ip, size_t s_ip_len, char *d_ip, size_t d_ip_len)
{
	struct stream_tuple4_v4 *v4=NULL;
	struct stream_tuple4_v6 *v6=NULL;
	
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
			v4=a_stream->addr.tuple4_v4;
			inet_ntop(AF_INET, &(v4->saddr), s_ip, s_ip_len);
			inet_ntop(AF_INET, &(v4->daddr), d_ip, d_ip_len);
			break;
		case	ADDR_TYPE_IPV6:
			v6=a_stream->addr.tuple4_v6;
			inet_ntop(AF_INET6, v6->saddr, s_ip, s_ip_len);
			inet_ntop(AF_INET6, v6->daddr, d_ip, d_ip_len);
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

int ip_address_convert(const struct streaminfo *a_stream, struct ip_addr *s_ip, struct ip_addr *d_ip)
{
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
			s_ip->ip_type=4;
			s_ip->ipv4=a_stream->addr.tuple4_v4->saddr;
			
			d_ip->ip_type=4;
			d_ip->ipv4=a_stream->addr.tuple4_v4->daddr;
			break;
		case	ADDR_TYPE_IPV6:
			s_ip->ip_type=6;
			memcpy((char *)(s_ip->ipv6), a_stream->addr.tuple4_v6->saddr, IPV6_ADDR_LEN);
			
			d_ip->ip_type=6;
			memcpy((char *)(d_ip->ipv6), a_stream->addr.tuple4_v6->daddr, IPV6_ADDR_LEN);
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

int srt_attribute_set_ip_asn(const struct streaminfo *a_stream, struct maat *feather, struct asn_info **client_asn, struct asn_info **server_asn)
{
	struct ip_addr dest_ip={0}, source_ip={0};
	ip_address_convert(a_stream, &source_ip, &dest_ip);
	
	if(*client_asn==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_USER_DEFINED].id, &source_ip, (void **)client_asn, 1);
	}
	
	if(*client_asn==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_BUILT_IN].id, &source_ip, (void **)client_asn, 1);
	}

	if(*server_asn==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_USER_DEFINED].id, &dest_ip, (void **)server_asn, 1);
	}

	if(*server_asn==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_ASN_BUILT_IN].id, &dest_ip, (void **)server_asn, 1);
	}

	return 1;
}

int srt_attribute_set_ip_location(const struct streaminfo *a_stream, struct maat *feather, struct location_info **client_location, struct location_info **server_location)
{
	struct ip_addr dest_ip={0}, source_ip={0};
	ip_address_convert(a_stream, &source_ip, &dest_ip);

	if(*client_location==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, &source_ip, (void **)client_location, 1);
	}
	
	if(*client_location==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &source_ip, (void **)client_location, 1);
	}
	
	if(*server_location==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, &dest_ip, (void **)server_location, 1);
	}

	if(*server_location==NULL)
	{
		maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &dest_ip, (void **)server_location, 1);
	}

	return 1;
}

int srt_attribute_set_subscriber_id(const struct streaminfo *a_stream, struct maat *feather, struct subscribe_id_info **source_subscribe_id, struct subscribe_id_info **dest_subscribe_id)
{
	char source_ip[MAX_IPV6_ADDR_LEN]={0};
	char dest_ip[MAX_IPV6_ADDR_LEN]={0};

	int ret=ip_int2string(a_stream, source_ip, MAX_IPV6_ADDR_LEN, dest_ip, MAX_IPV6_ADDR_LEN);
	if(ret==0)
	{
		return 0;
	}
	
	if(strlen(dest_ip)>0 && *dest_subscribe_id==NULL)
	{
		*dest_subscribe_id=(struct subscribe_id_info *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, dest_ip);
	}

	if(strlen(source_ip)>0 && *source_subscribe_id==NULL)
	{
		*source_subscribe_id=(struct subscribe_id_info *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, source_ip);
	}

	return 0;
}

size_t matche_rules_convert(struct maat *feather,long long *matched_rules, size_t n_matched_rules, struct maat_rule *results, size_t n_results)
{
	size_t offset=0;
	for(size_t i=0; i<n_matched_rules && offset<n_results; i++)
	{
		struct maat_compile *maat_compile=(struct maat_compile *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (const char *)&(matched_rules[i]));
		if(maat_compile==NULL)
		{
			continue;
		}

		results[offset++]=maat_compile->rule;
		ex_data_security_compile_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (void **)&(maat_compile), 0, NULL);
	}

	return offset;
}

size_t tsg_scan_integer(const struct streaminfo *a_stream, struct maat *feather, long long s_integer, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	size_t n_matched_rules=0;
	long long matched_rules[MAX_RESULT_NUM];
	int is_hited=maat_scan_integer(feather, g_tsg_maat_rt_para.scan_tb[idx].id, s_integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
	if(is_hited==MAAT_SCAN_HIT)
	{
		return matche_rules_convert(feather, matched_rules, n_matched_rules, results, n_results);
	}

	MESA_handle_runtime_log(g_tsg_maat_rt_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_INTEGER",
								"No hit: %lld: scan ret: %d table_name: %s addr: %s",
								s_integer,
								is_hited,
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_maat_rt_para.level)
							);
	return 0;
}

size_t tsg_scan_flags(const struct streaminfo *a_stream, struct maat *feather, unsigned long long flags, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	size_t n_matched_rules=0;
	long long matched_rules[MAX_RESULT_NUM];
	int is_hited=maat_scan_flag(feather, g_tsg_maat_rt_para.scan_tb[idx].id, flags, matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
	if(is_hited==MAAT_SCAN_HIT)
	{
		return matche_rules_convert(feather, matched_rules, n_matched_rules, results, n_results);
	}

	MESA_handle_runtime_log(g_tsg_maat_rt_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_FLAGS",
								"No hit: %llu scan ret: %d table_name: %s addr: %s",
								flags,
								is_hited,
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_maat_rt_para.level)
							);
	return 0;
}

size_t tsg_scan_string(const struct streaminfo *a_stream, struct maat *feather, const char *s_data, size_t s_data_len, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	size_t n_matched_rules=0;
	long long matched_rules[MAX_RESULT_NUM];
	int is_hited=maat_scan_string(feather, g_tsg_maat_rt_para.scan_tb[idx].id, s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
	if(is_hited==MAAT_SCAN_HIT)
	{
		return matche_rules_convert(feather, matched_rules, n_matched_rules, results, n_results);
	}

	MESA_handle_runtime_log(g_tsg_maat_rt_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_STRING",
								"No hit: %s len: %lu scan ret: %d table_name: %s addr: %s",
								s_data,
								s_data_len,
								is_hited,
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_maat_rt_para.level)
							);
	return 0;
}

size_t tsg_scan_ipv4_address(const struct streaminfo *a_stream, struct maat *feather, struct ipaddr* p_addr, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *rules, size_t n_rules)
{
	if(p_addr==NULL)
	{
		return 0;
	}

	int is_hited=0;
	int protocol=-1;
	size_t n_matched_rules=0;
	long long matched_rules[MAX_RESULT_NUM];

	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			protocol=6;
			break;
		case	STREAM_TYPE_UDP:
			protocol=17;
			break;
		default:
			protocol=-1;
			break;
	}
	
	switch(idx)
	{
		case	MAAT_SCAN_SRC_IP_ADDR:
			is_hited=maat_scan_ipv4(feather, g_tsg_maat_rt_para.scan_tb[idx].id, p_addr->v4->saddr, p_addr->v4->source, protocol,
											matched_rules+n_matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
			break;
		case	MAAT_SCAN_DST_IP_ADDR:
			is_hited=maat_scan_ipv4(feather, g_tsg_maat_rt_para.scan_tb[idx].id, p_addr->v4->daddr, p_addr->v4->dest, protocol,
											matched_rules+n_matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
			break;
		default:
			return 0;
	}
	
	if(n_matched_rules>0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IPV4",
								"Hit %s addr: %s return n_rules: %llu",
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_para.level),
								n_matched_rules
							);
		return matche_rules_convert(feather, matched_rules, n_matched_rules, rules, n_rules);
	}

	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IPV4",
								"Not hit %s addr: %s Scan return: %d ",
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_para.level),
								is_hited
							);

	return 0;
}

size_t tsg_scan_ipv6_address(const struct streaminfo *a_stream, struct maat *feather, struct ipaddr* p_addr, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *rules, size_t n_rules)
{
	if(p_addr==NULL)
	{
		return 0;
	}

	int is_hited=0;
	size_t n_matched_rules=0;
	long long matched_rules[MAX_RESULT_NUM];
	switch(idx)
	{
		case	MAAT_SCAN_SRC_IP_ADDR:
			is_hited=maat_scan_ipv6(feather, g_tsg_maat_rt_para.scan_tb[idx].id, p_addr->v6->saddr, p_addr->v6->source, -1,
											matched_rules+n_matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
			break;
		case	MAAT_SCAN_DST_IP_ADDR:
			is_hited=maat_scan_ipv6(feather, g_tsg_maat_rt_para.scan_tb[idx].id, p_addr->v6->daddr, p_addr->v6->dest, -1,
											matched_rules+n_matched_rules, MAX_RESULT_NUM, &n_matched_rules, s_mid);
			break;
		default:
			return 0;
	}
	
	if(n_matched_rules>0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IPV6",
								"Hit %s addr: %s return n_rules: %llu",
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_para.level),
								n_matched_rules
							);
		return matche_rules_convert(feather, matched_rules, n_matched_rules, rules, n_rules);
	}

	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IPV6",
								"Not hit %s addr: %s Scan return: %d ",
								g_tsg_maat_rt_para.scan_tb[idx].name,
								PRINTADDR(a_stream, g_tsg_para.level),
								is_hited
							);

	return 0;
}

size_t tsg_scan_ip_asn(const struct streaminfo *a_stream, struct maat *feather, struct asn_info *asn, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_result)
{
	if(asn==NULL || asn->asn_id==NULL|| results==NULL || n_result==0)
	{
		return 0;
	}

	return tsg_scan_string(a_stream, feather, asn->asn_id, strlen(asn->asn_id), idx, s_mid, results, n_result);
}

size_t tsg_scan_ip_location(const struct streaminfo *a_stream, struct maat *feather, struct location_info *location, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	char full_address[1024]={0};
	if(location==NULL || results==NULL || n_results==0)
	{
		return 0;
	}

	if(g_tsg_maat_rt_para.location_field_num==19)
	{
		snprintf(full_address, 
					sizeof(full_address),
					"%s.%s.%s.%s.", 
					location->country_full,
					location->province_full,
					location->city_full,
					location->subdivision_addr==NULL ? "" : location->subdivision_addr);
	}
	else
	{
		snprintf(full_address, sizeof(full_address), "%s.%s.", location->country_full, location->city_full);
	}

	return tsg_scan_string(a_stream, feather, full_address, strlen(full_address), idx, s_mid, results, n_results);
}

int tsg_scan_intercept_exclusion(const struct streaminfo *a_stream, struct maat *feather, struct maat_rule *p_result, char *domain, int thread_seq)
{
	if(domain==NULL)
	{
		return 0;
	}
	
	struct maat_state *s_mid=maat_state_new(g_tsg_maat_feather, thread_seq);
	struct maat_rule tmp_result;
	size_t ret=tsg_scan_string(a_stream, g_tsg_maat_feather, domain, strlen(domain), MAAT_SCAN_EXCLUSION_SSL_SNI, s_mid, &tmp_result, 1);
	maat_state_free(s_mid);
	s_mid=NULL;

	if(ret>0)
	{	
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"EXCLUSION_SSL_SNI",
									"Hit %s policy_id: %d service: %d action: %d Decryption Exclusion: [ policy_id: %d service: %d action: %d ] addr: %s",
									domain,
									tmp_result.rule_id,
									tmp_result.service_id,
									(unsigned char)tmp_result.action,
									p_result->rule_id,
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
	

	return 0;
}

static int get_one_endpoint_ids(const struct streaminfo *a_stream, struct maat *feather, struct ip_addr *ip, struct tunnel_endpoint **endpoint, long long *id_array, int id_array_num)
{
	int i=0,ret=0,offset=0,free_flag=0;
	struct tunnel_endpoint *all_endpoint[TUNNEL_BOOL_ID_MAX];

	if(id_array_num<=0)
	{
		return 0;
	}

	ret=maat_ip_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (const struct ip_addr *)ip, (void **)all_endpoint, TUNNEL_BOOL_ID_MAX);
	for(i=0; i<ret; i++)
	{
		if(offset>=id_array_num)
		{		
			ex_data_tunnel_endpoint_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (void **)&(all_endpoint[i]), 0, NULL);
			continue;
		}
		
		if(*endpoint==NULL)
		{
			*endpoint=all_endpoint[i];
		}
		else if((*endpoint)->id < all_endpoint[i]->id)
		{
			ex_data_tunnel_endpoint_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (void **)endpoint, 0, NULL);
			*endpoint=all_endpoint[i];
		}
		else
		{
			free_flag=1;
		}
		
		id_array[offset++]=all_endpoint[i]->id;
		MESA_handle_runtime_log(g_tsg_maat_rt_para.logger, RLOG_LV_DEBUG, "endpoint", "addr: %s Get endpoint id: %d", PRINTADDR(a_stream, g_tsg_maat_rt_para.level), all_endpoint[i]->id);

		if(free_flag==1)
		{
			free_flag=0;
			ex_data_tunnel_endpoint_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (void **)&(all_endpoint[i]), 0, NULL);
		}
	}

	return offset;
}

int tsg_get_endpoint_id(const struct streaminfo *a_stream, struct maat *feather, struct tunnel_endpoint **client_endpoint, struct tunnel_endpoint **server_endpoint, long long *endpoint_id_array, int endpoint_id_array_num)
{
	int offset=0;
	struct ip_addr dest_ip={0}, source_ip={0};
	ip_address_convert(a_stream, &source_ip, &dest_ip);
	offset+=get_one_endpoint_ids(a_stream, feather, &source_ip, client_endpoint, endpoint_id_array+offset, endpoint_id_array_num-offset);
	offset+=get_one_endpoint_ids(a_stream, feather, &dest_ip, server_endpoint, endpoint_id_array+offset, endpoint_id_array_num-offset);
	
	return offset;
}

int tsg_get_vlan_label_id(struct maat *feather, struct single_layer_vlan_addr *vlan_array, int vlan_array_num, long long *label_id_array, int label_id_array_num)
{
	if(vlan_array_num<=0 || label_id_array_num<=0 || vlan_array==NULL || label_id_array==NULL)
	{
		return 0;
	}
	
	int idx=0;
	for(int i=0; i<vlan_array_num; i++)
	{
		void *label_id=maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_LABEL].id, (const char *)&(vlan_array[i].VID));
		if(label_id==NULL)
		{
			continue;
		}

		if(idx>=label_id_array_num)
		{
			break;
		}

		label_id_array[idx++]=(long long)(label_id);
	}

	return idx;
}

size_t tsg_scan_tunnel_id(const struct streaminfo *a_stream, struct maat *feather, struct maat_rule *results, size_t n_results, struct maat_state *s_mid, long long *bool_id_array, size_t n_bool_id_array)
{
	size_t hit_num=0;
	struct tunnel_catalog *t_catalog[TUNNEL_CATALOG_MAX];
	int ret=maat_bool_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_CATALOG].id, (unsigned long long *)bool_id_array, n_bool_id_array, (void**)(&t_catalog), TUNNEL_CATALOG_MAX);
	for(int i=0; i<ret; i++)
	{
		hit_num+=tsg_scan_integer(a_stream, feather, (long long)t_catalog[i]->id, MAAT_SCAN_TUNNEL_ID, s_mid, results+hit_num, n_results-hit_num);
		ex_data_tunnel_catalog_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_CATALOG].id, (void **)&(t_catalog[i]), 0, NULL);
	}

	return hit_num;
}

size_t tsg_scan_subscribe_id_policy(const struct streaminfo *a_stream, struct maat *feather, struct subscribe_id_info *user_info, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	if(user_info==NULL || user_info->subscribe_id==NULL || results==NULL || n_results==0)
	{
		return 0;
	}

	return tsg_scan_string(a_stream, feather, user_info->subscribe_id, strlen(user_info->subscribe_id), MAAT_SCAN_SUBSCRIBER_ID, s_mid, results, n_results);
}

size_t tsg_scan_gtp_apn_policy(const struct streaminfo *a_stream, struct maat *feather, char *apn, struct maat_state *s_mid,struct maat_rule *results, size_t n_results)
{
	if(apn==NULL || results==NULL || n_results==0)
	{
		return 0;
	}
	
	return tsg_scan_string(a_stream, feather, apn, strlen(apn), MAAT_SCAN_GTP_APN, s_mid, results, n_results);
}

size_t tsg_scan_gtp_imsi_policy(const struct streaminfo *a_stream, struct maat *feather, char *imsi, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	if(imsi==NULL || results==NULL || n_results==0)
	{
		return 0;
	}
	
	return tsg_scan_string(a_stream, feather, imsi, strlen(imsi), MAAT_SCAN_GTP_IMSI, s_mid, results, n_results);
}

size_t tsg_scan_gtp_phone_number_policy(const struct streaminfo *a_stream, struct maat *feather, char *phone_number, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	if(phone_number==NULL || results==NULL || n_results==0)
	{
		return 0;
	}
	
	return tsg_scan_string(a_stream, feather, phone_number, strlen(phone_number), MAAT_SCAN_GTP_PHONE_NUMBER, s_mid, results, n_results);
}

//return value: -1: failed, 0: not hit, >0: hit count 
size_t tsg_scan_shared_policy(const struct streaminfo *a_stream, struct maat *feather, char *domain, int idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	if(domain==NULL)
	{
		return 0;
	}

	int fqdn_len=get_fqdn_len(domain);
	if(fqdn_len==0)
	{
		return 0;
	}

	return tsg_scan_string(a_stream, feather, domain, fqdn_len, (enum MAAT_SCAN_TB)idx, s_mid, results, n_results);
}

size_t tsg_scan_session_flags(const struct streaminfo *a_stream, struct maat *feather, unsigned long flag, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	return tsg_scan_flags(a_stream, feather, flag, MAAT_SCAN_SESSION_FLAGS, s_mid, results, n_results);
}

struct maat_rule *tsg_select_deny_rule(struct maat_rule *rules, size_t n_rules)
{
	struct maat_rule *p_result=NULL; 

	for(size_t i=0; i< n_rules; i++)
	{
		if(rules[i].action==TSG_ACTION_DENY || rules[i].action==TSG_ACTION_BYPASS)
		{
			if(p_result==NULL)
			{
				p_result=&rules[i];
				continue;
			}

			if(rules[i].action > p_result->action)
			{
				p_result=&rules[i];
				continue;
			}

			if((rules[i].action==p_result->action) && (rules[i].rule_id > p_result->rule_id))
			{
				p_result=&rules[i];
			}
		}
	}

	return p_result;
}

int tsg_get_fqdn_category_ids(struct maat *feather, char *fqdn, unsigned int *category_ids, int n_category_ids)
{
	if(category_ids!=NULL && n_category_ids>0)
	{
		int ret=get_fqdn_category_id(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_USER_DEFINED].id, fqdn, category_ids, n_category_ids);
		if(ret>0)
		{
			return ret;
		}

		ret=get_fqdn_category_id(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_BUILT_IN].id, fqdn, category_ids, n_category_ids);
		if(ret>0)
		{
			return ret;
		}
	}
	
	return 0;
}

size_t tsg_scan_fqdn_category_id(const struct streaminfo *a_stream, struct maat *feather, unsigned int *category_ids, int n_category_ids, int table_idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	if(n_results==0 || category_ids==NULL || n_category_ids<=0 || table_idx<0)
	{
		return 0;
	}

	size_t hit_num=0;
	
	for(int i=0; i<n_category_ids; i++)
	{
		hit_num+=tsg_scan_integer(a_stream, feather, (long long)category_ids[i], (enum MAAT_SCAN_TB)table_idx, s_mid, results, n_results);
	}

	return hit_num;
}

size_t tsg_scan_app_id_policy(const struct streaminfo *a_stream, struct maat *feather, unsigned int app_id, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	return tsg_scan_integer(a_stream, feather, (long long)app_id, MAAT_SCAN_APP_ID, s_mid, results, n_results);
}

size_t tsg_scan_app_properties_policy(const struct streaminfo *a_stream, struct maat *feather, char *property, char *district, struct maat_state *s_mid, struct maat_rule *results, int n_results)
{
	if(property==NULL || district==NULL)
	{
		return 0;
	}

	size_t hit_num=0;
	struct maat_rule property_result[MAX_RESULT_NUM]={0};
	maat_state_set_scan_district(s_mid,  g_tsg_maat_rt_para.scan_tb[MAAT_SCAN_SELECTOR_PROPERTIES].id, (const char *)district, strlen(district));
	size_t ret=tsg_scan_string(a_stream, feather, property, strlen(property), MAAT_SCAN_SELECTOR_PROPERTIES, s_mid, property_result, MAX_RESULT_NUM);
	for(size_t i=0; i<ret; i++)
	{
		hit_num+=tsg_scan_integer(a_stream, feather, property_result[i].rule_id, MAAT_SCAN_SELECTOR_ID, s_mid, results+hit_num, n_results-hit_num);
	}

	return hit_num;
}

size_t tsg_scan_nesting_addr(const struct streaminfo *a_stream, struct maat *feather, enum TSG_PROTOCOL proto, struct maat_state *s_mid, struct maat_rule *results, size_t n_results)
{
	size_t hit_num=0;
	unsigned int proto_id=0;
	struct ipaddr t_addr;
	struct ipaddr* p_addr=NULL;
	const struct streaminfo *cur_stream = a_stream;
	int bool_id_array_idx=0;
	long long bool_id_array[TUNNEL_BOOL_ID_MAX]={0};

	if(results==NULL || n_results==0 || a_stream==NULL || feather==NULL)
	{
		MESA_handle_runtime_log(g_tsg_maat_rt_para.logger, RLOG_LV_DEBUG, "SCAN_NESTING_ADDR", "result==NULL || result_num<=0 || maat_feather==NULL || a_stream==NULL");
		return 0;
	}

	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_get(a_stream);
	srt_attribute_set_ip_asn(a_stream, feather, &(srt_attribute->client_asn), &(srt_attribute->server_asn));
	srt_attribute_set_ip_location(a_stream, feather, &(srt_attribute->client_location), &(srt_attribute->server_location));

	do
	{
		switch(cur_stream->addr.addrtype)
		{
			case	ADDR_TYPE_IPV4:
			case	__ADDR_TYPE_IP_PAIR_V4:
				if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
				{
					memcpy(&t_addr, &cur_stream->addr, sizeof(t_addr));
					t_addr.addrtype = ADDR_TYPE_IPV4;
					p_addr=&t_addr;
				}
				else
				{
					p_addr=(struct ipaddr *)&cur_stream->addr;
				}
				hit_num+=tsg_scan_ipv4_address(cur_stream, feather,p_addr, MAAT_SCAN_SRC_IP_ADDR, s_mid, results+hit_num, n_results-hit_num);
				hit_num+=tsg_scan_ipv4_address(cur_stream, feather,p_addr, MAAT_SCAN_DST_IP_ADDR, s_mid, results+hit_num, n_results-hit_num);
				break;
			case	ADDR_TYPE_IPV6:
			case	__ADDR_TYPE_IP_PAIR_V6:
				if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
				{
					memcpy(&t_addr, &cur_stream->addr, sizeof(t_addr));
					t_addr.addrtype = ADDR_TYPE_IPV6;
					p_addr=&t_addr;
				}
				else
				{
					p_addr=(struct ipaddr *)&cur_stream->addr;
				}

				hit_num+=tsg_scan_ipv6_address(cur_stream, feather, p_addr, MAAT_SCAN_SRC_IP_ADDR, s_mid, results+hit_num, n_results-hit_num);
				hit_num+=tsg_scan_ipv6_address(cur_stream, feather, p_addr, MAAT_SCAN_DST_IP_ADDR, s_mid, results+hit_num, n_results-hit_num);
				break;
			case	ADDR_TYPE_L2TP:
				proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_L2TP].name);
				hit_num+=tsg_scan_integer(cur_stream, feather, (long long)proto_id, MAAT_SCAN_APP_ID, s_mid, results+hit_num, n_results-hit_num);
				break;
			case	ADDR_TYPE_PPTP:
				proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_PPTP].name);
				hit_num+=tsg_scan_integer(cur_stream, feather, (long long)proto_id, MAAT_SCAN_APP_ID, s_mid, results+hit_num, n_results-hit_num);
				break;
			case	ADDR_TYPE_VLAN:
				bool_id_array_idx+=tsg_get_vlan_label_id(feather, cur_stream->addr.vlan->c2s_addr_array, cur_stream->addr.vlan->c2s_layer_num, bool_id_array+bool_id_array_idx, TUNNEL_BOOL_ID_MAX-bool_id_array_idx);
				bool_id_array_idx+=tsg_get_vlan_label_id(feather, cur_stream->addr.vlan->s2c_addr_array, cur_stream->addr.vlan->s2c_layer_num, bool_id_array+bool_id_array_idx, TUNNEL_BOOL_ID_MAX-bool_id_array_idx);
				break;
			case	ADDR_TYPE_GPRS_TUNNEL:
				bool_id_array_idx+=tsg_get_endpoint_id(cur_stream->pfather,
														feather,
														&(srt_attribute->client_endpoint),
														&(srt_attribute->server_endpoint),
														bool_id_array+bool_id_array_idx,
														TUNNEL_BOOL_ID_MAX-bool_id_array_idx
													);
				
				cur_stream=cur_stream->pfather;  // skip gtp tuple4
				break;
			default:
				break;
		}
		
		cur_stream=cur_stream->pfather;
	}while(cur_stream!=NULL && hit_num<n_results);

	if(hit_num<n_results)
	{
		hit_num+=tsg_scan_tunnel_id(a_stream, feather, results+hit_num, n_results-hit_num, s_mid, bool_id_array, bool_id_array_idx);
	}

	if(hit_num<n_results && proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[proto].name);
		hit_num+=tsg_scan_integer(a_stream, feather, (long long)proto_id, MAAT_SCAN_APP_ID, s_mid, results+hit_num, n_results-hit_num);
		if(proto==PROTO_SMTP || proto==PROTO_IMAP || proto==PROTO_POP3)
		{
			proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_MAIL].name);
			hit_num+=tsg_scan_integer(a_stream, feather, (long long)proto_id, MAAT_SCAN_APP_ID, s_mid, results+hit_num, n_results-hit_num);
		}
	}

	if(hit_num<n_results)
	{
		hit_num+=tsg_scan_ip_location(a_stream, feather,srt_attribute->client_location, MAAT_SCAN_SRC_LOCATION, s_mid, results+hit_num, n_results-hit_num);
		hit_num+=tsg_scan_ip_location(a_stream, feather, srt_attribute->server_location, MAAT_SCAN_DST_LOCATION, s_mid, results+hit_num, n_results-hit_num);
	}

	if(hit_num<n_results)
	{
		hit_num+=tsg_scan_ip_asn(a_stream, feather, srt_attribute->client_asn, MAAT_SCAN_SRC_ASN, s_mid, results+hit_num, n_results-hit_num);
		hit_num+=tsg_scan_ip_asn(a_stream, feather, srt_attribute->server_asn, MAAT_SCAN_DST_ASN, s_mid, results+hit_num, n_results-hit_num);
	}

	if(hit_num<n_results)
	{
		srt_attribute_set_subscriber_id(a_stream, feather, &srt_attribute->client_subscribe_id, &srt_attribute->server_subscribe_id);
		hit_num+=tsg_scan_subscribe_id_policy(a_stream, feather, srt_attribute->client_subscribe_id, s_mid, results+hit_num, n_results-hit_num);
		hit_num+=tsg_scan_subscribe_id_policy(a_stream, feather, srt_attribute->server_subscribe_id, s_mid, results+hit_num, n_results-hit_num);
	}

	if(hit_num<n_results)
	{
		int ret=session_runtine_attribute_get_umts_user_info(a_stream, &(srt_attribute->user_info));
		if(ret==1 && srt_attribute->user_info!=NULL)
		{
			hit_num+=tsg_scan_gtp_apn_policy(a_stream, feather, srt_attribute->user_info->apn, s_mid, results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_gtp_imsi_policy(a_stream, feather, srt_attribute->user_info->imsi, s_mid, results+hit_num, n_results-hit_num);
			hit_num+=tsg_scan_gtp_phone_number_policy(a_stream, feather, srt_attribute->user_info->msisdn, s_mid, results+hit_num, n_results-hit_num);
		}
	}

	return hit_num;
}

int tsg_get_app_name_by_id(struct maat *feather, int app_id, char *app_name, int app_name_len, int is_joint_parent)
{
	if(app_id<=0 || app_name==NULL || app_name_len<=0)
	{
		return 0;
	}

	int offset=0;
	long long ll_app_id=(long long)app_id;
	struct app_id_dict *dict=(struct app_id_dict *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&(ll_app_id));
	if(dict!=NULL)
	{
		if((int)strlen(dict->app_name) > app_name_len)
		{
			ex_data_app_id_dict_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (void **)&dict, 0, NULL);
			return offset;
		}
		
		if(dict->parent_app_id!=0 && is_joint_parent==1)
		{		
			offset=snprintf(app_name, app_name_len, "%s.%s", dict->parent_app_name, dict->app_name);
		}
		else
		{
			offset=snprintf(app_name, app_name_len, "%s", dict->app_name);
		}
		
		ex_data_app_id_dict_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (void **)&dict, 0, NULL);

		return offset;
	}

	return offset;
}

struct maat_compile *matched_rule_cites_security_compile(struct maat *feather, struct maat_rule *result)
{
	return (struct maat_compile *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (const char *)&(result->rule_id));
}

int session_packet_capture_notify(const struct streaminfo *a_stream, struct maat_rule *results, size_t n_results, int thread_seq)
{
	struct maat_compile *maat_compile=NULL;
	struct traffic_mirror_profile *mirror_profile=NULL;

	for(size_t i=0; i<n_results; i++)
	{
		if(results[i].action!=TSG_ACTION_MONITOR && results[i].action!=TSG_ACTION_DENY)
		{
			continue;
		}
		
		maat_compile=matched_rule_cites_security_compile(g_tsg_maat_feather, &(results[i]));
		if(maat_compile==NULL)
		{
			continue;
		}

		if(maat_compile->user_region==NULL)
		{
			plugin_ex_data_security_compile_free(maat_compile);
			continue;
		}
		
		if(maat_compile->user_region->method_type==TSG_METHOD_TYPE_MIRRORED && maat_compile->user_region->mirror!=NULL && maat_compile->user_region->mirror->enabled==1)
		{
			mirror_profile=(struct traffic_mirror_profile *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_PROFILE_MIRROR].id, (const char *)&(maat_compile->user_region->mirror->profile_id));
			if(mirror_profile!=NULL)
			{
				session_mirror_packets_sync(a_stream, &results[i], &(mirror_profile->vlan));
				ex_data_mirrored_profile_free(0, (void **)&mirror_profile, 0, NULL);
			}
			else
			{
				session_mirror_packets_sync(a_stream, &results[i], &(g_tsg_maat_rt_para.default_vlan));
			}
		}

		if(maat_compile->user_region->capture.enabled==1)
		{
			session_capture_packets_sync(a_stream, &results[i], maat_compile->user_region->capture.depth);
		}
		
		plugin_ex_data_security_compile_free(maat_compile);
		maat_compile=NULL;
	}
	
	return 1;
}

struct umts_user_info *tsg_get_umts_user_info_form_redis(struct maat *feather, long long teid)
{
	return (struct umts_user_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (const char *)&(teid));
}

void *matched_rule_cites_http_response_pages(struct maat *feather, long long profile_id)
{
	return maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
}

void plugin_ex_data_http_response_pages_free(struct http_response_pages *response_pages)
{
	ex_data_http_response_pages_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (void **)&response_pages, 0, NULL);
}

void *matched_rule_cites_security_compile(struct maat *feather, long long compile_id)
{
	return maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (const char *)&compile_id);
}

void plugin_ex_data_security_compile_free(struct maat_compile *maat_compile)
{
	ex_data_security_compile_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (void **)&maat_compile, 0, NULL);
}

void *matched_rule_cites_app_id_dict(struct maat *feather, long long app_id)
{
	return maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&app_id);
}

void plugin_ex_data_app_id_dict_free(struct app_id_dict *dict)
{
	ex_data_app_id_dict_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (void **)&dict, 0, NULL);
}

void *matched_rule_cites_dns_profile_record(struct maat *feather, long long profile_id)
{
	return maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
}

void plugin_ex_data_dns_profile_record_free(struct dns_profile_records *records)
{
	ex_data_app_id_dict_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (void **)&records, 0, NULL);
}

size_t tsg_matched_rules_select(struct maat *feather, TSG_SERVICE service, long long *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules)
{
	size_t offset=0;
	for(size_t i=0; i<n_matched_rules; i++)
	{
		struct maat_compile *maat_compile=(struct maat_compile *)maat_plugin_table_get_ex_data(feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (const char *)&(matched_rules[i]));
		if(maat_compile==NULL)
		{
			continue;
		}

		if(maat_compile->rule.service_id==service && offset<n_rules)
		{
			rules[offset++]=maat_compile->rule;
		}
		
		ex_data_security_compile_free(g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SECURITY_COMPILE].id, (void **)&(maat_compile), 0, NULL);
	}

	return offset;
}

size_t tm_select_result_by_service_id(struct maat_rule *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules, enum TSG_SERVICE service_id)
{
	size_t offset=0;
	for(size_t i=0; i<n_matched_rules; i++)
	{
		if(matched_rules[i].service_id==service_id && offset<n_rules)
		{
			rules[offset++]=matched_rules[i];
		}
	}

	return offset;
}

size_t tsg_select_matched_security_rules(struct maat_rule *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules)
{
	return tm_select_result_by_service_id(matched_rules, n_matched_rules, rules, n_rules, TSG_SERVICE_SECURITY);
}

size_t tsg_select_matched_shaping_rules(struct maat_rule *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules)
{
	return tm_select_result_by_service_id(matched_rules, n_matched_rules, rules, n_rules, TSG_SERVICE_SHAPING);
}

size_t tsg_select_matched_service_chaining_rules(struct maat_rule *matched_rules, size_t n_matched_rules, struct maat_rule *rules, size_t n_rules)
{
	return tm_select_result_by_service_id(matched_rules, n_matched_rules, rules, n_rules, TSG_SERVICE_CHAINING);
}

int tsg_table_idx_get_by_protocol(TSG_PROTOCOL proto)
{
	switch(proto)
	{
		case	PROTO_HTTP:
			return MAAT_SCAN_HTTP_HOST;
		case	PROTO_SSL:
			return MAAT_SCAN_SSL_SNI;
		case	PROTO_QUIC:
			return MAAT_SCAN_QUIC_SNI;
		case	PROTO_DTLS:
			return MAAT_SCAN_DTLS_SNI;
		default:
			break;
	}

	return -1;
}

int tsg_http_url_table_idx_get(void)
{
	return MAAT_SCAN_HTTP_URL;
}

int tsg_session_record_switch_get(void)
{
	return g_tsg_maat_rt_para.session_record_switch;
}

int tsg_location_type_get(void)
{
	return g_tsg_maat_rt_para.location_field_num;
}

long long tsg_default_compile_id_get(void)
{
	return g_tsg_maat_rt_para.default_compile_id;
}

char *tsg_data_center_get(void)
{
	return g_tsg_maat_rt_para.data_center;
}

char *tsg_device_tag_get(void)
{
	return g_tsg_maat_rt_para.device_tag;
}

