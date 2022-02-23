#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include "MESA/cJSON.h"
#include "MESA/MESA_handle_logger.h"
#include "Maat_rule.h"
#include "Maat_command.h"
#include "MESA/http.h"
#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"
#include "tsg_protocol_common.h"

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
extern id2field_t g_tsg_proto_name2id[PROTO_MAX];
const struct _str2index method2index[TSG_METHOD_TYPE_MAX]={	{TSG_METHOD_TYPE_UNKNOWN, 7, (char *)"unknown"},
													{TSG_METHOD_TYPE_DROP, 4, (char *)"drop"},
													{TSG_METHOD_TYPE_REDIRECTION, 8, (char *)"redirect"},
													{TSG_METHOD_TYPE_BLOCK, 5, (char *)"block"},
													{TSG_METHOD_TYPE_RESET, 5, (char *)"reset"},
													{TSG_METHOD_TYPE_RESET, 3, (char *)"rst"},
													{TSG_METHOD_TYPE_ALERT, 5, (char *)"alert"},
													{TSG_METHOD_TYPE_RATE_LIMIT, 10, (char *)"rate_limit"}, 
                                                    {TSG_METHOD_TYPE_MIRRORED, 8, (char *)"mirrored"},
                                                    {TSG_METHOD_TYPE_TAMPER, 6, (char *)"tamper"},
                                                    {TSG_METHOD_TYPE_DEFAULT, 7, (char *)"default"}
	};


//functioned as strdup, for dictator compatible.
static char* tsg_strdup(const char* s)
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

unsigned short get_redis_port(char *redis_port_range)
{
	int	i=0,ret=0;
	int idx=0,port_num=0;
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
			ret=sscanf(buf, "%hu-%hu", &s_port, &e_port);
			assert(ret==2);
		}
		
		for(i=s_port; i<=e_port && port_num<32; i++)
		{
			redis_port[port_num++]=i;
		}
	}

	if(port_num==0)
	{
		return 0;
	}
	
	srand((unsigned int)time(NULL));
	idx=rand()%port_num;

	return redis_port[idx];
}

static int get_column_pos(const char* line, int column_seq, size_t *offset, size_t *len)
{
	const char* seps=" \t";
	char* saveptr=NULL, *subtoken=NULL, *str=NULL;
	char* dup_line=tsg_strdup(line);
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

static char* str_unescape(char* s)
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

static int sort_category_id(const void * a, const void * b)
{
	struct fqdn_category *x = (struct fqdn_category *) a;
	struct fqdn_category *y = (struct fqdn_category *) b;
	
	return (int)(x->category_id - y->category_id);
}

static int get_data_center(char *accept_tag, char *effective_tag_key, char *data_center, int data_center_len)
{
	int i=0,len;
	cJSON *object=cJSON_Parse(accept_tag);
	if(object!=NULL)
	{
		cJSON *array=cJSON_GetObjectItem(object, "tags");
		if(array!=NULL)
		{
			for(i=0; i<cJSON_GetArraySize(array); i++)
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
							len=strlen(v_item->valuestring);
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

static void _free_field(char *field)
{
	if(field!=NULL)
	{
		free(field);
		field=NULL;
	}
}

static char *_malloc_field(const char *field_start, size_t field_len)
{
	if(field_start==NULL || field_len<=0)
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

static int get_string_from_json(cJSON *object, const char *key, char **value)
{
	if(object==NULL || key==NULL)
	{
		return 0;
	}
	int len=0;
	cJSON *item=cJSON_GetObjectItem(object, key);
	if(item!=NULL)
	{
		len=strlen(item->valuestring);
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


void ASN_number_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct asn_info *asn=(struct asn_info *)(*from);
		atomic_inc(&asn->ref_cnt);
		*to=*from;
	}

	return;
}

void ASN_number_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int asn_field=5;
	int organization_field=6;

	struct asn_info *asn=(struct asn_info *)calloc(1, sizeof(struct asn_info));

	asn->asn_id=tsg_get_column_string_value(table_line, asn_field);
	asn->organization=tsg_get_column_string_value(table_line, organization_field);
	
	if(asn->asn_id==NULL && asn->organization==NULL)
	{
		_free_field((char *)asn);
		asn=NULL;
		return ;
	}

	str_unescape(asn->asn_id);
	str_unescape(asn->organization);

	atomic_inc(&asn->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)asn;
	
	return;
}

void ASN_number_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if(*ad!=NULL)
	{
		struct asn_info *asn=(struct asn_info *)(*ad);
		if((__sync_sub_and_fetch(&asn->ref_cnt, 1) == 0))	
		{
			_free_field(asn->asn_id);
			_free_field(asn->organization);
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
	
	return;
}

void location_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct location_info *location=(struct location_info *)(*from);
		atomic_inc(&location->ref_cnt);
		*to=*from;
	}
	
	return;
}

void location_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int country_full=13,province_full=15,city_full=16,subdivision_addr=17;
	struct location_info *location=(struct location_info *)calloc(1, sizeof(struct location_info));

	location->country_full=tsg_get_column_string_value(table_line, country_full);	
	location->province_full=tsg_get_column_string_value(table_line, province_full);
	location->city_full=tsg_get_column_string_value(table_line, city_full);
	str_unescape(location->country_full);
	str_unescape(location->province_full);
	str_unescape(location->city_full);
			
	if(g_tsg_para.location_field_num==19)
	{
		location->subdivision_addr=tsg_get_column_string_value(table_line, subdivision_addr);
		str_unescape(location->subdivision_addr);
	}
	
	atomic_inc(&location->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)location;
	
	return;
}

void location_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if(*ad!=NULL)
	{
		struct location_info *location=(struct location_info *)(*ad);
		if((__sync_sub_and_fetch(&location->ref_cnt, 1) == 0))	
		{
			_free_field(location->country_full);
			_free_field(location->province_full);
			_free_field(location->city_full);
			_free_field(location->subdivision_addr);

			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
	
	return;
}

void fqdn_category_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct fqdn_category *fqdn_cat=(struct fqdn_category *)(*from);
		atomic_inc(&fqdn_cat->ref_cnt);
		*to=*from;
	}
	return;
}

void fqdn_category_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int category_id=2;

	struct fqdn_category * fqdn_cat=(struct fqdn_category *)calloc(1, sizeof(struct fqdn_category));
	fqdn_cat->category_id=(unsigned int)tsg_get_column_integer_value(table_line, category_id);
	if(fqdn_cat->category_id==((unsigned int)-1))
	{
		_free_field((char *)fqdn_cat);
		fqdn_cat=NULL;
		return ;
	}
	
	atomic_inc(&fqdn_cat->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)fqdn_cat;
	
	return;
}

void fqdn_category_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct fqdn_category *fqdn_cat=(struct fqdn_category *)(*ad);
		if((__sync_sub_and_fetch(&fqdn_cat->ref_cnt, 1) == 0))	
		{
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
	
	return;
}

void subscriber_id_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct subscribe_id_info *subscribe_id=(struct subscribe_id_info *)(*from);
		atomic_inc(&subscribe_id->ref_cnt);
		*to=*from;
	}
	
	return;
}

void subscriber_id_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int subscribe_id=4;
	struct subscribe_id_info *subscriber=(struct subscribe_id_info *)calloc(1, sizeof(struct subscribe_id_info));
	subscriber->subscribe_id=tsg_get_column_string_value(table_line, subscribe_id);

	if(subscriber->subscribe_id==NULL)
	{
		_free_field((char *)subscriber);
		subscriber=NULL;
		
		return;
	}
	
	atomic_inc(&subscriber->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)subscriber;
	
	return;
}

void subscriber_id_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct subscribe_id_info *subscriber=(struct subscribe_id_info *)(*ad);			
		if((__sync_sub_and_fetch(&subscriber->ref_cnt, 1) == 0))	
		{
			_free_field(subscriber->subscribe_id);
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
	
	return;
}

static int parse_deny_action(char *deny_action_str, struct deny_user_region *deny_app_para)
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
				get_integer_from_json(app_para, "send_tcp_reset", &(deny_app_para->app_para.send_reset_enable));	
				get_integer_from_json(app_para, "after_n_packets", &(deny_app_para->after_n_packets));	
				get_integer_from_json(app_para, "send_icmp_unreachable", &(deny_app_para->app_para.send_icmp_enable));
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

static void app_id_dict_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct app_id_dict *dict=(struct app_id_dict *)(*from);
		atomic_inc(&dict->ref_cnt);
		*to=*from;
	}
	
	return;
}

static void app_id_dict_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	char *deny_action_str=NULL;
	struct app_id_dict *dict=NULL;

	switch(g_tsg_para.app_dict_field_num)
	{
		case	16:
			dict=(struct app_id_dict *)calloc(1, sizeof(struct app_id_dict));
			
			dict->app_id=tsg_get_column_integer_value(table_line, 1);
			dict->app_name=tsg_get_column_string_value(table_line, 2);
			dict->category=tsg_get_column_string_value(table_line, 3);
			dict->subcategroy=tsg_get_column_string_value(table_line, 4);
			dict->technology=tsg_get_column_string_value(table_line, 5);
			dict->risk=tsg_get_column_string_value(table_line, 6); 
			dict->characteristics=tsg_get_column_string_value(table_line, 7);
			dict->continue_scanning=tsg_get_column_integer_value(table_line, 11); 
			dict->tcp_timeout=(unsigned short)tsg_get_column_integer_value(table_line, 12);
			dict->udp_timeout=(unsigned short)tsg_get_column_integer_value(table_line, 13); 
			dict->tcp_half_close=tsg_get_column_integer_value(table_line, 14);
			dict->tcp_time_wait=tsg_get_column_integer_value(table_line, 15);
			
			deny_action_str=tsg_get_column_string_value(table_line, 10);
			break;
		case	18:
			dict=(struct app_id_dict *)calloc(1, sizeof(struct app_id_dict));
			
			dict->app_id=tsg_get_column_integer_value(table_line, 1);
			dict->app_name=tsg_get_column_string_value(table_line, 2);
			dict->parent_app_id=tsg_get_column_integer_value(table_line, 3); 
			dict->parent_app_name=tsg_get_column_string_value(table_line, 4);
			dict->category=tsg_get_column_string_value(table_line, 5);
			dict->subcategroy=tsg_get_column_string_value(table_line, 6);
			dict->technology=tsg_get_column_string_value(table_line, 7);
			dict->risk=tsg_get_column_string_value(table_line, 8); 
			dict->characteristics=tsg_get_column_string_value(table_line, 9);
			dict->continue_scanning=tsg_get_column_integer_value(table_line, 13); 
			dict->tcp_timeout=tsg_get_column_integer_value(table_line, 14);
			dict->udp_timeout=tsg_get_column_integer_value(table_line, 15); 
			dict->tcp_half_close=tsg_get_column_integer_value(table_line, 16);
			dict->tcp_time_wait=tsg_get_column_integer_value(table_line, 17);

			deny_action_str=tsg_get_column_string_value(table_line, 12);
			break;
		default:
			return ;
			break;
	}

	parse_deny_action(deny_action_str, &(dict->deny_app_para));
	_free_field(deny_action_str);
	deny_action_str=NULL;
	
	str_unescape(dict->risk);
	str_unescape(dict->app_name);
	str_unescape(dict->parent_app_name);
	str_unescape(dict->category);
	str_unescape(dict->subcategroy);
	str_unescape(dict->technology);
	str_unescape(dict->characteristics);

	atomic_inc(&dict->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)dict;
	
	return;
}

void app_id_dict_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct app_id_dict *dict=(struct app_id_dict *)(*ad);
		if((__sync_sub_and_fetch(&dict->ref_cnt, 1) == 0))
		{
			_free_field(dict->app_name);
			_free_field(dict->parent_app_name);
			_free_field(dict->category);
			_free_field(dict->subcategroy);
			_free_field(dict->technology);
			_free_field(dict->risk);
			_free_field(dict->characteristics);
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
	return;
}

static int parse_answer_ttl(struct dns_user_region *user_region_records, cJSON *one_record, int answer_type)
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

static int parse_answer_profile(struct dns_user_region *user_region_records, cJSON *record_profile, int answer_type)
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

static int parse_answer_value(struct dns_user_region *user_region_records, cJSON *record_value, int answer_type)
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

static int parse_answer_records(struct dns_user_region *user_region_records, cJSON *answer_array)
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
			ret=parse_answer_value(user_region_records, a_item, answer_type);
		}
		else
		{
			ret=parse_answer_profile(user_region_records, one_record, answer_type);
		}

		if(ret>0)
		{
			parse_answer_ttl(user_region_records, one_record, answer_type);
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
		
		parse_answer_records(&(records[i]), answer_array);
	}

	return records;
}

static int parse_default_para(cJSON *deny_user_region_object, struct compile_user_region *user_region)
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
				get_integer_from_json(tcp_session_item, "after_n_packets", &(user_region->session_para->tcp.after_n_packets));
				get_integer_from_json(tcp_session_item, "send_icmp_unreachable", &(user_region->session_para->tcp.send_icmp_enable));
				if(user_region->session_para->tcp.send_icmp_enable==1)
				{
					user_region->session_para->tcp.type=TSG_DENY_TYPE_SEND_ICMP;
				}
				else
				{					
					user_region->session_para->tcp.type=TSG_DENY_TYPE_DEFAULT_DROP;
				}
				break;
			default:
				break;
		}

	}

	method_item=cJSON_GetObjectItem(udp_session_item, "method");
	if(method_item!=NULL)
	{
		user_region->session_para->udp.type=TSG_DENY_TYPE_DEFAULT_DROP;
		get_integer_from_json(udp_session_item, "after_n_packets", &(user_region->session_para->udp.after_n_packets));
		get_integer_from_json(udp_session_item, "send_icmp_unreachable", &(user_region->session_para->udp.send_icmp_enable));
		if(user_region->session_para->udp.send_icmp_enable==1)
		{
			user_region->session_para->udp.type=TSG_DENY_TYPE_SEND_ICMP;
		}
		else
		{					
			user_region->session_para->udp.type=TSG_DENY_TYPE_DEFAULT_DROP;
		}
	}

	return 1;
}


static int parse_packet_capture(cJSON *packet_capture_object, struct compile_user_region *user_region)
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

static int parse_packet_mirrored(cJSON *user_region_object, struct compile_user_region *user_region)
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
			ret=get_integer_from_json(deny_user_region_object, "send_icmp_unreachable", &(user_region->deny->send_icmp_enable));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_SEND_ICMP;
				break;
			}
            break;
		case	TSG_METHOD_TYPE_RST:
		case	TSG_METHOD_TYPE_RESET:
			break;
        case    TSG_METHOD_TYPE_TAMPER:
            break;
		default:			
			parse_default_para(deny_user_region_object, user_region);
			break;
	}
	
	return user_region;
}

void security_compile_new(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp)
{	
	cJSON *user_region_object=NULL;	
	cJSON *packet_capture_object=NULL;
	struct compile_user_region *user_region=NULL;
	
	if(rule==NULL)
	{
		return ;
	}
	
	if(srv_def_large!=NULL && strlen(srv_def_large)>2)
	{
		user_region_object=cJSON_Parse(srv_def_large);
		if(user_region_object!=NULL)
		{			
			packet_capture_object=cJSON_GetObjectItem(user_region_object, "packet_capture");

			switch(rule->action)
			{
				case	TSG_ACTION_DENY:
					user_region=parse_deny_user_region(user_region_object);					
					parse_packet_capture(packet_capture_object, user_region);
					parse_packet_mirrored(user_region_object,user_region);
					atomic_inc(&user_region->ref_cnt);
					break;
				case	TSG_ACTION_MONITOR:
					user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));
					parse_packet_capture(packet_capture_object, user_region);					
					parse_packet_mirrored(user_region_object,user_region);
					atomic_inc(&user_region->ref_cnt);
					break; 
				default:
					break;
			}

			cJSON_Delete(user_region_object);
			user_region_object=NULL;
		}
	}

	if(g_tsg_para.default_compile_id==rule->config_id && user_region!=NULL)
	{
		if(user_region->method_type==TSG_METHOD_TYPE_DEFAULT && user_region->session_para!=NULL)
		{
			memcpy(&(user_region->session_para->result), rule, sizeof(struct Maat_rule_t));
		}
	}

	*ad=(MAAT_RULE_EX_DATA)user_region;

	return ;
}

void security_compile_dup(int idx, MAAT_RULE_EX_DATA *to, MAAT_RULE_EX_DATA *from, long argl, void *argp)
{
	struct compile_user_region *user_region=(struct compile_user_region *)(*from);
	if(user_region!=NULL)
	{
		atomic_inc(&user_region->ref_cnt);
		*to=*from;
	}
}

static void free_dns_records_val(struct dns_record_val *record_val, int record_val_num)
{
	int i=0;
	for(i=0; i<record_val_num; i++)
	{
		_free_field(record_val[i].cname);
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

		_free_field((char *)answer_records);
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
			_free_field(deny->message);
			deny->message=NULL;
			break;
		case	TSG_DENY_TYPE_REDIRECT_RECORD:
			free_dns_answer_records(deny->records->a);
			free_dns_answer_records(deny->records->aaaa);
			free_dns_answer_records(deny->records->cname);
			_free_field(deny->message);
			deny->message=NULL;
			break;
		default:
			break;
	}

}

void security_compile_free(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp)
{
	struct compile_user_region *user_region=(struct compile_user_region *)(*ad);
	if(user_region==NULL)
	{
		return ;
	}
	
	if((__sync_sub_and_fetch(&user_region->ref_cnt, 1) == 0))
	{
		switch(user_region->method_type)
		{
			case	TSG_METHOD_TYPE_ALERT:
			case	TSG_METHOD_TYPE_BLOCK:
			case	TSG_METHOD_TYPE_RATE_LIMIT:
			case	TSG_METHOD_TYPE_REDIRECTION:
				free_deny_user_region(user_region->deny);
				break;
			default:
				break;
		}
		
		if(user_region->user_region_para!=NULL)
		{
			_free_field((char *)(user_region->user_region_para));
			user_region->user_region_para=NULL;
		}
		
		_free_field((char *)(*ad));
		*ad=NULL;
	}
		
}

static char *get_pages_content(const char *filename, int *filelen)
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


void http_response_pages_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	if((*from)!=NULL)
	{
		struct http_response_pages *res_pages=(struct http_response_pages *)(*from);
		*to=*from;
		atomic_inc(&res_pages->ref_cnt);
	}
}

void http_response_pages_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	char *path=NULL, *format=NULL;
	struct http_response_pages *res_pages=(struct http_response_pages *)calloc(1, sizeof(struct http_response_pages));
	res_pages->profile_id=tsg_get_column_integer_value(table_line, 1);

	format=tsg_get_column_string_value(table_line, 3);
	path=tsg_get_column_string_value(table_line, 4);

	if(format==NULL && path==NULL)
	{
		_free_field((char *)res_pages);
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

	_free_field(format);
	format=NULL;
	
	res_pages->content=get_pages_content(path, &res_pages->content_len);
	_free_field(path);
	path=NULL;
	
	if(res_pages->content!=NULL && res_pages->content_len>0)
	{		
		atomic_inc(&res_pages->ref_cnt);
		*ad=(MAAT_PLUGIN_EX_DATA)res_pages;
	}
	else
	{
		_free_field(res_pages->content);
		_free_field((char *)res_pages);
		res_pages=NULL;
	}
}

void http_response_pages_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	if((*ad)!=NULL)
	{
		struct http_response_pages *res_pages=(struct http_response_pages *)(*ad);
		if((__sync_sub_and_fetch(&res_pages->ref_cnt, 1) == 0))
		{
			_free_field(res_pages->content);
			_free_field((char *)(*ad));
			*ad=NULL;	
		}
	}
}

void dns_profile_records_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0;
	cJSON *one_record=NULL,*pSub=NULL;
	struct dns_profile_records *profile_records=(struct dns_profile_records *)calloc(1, sizeof(struct dns_profile_records));
	profile_records->record_id=tsg_get_column_integer_value(table_line, 1);
	char *answer_type=tsg_get_column_string_value(table_line, 3);
	char *json_record=tsg_get_column_string_value(table_line, 4);

	cJSON *records_array=cJSON_Parse(json_record);	
	if(records_array!=NULL)
	{
		profile_records->record_num=cJSON_GetArraySize(records_array);
		profile_records->record_val=(struct dns_record_val *)calloc(1, profile_records->record_num*sizeof(struct dns_record_val));		
		profile_records->answer_type=get_dns_qtype(answer_type, strlen(answer_type));

		for(i=0; i<profile_records->record_num; i++)
		{
			one_record=cJSON_GetArrayItem(records_array, i);
			if(one_record==NULL)
			{
				continue;
			}
			
			pSub=cJSON_GetObjectItem(one_record, "value");
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
		(*ad)=(MAAT_PLUGIN_EX_DATA)profile_records;

		cJSON_Delete(records_array);
		records_array=NULL;

		_free_field(json_record);
		json_record=NULL;

		_free_field(answer_type);
		answer_type=NULL;
	}
	else
	{		
		_free_field((char *)profile_records);
		profile_records=NULL;
	}

	return ;
}

void dns_profile_records_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct dns_profile_records *profile_records=(struct dns_profile_records *)(*from);
		atomic_inc(&profile_records->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

void dns_profile_records_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
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
			
			_free_field((char *)(profile_records->record_val));
			profile_records->record_val=NULL;
			
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
}

void mirrored_profile_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	int i=0,vlan_id_num=0;
	cJSON *one_vlan=NULL;
	struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)calloc(1, sizeof(struct traffic_mirror_profile));
	
	mirror_profile->profile_id=tsg_get_column_integer_value(table_line, 1);
	char *vlan_ids_str=tsg_get_column_string_value(table_line, 3);
	
	cJSON *vlan_ids_object=cJSON_Parse(vlan_ids_str);	
	if(vlan_ids_object!=NULL)
	{
		vlan_id_num=cJSON_GetArraySize(vlan_ids_object);
		for(i=0; i<vlan_id_num; i++)
		{
			one_vlan=cJSON_GetArrayItem(vlan_ids_object, i);
			if(one_vlan==NULL)
			{
				continue;
			}

			mirror_profile->vlan.id[mirror_profile->vlan.num++]=one_vlan->valueint;
		}
	}

	atomic_inc(&mirror_profile->ref_cnt);

	*ad=(MAAT_PLUGIN_EX_DATA)mirror_profile;
	
	cJSON_Delete(vlan_ids_object);
	vlan_ids_object=NULL;

	_free_field(vlan_ids_str);
	vlan_ids_str=NULL;

	return ;
}

void mirrored_profile_dup(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void *argp)
{
	if((*from)!=NULL)
	{
		struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)(*from);
		atomic_inc(&mirror_profile->ref_cnt);
		(*to)=(*from);
	}

	return ;
}

void mirrored_profile_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void *argp)
{
	if((*ad)!=NULL)
	{
		struct traffic_mirror_profile *mirror_profile=(struct traffic_mirror_profile *)*ad;
		if((__sync_sub_and_fetch(&mirror_profile->ref_cnt, 1) == 0))
		{	
			_free_field((char *)(*ad));
			*ad=NULL;
		}
	}
}

static int get_fqdn_category_id(Maat_feather_t maat_feather, int table_id, char *fqdn, unsigned int *category_id, int category_id_num, void *logger, int thread_seq)
{
	int i=0,j=0,ret=0;	
	struct fqdn_category *ex_data_array[8]={0};

	ret=Maat_fqdn_plugin_get_EX_data(maat_feather, table_id, fqdn, (MAAT_PLUGIN_EX_DATA *)ex_data_array, 8);
	if(ret>0)
	{
		qsort(ex_data_array, ret, sizeof(struct fqdn_category *), sort_category_id);
		
		for(i=0; i<ret; i++)
		{
			if(j==0)
			{
				category_id[j++]=ex_data_array[i]->category_id;
			}
			else
			{
				if(j<category_id_num && ex_data_array[i]->category_id!=category_id[j-1])
				{
					category_id[j++]=ex_data_array[i]->category_id;
				}
			}
			
			fqdn_category_free(table_id, (MAAT_PLUGIN_EX_DATA *)&(ex_data_array[i]), 0, logger);
		}

		return j;
	}

	return 0;
}

static Maat_feather_t init_maat_feather(const char* conffile, char* instance_name, char *module, void *maat_logger)
{
	int redis_index=0;
	unsigned short redis_port=0;
	int ret=0,scan_detail=0,effect_interval=60;
	Maat_feather_t _maat_feather=NULL;
	char redis_port_range[256]={0};
	char effective_tag_key[128]={0};
	char effective_range_filename[1024]={0};
	char redis_ip[16]={0}, effective_flag[1024]={0};
	int output_prometheus=0;
	int maat_mode=0,maat_stat_on=0,maat_perf_on=0,thread_max=0;
	char json_cfg_file[MAX_PATH_LEN]={0},maat_stat_file[MAX_PATH_LEN]={0};
	char table_info[MAX_PATH_LEN]={0},inc_cfg_dir[MAX_PATH_LEN]={0},ful_cfg_dir[MAX_PATH_LEN]={0};

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

	if(strlen(g_tsg_para.device_tag)==0 && strlen(effective_flag)>0)
	{
		memcpy(g_tsg_para.device_tag, effective_flag, MIN(strlen(effective_flag), sizeof(g_tsg_para.device_tag)-1));
	}

	if(strlen(g_tsg_para.data_center)==0 && strlen(effective_flag)>0)
	{
		MESA_load_profile_string_def(conffile, module, "EFFECTIVE_TAG_KEY", effective_tag_key, sizeof(effective_tag_key),"data_center");
		get_data_center(effective_flag, effective_tag_key, g_tsg_para.data_center, sizeof(g_tsg_para.data_center));
	}
	
	MESA_load_profile_int_def(conffile, module,"MAAT_MODE", &(maat_mode),0);
	MESA_load_profile_int_def(conffile, module,"STAT_SWITCH", &(maat_stat_on),1);
	MESA_load_profile_int_def(conffile, module,"PERF_SWITCH", &(maat_perf_on),1);
	MESA_load_profile_int_def(conffile, module,"OUTPUT_PROMETHEUS", &(output_prometheus), 1);

	MESA_load_profile_string_def(conffile,module,"TABLE_INFO",table_info, sizeof(table_info), "");
	MESA_load_profile_string_def(conffile,module,"STAT_FILE",maat_stat_file, sizeof(maat_stat_file), "");
	MESA_load_profile_int_def(conffile, module,"EFFECT_INTERVAL_S", &(effect_interval), 60);
	effect_interval*=1000;//convert s to ms

	thread_max=get_thread_count();
	_maat_feather=Maat_feather(thread_max, table_info, maat_logger);
	
	if(maat_mode==2)
	{
		MESA_load_profile_string_def(conffile,module,"REDIS_IP", redis_ip, sizeof(redis_ip),"");
		MESA_load_profile_int_def(conffile, module,"REDIS_INDEX", &redis_index, 0);
		MESA_load_profile_string_def(conffile,module,"REDIS_PORT", redis_port_range, sizeof(redis_port_range), "6379;");
		redis_port=get_redis_port(redis_port_range);
		
		if(strlen(effective_flag)!=0)
		{
			Maat_set_feather_opt(_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
		}
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_EFFECT_INVERVAL_MS, &effect_interval, sizeof(effect_interval));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_IP, redis_ip, strlen(redis_ip)+1);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_PORT, (void *)&redis_port, sizeof(redis_port));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_FILE_PATH, maat_stat_file, strlen(maat_stat_file)+1);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STAT_ON, NULL, 0);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_PERF_ON, NULL, 0);
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_REDIS_INDEX, &redis_index, sizeof(redis_index));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_SCAN_DETAIL, &scan_detail, sizeof(scan_detail));
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_FOREIGN_CONT_DIR, "./alerts_files", strlen("./alerts_files")+1);		
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_INSTANCE_NAME,instance_name, strlen(instance_name)+1);		
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STATUS_OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));
	}
	else
	{
		if(strlen(effective_flag)!=0)
		{
			ret=Maat_set_feather_opt(_maat_feather,MAAT_OPT_ACCEPT_TAGS,effective_flag, strlen(effective_flag)+1);
			assert(ret>=0);
		}
		else
		{
			MESA_handle_runtime_log(maat_logger, RLOG_LV_FATAL, "EFFECTIVE_RANGE", "Effective range is empty, please check %s", effective_range_filename);
		}
		Maat_set_feather_opt(_maat_feather,MAAT_OPT_INSTANCE_NAME,instance_name, strlen(instance_name)+1);		
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_STATUS_OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));
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
	int log_level=30;
	char log_path[128]={0};
	char maat_conffile[256]={0};
	char cb_subscriber_ip_table[32]={0};
	
	MESA_load_profile_int_def(conffile, "MAAT","APP_ID_TABLE_TYPE", &g_tsg_para.app_dict_field_num, 18);
	MESA_load_profile_int_def(conffile, "MAAT","LOCATION_TABLE_TYPE", &g_tsg_para.location_field_num, 18);

	MESA_load_profile_string_def(conffile, "MAAT", "PROFILE", maat_conffile, sizeof(maat_conffile), "./tsgconf/maat.conf");		
	MESA_load_profile_string_def(conffile, "MAAT", "SECURITY_COMPILE", g_tsg_para.table_name[TABLE_SECURITY_COMPILE], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_COMPILE");
	MESA_load_profile_string_def(conffile, "MAAT", "IP_ADDR_TABLE", g_tsg_para.table_name[TABLE_IP_ADDR], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_ADDR");
	MESA_load_profile_string_def(conffile, "MAAT", "SUBSCRIBER_ID_TABLE", g_tsg_para.table_name[TABLE_SUBSCRIBER_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_SUBSCRIBER_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_TABLE", g_tsg_para.table_name[TABLE_APP_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_APP_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "HTTP_HOST_TABLE", g_tsg_para.table_name[TABLE_HTTP_HOST], _MAX_TABLE_NAME_LEN, "TSG_FIELD_HTTP_HOST");
	MESA_load_profile_string_def(conffile, "MAAT", "SSL_SNI_TABLE", g_tsg_para.table_name[TABLE_SSL_SNI], _MAX_TABLE_NAME_LEN, "TSG_FIELD_SSL_SNI");
	MESA_load_profile_string_def(conffile, "MAAT", "DECYPTION_EXCLUSION_SSL_SNI", g_tsg_para.table_name[TABLE_EXCLUSION_SSL_SNI], _MAX_TABLE_NAME_LEN, "TSG_DECYPTION_EXCLUSION_SSL_SNI");

	MESA_load_profile_string_def(conffile, "MAAT", "SRC_ASN_TABLE", g_tsg_para.table_name[TABLE_SRC_ASN], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_SOURCE_ASN");
	MESA_load_profile_string_def(conffile, "MAAT", "DST_ASN_TABLE", g_tsg_para.table_name[TABLE_DST_ASN], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_DESTINATION_ASN");
	MESA_load_profile_string_def(conffile, "MAAT", "SRC_LOCATION_TABLE", g_tsg_para.table_name[TABLE_SRC_LOCATION], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_SOURCE_LOCATION");
	MESA_load_profile_string_def(conffile, "MAAT", "DST_LOCATION_TABLE", g_tsg_para.table_name[TABLE_DST_LOCATION], _MAX_TABLE_NAME_LEN, "TSG_SECURITY_DESTINATION_LOCATION");
	
	MESA_load_profile_string_def(conffile, "MAAT", "ASN_BUILT_IN_TABLE", g_tsg_para.table_name[TABLE_ASN_BUILT_IN], _MAX_TABLE_NAME_LEN, "TSG_IP_ASN_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "ASN_USER_DEFINED_TABLE", g_tsg_para.table_name[TABLE_ASN_USER_DEFINED], _MAX_TABLE_NAME_LEN, "TSG_IP_ASN_USER_DEFINED");
	MESA_load_profile_string_def(conffile, "MAAT", "LOCATION_BUILT_IN_TABLE", g_tsg_para.table_name[TABLE_LOCATION_BUILT_IN], _MAX_TABLE_NAME_LEN, "TSG_IP_LOCATION_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "LOCATION_USER_DEFINED_TABLE", g_tsg_para.table_name[TABLE_LOCATION_USER_DEFINED], _MAX_TABLE_NAME_LEN, "TSG_IP_LOCATION_USER_DEFINED");

	MESA_load_profile_string_def(conffile, "MAAT", "QUIC_SNI_TABLE", g_tsg_para.table_name[TABLE_QUIC_SNI], _MAX_TABLE_NAME_LEN, "TSG_FIELD_QUIC_SNI");

	MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_ID_TABLE", g_tsg_para.table_name[TABLE_FQDN_CAT_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_FQDN_CAT");
	MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_BUILT_IN_TABLE", g_tsg_para.table_name[TABLE_FQDN_CAT_BUILT_IN], _MAX_TABLE_NAME_LEN, "TSG_FQDN_CATEGORY_BUILT_IN");
	MESA_load_profile_string_def(conffile, "MAAT", "FQDN_CAT_USER_DEFINED_TABLE", g_tsg_para.table_name[TABLE_FQDN_CAT_USER_DEFINED], _MAX_TABLE_NAME_LEN, "TSG_FQDN_CATEGORY_USER_DEFINED");

	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_DICT_TABLE", g_tsg_para.table_name[TABLE_APP_ID_DICT], _MAX_TABLE_NAME_LEN, "APP_ID_DICT");
	MESA_load_profile_string_def(conffile, "MAAT", "APP_ID_TABLE", g_tsg_para.table_name[TABLE_APP_ID], _MAX_TABLE_NAME_LEN, "TSG_OBJ_APP_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "SELECTOR_ID_TABLE", g_tsg_para.table_name[TABLE_SELECTOR_ID], _MAX_TABLE_NAME_LEN, "APP_SELECTOR_ID");
	MESA_load_profile_string_def(conffile, "MAAT", "SELECTOR_PROPERTIES_TABLE", g_tsg_para.table_name[TABLE_SELECTOR_PROPERTIES], _MAX_TABLE_NAME_LEN, "APP_SELECTOR_PROPERTIES");

	MESA_load_profile_string_def(conffile, "MAAT", "GTP_APN", g_tsg_para.table_name[TABLE_GTP_APN], _MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_APN");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_IMSI", g_tsg_para.table_name[TABLE_GTP_IMSI], _MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_IMSI");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_PHONE_NUMBER", g_tsg_para.table_name[TABLE_GTP_PHONE_NUMBER], _MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_PHONE_NUMBER");
	MESA_load_profile_string_def(conffile, "MAAT", "GTP_PHONE_NUMBER", g_tsg_para.table_name[TABLE_GTP_PHONE_NUMBER], _MAX_TABLE_NAME_LEN, "TSG_FILED_GTP_PHONE_NUMBER");
	MESA_load_profile_string_def(conffile, "MAAT", "RESPONSE_PAGES_TABLE", g_tsg_para.table_name[TABLE_RESPONSE_PAGES], _MAX_TABLE_NAME_LEN, "TSG_PROFILE_RESPONSE_PAGES");
	MESA_load_profile_string_def(conffile, "MAAT", "DNS_PROFILE_RECORDS", g_tsg_para.table_name[TABLE_DNS_PROFILE_RECORD], _MAX_TABLE_NAME_LEN, (char *)"TSG_PROFILE_DNS_RECORDS");
	MESA_load_profile_string_def(conffile, "MAAT", "TRAFFIC_MIRROR_PROFILE", g_tsg_para.table_name[TABLE_PROFILE_MIRROR], _MAX_TABLE_NAME_LEN, (char *)"TSG_PROFILE_TRAFFIC_MIRROR");

	MESA_load_profile_int_def(conffile, "MAAT","LOG_LEVEL", &log_level, 30);
	MESA_load_profile_string_def(conffile, "MAAT", "LOG_PATH", log_path, sizeof(log_path), "./tsglog/maat/tsg_maat.log");
	g_tsg_para.maat_logger=MESA_create_runtime_log_handle(log_path, log_level);
	if(g_tsg_para.maat_logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ...\n");
		return -1;
	}

	//init static maat feather
	g_tsg_maat_feather=init_maat_feather(maat_conffile, (char *)"TSG_STATIC", (char *)"STATIC", g_tsg_para.maat_logger);
	if(g_tsg_maat_feather==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL, "init_maat_feather failed, instance_name: %s module: %s", "TSG_STATIC", "STATIC"); 
		return -1;
	}

	g_tsg_para.table_id[TABLE_SECURITY_COMPILE]=Maat_rule_get_ex_new_index(g_tsg_maat_feather,
																g_tsg_para.table_name[TABLE_SECURITY_COMPILE],
																security_compile_new,
																security_compile_free,
																security_compile_dup,
																0,
																g_tsg_para.maat_logger
															);
	
	if(g_tsg_para.table_id[TABLE_SECURITY_COMPILE]<0)
	{
		
		MESA_handle_runtime_log(g_tsg_para.maat_logger,	RLOG_LV_FATAL, "REGISTER_TABLE", "Register table: %s failed ...", g_tsg_para.table_name[TABLE_SECURITY_COMPILE]);		
		return -1;
	}

	for(i=TABLE_IP_ADDR; i<TABLE_MAX; i++)
	{
		g_tsg_para.table_id[i]=Maat_table_register(g_tsg_maat_feather, g_tsg_para.table_name[i]);
		if(g_tsg_para.table_id[i]<0)
		{
			MESA_handle_runtime_log(g_tsg_para.maat_logger,
									RLOG_LV_FATAL,
									"Maat_table_register %s failed, Please check tsgconf/tsg_static_tableinfo.conf",
									g_tsg_para.table_name[i]
									); 
			return -1;
		}
	}

	for(i=TABLE_ASN_USER_DEFINED; i<=TABLE_ASN_BUILT_IN; i++)
	{
		ret=Maat_ip_plugin_EX_register(g_tsg_maat_feather,
									g_tsg_para.table_id[i],
									ASN_number_new,
									ASN_number_free,
									ASN_number_dup,
									0,
									g_tsg_para.maat_logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL,
										"RULE_INIT",
										"Maat_ip_plugin_EX_register failed, table_name: %s table_id: %d",
										g_tsg_para.table_name[i],
										g_tsg_para.table_id[i]
									); 
			return -1;		
		}
	}


	for(i=TABLE_LOCATION_USER_DEFINED; i<=TABLE_LOCATION_BUILT_IN; i++)
	{
		ret=Maat_ip_plugin_EX_register(g_tsg_maat_feather,
									g_tsg_para.table_id[i],
									location_new_data,
									location_free_data,
									location_dup_data,
									0,
									g_tsg_para.maat_logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL,
										"RULE_INIT",
										"Maat_ip_plugin_EX_register failed, table_name: %s table_id: %d",
										g_tsg_para.table_name[i],
										g_tsg_para.table_id[i]
									); 
			return -1;		
		}
	}

	for(i=TABLE_FQDN_CAT_USER_DEFINED; i<=TABLE_FQDN_CAT_BUILT_IN; i++)
	{
		ret=Maat_fqdn_plugin_EX_register(g_tsg_maat_feather,
										g_tsg_para.table_id[i],
										fqdn_category_new,
										fqdn_category_free,
										fqdn_category_dup,
										0,
										g_tsg_para.maat_logger
									);
		if(ret<0)
		{
			MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL,
										"RULE_INIT",
										"Maat_ip_plugin_EX_register failed, table_name: %s table_id: %d",
										g_tsg_para.table_name[i],
										g_tsg_para.table_id[i]
									); 
			return -1;		
		}
	}

	ret=Maat_plugin_EX_register(g_tsg_maat_feather,
									g_tsg_para.table_id[TABLE_APP_ID_DICT],
									app_id_dict_new,
									app_id_dict_free,
									app_id_dict_dup,
									NULL,
									0,
									g_tsg_para.maat_logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL,
									"RULE_INIT",
									"Maat_ip_plugin_EX_register failed, table_name: %s table_id: %d",
									g_tsg_para.table_name[TABLE_APP_ID_DICT],
									g_tsg_para.table_id[TABLE_APP_ID_DICT]
								); 
		return -1;		
	}
	
	ret=Maat_plugin_EX_register(g_tsg_maat_feather,
							g_tsg_para.table_id[TABLE_RESPONSE_PAGES],
							http_response_pages_new,
							http_response_pages_free,
							http_response_pages_dup,
							NULL,
							0,
							g_tsg_para.maat_logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, 
								RLOG_LV_FATAL,
								"RESPONSE_PAGES",
								"Maat_plugin_EX_register failed, table_name: %s table_id: %d",
								g_tsg_para.table_name[TABLE_RESPONSE_PAGES],
								g_tsg_para.table_id[TABLE_RESPONSE_PAGES]); 
		return -1;		
	}

	ret=Maat_plugin_EX_register(g_tsg_maat_feather,
								g_tsg_para.table_id[TABLE_DNS_PROFILE_RECORD],
								dns_profile_records_new,
								dns_profile_records_free,
								dns_profile_records_dup,
								NULL,
								0, 
								NULL);

	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_plugin_EX_register failed, table_name: %s", g_tsg_para.table_name[TABLE_DNS_PROFILE_RECORD]);
		return -1;
	}

	ret=Maat_plugin_EX_register(g_tsg_maat_feather,
								g_tsg_para.table_id[TABLE_PROFILE_MIRROR],
								mirrored_profile_new,
								mirrored_profile_free,
								mirrored_profile_dup,
								NULL,
								0, 
								NULL);

	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL, "REGISTER_TABLE", "Maat_plugin_EX_register failed, table_name: %s", g_tsg_para.table_name[TABLE_PROFILE_MIRROR]);
		return -1;
	}

	//init dynamic maat feather	
	MESA_load_profile_int_def(conffile, "MAAT", "DYNAMIC_MAAT_SWITCH", &g_tsg_para.dynamic_maat_switch, 0);
	if(g_tsg_para.dynamic_maat_switch==1)
	{
		g_tsg_dynamic_maat_feather=init_maat_feather(maat_conffile, (char *)"TSG_DYNAMIC", (char *)"DYNAMIC", logger);
		if(g_tsg_maat_feather==NULL)
		{
			MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL, "init_maat_feather failed, instance_name: %s module: %s", "TSG_DYNAMIC", "DYNAMIC"); 
			return -1;
		}
	}
	else
	{
		g_tsg_dynamic_maat_feather=g_tsg_maat_feather;
	}
	
	MESA_load_profile_string_def(conffile, "MAAT", "CB_SUBSCRIBER_IP_TABLE", cb_subscriber_ip_table, sizeof(cb_subscriber_ip_table), "TSG_DYN_SUBSCRIBER_IP");

	g_tsg_para.dyn_subscribe_ip_table_id=Maat_table_register(g_tsg_dynamic_maat_feather, cb_subscriber_ip_table);
	if(g_tsg_para.dyn_subscribe_ip_table_id<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger,
								RLOG_LV_FATAL,
								"RULE_INIT",
								"Maat_table_register %s failed, Please check tsgconf/tsg_static_tableinfo.conf",
								cb_subscriber_ip_table
								); 
		return -1;
	}
	ret=Maat_plugin_EX_register(g_tsg_dynamic_maat_feather,
							g_tsg_para.dyn_subscribe_ip_table_id,
							subscriber_id_new,
							subscriber_id_free,
							subscriber_id_dup,
							NULL,
							0,
							g_tsg_para.maat_logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.maat_logger, RLOG_LV_FATAL, "RULE_INIT", "Maat_plugin_EX_register failed, table_name: %s table_id: %d", cb_subscriber_ip_table, g_tsg_para.dyn_subscribe_ip_table_id); 
		return -1;		
	}

	return 0;
}

int tsg_pull_policy_result(struct streaminfo *a_stream, PULL_RESULT_TYPE pull_result_type, Maat_rule_t*result, int result_num, struct identify_info *identify_info)
{
	int num=0;
	struct policy_priority_label *label=NULL;

	label=(struct policy_priority_label *)project_req_get_struct(a_stream, g_tsg_para.priority_project_id);
	if(label!=NULL && result!=NULL && result_num>0 && identify_info!=NULL)
	{
		if((label->result_type==pull_result_type) || (pull_result_type==PULL_ALL_RESULT))
		{
			num=MIN(label->result_num, result_num);
			memcpy(result, label->result, num*sizeof(Maat_rule_t));

			if(label->domain_len>0)
			{
				memcpy(identify_info->domain, label->domain, label->domain_len);
				identify_info->domain_len=label->domain_len;
			}
			
			identify_info->proto = label->proto;
			
			return num;
		}
	}

	return 0;
}

int tsg_get_ip_asn(const struct streaminfo *a_stream, int table_id, MAAT_PLUGIN_EX_DATA* client_asn, MAAT_PLUGIN_EX_DATA* server_asn)
{
	struct ip_address dest_ip={0}, source_ip={0};
	
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
			source_ip.ip_type=4;
			source_ip.ipv4=a_stream->addr.tuple4_v4->saddr;
			
			dest_ip.ip_type=4;
			dest_ip.ipv4=a_stream->addr.tuple4_v4->daddr;
			break;
		case	ADDR_TYPE_IPV6:
			source_ip.ip_type=6;
			memcpy((char *)(source_ip.ipv6), a_stream->addr.tuple4_v6->saddr, IPV6_ADDR_LEN);
			
			dest_ip.ip_type=6;
			memcpy((char *)(dest_ip.ipv6), a_stream->addr.tuple4_v6->daddr, IPV6_ADDR_LEN);
			break;
		default:
			return 0;
			break;
	}

	if(*client_asn==NULL)
	{
		Maat_ip_plugin_get_EX_data(g_tsg_maat_feather, table_id, &source_ip, client_asn, 1);
	}

	if(*server_asn==NULL)
	{
		Maat_ip_plugin_get_EX_data(g_tsg_maat_feather, table_id, &dest_ip, server_asn, 1);
	}
	
	return 0;
}


int tsg_get_ip_location(const struct streaminfo *a_stream, int table_id, MAAT_PLUGIN_EX_DATA *client_location, MAAT_PLUGIN_EX_DATA *server_location)
{
	struct ip_address dest_ip={0}, source_ip={0};
	
	switch(a_stream->addr.addrtype)
	{
		case	ADDR_TYPE_IPV4:
			source_ip.ip_type=4;
			source_ip.ipv4=a_stream->addr.tuple4_v4->saddr;
			
			dest_ip.ip_type=4;
			dest_ip.ipv4=a_stream->addr.tuple4_v4->daddr;
			break;
		case	ADDR_TYPE_IPV6:
			source_ip.ip_type=6;
			memcpy((char *)(source_ip.ipv6), a_stream->addr.tuple4_v6->saddr, IPV6_ADDR_LEN);
			
			dest_ip.ip_type=6;
			memcpy((char *)(dest_ip.ipv6), a_stream->addr.tuple4_v6->daddr, IPV6_ADDR_LEN);
			break;
		default:
			return 0;
			break;
	}

	if(*client_location==NULL)
	{
		Maat_ip_plugin_get_EX_data(g_tsg_maat_feather, table_id, &source_ip, client_location, 1);
	}
	if(*server_location==NULL)
	{
		Maat_ip_plugin_get_EX_data(g_tsg_maat_feather, table_id, &dest_ip, server_location, 1);
	}
	
	return 0;
}

int tsg_get_subscribe_id(const struct streaminfo *a_stream, struct subscribe_id_info **source_subscribe_id, struct subscribe_id_info **dest_subscribe_id)
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

	if(strlen(dest_ip)>0 && *dest_subscribe_id==NULL)
	{
		*dest_subscribe_id = (struct subscribe_id_info *)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, dest_ip);
	}

	if(strlen(source_ip)>0 && *source_subscribe_id==NULL)
	{
		*source_subscribe_id = (struct subscribe_id_info *)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, source_ip);
	}

	return 0;
}

int tsg_scan_ip_asn(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct asn_info *asn, enum MASTER_TABLE idx, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;

	if(asn==NULL || asn->asn_id==NULL|| result==NULL || result_num==0)
	{
		return 0;
	}

	ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[idx], CHARSET_GBK, asn->asn_id, strlen(asn->asn_id), result, NULL, result_num, mid, a_stream->threadnum);
	if(ret > 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_ASN",
									"Hit IP_ASN: %s scan ret: %d table_name: %s policy_id: %d service: %d action: %d addr: %s",
									asn->asn_id,
									ret,
									g_tsg_para.table_name[idx],
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return ret;
	}

	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IP_ASN",
								"No hit IP_ASN: %s scan ret: %d table_name: %s addr: %s",
								asn->asn_id,
								ret,
								g_tsg_para.table_name[idx],
								PRINTADDR(a_stream, g_tsg_para.level)
							);
	return 0;
}


int tsg_scan_ip_location(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct location_info *location, enum MASTER_TABLE idx, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;
	char full_address[1024]={0};

	if(location==NULL || result==NULL || result_num==0)
	{
		return 0;
	}

	if(g_tsg_para.location_field_num==19)
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
	
	ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[idx], CHARSET_GBK, full_address, strlen(full_address), result, NULL, result_num, mid, a_stream->threadnum);
	if(ret > 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_LOCATION",
									"Hit IP_LOCATION: %s scan ret: %d table_name: %s policy_id: %d service: %d action: %d addr: %s",
									full_address,
									ret,
									g_tsg_para.table_name[idx],
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);
		return ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_IP_LOCATION",
								"No hit IP_LOCATION: %s scan ret: %d table_name: %s addr: %s",
								full_address,
								ret,
								g_tsg_para.table_name[idx],
								PRINTADDR(a_stream, g_tsg_para.level)
							);
	
	return 0;
}


static unsigned short get_trans_protocol(const struct streaminfo *a_stream)
{
	if(a_stream==NULL)
	{
		return 255;
	}
	
	switch(a_stream->type)
	{
		case	STREAM_TYPE_TCP:
			return 6;
			break;
		case	STREAM_TYPE_UDP:
			return 17;
			break;
		default:
			break;
	}

	return 255;
}


int tsg_scan_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int hit_num=0,maat_ret=0;
	unsigned short tans_proto=0;
	unsigned int proto_id=0;
	struct ipaddr t_addr;
	struct ipaddr* p_addr=NULL;	
	const struct streaminfo *cur_stream = a_stream;

	do
	{
		switch(cur_stream->addr.addrtype)
		{
			case	ADDR_TYPE_IPV4:
			case	ADDR_TYPE_IPV6:
			case	__ADDR_TYPE_IP_PAIR_V4:
			case	__ADDR_TYPE_IP_PAIR_V6:
				if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4 ||
					cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V6)
				{
					memcpy(&t_addr, &cur_stream->addr, sizeof(t_addr));
					if(cur_stream->addr.addrtype == __ADDR_TYPE_IP_PAIR_V4)
					{
						t_addr.addrtype = ADDR_TYPE_IPV4;
					}
					else
					{
						t_addr.addrtype = ADDR_TYPE_IPV6;
					}
					p_addr = &t_addr;
				}
				else
				{
					p_addr = (struct ipaddr *)&cur_stream->addr;
				}

				if(p_addr==NULL)
				{
					break;
				}

				tans_proto=get_trans_protocol(cur_stream);
	 			maat_ret=Maat_scan_proto_addr(maat_feather, g_tsg_para.table_id[TABLE_IP_ADDR], p_addr, tans_proto, result+hit_num, result_num-hit_num, mid, (int)cur_stream->threadnum);
				if(maat_ret>0)
				{
					MESA_handle_runtime_log(g_tsg_para.logger,
												RLOG_LV_DEBUG,
												"SCAN_IP",
												"Hit addr: %s scan ret: %d policy_id: %d service: %d action: %d",
												PRINTADDR(a_stream, g_tsg_para.level),
												maat_ret,
												result[hit_num].config_id,
												result[hit_num].service_id,
												(unsigned char)result[hit_num].action
											);

					hit_num+=maat_ret;
				}
				else
				{
					MESA_handle_runtime_log(g_tsg_para.logger,RLOG_LV_DEBUG, "SCAN_IP", "No hit addr: %s scan ret: %d", PRINTADDR(a_stream, g_tsg_para.level), maat_ret);	
				}
				break;
			case	ADDR_TYPE_L2TP:
				proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_L2TP].name);				
				hit_num+=tsg_scan_app_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, g_tsg_proto_name2id[PROTO_L2TP].name, proto_id, (int)a_stream->threadnum);
				break;
			case	ADDR_TYPE_PPTP:
				proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_PPTP].name);
				hit_num+=tsg_scan_app_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, g_tsg_proto_name2id[PROTO_PPTP].name, proto_id, (int)a_stream->threadnum);
				break;
			default:
				break;
		}
		
		cur_stream = cur_stream->pfather;
		
	}while(cur_stream != NULL && hit_num < result_num);

	return hit_num;
}

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;
	unsigned int proto_id=0;
	int hit_num=0;
	struct session_attribute_label *attribute_label=NULL;

	if(result==NULL || result_num<=0 || a_stream==NULL || maat_feather==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_NESTING_ADDR", "result==NULL || result_num<=0 || maat_feather==NULL || a_stream==NULL");
		return -1;
	}

	hit_num+=tsg_scan_addr(maat_feather, a_stream, proto, mid, result+hit_num, result_num-hit_num);

	if(hit_num<result_num && proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[proto].name);
		hit_num+=tsg_scan_app_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, g_tsg_proto_name2id[proto].name, proto_id, (int)a_stream->threadnum);
		if(proto==PROTO_SMTP || proto==PROTO_IMAP || proto==PROTO_POP3)
		{
			proto_id=tsg_l7_protocol_name2id(g_tsg_proto_name2id[PROTO_MAIL].name);
			hit_num+=tsg_scan_app_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid, g_tsg_proto_name2id[PROTO_MAIL].name, proto_id, (int)a_stream->threadnum);
		}
	}

	attribute_label=(struct session_attribute_label *)project_req_get_struct(a_stream, g_tsg_para.session_attribute_project_id);
	if(attribute_label==NULL)
	{
		attribute_label=(struct session_attribute_label *)dictator_malloc(a_stream->threadnum, sizeof(struct session_attribute_label));
		memset(attribute_label, 0, sizeof(struct session_attribute_label));
	}

	if(hit_num<result_num)
	{
		tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_USER_DEFINED], (void **)&(attribute_label->client_location), (void **)&(attribute_label->server_location));
		tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_BUILT_IN], (void **)&(attribute_label->client_location), (void **)&(attribute_label->server_location));
		
		hit_num+=tsg_scan_ip_location(maat_feather, a_stream, attribute_label->client_location, TABLE_SRC_LOCATION, mid, result+hit_num, result_num-hit_num);
		hit_num+=tsg_scan_ip_location(maat_feather, a_stream, attribute_label->server_location, TABLE_DST_LOCATION, mid, result+hit_num, result_num-hit_num);
	}

	if(hit_num<result_num)
	{
		tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_USER_DEFINED], (void **)&(attribute_label->client_asn), (void **)&(attribute_label->server_asn));
		tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_BUILT_IN], (void **)&(attribute_label->client_asn), (void **)&(attribute_label->server_asn));
		
		hit_num+=tsg_scan_ip_asn(maat_feather, a_stream, attribute_label->client_asn, TABLE_SRC_ASN, mid, result+hit_num, result_num-hit_num);
		hit_num+=tsg_scan_ip_asn(maat_feather, a_stream, attribute_label->server_asn, TABLE_DST_ASN, mid, result+hit_num, result_num-hit_num);
	}

	if(hit_num<result_num)
	{
		tsg_get_subscribe_id(a_stream, &attribute_label->client_subscribe_id, &attribute_label->server_subscribe_id);
		hit_num+=tsg_scan_subscribe_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid,attribute_label->client_subscribe_id, (int)a_stream->threadnum);		
		hit_num+=tsg_scan_subscribe_id_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid,attribute_label->server_subscribe_id, (int)a_stream->threadnum);
	}

	if(hit_num<result_num)
	{
		ret=tsg_get_umts_user_info(a_stream, &(attribute_label->user_info));
		if(ret==1 && attribute_label->user_info!=NULL)
		{
			hit_num+=tsg_scan_gtp_apn_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid,attribute_label->user_info->apn, (int)a_stream->threadnum);
			hit_num+=tsg_scan_gtp_imsi_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid,attribute_label->user_info->imsi, (int)a_stream->threadnum);
			hit_num+=tsg_scan_gtp_phone_number_policy(maat_feather, a_stream, result+hit_num, result_num-hit_num, mid,attribute_label->user_info->msisdn, (int)a_stream->threadnum);
		}
	}
	
	ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.session_attribute_project_id, (void *)attribute_label);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "ADD_INTERNAL_LABEL", "Add internal label failed, ret: %d addr: %s", ret, PRINTADDR(a_stream, g_tsg_para.level));
	}

	return hit_num;
}


//return value: -1: failed, 0: not hit, >0: hit count 
int tsg_scan_shared_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, char *domain, Maat_rule_t *result, int result_num,  scan_status_t *mid, int table_id, int thread_seq)
{
	int ret=0,fqdn_len=0;
	
	if(table_id<0 || domain==NULL)
	{
		return 0;
	}

	fqdn_len=get_fqdn_len(domain);
	ret=Maat_full_scan_string(g_tsg_maat_feather, table_id, CHARSET_UTF8, domain, fqdn_len, result, NULL, result_num, mid, thread_seq);
	if(ret>0)
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_HIT_SHARE], 0, FS_OP_ADD, 1);
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_FQDN",
									"Hit %s policy_id: %d service: %d action: %d addr: %s",
									domain,
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_FQDN", "Not hit %s ret: %d stream_dir: %d addr: %s", domain, ret, a_stream->dir, PRINTADDR(a_stream, g_tsg_para.level));
	
	return 0;
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

int tsg_get_fqdn_category_id(Maat_feather_t maat_feather, char *fqdn, unsigned int *category_id, int category_id_num, void *logger, int thread_seq)
{
	int ret=0;

	if(category_id!=NULL && category_id_num>0)
	{
		ret=get_fqdn_category_id(maat_feather, g_tsg_para.table_id[TABLE_FQDN_CAT_USER_DEFINED], fqdn, category_id, category_id_num, logger, thread_seq);
		if(ret>0)
		{
			return ret;
		}

		ret=get_fqdn_category_id(maat_feather, g_tsg_para.table_id[TABLE_FQDN_CAT_BUILT_IN], fqdn, category_id, category_id_num, logger, thread_seq);
		if(ret>0)
		{
			return ret;
		}
	}
	
	return 0;
}

int tsg_scan_fqdn_category_id(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, int table_id, unsigned int *category_id, int category_id_num, int thread_seq)
{
	int i=0,ret=0,hit_num=0;

	if(table_id<0 || result_num<=0 || category_id==NULL || category_id_num <=0)
	{
		return 0;
	}
	
	for(i=0; i<category_id_num; i++)
	{
		ret=Maat_scan_intval(g_tsg_maat_feather, table_id, (unsigned int)category_id[i], result+hit_num, result_num-hit_num, mid, thread_seq);
		if(ret>0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_FQDN_CAT",
									"Hit category_id: %d policy_id: %d service: %d action: %d addr: %s",
									category_id[i],
									result[hit_num].config_id,
									result[hit_num].service_id,
									(unsigned char)result[hit_num].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);
			hit_num+=ret;
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_FQDN_CAT", "Not hit category_id: %d ret: %d addr: %s", category_id[i], ret, PRINTADDR(a_stream, g_tsg_para.level));
		}
	}

	return hit_num;
}


int tsg_scan_app_id_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *name, unsigned int id, int thread_seq)
{
	int ret=0;

	ret=Maat_scan_intval(maat_feather, g_tsg_para.table_id[TABLE_APP_ID], id, result, result_num, mid, thread_seq);
	if(ret>0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, 
									RLOG_LV_DEBUG,
									"SCAN_ID",
									"Hit %s id: %d ret: %d policy_id: %d service: %d action: %d addr: %s",
									name,
									id,
									ret,
									result[0].config_id,
									result[0].service_id,
									result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return ret;
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_ID", "scan %s id: %d ret: %d addr: %s", name, id, ret, PRINTADDR(a_stream, g_tsg_para.level));
	
	return 0;
}

int tsg_scan_app_properties_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *property, char *district, int thread_seq)
{
	int i=0,ret=0;
	int ret2=0, hit_num=0;
	struct Maat_rule_t property_result[MAX_RESULT_NUM]={0};
	
	if(property!=NULL && district!=NULL)
	{
		Maat_set_scan_status(g_tsg_maat_feather, mid, MAAT_SET_SCAN_DISTRICT, (void *)district, strlen(district));
		ret=Maat_full_scan_string(g_tsg_maat_feather, 
									g_tsg_para.table_id[TABLE_SELECTOR_PROPERTIES],
									CHARSET_UTF8,
									property,
									strlen(property),
									property_result, 
									NULL,
									MAX_RESULT_NUM,
									mid,
									thread_seq
								);
		for(i=0; i<ret; i++)
		{
			ret2=Maat_scan_intval(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_SELECTOR_ID], property_result[i].config_id, result+hit_num, result_num-hit_num, mid, thread_seq);
			if(ret2>0)
			{
				MESA_handle_runtime_log(g_tsg_para.logger, 
										RLOG_LV_DEBUG,
										"SCAN_ID",
										"Hit selector_id: %d ret: %d policy_id: %d service: %d action: %d addr: %s",
										property_result[i].config_id,
										ret2,
										result[hit_num].config_id,
										result[hit_num].service_id,
										result[hit_num].action,
										PRINTADDR(a_stream, g_tsg_para.level)
									);
				
				hit_num+=ret2;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_ID","Hit %s selector_id: %d ret: %d addr: %s", 
												property, property_result[i].config_id, ret2,PRINTADDR(a_stream, g_tsg_para.level));
			}
		}

		MESA_handle_runtime_log(g_tsg_para.logger, 	RLOG_LV_DEBUG, "SCAN_PROPERTY", "scan %s: %s ret: %d addr: %s", district, property, ret, PRINTADDR(a_stream, g_tsg_para.level));
	}

	return hit_num;
}

int tsg_scan_subscribe_id_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, struct subscribe_id_info *user_info, int thread_seq)
{
	int maat_ret=0;

	if(user_info==NULL || user_info->subscribe_id==NULL || result==NULL || result_num==0)
	{
		return 0;
	}
	
	maat_ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[TABLE_SUBSCRIBER_ID], CHARSET_GBK, user_info->subscribe_id, strlen(user_info->subscribe_id), result, NULL,	result_num, mid, thread_seq);
	if(maat_ret>0)
	{				
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_SUBSCRIBER",
									"Hit source subscribe id: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
									user_info->subscribe_id,
									maat_ret,
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return maat_ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_SUBSCRIBER", "No hit source subscribe id: %s scan ret: %d addr: %s", user_info->subscribe_id, maat_ret, PRINTADDR(a_stream, g_tsg_para.level));

	return 0;
}

int tsg_scan_gtp_apn_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *apn, int thread_seq)
{
	int maat_ret=0;

	if(apn==NULL || result==NULL || result_num==0)
	{
		return 0;
	}
	
	maat_ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[TABLE_GTP_APN], CHARSET_GBK, apn, strlen(apn), result, NULL, result_num, mid, thread_seq);
	if(maat_ret>0)
	{				
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_APN",
									"Hit APN: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
									apn,
									maat_ret,
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return maat_ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_APN", "No hit APN: %s scan ret: %d addr: %s", apn, maat_ret, PRINTADDR(a_stream, g_tsg_para.level));

	return 0;
}

int tsg_scan_gtp_imsi_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *imsi, int thread_seq)
{
	int maat_ret=0;

	if(imsi==NULL || result==NULL || result_num==0)
	{
		return 0;
	}
	
	maat_ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[TABLE_GTP_IMSI], CHARSET_GBK, imsi, strlen(imsi), result, NULL, result_num, mid, thread_seq);
	if(maat_ret>0)
	{				
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IMSI",
									"Hit IMSI: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
									imsi,
									maat_ret,
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return maat_ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "SCAN_IMSI", "No hit IMSI: %s scan ret: %d addr: %s", imsi, maat_ret, PRINTADDR(a_stream, g_tsg_para.level));

	return 0;
}

int tsg_scan_gtp_phone_number_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, char *phone_number, int thread_seq)
{
	int maat_ret=0;

	if(phone_number==NULL || result==NULL || result_num==0)
	{
		return 0;
	}
	
	maat_ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[TABLE_GTP_PHONE_NUMBER], CHARSET_GBK, phone_number, strlen(phone_number), result, NULL, result_num, mid, thread_seq);
	if(maat_ret>0)
	{				
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"PHONE_NUMBER",
									"Hit PHONE_NUMBER: %s scan ret: %d policy_id: %d service: %d action: %d addr: %s",
									phone_number,
									maat_ret,
									result[0].config_id,
									result[0].service_id,
									(unsigned char)result[0].action,
									PRINTADDR(a_stream, g_tsg_para.level)
								);

		return maat_ret;
	}
	
	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PHONE_NUMBER", "No hit PHONE_NUMBER: %s scan ret: %d addr: %s", phone_number, maat_ret, PRINTADDR(a_stream, g_tsg_para.level));

	return 0;
}

int tsg_app_id2name(int app_id, char *app_name, int app_name_len, int is_joint_parent)
{
	int offset=0;
	char app_id_buff[128]={0};
	struct app_id_dict *dict=NULL;

	if(app_id<=0 || app_name==NULL || app_name_len<=0)
	{
		return offset;
	}

	snprintf(app_id_buff, sizeof(app_id_buff), "%d", app_id);
	dict=(struct app_id_dict *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
	if(dict!=NULL)
	{
		if(dict->parent_app_id!=0 && is_joint_parent==1)
		{		
			offset=snprintf(app_name, app_name_len, "%s.%s", dict->parent_app_name, dict->app_name);
		}
		else
		{
			offset=snprintf(app_name, app_name_len, "%s", dict->app_name);
		}
		
		app_id_dict_free(g_tsg_para.table_id[TABLE_APP_ID_DICT], (MAAT_PLUGIN_EX_DATA *)&dict, 0, NULL);

		return offset;
	}

	return offset;
}

int tsg_free_compile_user_region(const struct Maat_rule_t *rule, struct compile_user_region *user_region)
{
	security_compile_free(0,  rule, NULL , (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);

	return 0;
}

struct compile_user_region *tsg_get_compile_user_region(const Maat_feather_t maat_feather,  struct Maat_rule_t *result)
{
	return ((struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, result, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]));
}

int tsg_notify_hited_monitor_result(const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, int thread_seq)
{
	int i=0;
	char profile_id_str[32]={0};
	struct tsg_notify_data notify_data={0};
	struct compile_user_region *user_region=NULL;
	struct traffic_mirror_profile *mirror_profile=NULL;

	for(i=0; i<result_num; i++)
	{
		if(result[i].action!=TSG_ACTION_MONITOR && result[i].action!=TSG_ACTION_DENY)
		{
			continue;
		}
		
		user_region=tsg_get_compile_user_region(g_tsg_maat_feather, &(result[i]));
		if(user_region==NULL)
		{
			continue;
		}
		
		if(user_region->method_type==TSG_METHOD_TYPE_MIRRORED && user_region->mirror!=NULL && user_region->mirror->enabled==1)
		{
			snprintf(profile_id_str, sizeof(profile_id_str), "%d", user_region->mirror->profile_id);
			mirror_profile=(struct traffic_mirror_profile *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_PROFILE_MIRROR], profile_id_str);
			if(mirror_profile!=NULL)
			{
				notify_data.compile_id=result[i].config_id;
				notify_data.type=NOTIFY_TYPE_MIRRORED;
				notify_data.vlan=&(mirror_profile->vlan);
				
				stream_bridge_sync_data_put(a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA], (void *)&(notify_data));
				mirrored_profile_free(0, (MAAT_PLUGIN_EX_DATA *)&mirror_profile, 0, NULL);
			}
			else
			{
				notify_data.compile_id=result[i].config_id;
				notify_data.type=NOTIFY_TYPE_MIRRORED;
				notify_data.vlan=&(g_tsg_para.default_vlan);				
				stream_bridge_sync_data_put(a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA], (void *)&(notify_data));
			}
		}

		if(user_region->capture.enabled==1)
		{
			notify_data.compile_id=result[i].config_id;
			notify_data.type=NOTIFY_TYPE_CAPTURE;
			notify_data.capture_depth=user_region->capture.depth;
			stream_bridge_sync_data_put(a_stream, g_tsg_para.bridge_id[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA], (void *)&(notify_data));
		}
		
		tsg_free_compile_user_region(&(result[i]), user_region);
		user_region=NULL;
	}
	
	return 1;
}

int tsg_set_method_to_tcpall(const struct streaminfo *a_stream, struct tcpall_context **context, enum TSG_METHOD_TYPE method_type, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)get_struct_project(a_stream, g_tsg_para.tcpall_project_id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		set_struct_project(a_stream, g_tsg_para.tcpall_project_id, (void *)_context);
	}

	switch(_context->method_type)
	{
		case	TSG_METHOD_TYPE_DEFAULT:
		case	TSG_METHOD_TYPE_MIRRORED:			
			_context->method_type=method_type;
			*context=_context;
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

int tsg_set_bucket_to_tcpall(const struct streaminfo *a_stream, struct tcpall_context **context, struct leaky_bucket *bucket, int thread_seq)
{
	struct tcpall_context *_context=(struct tcpall_context *)get_struct_project(a_stream, g_tsg_para.tcpall_project_id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		set_struct_project(a_stream, g_tsg_para.tcpall_project_id, (void *)_context);
	}

	switch(_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			*context=_context;
			return 1;	
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
			break;
		default:
			return 0;
			break;
	}

	_context->method_type=TSG_METHOD_TYPE_RATE_LIMIT;
	_context->bucket=bucket;
	*context=_context;
	
	return 1;
}

char *tsg_get_column_string_value(const char* line, int column_seq)
{
	int ret=0;
	size_t offset=0;
	size_t length=0;

	ret=get_column_pos(line, column_seq, &offset, &length);
	if(ret>=0)
	{
		return _malloc_field(line+offset, length);
	}

	return NULL;
}

int tsg_get_column_integer_value(const char* line, int column_seq)
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

int tsg_set_fqdn_category_id(const struct streaminfo *a_stream, unsigned int *category_id, int category_id_num, int thread_seq)
{
	if(category_id!=NULL && category_id_num>0)
	{
		set_session_attribute_label(a_stream, TSG_ATTRIBUTE_TYPE_CATEGORY_ID, (void *)category_id, category_id_num, thread_seq);
	}
	
	return 0;
}
