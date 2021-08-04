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
													{TSG_METHOD_TYPE_RESET, 3, (char *)"rst"},
													{TSG_METHOD_TYPE_ALERT, 5, (char *)"alert"},
													{TSG_METHOD_TYPE_ALERT, 10, (char *)"rate_limit"}
	};

static char* str_unescape(char* s)
{
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

static int copy_id(int *dst_id, int dst_id_num, int *src_id, int src_id_num)
{
	int num=MIN(dst_id_num, src_id_num);
	memcpy(dst_id, src_id, num);

	return num;
}

static int copy_vlan_id(struct mirrored_vlan *vlan, int vlan_num, int vlan_id, int *compile_id, int compile_id_num)
{
	int i=0;

	for(i=0; i<vlan_num; i++)
	{
		if(vlan[i].vlan_id==vlan_id)
		{
			vlan[i].compile_id_num+=copy_id(vlan[i].compile_id, MAX_RESULT_NUM-vlan[i].compile_id_num, compile_id, compile_id_num);
			return 0;
		}
	}

	vlan[vlan_num].vlan_id=vlan_id;
	vlan[vlan_num].compile_id_num=copy_id(vlan[vlan_num].compile_id, MAX_RESULT_NUM, compile_id, compile_id_num);

	return 1;
}

static int sort_category_id(const void * a, const void * b)
{
	struct _fqdn_category_t *x = (struct _fqdn_category_t *) a;
	struct _fqdn_category_t *y = (struct _fqdn_category_t *) b;
	
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

static void eliminate_default_value(char *value)
{
	if(value!=NULL && (memcmp(value, "null", 4))==0)
	{
		value[0]='\0';
	}
}

void ASN_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct _asn_info_t *asn=(struct _asn_info_t *)(*from);

	if(asn!=NULL)
	{
		atomic_inc(&asn->ref_cnt);
		*to=*from;
	}

	return;
}

void ASN_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int ret=0,id=0,is_valid=0;

	struct _asn_info_t *asn=NULL;
	asn=(struct _asn_info_t *)calloc(1, sizeof(struct _asn_info_t));
	
	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%s\t%s\t%d", &id, &asn->addr_type, asn->start_ip, asn->end_ip, asn->asn, asn->organization, &is_valid);
	if(ret!=7)
	{
		free(asn);
		asn=NULL;
		return;
	}
	
	str_unescape(asn->organization);
	eliminate_default_value(asn->organization);

	atomic_inc(&asn->ref_cnt);
	asn->table_id=table_id;
	*ad=(MAAT_PLUGIN_EX_DATA)asn;
	
	return;
}

void ASN_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct _asn_info_t *asn=(struct _asn_info_t *)(*ad);

	if(asn!=NULL)
	{
		atomic_dec(&asn->ref_cnt);
				
		if(asn->ref_cnt<=0)
		{
			free(*ad);
			*ad=NULL;
		}
	}
	return;
}

void location_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct _location_info_t *location=(struct _location_info_t *)(*from);

	if(location!=NULL)
	{
		atomic_inc(&location->ref_cnt);
		*to=*from;
	}
	
	return;
}

void location_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	int ret=0,id=0,is_valid=0;
	struct _location_info_t *location=NULL;

	location=(struct _location_info_t *)calloc(1, sizeof(struct _location_info_t));
	
	ret=sscanf(table_line,
				"%d\t%d\t%d\t%s\t%s\t%lf\t%lf\t%lf\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d",
				&id,
				&location->geoname_id,
				&location->addr_type,
				location->start_ip,
				location->end_ip,
				&location->latitude,
				&location->longitude,
				&location->coords,
				location->language,
				location->continent_abbr,
				location->continent_full,
				location->country_abbr,
				location->country_full,
				location->province_abbr,
				location->province_full,
				location->city_full,
				location->time_zone,
				&is_valid);
	if(ret!=18)
	{
		free(location);
		location=NULL;
		
		MESA_handle_runtime_log(logger, 
									RLOG_LV_FATAL,
									"IP_LOCATION",
									"Parse ip location failed, ret: %d table_id: %d table_line: %s",
									ret,
									table_id,
									table_line
								);
		return;
	}

	str_unescape(location->continent_full);
	str_unescape(location->country_full);
	str_unescape(location->province_full);
	str_unescape(location->city_full);
	eliminate_default_value(location->language);
	eliminate_default_value(location->continent_abbr);
	eliminate_default_value(location->continent_full);
	eliminate_default_value(location->country_abbr);
	eliminate_default_value(location->country_full);
	eliminate_default_value(location->province_abbr);
	eliminate_default_value(location->province_full);
	eliminate_default_value(location->city_full);
	eliminate_default_value(location->time_zone);
	
	atomic_inc(&location->ref_cnt);
	location->table_id=table_id;
	*ad=(MAAT_PLUGIN_EX_DATA)location;
	
	return;
}

void location_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct _location_info_t *location=(struct _location_info_t *)(*ad);

	if(location!=NULL)
	{
		atomic_dec(&location->ref_cnt);

		if(location->ref_cnt<=0)
		{
			free(*ad);
			*ad=NULL;
		}
	}
	
	return;
}

void fqdn_cat_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct _fqdn_category_t *fqdn_cat=(struct _fqdn_category_t *)(*from);

	if(fqdn_cat!=NULL)
	{
		atomic_inc(&fqdn_cat->ref_cnt);
		*to=*from;
	}
	return;
}

void fqdn_cat_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	int ret=0,id=0,is_valid=0;
	struct _fqdn_category_t *fqdn_cat=NULL;

	fqdn_cat=(struct _fqdn_category_t *)calloc(1, sizeof(struct _fqdn_category_t));
	
	ret=sscanf(table_line,
				"%d\t%u\t%s\t\t%d\t%d",
				&id,
				&fqdn_cat->category_id,
				fqdn_cat->fqdn,
				&fqdn_cat->match_method,
				&is_valid
				);
	if(ret!=5)
	{
		free(fqdn_cat);
		fqdn_cat=NULL;
		
		MESA_handle_runtime_log(logger, 
									RLOG_LV_FATAL,
									"FQDN_CAT",
									"Parse fqdn category failed, ret: %d table_id: %d table_line: %s",
									ret,
									table_id,
									table_line
								);
		return;
	}
	
	atomic_inc(&fqdn_cat->ref_cnt);
	*ad=(MAAT_PLUGIN_EX_DATA)fqdn_cat;
	
	return;
}

void fqdn_cat_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct _fqdn_category_t *fqdn_cat=(struct _fqdn_category_t *)(*ad);

	if(fqdn_cat!=NULL)
	{
		atomic_dec(&fqdn_cat->ref_cnt);
		
		if(fqdn_cat->ref_cnt<=0)
		{
			free(*ad);
			*ad=NULL;
		}
	}
	return;
}


void subscribe_id_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct _subscribe_id_info_t *subscribe_id=(struct _subscribe_id_info_t *)(*from);

	if(subscribe_id!=NULL)
	{
		atomic_inc(&subscribe_id->ref_cnt);
		*to=*from;
	}
	
	return;
}

void subscribe_id_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	int ret=0,id=0,type=0,is_valid=0;
	char ip_addr[MAX_IPV6_ADDR_LEN]={0};
	struct _subscribe_id_info_t *subscribe_id=NULL;

	subscribe_id=(struct _subscribe_id_info_t *)calloc(1, sizeof(struct _subscribe_id_info_t));
	
	ret=sscanf(table_line, "%d\t%d\t%s\t%s\t%d", &id, &type, ip_addr, subscribe_id->subscribe_id, &is_valid);
	if(ret!=5)
	{
		free(subscribe_id);
		subscribe_id=NULL;
		
		MESA_handle_runtime_log(logger, 
								RLOG_LV_FATAL,
								"SUBSCRIBE_ID",
								"Parse subscribe_id failed, ret: %d table_id: %d table_line: %s",
								ret,
								table_id,
								table_line
								);
		return;
	}
	
	
	
	atomic_inc(&subscribe_id->ref_cnt);
	subscribe_id->table_id=table_id;
	*ad=(MAAT_PLUGIN_EX_DATA)subscribe_id;
	
	return;
}

void subscribe_id_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct _subscribe_id_info_t *subscribe_id=(struct _subscribe_id_info_t *)(*ad);

	if(subscribe_id!=NULL)
	{
		atomic_dec(&subscribe_id->ref_cnt);
			
		if(subscribe_id->ref_cnt<=0)
		{
			free(*ad);
			*ad=NULL;
		}
	}
	
	return;
}

static void app_id_dict_dup_data(int table_id, MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from, long argl, void* argp)
{
	struct app_id_dict_table *app_id_dict=(struct app_id_dict_table *)(*from);

	if(*from!=NULL)
	{
		atomic_inc(&app_id_dict->ref_cnt);
		*to=*from;
	}
	return;
}

static void app_id_dict_new_data(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	void *logger=argp;
	int ret=0;

	struct app_id_dict_table *app_id_dict=NULL;
	app_id_dict=(struct app_id_dict_table *)calloc(1, sizeof(struct app_id_dict_table));
	if(g_tsg_para.app_dict_field_num==18)
	{
		ret=sscanf(table_line,
				"%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d",
				&app_id_dict->app_id, 
				app_id_dict->app_name,
				&app_id_dict->parent_app_id, 
				app_id_dict->parent_app_name,
				app_id_dict->category, 
				app_id_dict->subcategroy, 
				app_id_dict->technology,
				app_id_dict->risk, 
				app_id_dict->characteristics, 
				app_id_dict->depends_on_app_ids, 
				app_id_dict->implicitly_uses_app_ids, 
				&app_id_dict->deny_action, 
				&app_id_dict->continue_scanning, 
				&app_id_dict->tcp_timeout, 
				&app_id_dict->udp_timeout, 
				&app_id_dict->tcp_half_close,
				&app_id_dict->tcp_time_wait, 
				&app_id_dict->is_valid);
	}
	else
	{
		ret=sscanf(table_line,
				"%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d",
				&app_id_dict->app_id, 
				app_id_dict->app_name,
				app_id_dict->category, 
				app_id_dict->subcategroy, 
				app_id_dict->technology,
				app_id_dict->risk, 
				app_id_dict->characteristics, 
				app_id_dict->depends_on_app_ids, 
				app_id_dict->implicitly_uses_app_ids, 
				&app_id_dict->deny_action, 
				&app_id_dict->continue_scanning, 
				&app_id_dict->tcp_timeout, 
				&app_id_dict->udp_timeout, 
				&app_id_dict->tcp_half_close,
				&app_id_dict->tcp_time_wait, 
				&app_id_dict->is_valid);
	}
	
	if(ret!=g_tsg_para.app_dict_field_num)
	{
		free(app_id_dict);
		app_id_dict=NULL;
		
		MESA_handle_runtime_log(logger, 
									RLOG_LV_FATAL,
									"APP_ID_DICT",
									"Parse app_id_dict failed, ret: %d table_id: %d table_line: %s",
									ret,
									table_id,
									table_line
								);
		return;
	}

	str_unescape(app_id_dict->app_name);
	str_unescape(app_id_dict->parent_app_name);
	str_unescape(app_id_dict->category);
	str_unescape(app_id_dict->subcategroy);
	str_unescape(app_id_dict->technology);
	str_unescape(app_id_dict->characteristics);
	str_unescape(app_id_dict->depends_on_app_ids);
	str_unescape(app_id_dict->implicitly_uses_app_ids);

	atomic_inc(&app_id_dict->ref_cnt);
	eliminate_default_value(app_id_dict->app_name);
	eliminate_default_value(app_id_dict->parent_app_name);
	eliminate_default_value(app_id_dict->category);
	eliminate_default_value(app_id_dict->subcategroy);
	eliminate_default_value(app_id_dict->technology);
	eliminate_default_value(app_id_dict->risk);
	eliminate_default_value(app_id_dict->characteristics);
	eliminate_default_value(app_id_dict->depends_on_app_ids);
	eliminate_default_value(app_id_dict->implicitly_uses_app_ids);
	
	*ad=(MAAT_PLUGIN_EX_DATA)app_id_dict;
	
	return;
}

void app_id_dict_free_data(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct app_id_dict_table *app_id_dict=(struct app_id_dict_table *)(*ad);

	if(app_id_dict!=NULL)
	{
		atomic_dec(&app_id_dict->ref_cnt);
		if(app_id_dict->ref_cnt<=0)
		{
			free(*ad);
			*ad=NULL;
		}
	}
	return;
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

static struct compile_user_region *parse_monitor_user_region(cJSON *object)
{
	cJSON *mirror_item=NULL;
	struct compile_user_region *user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));
	mirror_item=cJSON_GetObjectItem(object, "packet_mirror");
	if(mirror_item)
	{		
		user_region->method_type=TSG_METHOD_TYPE_MIRRORED;
		user_region->mirror=(struct monitor_user_region *)calloc(1, sizeof(struct monitor_user_region));
		get_integer_from_json(mirror_item, "enable", &(user_region->mirror->enabled));		
		get_integer_from_json(mirror_item, "mirror_vlan", &(user_region->mirror->vlan_id));
	}

	return user_region;
}

static struct compile_user_region *parse_deny_user_region(cJSON *object)
{
	int ret=0;
	cJSON *item=NULL;	
	struct compile_user_region *user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));
	
	item=cJSON_GetObjectItem(object, "method");
	if(item!=NULL)
	{
		user_region->method_type=(TSG_METHOD_TYPE)tsg_get_method_id(item->valuestring);
	}

	switch(user_region->method_type)
	{
		case	TSG_METHOD_TYPE_ALERT:
		case	TSG_METHOD_TYPE_BLOCK:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			get_integer_from_json(object, "code", &(user_region->deny->code));
			ret=get_integer_from_json(object, "html_profile", &(user_region->deny->profile_id));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_PROFILE;
				break;
			}
			
			ret=get_string_from_json(object, "message", &(user_region->deny->message));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_MESSAGE;
				break;
			}
			
			user_region->deny->type=TSG_DENY_TYPE_MAX;
			break;
		case	TSG_METHOD_TYPE_REDIRECTION:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			get_integer_from_json(object, "code", &(user_region->deny->code));
			ret=get_string_from_json(object, "redirect_url", &(user_region->deny->redirect_url_to));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_REDIRECT_TO;
				break;
			}
			ret=get_string_from_json(object, "to", &(user_region->deny->redirect_url_to));
			if(ret==1)
			{
				user_region->deny->type=TSG_DENY_TYPE_REDIRECT_TO;
				break;
			}
			break;
		case	TSG_METHOD_TYPE_RATE_LINIT:
			user_region->deny=(struct deny_user_region *)calloc(1, sizeof(struct deny_user_region));
			get_integer_from_json(object, "bytes_per_sec", &(user_region->deny->bytes_per_sec));
			break;
		case	TSG_METHOD_TYPE_DROP:
		case	TSG_METHOD_TYPE_RESET:
			break;
		default:
			break;
	}
	
	return user_region;
}

void security_compile_new(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp)
{
	cJSON *object=NULL;
	struct compile_user_region *user_region=NULL;
	
	if(rule==NULL)
	{
		return ;
	}
	
	if(srv_def_large!=NULL && strlen(srv_def_large)>2)
	{
		object=cJSON_Parse(srv_def_large);
		if(object!=NULL)
		{				
			switch(rule->action)
			{
				case	TSG_ACTION_DENY:
					user_region=parse_deny_user_region(object);
					atomic_inc(&user_region->ref_cnt);
					break;
				case	TSG_ACTION_MONITOR:
					user_region=parse_monitor_user_region(object);
					atomic_inc(&user_region->ref_cnt);
					break; 
				default:
					break;
			}

			cJSON_Delete(object);
			object=NULL;
		}
	}

	if(g_tsg_para.default_compile_switch==1 && g_tsg_para.default_compile_id==rule->config_id)
	{
		if(user_region==NULL)
		{
			user_region=(struct compile_user_region *)calloc(1, sizeof(struct compile_user_region));				
			atomic_inc(&user_region->ref_cnt);
		}
		
		user_region->result=(struct Maat_rule_t *)calloc(1, sizeof(struct Maat_rule_t));
		memcpy(user_region->result, rule, sizeof(struct Maat_rule_t));
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

static void free_deny_user_region(struct deny_user_region *deny)
{
	if(deny==NULL)
	{
		return ;
	}

	switch(deny->type)
	{
		case	TSG_DENY_TYPE_MESSAGE:
		case	TSG_DENY_TYPE_REDIRECT_TO:
			if(deny->para)
			{
				free(deny->para);
				deny->para=NULL;
			}
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
	
	atomic_dec(&user_region->ref_cnt);
	if(user_region->ref_cnt>0)
	{
		return ;
	}
	
	switch(user_region->method_type)
	{
		case	TSG_METHOD_TYPE_ALERT:
		case	TSG_METHOD_TYPE_BLOCK:
		case	TSG_METHOD_TYPE_RATE_LINIT:
		case	TSG_METHOD_TYPE_REDIRECTION:
			free_deny_user_region(user_region->deny);
			break;
		default:
			break;
	}
	
	if(user_region->user_region_para!=NULL)
	{
		free(user_region->user_region_para);
		user_region->user_region_para=NULL;
	}
	
	free(*ad);
	*ad=NULL;
		
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
	struct http_response_pages *res_pages=(struct http_response_pages *)*from;

	if(*from!=NULL)
	{
		*to=*from;
		atomic_inc(&res_pages->ref_cnt);
	}
}

void http_response_pages_new(int table_id, const char* key, const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	int ret=0;
	void *logger=argp;
	int is_valid;
	char format[256]={0};
	char path[1024]={0};
	char profile_name[256]={0};
	struct http_response_pages *res_pages=NULL;

	res_pages=(struct http_response_pages *)calloc(1, sizeof(struct http_response_pages));
	
	ret=sscanf(table_line, "%d\t%s\t%s\t%s\t%d", &res_pages->profile_id, profile_name, format, path, &is_valid);
	if(ret!=5)
	{
		free(res_pages);
		res_pages=NULL;
		if(logger!=NULL)
		{
			MESA_handle_runtime_log(logger, 
									RLOG_LV_FATAL,
									"RESPONSE_PAGES",
									"Parse response pages failed, ret: %d table_id: %d key: %s table_line: %s",
									ret,
									table_id,
									key,
									table_line
									);
		}
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
	
	atomic_inc(&res_pages->ref_cnt);
	res_pages->content=get_pages_content(path, &res_pages->content_len);
	*ad=(MAAT_PLUGIN_EX_DATA)res_pages;
}

void http_response_pages_free(int table_id, MAAT_PLUGIN_EX_DATA* ad, long argl, void* argp)
{
	struct http_response_pages *res_pages=(struct http_response_pages *)*ad;

	atomic_dec(&res_pages->ref_cnt);
	if(res_pages->ref_cnt<=0)
	{
		free(res_pages->content);
		free(*ad);
		*ad=NULL;	
	}
}

static int get_fqdn_category_id(Maat_feather_t maat_feather, int table_id, char *fqdn, unsigned int *category_id, int category_id_num, void *logger, int thread_seq)
{
	int i=0,j=0,ret=0;	
	struct _fqdn_category_t *ex_data_array[8]={0};

	ret=Maat_fqdn_plugin_get_EX_data(maat_feather, table_id, fqdn, (MAAT_PLUGIN_EX_DATA *)ex_data_array, 8);
	if(ret>0)
	{
		qsort(ex_data_array, ret, sizeof(struct _fqdn_category_t *), sort_category_id);
		
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
			
			fqdn_cat_free_data(table_id, (MAAT_PLUGIN_EX_DATA *)&(ex_data_array[i]), 0, logger);
		}

		return j;
	}

	return 0;
}

static Maat_feather_t init_maat_feather(const char* conffile, char* instance_name, char *module, void *logger)
{
	unsigned short redis_port = 0;
	int ret=0,scan_detail=0,effect_interval=60;
	Maat_feather_t _maat_feather=NULL;
	int factor=0, redis_port_num=0,redis_index=0;
	char effective_tag_key[128]={0};
	char effective_range_filename[1024]={0};
	char redis_ip[16]={0}, effective_flag[1024]={0};
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

	if(strlen(g_tsg_para.data_center)==0 && strlen(effective_flag)>0)
	{
		MESA_load_profile_string_def(conffile, module, "EFFECTIVE_TAG_KEY", effective_tag_key, sizeof(effective_tag_key),"data_center");
		get_data_center(effective_flag, effective_tag_key, g_tsg_para.data_center, sizeof(g_tsg_para.data_center));
	}
	
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
		Maat_set_feather_opt(_maat_feather, MAAT_OPT_FOREIGN_CONT_DIR, "./alerts_files", strlen("./alerts_files")+1);
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
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "EFFECTIVE_RANGE", "Effective range is empty, please check %s", effective_range_filename);
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
	
	MESA_load_profile_int_def(conffile, "MAAT","APP_ID_TABLE_TYPE", &g_tsg_para.app_dict_field_num, 18);

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

	//init static maat feather
	g_tsg_maat_feather=init_maat_feather(maat_conffile, (char *)"TSG_STATIC", (char *)"STATIC", logger);
	if(g_tsg_maat_feather==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "init_maat_feather failed, instance_name: %s module: %s", "TSG_STATIC", "STATIC"); 
		return -1;
	}

	g_tsg_para.table_id[TABLE_SECURITY_COMPILE]=Maat_rule_get_ex_new_index(g_tsg_maat_feather,
																g_tsg_para.table_name[TABLE_SECURITY_COMPILE],
																security_compile_new,
																security_compile_free,
																security_compile_dup,
																0,
																logger
															);
	
	if(g_tsg_para.table_id[TABLE_SECURITY_COMPILE]<0)
	{
		
		MESA_handle_runtime_log(logger,	RLOG_LV_FATAL, "REGISTER_TABLE", "Register table: %s failed ...", g_tsg_para.table_name[TABLE_SECURITY_COMPILE]);		
		return -1;
	}

	for(i=TABLE_IP_ADDR; i<TABLE_MAX; i++)
	{
		g_tsg_para.table_id[i]=Maat_table_register(g_tsg_maat_feather, g_tsg_para.table_name[i]);
		if(g_tsg_para.table_id[i]<0)
		{
			MESA_handle_runtime_log(logger,
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
									ASN_new_data,
									ASN_free_data,
									ASN_dup_data,
									0,
									logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,
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
									logger);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,
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
										fqdn_cat_new_data,
										fqdn_cat_free_data,
										fqdn_cat_dup_data,
										0,
										logger
									);
		if(ret<0)
		{
			MESA_handle_runtime_log(logger, RLOG_LV_FATAL,
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
									app_id_dict_new_data,
									app_id_dict_free_data,
									app_id_dict_dup_data,
									NULL,
									0,
									logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL,
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
							logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(logger, 
								RLOG_LV_FATAL,
								"RESPONSE_PAGES",
								"Maat_plugin_EX_register failed, table_name: %s table_id: %d",
								g_tsg_para.table_name[TABLE_RESPONSE_PAGES],
								g_tsg_para.table_id[TABLE_RESPONSE_PAGES]); 
		return -1;		
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
		MESA_handle_runtime_log(logger,
								RLOG_LV_FATAL,
								"RULE_INIT",
								"Maat_table_register %s failed, Please check tsgconf/tsg_static_tableinfo.conf",
								cb_subscriber_ip_table
								); 
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

int tsg_pull_policy_result(struct streaminfo *a_stream, PULL_RESULT_TYPE pull_result_type, Maat_rule_t*result, int result_num, struct identify_info *identify_info)
{
	int num=0;
	policy_priority_label_t *label=NULL;

	label=(policy_priority_label_t *)project_req_get_struct(a_stream, g_tsg_para.priority_project_id);
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

int tsg_get_subscribe_id(const struct streaminfo *a_stream, struct _subscribe_id_info_t **source_subscribe_id, struct _subscribe_id_info_t **dest_subscribe_id)
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
		*dest_subscribe_id = (struct _subscribe_id_info_t *)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, dest_ip);
	}

	if(strlen(source_ip)>0 && *source_subscribe_id==NULL)
	{
		*source_subscribe_id = (struct _subscribe_id_info_t *)Maat_plugin_get_EX_data(g_tsg_dynamic_maat_feather, g_tsg_para.dyn_subscribe_ip_table_id, source_ip);
	}

	return 0;
}

int tsg_scan_ip_asn(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct _asn_info_t *asn, enum MASTER_TABLE idx, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;

	if(asn==NULL || result==NULL || result_num==0)
	{
		return 0;
	}

	ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[idx], CHARSET_GBK, asn->asn, strlen(asn->asn), result, NULL, result_num, mid, a_stream->threadnum);
	if(ret > 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_ASN",
									"Hit IP_ASN: %s scan ret: %d table_name: %s policy_id: %d service: %d action: %d addr: %s",
									asn->asn,
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
								asn->asn,
								ret,
								g_tsg_para.table_name[idx],
								PRINTADDR(a_stream, g_tsg_para.level)
							);
	return 0;
}


int tsg_scan_ip_location(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct _location_info_t *location, enum MASTER_TABLE idx, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;
	char buff[1024]={0};
	
	if(location==NULL || result==NULL || result_num==0)
	{
		return 0;
	}
	
	snprintf(buff, sizeof(buff), "%s.%s.", location->country_full, location->city_full);
	ret=Maat_full_scan_string(maat_feather, g_tsg_para.table_id[idx], CHARSET_GBK, buff, strlen(buff), result, NULL, result_num, mid, a_stream->threadnum);
	if(ret > 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_LOCATION",
									"Hit IP_LOCATION: %s scan ret: %d table_name: %s policy_id: %d service: %d action: %d addr: %s",
									buff,
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
								buff,
								ret,
								g_tsg_para.table_name[idx],
								PRINTADDR(a_stream, g_tsg_para.level)
							);
	
	return 0;
}

int tsg_scan_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int hit_num=0,tans_proto=0;
	struct ipaddr t_addr;
	struct ipaddr* p_addr=NULL;	
	int is_scan_addr=1, maat_ret=0;	
	const struct streaminfo *cur_stream = a_stream;

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
	struct _session_attribute_label_t *attribute_label=NULL;

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

	attribute_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, g_tsg_para.internal_project_id);
	if(attribute_label==NULL)
	{
		attribute_label=(struct _session_attribute_label_t *)dictator_malloc(a_stream->threadnum, sizeof(struct _session_attribute_label_t));
		memset(attribute_label, 0, sizeof(struct _session_attribute_label_t));
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
	
	ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.internal_project_id, (void *)attribute_label);
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

	if(table_id<0 || result_num<=0 || category_id==NULL)
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
	int district_len=strlen(district);
	int property_len=strlen(property); 
	struct Maat_rule_t property_result[MAX_RESULT_NUM]={0};
	
	if(property!=NULL && property_len>0 && district_len>0)
	{
		Maat_set_scan_status(g_tsg_maat_feather, mid, MAAT_SET_SCAN_DISTRICT, (void *)district, district_len);
		ret=Maat_full_scan_string(g_tsg_maat_feather, 
									g_tsg_para.table_id[TABLE_SELECTOR_PROPERTIES],
									CHARSET_UTF8,
									property,
									property_len,
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

int tsg_scan_subscribe_id_policy(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct Maat_rule_t *result, int result_num, scan_status_t *mid, struct _subscribe_id_info_t *user_info, int thread_seq)
{
	int maat_ret=0;

	if(user_info==NULL || result==NULL || result_num==0)
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
	struct app_id_dict_table *dict=NULL;

	if(app_id<=0 || app_name==NULL || app_name_len<=0)
	{
		return offset;
	}

	snprintf(app_id_buff, sizeof(app_id_buff), "%d", app_id);
	dict=(struct app_id_dict_table *)Maat_plugin_get_EX_data(g_tsg_maat_feather, g_tsg_para.table_id[TABLE_APP_ID_DICT], (const char *)app_id_buff);
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
		
		app_id_dict_free_data(g_tsg_para.table_id[TABLE_APP_ID_DICT], (MAAT_PLUGIN_EX_DATA *)&dict, 0, NULL);

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

int tsg_get_vlan_id_by_monitor_rule(Maat_feather_t maat_feather, struct Maat_rule_t *result, int result_num, struct mirrored_vlan *vlan, int vlan_num)
{
	int i=0,count=0;
	struct compile_user_region *user_region=NULL;

	for(i=0; i<result_num && count<vlan_num; i++)
	{
		if(result[i].action!=TSG_ACTION_MONITOR)
		{
			continue;
		}
		
		user_region=tsg_get_compile_user_region(maat_feather, &(result[i]));
		if(user_region!=NULL && user_region->method_type==TSG_METHOD_TYPE_MIRRORED && user_region->mirror!=NULL)
		{
			count+=copy_vlan_id(vlan, count, user_region->mirror->vlan_id, &(result[i].config_id), 1);
			tsg_free_compile_user_region(&(result[i]), user_region);
			user_region=NULL;
		}
	}
	
	return count;
}

int tsg_set_vlan_id_to_tcpall(const struct streaminfo *a_stream, struct tcpall_context **context, struct mirrored_vlan *vlan, int vlan_num, int thread_seq)
{
	int i=0;
	
	if(vlan==NULL || vlan_num<=0)
	{
		return 0;
	}
	
	struct tcpall_context * _context=(struct tcpall_context *)get_struct_project(a_stream, g_tsg_para.tcpall_project_id);
	if(_context==NULL)
	{
		_context=(struct tcpall_context *)dictator_malloc(thread_seq, sizeof(struct tcpall_context));
		memset(_context, 0, sizeof(struct tcpall_context));
		_context->method_type=TSG_METHOD_TYPE_MIRRORED;
		
		_context->vlan=(struct mirrored_vlan *)dictator_malloc(thread_seq, sizeof(struct mirrored_vlan)*MAX_RESULT_NUM);
		memset(_context->vlan, 0, sizeof(struct mirrored_vlan));
		
		set_struct_project(a_stream, g_tsg_para.tcpall_project_id, (void *)_context);
	}

	if(_context->method_type==TSG_METHOD_TYPE_MIRRORED && _context->vlan!=NULL)
	{
		for(i=0; i<vlan_num; i++)
		{
			_context->vlan_num+=copy_vlan_id(_context->vlan, _context->vlan_num, vlan[i].vlan_id, vlan[i].compile_id, vlan[i].compile_id_num);
		}

		(*context)=_context;
		return 1;
	}
	
	return 0;
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
	else
	{
		if(_context->method_type==TSG_METHOD_TYPE_MIRRORED && _context->vlan)
		{
			_context->vlan_num=0;
			dictator_free(thread_seq, _context->vlan);
			_context->vlan=NULL;
		}
	}
	
	_context->method_type=TSG_METHOD_TYPE_RATE_LINIT;
	_context->bucket=bucket;
	
	return 0;
}


