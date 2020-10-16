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
													{TSG_METHOD_TYPE_RESET, 3, (char *)"rst"},
													{TSG_METHOD_TYPE_ALERT, 5, (char *)"alert"}
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
										 {PROTO_QUIC, 5, (char *)"QUIC."},
										 {PROTO_SSH, 4, (char *)"SSH."},
										 {PROTO_SMTP, 5, (char *)"MAIL."},
										 {PROTO_IMAP, 5, (char *)"MAIL."},
										 {PROTO_POP3, 5, (char *)"MAIL."},
										 {PROTO_MAX, 0, (char *)""}
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

static int proto_str2id(tsg_protocol_t proto)
{
	switch(proto)
	{
		case	PROTO_TCP: return 100;
		case	PROTO_UDP: return 101;
		case	PROTO_HTTP: return 106;
		case	PROTO_MAIL:	return 110;
		case	PROTO_IMAP:	return 110;
		case	PROTO_POP3: return 110;//116
		case	PROTO_SMTP: return 110;//122
		case	PROTO_DNS: return 103;
		case	PROTO_FTP: return 104;
		case	PROTO_SSL: return 126;
		case	PROTO_SIP: return 120;
		case	PROTO_QUIC: return 119;
		case	PROTO_SSH: return 125;
		case	PROTO_IPv6:
		case	PROTO_IPv4:	
		case	PROTO_STREAMING_MEDIA:
		case	PROTO_BGP:
		default:
			break;
	}

	return 0;
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
	
	MESA_load_profile_int_def(conffile, "MAAT","APP_ID_TABLE_TYPE", &g_tsg_para.app_id_table_type, 1);

	MESA_load_profile_string_def(conffile, "MAAT", "PROFILE", maat_conffile, sizeof(maat_conffile), "./tsgconf/maat.conf");	
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

	//init static maat feather
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
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"PULL_RESULT", 
										"pull policy failed, hit: %s %s: %s policy_id: %d service: %d action: %d addr: %s",
										(label->result_type==PULL_KNI_RESULT) ? "KNI" : "FW",
										label->proto==PROTO_HTTP ? "host" : "sni",
										label->domain,
										label->result->config_id,
										label->result->service_id,
										label->result->action,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
	}
	else
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"PULL_RESULT",
									"pull policy failed, Not hit, label is %s addr: %s",
									(label==NULL) ? "NULL" : label->domain,
									(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
								);
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

	if(asn!=NULL)
	{
		ret=Maat_full_scan_string(maat_feather,
								g_tsg_para.table_id[idx],
								CHARSET_GBK,
								asn->asn,
								strlen(asn->asn),
								result,
								NULL,
								result_num,
								mid,
								a_stream->threadnum);
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
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"SCAN_IP_ASN",
										"No hit IP_ASN: %s scan ret: %d table_name: %s addr: %s",
										asn->asn,
										ret,
										g_tsg_para.table_name[idx],
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
	}	
	else
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_ASN",
									"IP_ASN is NULL scan ret: %d table_name: %s addr: %s",
									ret,
									g_tsg_para.table_name[idx],
									(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
								);
	}

	return (ret>0 ? ret : 0);
}


int tsg_scan_ip_location(Maat_feather_t maat_feather, const struct streaminfo *a_stream, struct _location_info_t *location, enum MASTER_TABLE idx, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;
	char buff[1024]={0};
	
	if(location!=NULL)
	{
		snprintf(buff, sizeof(buff), "%s.%s.", location->country_full, location->city_full);
		ret=Maat_full_scan_string(maat_feather,
								g_tsg_para.table_id[idx],
								CHARSET_GBK,
								buff,
								strlen(buff),
								result,
								NULL,
								result_num,
								mid,
								a_stream->threadnum);
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
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"SCAN_IP_LOCATION",
										"No hit IP_LOCATION: %s scan ret: %d table_name: %s addr: %s",
										buff,
										ret,
										g_tsg_para.table_name[idx],
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
	}	
	else
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
									RLOG_LV_DEBUG,
									"SCAN_IP_LOCATION",
									"IP_LOCATION is NULL scan ret: %d table_name: %s addr: %s",
									ret,
									g_tsg_para.table_name[idx],
									(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
								);
	}

	return (ret>0 ? ret : 0);
}

int tsg_scan_nesting_addr(Maat_feather_t maat_feather, const struct streaminfo *a_stream, tsg_protocol_t proto, scan_status_t *mid, Maat_rule_t*result, int result_num)
{
	int ret=0;
	struct ipaddr t_addr;
	struct ipaddr* p_addr=NULL;
	int hit_num=0,tans_proto=0;
	int is_scan_addr=1, maat_ret=0,found_pos=0;
	const struct streaminfo *cur_stream = a_stream;
	struct _session_attribute_label_t *internal_label=NULL;

	if(result==NULL || result_num<=0 || a_stream==NULL || maat_feather==NULL)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
								RLOG_LV_DEBUG,
								"SCAN_NESTING_ADDR",
								"result==NULL || result_num<=0 || maat_feather==NULL || a_stream==NULL"
								);
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
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&cur_stream->addr, cur_stream->threadnum) : ""),
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
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&cur_stream->addr, cur_stream->threadnum) : ""),
											maat_ret
										);	
			}
		}
		
		cur_stream = cur_stream->pfather;
		
	}while(cur_stream != NULL && hit_num < result_num);

	if(hit_num<result_num && proto>PROTO_UNKONWN && proto<PROTO_MAX)
	{
		if(g_tsg_para.app_id_table_type==0)
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
											a_stream->threadnum
										);
		}
		else
		{
			unsigned int proto_id=proto_str2id(proto);
			if(proto_id>0)
			{
				maat_ret=Maat_scan_intval(maat_feather,
											g_tsg_para.table_id[TABLE_APP_ID],
											proto_id,
											result+hit_num,
											result_num-hit_num,
											mid,
											a_stream->threadnum
										);
			}
		}
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
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);

			hit_num+=maat_ret;
		}
		else
		{
			MESA_handle_runtime_log(g_tsg_para.logger,
										RLOG_LV_DEBUG,
										"SCAN_PROTO",
										"No hit PROTO: %s(%d) scan ret: %d addr: %s",
										g_tsg_proto_string[proto].type,
										proto_str2id(proto),
										maat_ret,
										(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
									);
		}
	}

	internal_label=(struct _session_attribute_label_t *)project_req_get_struct(a_stream, g_tsg_para.internal_project_id);
	if(internal_label==NULL)
	{
		internal_label=(struct _session_attribute_label_t *)calloc(1, sizeof(struct _session_attribute_label_t));
		memset(internal_label, 0, sizeof(struct _session_attribute_label_t));
	}

	if(hit_num<result_num)
	{
		tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_USER_DEFINED], (void **)&(internal_label->client_location), (void **)&(internal_label->server_location));
		tsg_get_ip_location(a_stream, g_tsg_para.table_id[TABLE_LOCATION_BUILT_IN], (void **)&(internal_label->client_location), (void **)&(internal_label->server_location));
		
		hit_num+=tsg_scan_ip_location(maat_feather, a_stream, internal_label->client_location, TABLE_SRC_LOCATION, mid, result+hit_num, result_num-hit_num);
		hit_num+=tsg_scan_ip_location(maat_feather, a_stream, internal_label->server_location, TABLE_DST_LOCATION, mid, result+hit_num, result_num-hit_num);
	}

	if(hit_num<result_num)
	{
		tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_USER_DEFINED], (void **)&(internal_label->client_asn), (void **)&(internal_label->server_asn));
		tsg_get_ip_asn(a_stream, g_tsg_para.table_id[TABLE_ASN_BUILT_IN], (void **)&(internal_label->client_asn), (void **)&(internal_label->server_asn));
		
		hit_num+=tsg_scan_ip_asn(maat_feather, a_stream, internal_label->client_asn, TABLE_SRC_ASN, mid, result+hit_num, result_num-hit_num);
		hit_num+=tsg_scan_ip_asn(maat_feather, a_stream, internal_label->server_asn, TABLE_DST_ASN, mid, result+hit_num, result_num-hit_num);
	}


	if(hit_num<result_num)
	{
		tsg_get_subscribe_id(a_stream, &internal_label->client_subscribe_id, &internal_label->server_subscribe_id);
		
		if(internal_label->client_subscribe_id!=NULL)
		{
			maat_ret=Maat_full_scan_string(maat_feather,
										g_tsg_para.table_id[TABLE_SUBSCRIBER_ID],
										CHARSET_GBK,
										internal_label->client_subscribe_id->subscribe_id,
										strlen(internal_label->client_subscribe_id->subscribe_id),
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
											internal_label->client_subscribe_id->subscribe_id,
											maat_ret,
											result[hit_num].config_id,
											result[hit_num].service_id,
											(unsigned char)result[hit_num].action,
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
										);

				hit_num+=maat_ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"No hit source subscribe id: %s scan ret: %d addr: %s",
											internal_label->client_subscribe_id->subscribe_id,
											maat_ret,
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
										);
			}
		}
		
		if(internal_label->server_subscribe_id!=NULL)
		{
			maat_ret=Maat_full_scan_string(maat_feather,
										g_tsg_para.table_id[TABLE_SUBSCRIBER_ID],
										CHARSET_GBK,
										internal_label->server_subscribe_id->subscribe_id,
										strlen(internal_label->server_subscribe_id->subscribe_id),
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
											internal_label->server_subscribe_id->subscribe_id,
											maat_ret,
											result[hit_num].config_id,
											result[hit_num].service_id,
											(unsigned char)result[hit_num].action,
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
										);

				hit_num+=maat_ret;
			}
			else
			{
				MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_DEBUG,
											"SCAN_SUBSCRIBER",
											"No hit dest subscribe id: %s scan ret: %d addr: %s",
											internal_label->server_subscribe_id->subscribe_id,
											maat_ret,
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
										);
			}
		}
	}

	ret=project_req_add_struct((struct streaminfo *)a_stream, g_tsg_para.internal_project_id, (void *)internal_label);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger,
											RLOG_LV_FATAL,
											"ADD_INTERNAL_LABEL",
											"Add internal label failed, ret: %d addr: %s",
											ret,
											(g_tsg_para.level<RLOG_LV_FATAL ? printaddr(&a_stream->addr, a_stream->threadnum) : "")
										);
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
			case	PROTO_QUIC:
				idx=TABLE_QUIC_SNI;
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

int tsg_get_fqdn_category_id(Maat_feather_t maat_feather, char *fqdn, unsigned int *category_id, int category_id_num, void *logger, int thread_seq)
{
	int i=0,ret=0;
	struct _fqdn_category_t *ex_data_array[8]={0};

	if(category_id!=NULL && category_id_num>0)
	{
		ret=Maat_fqdn_plugin_get_EX_data(maat_feather, g_tsg_para.table_id[TABLE_FQDN_CAT_USER_DEFINED], fqdn, (MAAT_PLUGIN_EX_DATA *)ex_data_array, 8);
		if(ret>0)
		{
			for(i=0; i<ret; i++)
			{
				if(i<category_id_num)
				{
					category_id[i]=ex_data_array[i]->category_id;
				}
				
				fqdn_cat_free_data(g_tsg_para.table_id[TABLE_FQDN_CAT_USER_DEFINED], (MAAT_PLUGIN_EX_DATA *)&(ex_data_array[i]), 0, logger);
			}

			return i<category_id_num ? i : category_id_num;
		}
		
		ret=Maat_fqdn_plugin_get_EX_data(maat_feather, g_tsg_para.table_id[TABLE_FQDN_CAT_BUILT_IN], fqdn, (MAAT_PLUGIN_EX_DATA *)ex_data_array, 8);
		if(ret>0)
		{
			for(i=0; i<ret && i<category_id_num; i++)
			{
				if(i<category_id_num)
				{
					category_id[i]=ex_data_array[i]->category_id;
				}

				fqdn_cat_free_data(g_tsg_para.table_id[TABLE_FQDN_CAT_BUILT_IN], (MAAT_PLUGIN_EX_DATA *)&(ex_data_array[i]), 0, logger);
			}

			return i<category_id_num ? i : category_id_num;
		}
	}
	
	return 0;
}

