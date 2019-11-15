
#include "MESA/MESA_handle_logger.h"
#include "Maat_rule.h"
#include "Maat_command.h"
#include "tsg_ssl_utils.h"
#include "tsg_rule.h"

enum kni_scan_table{
    TSG_FIELD_SSL_SNI,
	TSG_FIELD_HTTP_HOST,
	SCAN_TABLE_MAX
};

Maat_feather_t g_kni_maat_feather;
const char *g_kni_scan_table_name[SCAN_TABLE_MAX];
int g_kni_scan_tableid[SCAN_TABLE_MAX] = {0};

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
    g_kni_maat_feather = maat_feather;
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


//return value: -1: failed, 0: not hit, >0: hit count 
int tsg_scan_shared_policy(Maat_feather_t maat_feather, void *pkt, int pkt_len, Maat_rule_t *result, int result_num, 
			struct _identify_info *identify_info, scan_status_t *mid, void *logger, int thread_seq){
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
	return Maat_full_scan_string(g_kni_maat_feather, tableid, CHARSET_UTF8, identify_info->domain, identify_info->domain_len,
									result, NULL, result_num, mid, thread_seq);
}