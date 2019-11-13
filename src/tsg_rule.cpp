
#include "MESA/MESA_handle_logger.h"
#include "Maat_rule.h"
#include "Maat_command.h"
#include "ssl_utils.h"

#define KNI_DOMAIN_MAX 	256

enum kni_protocol{
    KNI_PROTOCOL_UNKNOWN = 0,
	KNI_PROTOCOL_SSL,
	KNI_PROTOCOL_HTTP,
};

enum kni_scan_table
{
    TSG_FIELD_SSL_SNI,
	TSG_FIELD_HTTP_HOST,
	SCAN_TABLE_MAX
};

struct kni_protocol_identify_result{
	int protocol;
	char domain[KNI_DOMAIN_MAX];
	int domain_len;
};

Maat_feather_t g_kni_maat_feather;
const char *g_kni_scan_table_name[SCAN_TABLE_MAX];
int g_kni_scan_tableid[SCAN_TABLE_MAX] = {0};

static void protocol_identify(char *buff, int buff_len, struct kni_protocol_identify_result *result){
    result->protocol = KNI_PROTOCOL_UNKNOWN;
	//TODO:  http: get from http protocol plugin

	//ssl
	enum chello_parse_result chello_status = CHELLO_PARSE_INVALID_FORMAT;
	struct ssl_chello *chello = NULL;
	chello = ssl_chello_parse((const unsigned char*)buff, buff_len, &chello_status);
	if(chello_status == CHELLO_PARSE_SUCCESS){
		result->protocol = KNI_PROTOCOL_SSL;
		if(chello->sni == NULL){
			result->domain_len = 0;
		}
		else{
			result->domain_len = strnlen(chello->sni, KNI_DOMAIN_MAX);
			strncpy(result->domain, chello->sni, strnlen(chello->sni, sizeof(result->domain) - 1));
		}
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

//return -1 if failed, return 0 on success
int tsg_scan_shared_policy(Maat_feather_t maat_feather, void *pkt, int pkt_len, Maat_rule_t *result, int result_num, scan_status_t *mid, void *logger, int thread_seq){
    struct kni_protocol_identify_result protocol_identify_res;
    memset(&protocol_identify_res, 0, sizeof(protocol_identify_res));
    protocol_identify((char*)pkt, pkt_len, &protocol_identify_res);
    switch(protocol_identify_res.protocol){
		case KNI_PROTOCOL_UNKNOWN:
			//TODO: field_stat refactor
            //FS_operate(g_kni_fs_handle->handle, g_kni_fs_handle->fields[KNI_FIELD_STMERR_UNSUPPORTED_PROTOCOL], 0, FS_OP_ADD, 1);
			//pmeinfo->error = STREAM_ERROR_UNSUPPORTED_PROTOCOL;
			return -1;
		case KNI_PROTOCOL_SSL:
            return Maat_full_scan_string(g_kni_maat_feather, g_kni_scan_tableid[TSG_FIELD_SSL_SNI], CHARSET_UTF8, 
                                        protocol_identify_res.domain, protocol_identify_res.domain_len,
									    result, NULL, result_num, mid, thread_seq);
		case KNI_PROTOCOL_HTTP:
            return Maat_full_scan_string(g_kni_maat_feather, g_kni_scan_tableid[TSG_FIELD_HTTP_HOST], CHARSET_UTF8, 
                                        protocol_identify_res.domain, protocol_identify_res.domain_len,
									    result, NULL, result_num, mid, thread_seq);
		default:
            return -1;
	}
}