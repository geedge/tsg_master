#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_bridge.h"
#include "tsg_variable.h"
#include "tsg_sync_state.h"
#include "tsg_rule_internal.h"

extern int session_app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data);
extern int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data);
extern int tm_get_ssl_ja3_fingerprint(const struct streaminfo *a_stream, char **ja3_fingerprint);
extern int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *s_chaining_rules, size_t n_s_chaining_rules, int thread_seq);
extern int matched_shaping_rules_deal(const struct streaminfo * a_stream, struct maat_rule * shaping_results, size_t n_shaping_results, int thread_seq);

struct bridge_info
{
	int id;
	char name[MAX_BRIDGE_NAME_LEN];
	stream_bridge_free_cb_t *free_cb;
	stream_bridge_sync_cb_t *sync_cb;
};

struct bridge_info g_tm_bridge_para[BRIDGE_TYPE_MAX];

void session_sce_log_update_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if (data != NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data = NULL;
	}

	return;
}

void session_shaper_log_update_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if (data != NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data = NULL;
	}

	return;
}

void session_proxy_log_update_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	struct proxy_log_update *proxy = (struct proxy_log_update *)data;
	if (proxy != NULL)
	{

		if (proxy->ssl_downstream_version != NULL)
		{
			dictator_free(a_stream->threadnum, (void *)proxy->ssl_downstream_version);
			proxy->ssl_downstream_version = NULL;
		}

		if (proxy->ssl_error != NULL)
		{
			dictator_free(a_stream->threadnum, (void *)proxy->ssl_error);
			proxy->ssl_error = NULL;
		}

		if (proxy->ssl_passthrough_reason != NULL)
		{
			dictator_free(a_stream->threadnum, (void *)proxy->ssl_passthrough_reason);
			proxy->ssl_passthrough_reason = NULL;
		}

		if (proxy->ssl_upstream_version != NULL)
		{
			dictator_free(a_stream->threadnum, (void *)proxy->ssl_upstream_version);
			proxy->ssl_upstream_version = NULL;
		}

		dictator_free(a_stream->threadnum, (void *)proxy);
		proxy = NULL;
	}

	data = NULL;
	return;
}

void session_runtime_process_context_free_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	struct session_runtime_process_context *srt_process_context=(struct session_runtime_process_context *)data;
	if(srt_process_context!=NULL)
	{
		if(srt_process_context->domain!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)srt_process_context->domain);
			srt_process_context->domain=NULL;
		}

		if(srt_process_context->quic_ua!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)srt_process_context->quic_ua);
			srt_process_context->quic_ua=NULL;
		}

		if(srt_process_context->mid!=NULL)
		{
			tsg_maat_state_free(srt_process_context->mid);
			srt_process_context->mid=NULL;
		}

		dictator_free(a_stream->threadnum, (void *)srt_process_context);
		srt_process_context=NULL;
	}

	data=NULL;

	return ;
}

void session_runtime_action_context_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)data;
		if(srt_action_context->para!=NULL)
		{
			switch(srt_action_context->method_type)
			{
				case	TSG_METHOD_TYPE_RATE_LIMIT:
					destroy_bucket(&(srt_action_context->bucket), a_stream->threadnum);
					break;
				default:
					break;
			}
		}
		
		if (srt_action_context->l4_protocol != NULL)
		{
			dictator_free(a_stream->threadnum, srt_action_context->l4_protocol);
		}
		
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}

	return ;
}

void session_matched_rules_free_by_bridge(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

void session_segment_id_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

void session_gather_app_results_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

void session_runtime_attribute_free(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)data;

	if(srt_attribute!=NULL)
	{
		plugin_ex_data_asn_number_free(srt_attribute->client_asn);
		plugin_ex_data_asn_number_free(srt_attribute->server_asn);

		plugin_ex_data_location_free(srt_attribute->client_location);
		plugin_ex_data_location_free(srt_attribute->server_location);

		plugin_ex_data_subscriber_id_free(srt_attribute->client_subscribe_id);
		plugin_ex_data_subscriber_id_free(srt_attribute->server_subscribe_id);

		plugin_ex_data_gtp_c_free(srt_attribute->user_info);

		plugin_ex_data_tunnel_endpoint_free(srt_attribute->client_endpoint);
		plugin_ex_data_tunnel_endpoint_free(srt_attribute->server_endpoint);

		if(srt_attribute->ja3_fingerprint!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)srt_attribute->ja3_fingerprint);
			srt_attribute->ja3_fingerprint=NULL;
		}

		if(srt_attribute->proxy_tcp_attr != NULL)
		{
			dictator_free(a_stream->threadnum, (void *)srt_attribute->proxy_tcp_attr);
			srt_attribute->proxy_tcp_attr = NULL;
		}

		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

int session_async_bridge_set_data(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(a_stream==NULL || bridge_id<0)
	{
		return 0;
	}
	
	int ret=stream_bridge_async_data_put(a_stream, bridge_id, data);
	if(ret<0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "BRIDGE", "Add project failed, bridge_id: %d addr: %s", bridge_id, PRINTADDR(a_stream, g_tsg_para.level));
		return 0;
	}

	return 1;
}

void *session_async_bridge_get_data(const struct streaminfo *a_stream, int bridge_id)
{
	if(a_stream!=NULL && bridge_id>=0)
	{
		return stream_bridge_async_data_get(a_stream, bridge_id);
	}

	return NULL;
}

const struct session_runtime_attribute *session_runtime_attribute_new(const struct streaminfo *a_stream)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id);
	if(srt_attribute==NULL)
	{
		srt_attribute=(struct session_runtime_attribute *)dictator_malloc(a_stream->threadnum, sizeof(struct session_runtime_attribute));
		memset(srt_attribute, 0, sizeof(struct session_runtime_attribute));

		int ret=session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, (void *)srt_attribute);
		if(ret<0)
		{
			session_runtime_attribute_free(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id, (void *)srt_attribute);
			srt_attribute=NULL;
			return NULL;
		}
	}

	return (const struct session_runtime_attribute *)srt_attribute;
}

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo *a_stream)
{
	return (struct session_runtime_attribute *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].id);
}

void srt_attribute_free_proxy_tcp_option(const struct streaminfo *a_stream)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_get(a_stream);
	if(srt_attribute!=NULL && srt_attribute->proxy_tcp_attr!=NULL)
	{
		dictator_free(a_stream->threadnum, (void *)srt_attribute->proxy_tcp_attr);
		srt_attribute->proxy_tcp_attr=NULL;
	}
}

int srt_attribute_set_establish_latecy(const struct streaminfo *a_stream)
{
	unsigned long long create_time=0;
	unsigned long long current_time=0;
	int size=sizeof(create_time);

	int ret=MESA_get_stream_opt(a_stream, MSO_STREAM_CREATE_TIMESTAMP_MS, (void *)&create_time, &size);
	if(ret<0)
	{
		return 0;
	}
	
	size=sizeof(current_time);
	ret=sapp_get_platform_opt(SPO_CURTIME_TIMET_MS, (void *)&current_time, &size);
	if(ret<0)
	{
		return 0;
	}

	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->establish_latency_ms=current_time-create_time;
		return 1;
	}
	
	return 0;
}

int srt_attribute_set_protocol(const struct streaminfo *a_stream, TSG_PROTOCOL protocol)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->proto=protocol;
		return 1;
	}
	
	return 0;
}

int srt_attribute_set_reponse_size(const struct streaminfo *a_stream, int http_action_file_size)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->http_action_file_size=http_action_file_size;
		return 1;
	}
	
	return 0;
}

int srt_attribute_set_ja3_fingprint(const struct streaminfo *a_stream, const char *ja3_fingerprint)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->ja3_fingerprint=ja3_fingerprint;
		return 1;
	}
	
	return 0;
}

int srt_atttribute_set_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info *user_info)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->user_info=user_info;
		return 1;
	}
	
	return 0;
}

int srt_atttribute_set_subscriber_id(const struct streaminfo *a_stream, struct subscribe_id_info *c_subscribe_id, struct subscribe_id_info *s_subscribe_id)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->client_subscribe_id=c_subscribe_id;
		srt_attribute->server_subscribe_id=s_subscribe_id;
		return 1;
	}
	
	return 0;
}

int srt_atttribute_set_ip_asn(const struct streaminfo *a_stream, struct asn_info *c_asn, struct asn_info *s_asn)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->client_asn=c_asn;
		srt_attribute->server_asn=s_asn;
		return 1;
	}
	
	return 0;
}

int srt_atttribute_set_ip_location(const struct streaminfo *a_stream, struct location_info *c_location, struct location_info *s_location)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->client_location=c_location;
		srt_attribute->server_location=s_location;
		return 1;
	}
	
	return 0;
}

int srt_attribute_set_category_ids(const struct streaminfo *a_stream, unsigned int *category_ids, int n_category_ids)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		if(n_category_ids<=0 || n_category_ids>MAX_CATEGORY_ID_NUM)
		{
			return 0;
		}
		memcpy(srt_attribute->fqdn_category_ids, category_ids, sizeof(unsigned int)*n_category_ids);
		srt_attribute->n_fqdn_category_ids=n_category_ids;

		return 1;
	}
	
	return 0;
}

int srt_attribute_set_flags(const struct streaminfo *a_stream, unsigned long s_flags)
{
	struct session_runtime_attribute *srt_attribute=(struct session_runtime_attribute *)session_runtime_attribute_new(a_stream);
	if(srt_attribute)
	{
		srt_attribute->session_flags=s_flags;
		return 1;
	}
	
	return 0;
}

const char *srt_attribute_get_ja3_fingerprint(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const char *)(srt_attribute->ja3_fingerprint);
	}

	return NULL;
}
const char *srt_attribute_get_client_subscriber_id(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const char *)(srt_attribute->client_subscribe_id);
	}

	return NULL;
}
const char *srt_attribute_get_server_subscriber_id(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const char *)(srt_attribute->server_subscribe_id);
	}

	return NULL;
}

const struct asn_info *srt_attribute_get_client_ip_asn(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const struct asn_info *)(srt_attribute->client_asn);
	}

	return NULL;
}

const struct asn_info *srt_attribute_get_server_ip_asn(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const struct asn_info *)(srt_attribute->server_asn);
	}

	return NULL;
}

const struct location_info *srt_attribute_get_client_ip_location(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const struct location_info *)(srt_attribute->client_location);
	}

	return NULL;
}

const struct location_info *srt_attribute_get_server_ip_location(const struct session_runtime_attribute *srt_attribute)
{
	if(srt_attribute)
	{
		return (const struct location_info *)(srt_attribute->server_location);
	}

	return NULL;
}

size_t srt_attribute_get_category_ids(const struct session_runtime_attribute *srt_attribute, unsigned int *category_ids, size_t n_category_ids)
{
	if(srt_attribute==NULL || srt_attribute->n_fqdn_category_ids==0 || category_ids==NULL || n_category_ids==0)
	{
		return 0;
	}

	size_t n_real_category_ids=MIN(n_category_ids, srt_attribute->n_fqdn_category_ids);
	memcpy(category_ids, srt_attribute->fqdn_category_ids, n_real_category_ids*sizeof(unsigned int));

	return n_real_category_ids;
}

int session_runtime_process_context_async(const struct streaminfo *a_stream, void *data)
{
	return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, data);
}

const struct session_runtime_process_context *session_runtime_process_context_new(const struct streaminfo *a_stream)
{
	struct session_runtime_process_context *srt_attribute=(struct session_runtime_process_context *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id);
	if(srt_attribute==NULL)
	{
		srt_attribute=(struct session_runtime_process_context *)dictator_malloc(a_stream->threadnum, sizeof(struct session_runtime_process_context));
		memset(srt_attribute, 0, sizeof(struct session_runtime_process_context));

		int ret=session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, (void *)srt_attribute);
		if(ret<0)
		{
			session_runtime_process_context_free_cb(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, (void *)srt_attribute);
			srt_attribute=NULL;
			return NULL;
		}
	}

	return (const struct session_runtime_process_context *)srt_attribute;
}

const struct session_runtime_process_context *session_runtime_process_context_get(const struct streaminfo *a_stream)
{
	return (struct session_runtime_process_context *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id);
}

void session_runtime_process_context_free(const struct streaminfo *a_stream)
{
	const struct session_runtime_process_context *srt_process_context=session_runtime_process_context_get(a_stream);
	if(srt_process_context!=NULL)
	{
		session_runtime_process_context_free_cb(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].id, (void *)srt_process_context);
		session_runtime_process_context_async(a_stream, NULL);
	}
}

enum TSG_PROTOCOL srt_process_context_get_protocol(const struct session_runtime_process_context *srt_process_context)
{
	if(srt_process_context!=NULL)
	{
		return srt_process_context->proto;
	}
	
	return PROTO_UNKONWN;
}

const char *srt_process_context_get_domain(const struct session_runtime_process_context *srt_process_context)
{
	if(srt_process_context!=NULL)
	{
		return (const char *)(srt_process_context->domain);
	}
	
	return NULL;
}

const char *srt_process_context_get_http_url(const struct session_runtime_process_context *srt_process_context)
{
	if(srt_process_context!=NULL && srt_process_context->proto==PROTO_HTTP)
	{
		return (const char *)(srt_process_context->http_url);
	}
	
	return NULL;
}

const char *srt_process_context_get_quic_ua(const struct session_runtime_process_context *srt_process_context)
{
	if(srt_process_context!=NULL && srt_process_context->proto==PROTO_QUIC)
	{
		return (const char *)(srt_process_context->quic_ua);
	}
	
	return NULL;
}

unsigned char srt_process_context_get_hitted_allow_flag(const struct session_runtime_process_context *srt_process_context)
{
	if(srt_process_context!=NULL)
	{
		return srt_process_context->is_hitted_allow;
	}
	
	return 0;
}

int session_runtime_action_context_async(const struct streaminfo *a_stream, void *data)
{
	return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id, data);
}

const struct session_runtime_action_context *session_runtime_action_context_new(const struct streaminfo *a_stream)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(a_stream->threadnum, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));

		int ret=session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id, (void *)srt_action_context);
		if(ret<0)
		{
			session_runtime_action_context_free(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id, (void *)srt_action_context);
			srt_action_context=NULL;
			return NULL;
		}
	}

	return (const struct session_runtime_action_context *)srt_action_context;
}

const struct session_runtime_action_context *session_runtime_action_context_get(const struct streaminfo *a_stream)
{
	return (const struct session_runtime_action_context *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].id);
}

int srt_action_context_set_after_n_packet(const struct streaminfo *a_stream, int after_n_packets, int thread_seq)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_stream);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)srt_action_context);
	}
			
	srt_action_context->hited_para.after_n_packets=after_n_packets;
	
	return 1;
}

int srt_action_context_set_hitted_app_id(const struct streaminfo *a_stream, int hited_app_id, int thread_seq)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_stream);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)srt_action_context);
	}
			
	srt_action_context->hited_para.hited_app_id=hited_app_id;
	
	return 1;
}

int srt_action_context_set_l7_protocol(const struct streaminfo *a_stream, enum TSG_PROTOCOL protocol, int thread_seq)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_stream);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)srt_action_context);
	}
			
	srt_action_context->protocol=protocol;
	
	return 1;
}

int srt_action_context_set_rule_method(const struct streaminfo *a_stream, enum TSG_METHOD_TYPE method_type, int thread_seq)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_stream);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)srt_action_context);
	}

	if(method_type==TSG_METHOD_TYPE_SHUNT)
	{
		if(srt_action_context->method_type==TSG_METHOD_TYPE_RATE_LIMIT)
		{
			destroy_bucket(&(srt_action_context->bucket), thread_seq);
			srt_action_context->bucket=NULL;
		}
		srt_action_context->method_type=method_type;
	}

	switch(srt_action_context->method_type)
	{
		case	TSG_METHOD_TYPE_UNKNOWN:
		case	TSG_METHOD_TYPE_DEFAULT:
		case	TSG_METHOD_TYPE_MIRRORED:
			srt_action_context->method_type=method_type;
			break;
		default:
			return 0;
			break;
	}

	return 1;
}

int srt_action_context_set_leaky_bucket(const struct streaminfo *a_stream, struct leaky_bucket *bucket, int thread_seq)
{
	struct session_runtime_action_context *srt_action_context=(struct session_runtime_action_context *)session_runtime_action_context_new(a_stream);
	if(srt_action_context==NULL)
	{
		srt_action_context=(struct session_runtime_action_context *)dictator_malloc(thread_seq, sizeof(struct session_runtime_action_context));
		memset(srt_action_context, 0, sizeof(struct session_runtime_action_context));
		session_runtime_action_context_async(a_stream, (void *)srt_action_context);
	}

	switch(srt_action_context->method_type)
	{
		case	TSG_METHOD_TYPE_RATE_LIMIT:
			return 1;
			break;
		case	TSG_METHOD_TYPE_DEFAULT:
		case	TSG_METHOD_TYPE_UNKNOWN:
			break;
		default:
			return 0;
			break;
	}

	srt_action_context->method_type=TSG_METHOD_TYPE_RATE_LIMIT;
	srt_action_context->bucket=bucket;

	return 1;
}

char srt_action_context_get_direction(const struct session_runtime_action_context *srt_action_context)
{
	if(srt_action_context!=NULL)
	{
		return srt_action_context->direction;
	}

	return -1;
}

enum TSG_METHOD_TYPE srt_action_context_get_method_type(const struct session_runtime_action_context *srt_action_context)
{
	if(srt_action_context!=NULL)
	{
		return srt_action_context->method_type;
	}

	return TSG_METHOD_TYPE_UNKNOWN;
}


int session_mirror_packets_sync(const struct streaminfo *a_stream, struct maat_rule *rules, struct mirrored_vlan *vlan)
{
	struct tsg_notify_data notify_data={0};

	notify_data.compile_id=rules->rule_id;
	notify_data.type=NOTIFY_TYPE_MIRRORED;
	notify_data.vlan=vlan;
	stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].id, (void *)&(notify_data));

	return 1;
}

int session_capture_packets_sync(const struct streaminfo *a_stream, struct maat_rule *result, int depth)
{
	struct tsg_notify_data notify_data={0};

	notify_data.compile_id=result->rule_id;
	notify_data.type=NOTIFY_TYPE_CAPTURE;
	notify_data.capture_depth=depth;
	stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].id, (void *)&(notify_data));

	return 1;
}

size_t session_matched_rules_copy(const struct streaminfo *a_stream, enum TSG_SERVICE service, struct maat_rule *rules, size_t n_rules)
{
	if(rules==NULL || n_rules==0)
	{
		return 0;
	}

	struct matched_policy_rules *matched_policy=NULL;
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			matched_policy=(struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].id);
			break;
		case	TSG_SERVICE_CHAINING:
			matched_policy=(struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id);
			break;
		case	TSG_SERVICE_SHAPING:
			matched_policy=(struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id);
			break;
		case	TSG_SERVICE_INTERCEPT:
			matched_policy=(struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id);
			break;
		default:
			break;
	}

	if(matched_policy!=NULL)
	{
		size_t num=MIN(matched_policy->n_rules, n_rules);
		memcpy(rules, matched_policy->rules, num*sizeof(struct maat_rule));
		return num;
	}

	return 0;
}

const struct matched_policy_rules *session_matched_rules_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			return (struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].id);
		case	TSG_SERVICE_CHAINING:
			return (struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id);
		case	TSG_SERVICE_SHAPING:
			return (struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id);
		case	TSG_SERVICE_INTERCEPT:
			return (struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id);
		case 	TSG_SERVICE_SIGNATURE:
			return (struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].id);
		default:
			break;
	}

	return NULL;
}

int session_matched_rules_sync(const struct streaminfo *a_stream, TSG_SERVICE service, void *data)
{
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			break;
		case	TSG_SERVICE_CHAINING:
			return stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id, data);
		case	TSG_SERVICE_SHAPING:
			return stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id, data);
		case	TSG_SERVICE_INTERCEPT:
			return stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id, data);
		case	TSG_SERVICE_SIGNATURE:
			return stream_bridge_sync_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].id, data);
		default:
			break;
	}

	return 0;
}

int session_matched_rules_async(const struct streaminfo *a_stream, TSG_SERVICE service, void *data)
{
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].id, data);
			break;
		case	TSG_SERVICE_CHAINING:
			return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id, data);
			break;
		case	TSG_SERVICE_SHAPING:
			return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id, data);
			break;
		case	TSG_SERVICE_INTERCEPT:
			return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id, data);
		case	TSG_SERVICE_SIGNATURE:
			return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].id, data);
		default:
			break;
	}

	return 0;
}

void session_matched_rules_free(const struct streaminfo *a_stream, TSG_SERVICE service, void *data)
{
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].id, data);
			break;
		case	TSG_SERVICE_CHAINING:
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].id, data);
			break;
		case	TSG_SERVICE_SHAPING:
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].id, data);
			break;
		case	TSG_SERVICE_INTERCEPT:
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].id, data);
			break;
		case	TSG_SERVICE_SIGNATURE:
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].id, data);
		default:
			break;
	}
}

void session_matched_rules_notify(const struct streaminfo *a_stream, TSG_SERVICE service, struct maat_rule *rules, size_t n_rules, int thread_seq)
{
	if(rules==NULL || n_rules==0)
	{
		return ;
	}

	enum BRIDGE_TYPE bridge_idx;
	switch(service)
	{
		case	TSG_SERVICE_SECURITY:
			bridge_idx=BRIDGE_TYPE_SECURITY_RESULT;
			break;
		case	TSG_SERVICE_INTERCEPT:
			//bridge_idx=BRIDGE_TYPE_INTERCEPT_RESULT;
			return;
		case	TSG_SERVICE_CHAINING:
			matched_service_chaining_rules_deal(a_stream, rules, n_rules, thread_seq);
			return;
		case	TSG_SERVICE_SHAPING:
			matched_shaping_rules_deal(a_stream, rules, n_rules, thread_seq);
			return;
		default:
			return ;
	}

	struct matched_policy_rules *matched_policy=(struct matched_policy_rules *)session_async_bridge_get_data(a_stream, g_tm_bridge_para[bridge_idx].id);
	if(matched_policy==NULL)
	{
		matched_policy=(struct matched_policy_rules *)dictator_malloc(thread_seq, sizeof(struct matched_policy_rules));
		memset(matched_policy, 0, sizeof(struct matched_policy_rules));

		int ret=session_async_bridge_set_data(a_stream, g_tm_bridge_para[bridge_idx].id, (void *)matched_policy);
		if(ret<0)
		{
			session_matched_rules_free_by_bridge(a_stream, g_tm_bridge_para[bridge_idx].id, (void *)matched_policy);
		}
	}
	
	size_t num=MIN(MAX_RESULT_NUM-matched_policy->n_rules, n_rules);
	for(size_t i=0; i<num; i++)
	{
		int repeat_result=0;
		for(size_t j=0; j<matched_policy->n_rules; j++)
		{
			if(rules[i].rule_id==matched_policy->rules[j].rule_id)
			{
				repeat_result=1;
				break;
			}
		}

		if(repeat_result==0)
		{
			memcpy(&(matched_policy->rules[matched_policy->n_rules++]), &(rules[i]), sizeof(struct maat_rule));
		}
	}

	return ;
}

void *session_mac_linkinfo_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_MAC_LINKINFO].id);
}

void *session_nat_c2s_linkinfo_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_NAT_C2S_LINKINFO].id);
}

void *session_nat_s2c_linkinfo_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_NAT_S2C_LINKINFO].id);
}

void *session_gather_app_results_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_GATHER_APP_RESULT].id);
}

int session_gather_app_results_async(const struct streaminfo *a_stream, void *data)
{
	return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_GATHER_APP_RESULT].id, data);
}

int session_control_segment_ids_async(const struct streaminfo *a_stream, void *data)
{
	return session_async_bridge_set_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SEGMENT_IDS].id, data);
}

void *session_control_segment_ids_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_SEGMENT_IDS].id);
}

void *session_conn_sketch_notify_data_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].id);
}

void *session_business_data_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_BUSINESS_S3_FILENAME].id);
}

void *session_session_flags_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_ASYNC_SESSION_FLAGS].id);
}

void *session_application_behavior_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_BEHAVIOR_RESULT].id);
}

void *session_mirrored_and_capture_packets_exec_result_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_POLICY_ACTION_PARA_EXEC_RESULT].id);
}

void *session_lua_user_defined_attribute_get(const struct streaminfo *a_stream)
{
	return session_async_bridge_get_data(a_stream, g_tm_bridge_para[BRIDGE_TYPE_APP_LUA_RESULT].id);
}

void *session_log_update_data_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	switch (service)
	{
		case TSG_SERVICE_INTERCEPT:
			return stream_bridge_async_data_get(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_PROXY].id);

		case TSG_SERVICE_CHAINING:
			return stream_bridge_async_data_get(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SCE].id);

		case TSG_SERVICE_SHAPING:
			return stream_bridge_async_data_get(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SHAPER].id);
			
		default:
			return NULL;
	}
}

int session_log_update_data_put(const struct streaminfo *a_stream, enum TSG_SERVICE service, void *data)
{
	switch (service)
	{
		case TSG_SERVICE_INTERCEPT:
			return stream_bridge_async_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_PROXY].id, data);

		case TSG_SERVICE_CHAINING:
			return stream_bridge_async_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SCE].id, data);

		case TSG_SERVICE_SHAPING:
			return stream_bridge_async_data_put(a_stream, g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SHAPER].id, data);

		default:
			return 0;
		}
}

int tsg_bridge_init(const char *conffile)
{
	MESA_load_profile_string_def(conffile, "BRIDGE", "APP_IDENTIFY_RESULT_BRIDGE", g_tm_bridge_para[BRIDGE_TYPE_SYNC_APP_IDENTIFY_RESULT].name, MAX_BRIDGE_NAME_LEN, "APP_IDENTIFY_RESULT_BRIDGE");
	g_tm_bridge_para[BRIDGE_TYPE_SYNC_APP_IDENTIFY_RESULT].sync_cb=session_app_identify_result_cb;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SKETCH_NOTIFY_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].name, MAX_BRIDGE_NAME_LEN, "TSG_CONN_SKETCH_NOTIFY_DATA");
	MESA_load_profile_string_def(conffile, "BRIDGE", "MASTER_NOTIFY_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].name, MAX_BRIDGE_NAME_LEN, "TSG_MASTER_NOTIFY_DATA");

	MESA_load_profile_string_def(conffile, "SESSION_FLAGS", "FLAGS_NOTIFY_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SYNC_SESSION_FLAGS].name, MAX_BRIDGE_NAME_LEN, "SESSION_FLAGS_SYNC_NOTIFY_DATA");
	g_tm_bridge_para[BRIDGE_TYPE_SYNC_SESSION_FLAGS].sync_cb=session_flags_identify_result_cb;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SHAPING_RESULT_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].name, MAX_BRIDGE_NAME_LEN, "NOTIFY_SHAPING_RESULT");
	g_tm_bridge_para[BRIDGE_TYPE_SHAPING_RESULT].free_cb=session_matched_rules_free_by_bridge;

	MESA_load_profile_string_def(conffile, "BRIDGE", "DATA_CONTEXT_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].name, MAX_BRIDGE_NAME_LEN, "TSG_DATA_CONTEXT");
	g_tm_bridge_para[BRIDGE_TYPE_SESSION_PROCESS_CONTEXT].free_cb=session_runtime_process_context_free_cb;

	MESA_load_profile_string_def(conffile, "BRIDGE", "ALL_RESULT_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].name, MAX_BRIDGE_NAME_LEN, "TSG_ALL_CONTEXT");
	g_tm_bridge_para[BRIDGE_TYPE_SESSION_ACTION_CONTEXT].free_cb=session_runtime_action_context_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "GATHER_APP_RESULT_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_GATHER_APP_RESULT].name, MAX_BRIDGE_NAME_LEN, "GATHER_APP_IDENTIFY_RESULT");
	g_tm_bridge_para[BRIDGE_TYPE_GATHER_APP_RESULT].free_cb=session_gather_app_results_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SECURITY_RESULT_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].name, MAX_BRIDGE_NAME_LEN, "TSG_POLICY_PRIORITY");
	g_tm_bridge_para[BRIDGE_TYPE_SECURITY_RESULT].free_cb=session_matched_rules_free_by_bridge;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SESSION_ATTRIBUTE_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].name, MAX_BRIDGE_NAME_LEN, "TSG_SESSION_ATTRIBUTE");
	g_tm_bridge_para[BRIDGE_TYPE_SESSION_ATTRIBUTE].free_cb=session_runtime_attribute_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "LINKINFO_FROM_MAC", g_tm_bridge_para[BRIDGE_TYPE_MAC_LINKINFO].name, MAX_BRIDGE_NAME_LEN, "mirror_linkinfo_from_mac");
	MESA_load_profile_string_def(conffile, "BRIDGE", "NAT_C2S_LINKINFO", g_tm_bridge_para[BRIDGE_TYPE_NAT_C2S_LINKINFO].name, MAX_BRIDGE_NAME_LEN, "common_link_info_c2s");
	MESA_load_profile_string_def(conffile, "BRIDGE", "NAT_S2C_LINKINFO", g_tm_bridge_para[BRIDGE_TYPE_NAT_S2C_LINKINFO].name, MAX_BRIDGE_NAME_LEN, "common_link_info_s2c");
	MESA_load_profile_string_def(conffile, "BRIDGE", "APP_LUA_SCRIPTS_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_APP_LUA_RESULT].name, MAX_BRIDGE_NAME_LEN, "LUA_USER_DEFINED_ATTRIBUTE");
	MESA_load_profile_string_def(conffile, "BRIDGE", "BUSINESS_S3_FILENAME", g_tm_bridge_para[BRIDGE_TYPE_BUSINESS_S3_FILENAME].name, MAX_BRIDGE_NAME_LEN, "TSG_BUSINESS_S3_FILENAME");
	MESA_load_profile_string_def(conffile, "BRIDGE", "APP_BEHAVIOR_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_APP_BEHAVIOR_RESULT].name, MAX_BRIDGE_NAME_LEN, "TSG_APPLICATION_BEHAVIOR");
	MESA_load_profile_string_def(conffile, "BRIDGE", "POLICY_ACTION_PARA_EXEC_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_POLICY_ACTION_PARA_EXEC_RESULT].name, MAX_BRIDGE_NAME_LEN, "TSG_NOTIFICATION_EXECUTION_RESULT");
	MESA_load_profile_string_def(conffile, "BRIDGE", "NOTIFY_ASYNC_FLAGS_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_ASYNC_SESSION_FLAGS].name, MAX_BRIDGE_NAME_LEN, "SESSION_FLAGS_ASYNC_NOTIFY_DATA");

	MESA_load_profile_string_def(conffile, "BRIDGE", "SYNC_APP_SIGNATURE_ID_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_APP_SIGNATURE_RESULT].name, MAX_BRIDGE_NAME_LEN, "TSG_SYNC_APP_SIGNATURE_ID");

	MESA_load_profile_string_def(conffile, "BRIDGE", "S_CHAINING_RESULT_BRIDGE_NAME",g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].name, MAX_BRIDGE_NAME_LEN, "SERVICE_CHAINING_RESULT");
	g_tm_bridge_para[BRIDGE_TYPE_SERVICE_CHAINING_RESULT].free_cb=session_matched_rules_free_by_bridge;

	MESA_load_profile_string_def(conffile, "BRIDGE", "INTERCEPT_RESULT_BRIDGE_NAME",g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].name, MAX_BRIDGE_NAME_LEN, "INTERCEPT_RESULT");
	g_tm_bridge_para[BRIDGE_TYPE_INTERCEPT_RESULT].free_cb=session_matched_rules_free_by_bridge;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SEGMENT_IDS_BRIDGE_NAME",g_tm_bridge_para[BRIDGE_TYPE_SEGMENT_IDS].name, MAX_BRIDGE_NAME_LEN, "SEGMENT_IDS");
	g_tm_bridge_para[BRIDGE_TYPE_SEGMENT_IDS].free_cb=session_segment_id_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SCE_LOG_UPDATE_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SCE].name, MAX_BRIDGE_NAME_LEN, "SCE_LOG_UPDATE");
	g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SCE].free_cb = session_sce_log_update_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "SHAPER_LOG_UPDATE_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SHAPER].name, MAX_BRIDGE_NAME_LEN, "SHAPER_LOG_UPDATE");
	g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_SHAPER].free_cb = session_shaper_log_update_free;

	MESA_load_profile_string_def(conffile, "BRIDGE", "PROXY_LOG_UPDATE_BRIDGE_NAME", g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_PROXY].name, MAX_BRIDGE_NAME_LEN, "PROXY_LOG_UPDATE");
	g_tm_bridge_para[BRIDGE_TYPE_LOG_UPDATE_PROXY].free_cb = session_proxy_log_update_free;

	for(int i=0; i<BRIDGE_TYPE_MAX; i++)
	{
		g_tm_bridge_para[i].id=stream_bridge_build(g_tm_bridge_para[i].name, "w");
		if(g_tm_bridge_para[i].id<0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_BRIDGE", "stream_bridge_build is error, bridge_name: %s", g_tm_bridge_para[i].name);
			return -1;
		}

		if(g_tm_bridge_para[i].sync_cb)
		{	
			int ret=stream_bridge_register_data_sync_cb(g_tm_bridge_para[i].id, g_tm_bridge_para[i].sync_cb);
			if(ret<0)
			{		
				MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "BRIDGE_SYNC_CB", "Register callback failed, bridge_name: %d",g_tm_bridge_para[i].name);
				return -1;
			}
		}

		if(g_tm_bridge_para[i].free_cb)
		{
			int ret=stream_bridge_register_data_free_cb(g_tm_bridge_para[i].id, g_tm_bridge_para[i].free_cb);
			if(ret<0)
			{		
				MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "BRIDGE_FREE_CB", "Register async free callback failed, bridge_name: %d", g_tm_bridge_para[i].name);
				return -1;
			}
		}
	}

	return 0;
}

