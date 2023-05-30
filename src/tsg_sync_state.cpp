#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MESA/cJSON.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_variable.h"
#include "tsg_sync_state.h"
#include "tsg_send_log.h"
#include "mpack.h"

static int mpack_init_map(const struct streaminfo *a_stream, mpack_writer_t *writer, const char *state, char **mpack_data, size_t *mpack_size)
{
	mpack_writer_init_growable(writer, mpack_data, mpack_size);
	mpack_build_map(writer);

	// tsync : 2.0
	mpack_write_cstr(writer, "tsync");
	mpack_write_cstr(writer, "2.0");

	// session_id
	mpack_write_cstr(writer, "session_id");
	mpack_write_u64(writer, tsg_get_stream_trace_id((struct streaminfo *)a_stream));

	// state
	mpack_write_cstr(writer, "state");
	mpack_write_cstr(writer, state);

	return 0;
}

static int mpack_send_pkt(const struct streaminfo *a_stream, mpack_writer_t *writer, char **mpack_data, size_t *mpack_size)
{
	int ret = 0;
	mpack_complete_map(writer); // mpack_init_map
	if (mpack_writer_destroy(writer) != mpack_ok)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "MPACK_WRITER", "An error occurred encoding the data!");
		return -1;
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "MSGPACK_BUFF", "send buff_len = %lu, state: %u", *mpack_size, (uint8_t)a_stream->opstate);
	ret = sapp_inject_ctrl_pkt((struct streaminfo *)a_stream, SIO_DEFAULT, *mpack_data, *mpack_size, a_stream->routedir);
	if (ret == -1)
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INJECT_CTRL_FAILED], 0, FS_OP_ADD, 1);
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "MSGPACK_BUFF_SEND", "An error occurred injecting the data! addr: %s", PRINTADDR(a_stream, g_tsg_para.level));
	}
	else
	{
		FS_operate(g_tsg_para.fs2_handle, g_tsg_para.fs2_field_id[TSG_FS2_INJECT_CTRL_SUCCESS], 0, FS_OP_ADD, 1);
	}
	
	free(*mpack_data);
	*mpack_data = NULL;
	*mpack_size = 0;
	return ret;
}

int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state)
{
	if (a_stream == NULL)
	{
		return -1;
	}

	char *mpack_data = NULL;
	size_t mpack_size = 0;
	mpack_writer_t writer;
	if (state == OP_STATE_PENDING)
	{
		mpack_init_map(a_stream, &writer, "opening", &mpack_data, &mpack_size);
	}
	else if (state == OP_STATE_CLOSE)
	{
		mpack_init_map(a_stream, &writer, "closing", &mpack_data, &mpack_size);
	}
	else
	{
		return -1;
	}

	return mpack_send_pkt(a_stream, &writer, &mpack_data, &mpack_size);
}

int tsg_sync_resetall_state(const struct streaminfo *a_stream)
{
	if (a_stream == NULL)
	{
		return -1;
	}

	char *mpack_data = NULL;
	size_t mpack_size = 0;
	mpack_writer_t writer;
	mpack_init_map(a_stream, &writer, "resetall", &mpack_data, &mpack_size);

	return mpack_send_pkt(a_stream, &writer, &mpack_data, &mpack_size);
}

static void mpack_append_string(mpack_writer_t *writer, char *str)
{
	if (str)
	{
		mpack_write_cstr(writer, str);
	}
	else
	{
		mpack_write_nil(writer);
	}

	return;
}

static void mpack_append_fqdn_cat_ids(mpack_writer_t *writer, struct fqdn_cat_id_val *array)
{
	int num = MIN(array->num, FQDN_CAT_ID_VALS);
	mpack_build_array(writer);
	for (int i = 0; i < num; i++)
	{
		mpack_write_u32(writer, array->value[i]);
	}
	mpack_complete_array(writer);

	return;
}

static void mpack_append_tcp_sids(mpack_writer_t *writer, struct tcp_sids *array)
{
	int num = MIN(array->num, TCP_XXX_SIDS);
	mpack_build_array(writer);
	for (int i = 0; i < num; i++)
	{
		mpack_write_u16(writer, array->value[i]);
	}
	mpack_complete_array(writer);
	
	return;
}

static void mpack_append_route_ctx(mpack_writer_t *writer, struct tcp_route_ctx *array)
{
    
	int num = MIN(array->num, TCP_XXX_ROUTE_CTX);
	mpack_build_array(writer);
	for (int i = 0; i < num; i++)
	{
		mpack_write_u8(writer, array->value[i]);
	}
	mpack_complete_array(writer);
	
	return;
}

static void mpack_append_cmsg_value(mpack_writer_t *writer, struct proxy_cmsg *cmsg)
{
	if (cmsg == NULL)
	{
		mpack_write_nil(writer);
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "MSGPACK_PROXY", "No cmsg!");
	}
	else
	{
		mpack_build_array(writer); // array

		mpack_write_u32(writer, cmsg->tcp_seq);
		mpack_write_u32(writer, cmsg->tcp_ack);
		mpack_write_u16(writer, cmsg->tcp_mss_client);
		mpack_write_u16(writer, cmsg->tcp_mss_server);
		if (cmsg->tcp_wsacle_exist == 1)
		{
			mpack_write_u8(writer, cmsg->tcp_wsacle_client);
			mpack_write_u8(writer, cmsg->tcp_wsacle_server);
		}
		else
		{
			mpack_write_u8(writer, 0);
			mpack_write_u8(writer, 0);
		}
		mpack_write_u8(writer, cmsg->tcp_sack_client);
		mpack_write_u8(writer, cmsg->tcp_sack_server);
		mpack_write_u8(writer, cmsg->tcp_ts_client);
		mpack_write_u8(writer, cmsg->tcp_ts_server);
		mpack_write_u8(writer, cmsg->tcp_protocol);
		mpack_write_u16(writer, cmsg->tcp_window_client);
		mpack_write_u16(writer, cmsg->tcp_window_server);
		mpack_write_u32(writer, cmsg->tcp_ts_client_val);
		mpack_write_u32(writer, cmsg->tcp_ts_server_val);
		mpack_write_u8(writer, cmsg->tcp_info_packet_cur_dir);

		mpack_append_string(writer, cmsg->src_sub_id);
		mpack_append_string(writer, cmsg->dst_sub_id);
		mpack_append_string(writer, cmsg->src_asn);
		mpack_append_string(writer, cmsg->dst_asn);
		mpack_append_string(writer, cmsg->src_organization);
		mpack_append_string(writer, cmsg->dst_organization);
		mpack_append_string(writer, cmsg->src_ip_location_country);
		mpack_append_string(writer, cmsg->dst_ip_location_country);
		mpack_append_string(writer, cmsg->src_ip_location_provine);
		mpack_append_string(writer, cmsg->dst_ip_location_provine);
		mpack_append_string(writer, cmsg->src_ip_location_city);
		mpack_append_string(writer, cmsg->dst_ip_location_city);
		mpack_append_string(writer, cmsg->src_ip_location_subdivision);
		mpack_append_string(writer, cmsg->dst_ip_location_subdivision);
		mpack_append_string(writer, cmsg->ssl_client_ja3_fingerprint);

        // fqdn_cat_id_val
		mpack_append_fqdn_cat_ids(writer, &cmsg->fqdn_cat_ids);

		// tcp_seq_sids
		mpack_append_tcp_sids(writer, &cmsg->tcp_seq_sids);

		// tcp_ack_sids
		mpack_append_tcp_sids(writer, &cmsg->tcp_ack_sids);

		// tcp_seq_route_ctx
		mpack_append_route_ctx(writer, &cmsg->tcp_seq_route_ctx);

		// tcp_ack_route_ctx
		mpack_append_route_ctx(writer, &cmsg->tcp_ack_route_ctx);

		mpack_complete_array(writer); // array
	}

	return;
}

static void mpack_append_update_policy(mpack_writer_t *writer, struct update_policy *policy_update, enum policy_type type)
{
	switch (type)
	{
		case POLICY_UPDATE_INTERCEPT:
			mpack_write_cstr(writer, "proxy");
			break;
		case POLICY_UPDATE_SERVICE_CHAINING:
			mpack_write_cstr(writer, "sce");
			break;
		case POLICY_UPDATE_SHAPING:
			mpack_write_cstr(writer, "shaper");
			break;
		default:
			return;
	}

	mpack_build_map(writer); // update_policy_type
	mpack_write_cstr(writer, "rule_ids");
	if (policy_update->n_ids > 0)
	{
		int n_ids = MIN(policy_update->n_ids, UPDATE_POLICY_RULE_IDS);
		mpack_build_array(writer); // rule_ids
		for (int i = 0; i < n_ids; i++)
		{
			mpack_write_i64(writer, policy_update->ids[i]);
		}
		mpack_complete_array(writer); // rule_ids
	}
	else
	{
		mpack_write_nil(writer);
	}

	if (type == POLICY_UPDATE_INTERCEPT)
	{
		mpack_write_cstr(writer, "tcp_handshake");
		mpack_append_cmsg_value(writer, &policy_update->cmsg);
	}
	mpack_complete_map(writer); // update_policy_type

	return;
}

int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_update, size_t n_policy_update)
{
	if (a_stream == NULL || policy_update == NULL || policy_update->type >= POLICY_UPDATE_MAX || n_policy_update == 0)
	{
		return -1;
	}

	char *mpack_data = NULL;
	size_t mpack_size = 0;
	mpack_writer_t writer;
	mpack_init_map((struct streaminfo *)a_stream, &writer, "active", &mpack_data, &mpack_size);

	// method: policy_update
	mpack_write_cstr(&writer, "method");
	mpack_write_cstr(&writer, "policy_update");

	// params
	mpack_write_cstr(&writer, "params");
	mpack_build_map(&writer);
	for (int i = 0; i < (int)n_policy_update; i++)
	{
		mpack_append_update_policy(&writer, &policy_update[i], policy_update[i].type);
	}
	mpack_complete_map(&writer); // params

	return mpack_send_pkt(a_stream, &writer, &mpack_data, &mpack_size);
}

int tsg_sync_closing_state(const struct streaminfo *a_stream, unsigned char state)
{
	return tsg_send_session_state(a_stream, state);
}

int tsg_sync_opening_state(const struct streaminfo *a_stream, unsigned char state)
{
	tsg_send_session_state(a_stream, state);

	return 0;
}

static char *mpack_parse_get_string(mpack_node_t node, char *p_str, int thread_seq)
{
	if (p_str != NULL)
	{
		dictator_free(thread_seq, p_str);
		p_str = NULL;
	}

	int str_len = 0;
	const char *str = NULL;
	char *result = NULL;

	str = mpack_node_str(node);
	str_len = mpack_node_strlen(node);

	result = (char *)dictator_malloc(thread_seq, str_len + 1);
	memset(result, 0, str_len + 1);
	memcpy(result, str, str_len);

	return result;
}

static void mpack_parse_intercept_info(mpack_node_t node, struct proxy_log_update *proxy, int thread_seq)
{
	if (mpack_node_array_length(node) != (size_t)(SSL_INTERCEPT_MAX_INDEX))
	{
		return;
	}

	proxy->ssl_intercept_state = mpack_node_u8(mpack_node_array_at(node, SSL_INTERCEPT_STATE));
	proxy->ssl_upstream_latency = mpack_node_u64(mpack_node_array_at(node, SSL_UPSTREAM_LATENCY));
	proxy->ssl_downstream_latency = mpack_node_u64(mpack_node_array_at(node, SSL_DOWNSTREAM_LATENCY));
	proxy->ssl_upstream_version = mpack_parse_get_string(mpack_node_array_at(node, SSL_UPSTREAM_VERSION), proxy->ssl_upstream_version, thread_seq);
	proxy->ssl_downstream_version = mpack_parse_get_string(mpack_node_array_at(node, SSL_DOWNSTREAM_VERSION), proxy->ssl_downstream_version, thread_seq);
	proxy->ssl_pinning_state = mpack_node_u8(mpack_node_array_at(node, SSL_PINNING_STATE));
	proxy->ssl_cert_verify = mpack_node_u8(mpack_node_array_at(node, SSL_CERT_VERIFY));
	proxy->ssl_error = mpack_parse_get_string(mpack_node_array_at(node, SSL_ERROR), proxy->ssl_error, thread_seq);
	proxy->ssl_passthrough_reason = mpack_parse_get_string(mpack_node_array_at(node, SSL_PASSTHROUGH_REASON), proxy->ssl_passthrough_reason, thread_seq);

	return;
}

static void mpack_parse_append_profile_id(mpack_node_t profile_ids_node, uint32_t *ids, size_t *n_id, size_t max)
{
	*n_id = MIN(mpack_node_array_length(profile_ids_node), max);
	for (int i = 0; i < (int)(*n_id); i++)
	{
		ids[i] = mpack_node_u32(mpack_node_array_at(profile_ids_node, i));
	}

	return;
}

int mpack_parse_sce_profile_ids(const struct streaminfo *a_stream, mpack_tree_t tree, mpack_node_t sce_node)
{
	mpack_node_t sf_profile_ids = mpack_node_map_cstr(sce_node, "sf_profile_ids");
	if (mpack_node_type(sf_profile_ids) != mpack_type_array || mpack_node_array_length(sf_profile_ids) == 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_SCE", "sf_profile_ids error! mpack_node_type(sf_profile_ids): %d, n_sf_profile_ids = 0", (int)mpack_node_type(sf_profile_ids));
		mpack_tree_destroy(&tree);
		return -1;
	}

	struct sce_log_update *sce_handle = (struct sce_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_CHAINING);
	if (sce_handle == NULL)
	{
		sce_handle = (struct sce_log_update *)dictator_malloc(a_stream->threadnum, sizeof(struct sce_log_update));
		memset(sce_handle, 0, sizeof(struct sce_log_update));
		session_log_update_data_put(a_stream, TSG_SERVICE_CHAINING, (void *)sce_handle);
	}
	mpack_parse_append_profile_id(sf_profile_ids, sce_handle->profile_ids, &sce_handle->n_profile_ids, SCE_PROFILE_IDS);

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PARSE_SCE", "n_profile_ids: %lu", sce_handle->n_profile_ids);
	mpack_tree_destroy(&tree);
	return 0;
}

int mpack_parse_shaper_profile_ids(const struct streaminfo *a_stream, mpack_tree_t tree, mpack_node_t shaper_node)
{
	size_t n_shaper_rule = mpack_node_array_length(shaper_node);
	if (n_shaper_rule == 0)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_SHAPER", "n_sh_profile_ids: 0");
		mpack_tree_destroy(&tree);
		return -1;
	}

	struct shaper_log_update *shaper_handle = (struct shaper_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_SHAPING);
	if (shaper_handle == NULL)
	{
		shaper_handle = (struct shaper_log_update *)dictator_malloc(a_stream->threadnum, sizeof(struct shaper_log_update));
		memset(shaper_handle, 0, sizeof(struct shaper_log_update));
		session_log_update_data_put(a_stream, TSG_SERVICE_SHAPING, (void *)shaper_handle);
	}

	shaper_handle->n_shaper_rule = MIN(n_shaper_rule, SHAPR_RULE_IDS);
	mpack_node_t sh_ids_node;
	for (int i = 0; i < (int)shaper_handle->n_shaper_rule; i++)
	{
		sh_ids_node = mpack_node_array_at(shaper_node, i);
		shaper_handle->shaper_rules[i].rule_id = mpack_node_i64(mpack_node_map_cstr(sh_ids_node, "rule_id"));

		mpack_parse_append_profile_id(mpack_node_map_cstr(sh_ids_node, "profile_ids"), shaper_handle->shaper_rules[i].profile_ids, &shaper_handle->shaper_rules[i].n_profile_ids, SHAPR_PROFILE_IDS);
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PARSE_SHAPER", "n_sh_profile_ids: %lu;", shaper_handle->n_shaper_rule);
	mpack_tree_destroy(&tree);
	return 0;
}

int mpack_parse_proxy_intercept_info(const struct streaminfo *a_stream, mpack_tree_t tree, mpack_node_t proxy_node)
{
	mpack_node_t ssl_intercept_info = mpack_node_map_str_optional(proxy_node, "ssl_intercept_info", 18);
	if (mpack_node_type(ssl_intercept_info) != mpack_type_array)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_PROXY", "ssl_intercept_info error! mpack_node_type(ssl_intercept_info): %d", (int)mpack_node_type(ssl_intercept_info));
		mpack_tree_destroy(&tree);
		return -1;
	}

	struct proxy_log_update *proxy_handle = (struct proxy_log_update *)session_log_update_data_get(a_stream, TSG_SERVICE_INTERCEPT);
	if (proxy_handle == NULL)
	{
		proxy_handle = (struct proxy_log_update *)dictator_malloc(a_stream->threadnum, sizeof(struct proxy_log_update));
		memset(proxy_handle, 0, sizeof(struct proxy_log_update));
		session_log_update_data_put(a_stream, TSG_SERVICE_INTERCEPT, (void *)proxy_handle);
	}
	mpack_parse_intercept_info(ssl_intercept_info, proxy_handle, a_stream->threadnum);

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG,
							"PARSE_PROXY",
							"ssl_intercept_state: %u; ssl_upstream_latency: %llu; ssl_downstream_latency: %llu; ssl_upstream_version: %s; ssl_downstream_version: %s; ssl_pinning_state: %u; ssl_cert_verify: %u; ssl_error: %s; ssl_passthrough_reason: %s;",
							proxy_handle->ssl_intercept_state,
							proxy_handle->ssl_upstream_latency,
							proxy_handle->ssl_downstream_latency,
							proxy_handle->ssl_upstream_version,
							proxy_handle->ssl_downstream_version,
							proxy_handle->ssl_pinning_state,
							proxy_handle->ssl_cert_verify,
							proxy_handle->ssl_error,
							proxy_handle->ssl_passthrough_reason);

	mpack_tree_destroy(&tree);
	return 0;
}

int tsg_parse_log_update_payload(const struct streaminfo *a_stream, const void *payload, unsigned int payload_len)
{
	if (a_stream == NULL || payload == NULL || payload_len == 0)
	{
		return -1;
	}

	mpack_tree_t tree;
	mpack_tree_init_data(&tree, (const char *)payload, payload_len);
	mpack_tree_parse(&tree);
	mpack_node_t root = mpack_tree_root(&tree);

	if (mpack_node_type(root) == mpack_type_nil)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_LOG_UPDATE", "mpack_tree_parse error! payload_len = %u", payload_len);
		mpack_tree_destroy(&tree);
		return -1;
	}

	mpack_node_t method = mpack_node_map_cstr(root, "method");
	if (mpack_node_type(method) != mpack_type_str)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_LOG_UPDATE", "method error! mpack_node_type(method) = %d", (int)mpack_node_type(method));
		mpack_tree_destroy(&tree);
		return -1;
	}

	if (mpack_node_strlen(method) != strlen("log_update") || memcmp("log_update", mpack_node_str(method), strlen("log_update")) != 0)
	{
		// mpack_node_str(method) is contiguous memory
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_LOG_UPDATE", "method error! mpack_node_strlen(method) = %lu", mpack_node_strlen(method));
		mpack_tree_destroy(&tree);
		return -1;
	}

	uint64_t session_id = mpack_node_u64(mpack_node_map_cstr(root, "session_id"));
	if (session_id != tsg_get_stream_trace_id(a_stream))
	{
		// if session_id = 0, it's could be mpack_node_type(root) = nil
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_LOG_UPDATE", "session_id error! session_id: %llu, real session_id: %llu", session_id, tsg_get_stream_trace_id(a_stream));
		mpack_tree_destroy(&tree);
		return -1;
	}

	mpack_node_t params_node = mpack_node_map_cstr(root, "params");
	if (mpack_node_type(params_node) == mpack_type_nil)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_INFO, "PARSE_LOG_UPDATE", "params_node error!");
		mpack_tree_destroy(&tree);
		return -1;
	}

	mpack_node_t temp_node = mpack_node_map_str_optional(params_node, "sce", 3);
	if (mpack_node_type(temp_node) != mpack_type_nil && mpack_node_type(temp_node) != mpack_type_missing)
	{
		return mpack_parse_sce_profile_ids(a_stream, tree, temp_node);
	}

	temp_node = mpack_node_map_str_optional(params_node, "shaper", 6);
	if (mpack_node_type(temp_node) != mpack_type_nil && mpack_node_type(temp_node) != mpack_type_missing)
	{
		return mpack_parse_shaper_profile_ids(a_stream, tree, temp_node);
	}

	temp_node = mpack_node_map_str_optional(params_node, "proxy", 5);
	if (mpack_node_type(temp_node) != mpack_type_nil && mpack_node_type(temp_node) != mpack_type_missing)
	{
		return mpack_parse_proxy_intercept_info(a_stream, tree, temp_node);
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "PDARSE_LOG_UPDATE", "pkt error! there is no log!");
	mpack_tree_destroy(&tree);
	return -1;
}