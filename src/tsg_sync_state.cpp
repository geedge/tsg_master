#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MESA/cJSON.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_variable.h"
#include "tsg_sync_state.h"
#include "tsg_send_log.h"
#include "mpack.h"

char *mpack_data = NULL;
size_t mpack_size = 0;
static int tsg_mpack_init_map(const struct streaminfo *a_stream, mpack_writer_t *writer, const char *state)
{
	mpack_writer_init_growable(writer, &mpack_data, &mpack_size);
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

static int tsg_mpack_send_pkt(const struct streaminfo *a_stream, mpack_writer_t *writer)
{
	mpack_complete_map(writer); // tsg_mpack_init_map
	if (mpack_writer_destroy(writer) != mpack_ok)
	{
		MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "MPACK_WRITER", "An error occurred encoding the data!");
		return -1;
	}

	MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_DEBUG, "MSGPACK_PROXY_BUFF", "send buff_len = %lu", mpack_size);
	sapp_inject_ctrl_pkt((struct streaminfo *)a_stream, SIO_DEFAULT, mpack_data, mpack_size, a_stream->routedir);
	free(mpack_data);
	mpack_data = NULL;
	mpack_size = 0;
	return 0;
}

int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state)
{
	if (a_stream == NULL)
	{
		return -1;
	}

	mpack_writer_t writer;
	if (state == OP_STATE_PENDING)
	{
		tsg_mpack_init_map(a_stream, &writer, "opening");
	}
	else if (state == OP_STATE_CLOSE)
	{
		tsg_mpack_init_map(a_stream, &writer, "closing");
	}
	else
	{
		return -1;
	}

	return tsg_mpack_send_pkt(a_stream, &writer);
}

int tsg_sync_resetall_state(const struct streaminfo *a_stream)
{
	if (a_stream == NULL)
	{
		return -1;
	}

	mpack_writer_t writer;
	tsg_mpack_init_map(a_stream, &writer, "resetall");

	return tsg_mpack_send_pkt(a_stream, &writer);
}

static void tsg_mpack_append_str(mpack_writer_t *writer, char *str)
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

static void tsg_mpack_append_array_u32(mpack_writer_t *writer, struct cmsg_int32_array *array)
{
    if (array->num > 0)
    {
        mpack_build_array(writer);
        for (size_t i = 0; i < array->num; i++)
        {
            mpack_write_u32(writer, array->value[i]);
        }
        mpack_complete_array(writer);
    }
    else
    {
        mpack_write_nil(writer);
    }

    return;
}

static void tsg_mpack_append_array_u16(mpack_writer_t *writer, struct cmsg_int16_array *array)
{
    if (array->num > 0)
    {
        mpack_build_array(writer);
        for (size_t i = 0; i < array->num; i++)
        {
            mpack_write_u16(writer, array->value[i]);
        }
        mpack_complete_array(writer);
    }
    else
    {
        mpack_write_nil(writer);
    }

    return;
}

static void tsg_mpack_append_array_u8(mpack_writer_t *writer, struct cmsg_int8_array *array)
{
    if (array->num > 0)
    {
        mpack_build_array(writer);
        for (size_t i = 0; i < array->num; i++)
        {
            mpack_write_u8(writer, array->value[i]);
        }
        mpack_complete_array(writer);
    }
    else
    {
        mpack_write_nil(writer);
    }

    return;
}

static void tsg_mpack_append_cmsg_value(mpack_writer_t *writer, struct proxy_cmsg *cmsg)
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
			mpack_write_nil(writer);
			mpack_write_nil(writer);
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

		tsg_mpack_append_str(writer, cmsg->src_sub_id);
		tsg_mpack_append_str(writer, cmsg->dst_sub_id);
		tsg_mpack_append_str(writer, cmsg->src_asn);
		tsg_mpack_append_str(writer, cmsg->dst_asn);
		tsg_mpack_append_str(writer, cmsg->src_organization);
		tsg_mpack_append_str(writer, cmsg->dst_organization);
		tsg_mpack_append_str(writer, cmsg->src_ip_location_country);
		tsg_mpack_append_str(writer, cmsg->dst_ip_location_country);
		tsg_mpack_append_str(writer, cmsg->src_ip_location_provine);
		tsg_mpack_append_str(writer, cmsg->dst_ip_location_provine);
		tsg_mpack_append_str(writer, cmsg->src_ip_location_city);
		tsg_mpack_append_str(writer, cmsg->dst_ip_location_city);
		tsg_mpack_append_str(writer, cmsg->src_ip_location_subdivision);
		tsg_mpack_append_str(writer, cmsg->dst_ip_location_subdivision);
		tsg_mpack_append_str(writer, cmsg->ssl_client_ja3_fingerprint);

        // fqdn_cat_id_val
        tsg_mpack_append_array_u32(writer, &cmsg->fqdn_cat_id_val);

        // tcp_seq_sids
        tsg_mpack_append_array_u16(writer, &cmsg->tcp_seq_sids);

        // tcp_ack_sids
        tsg_mpack_append_array_u16(writer, &cmsg->tcp_ack_sids);

        // tcp_seq_route_ctx
        tsg_mpack_append_array_u8(writer, &cmsg->tcp_seq_route_ctx);

        // tcp_ack_route_ctx
        tsg_mpack_append_array_u8(writer, &cmsg->tcp_ack_route_ctx);

        mpack_complete_array(writer); // array
    }

    return;
}

static void tsg_mpack_append_update_policy(mpack_writer_t *writer, struct update_policy *policy_update, enum policy_type type)
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
		mpack_build_array(writer); // rule_ids
		for (int i = 0; i < policy_update->n_ids; i++)
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
		tsg_mpack_append_cmsg_value(writer, &policy_update->cmsg);
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

	mpack_writer_t writer;

	tsg_mpack_init_map((struct streaminfo *)a_stream, &writer, "active");

	// method: policy_update
	mpack_write_cstr(&writer, "method");
	mpack_write_cstr(&writer, "policy_update");

	// params
	mpack_write_cstr(&writer, "params");
	mpack_build_map(&writer);
	for (int i = 0; i < (int)n_policy_update; i++)
	{
		tsg_mpack_append_update_policy(&writer, &policy_update[i], policy_update[i].type);
	}
	mpack_complete_map(&writer); // params

	return tsg_mpack_send_pkt(a_stream, &writer);
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
