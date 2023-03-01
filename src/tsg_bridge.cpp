#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_bridge.h"
#include "tsg_variable.h"

extern int app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data);
extern int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data);

void free_context_label(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	struct master_context *context=(struct master_context *)data;
	if(context!=NULL)
	{
		if(context->domain!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)context->domain);
			context->domain=NULL;
		}

		if(context->quic_ua!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)context->quic_ua);
			context->quic_ua=NULL;
		}

		if(context->mid!=NULL)
		{
			Maat_clean_status(&context->mid);
			context->mid=NULL;
		}

		if(context->hited_result!=NULL)
		{
			dictator_free(a_stream->threadnum, (void *)context->hited_result);
			context->hited_result=NULL;
		}

		dictator_free(a_stream->threadnum, (void *)context);
		context=NULL;
	}

	data=NULL;

	return ;
}

void free_tcpall_label(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		struct tcpall_context *context=(struct tcpall_context *)data;
		if(context->para!=NULL)
		{
			switch(context->method_type)
			{
				case	TSG_METHOD_TYPE_RATE_LIMIT:
					destroy_bucket(&(context->bucket), a_stream->threadnum);
					break;
				default:
					break;
			}
		}
		
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}

	return ;
}

void free_shaping_result(const struct streaminfo *stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(stream->threadnum, data);
		data=NULL;
	}
}

void free_s_chaining_result(const struct streaminfo *stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(stream->threadnum, data);
		data=NULL;
	}
}

void free_policy_label(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{		
		struct policy_priority_label *priority_label=(struct policy_priority_label *)data;
		if(priority_label->para!=NULL)
		{
			dictator_free(a_stream->threadnum, priority_label->para);
			priority_label->para=NULL;
		}
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

void free_gather_app_result(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	if(data!=NULL)
	{
		dictator_free(a_stream->threadnum, data);
		data=NULL;
	}
}

int tsg_set_xxx_to_bridge(const struct streaminfo *a_stream, int bridge_id, void *data)
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

void *tsg_get_xxx_from_bridge(const struct streaminfo *a_stream, int bridge_id)
{
	if(a_stream!=NULL && bridge_id>=0)
	{
		return stream_bridge_async_data_get(a_stream, bridge_id);
	}

	return NULL;
}

int tsg_init_bridge(const char *conffile)
{
	MESA_load_profile_string_def(conffile, "SYSTEM", "APP_IDENTIFY_RESULT_BRIDGE", g_tsg_para.bridge[BRIDGE_TYPE_APP_IDENTIFY_RESULT].name, MAX_BRIDGE_NAME_LEN, "APP_IDENTIFY_RESULT_BRIDGE");
	g_tsg_para.bridge[BRIDGE_TYPE_APP_IDENTIFY_RESULT].sync_cb=app_identify_result_cb;

	MESA_load_profile_string_def(conffile, "SYSTEM", "SKETCH_NOTIFY_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_RECV_CONN_SKETCH_DATA].name, MAX_BRIDGE_NAME_LEN, "TSG_CONN_SKETCH_NOTIFY_DATA");
	MESA_load_profile_string_def(conffile, "SYSTEM", "MASTER_NOTIFY_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_SEND_CONN_SKETCH_DATA].name, MAX_BRIDGE_NAME_LEN, "TSG_MASTER_NOTIFY_DATA");

	MESA_load_profile_string_def(conffile, "SESSION_FLAGS", "FLAGS_NOTIFY_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_FLAGS].name, MAX_BRIDGE_NAME_LEN, "SESSION_FLAGS_SYNC_NOTIFY_DATA");
	g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_FLAGS].sync_cb=session_flags_identify_result_cb;

	MESA_load_profile_string_def(conffile, "SYSTEM", "SHAPING_RESULT_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].name, MAX_BRIDGE_NAME_LEN, "NOTIFY_SHAPING_RESULT");
	g_tsg_para.bridge[BRIDGE_TYPE_NOTIFY_SHAPING_RESULT].free_cb=free_shaping_result;

	MESA_load_profile_string_def(conffile, "SYSTEM", "DATA_CONTEXT_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].name, MAX_BRIDGE_NAME_LEN, "TSG_DATA_CONTEXT");
	g_tsg_para.bridge[BRIDGE_TYPE_DATA_CONTEXT].free_cb=free_context_label;

	MESA_load_profile_string_def(conffile, "SYSTEM", "ALL_RESULT_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].name, MAX_BRIDGE_NAME_LEN, "TSG_ALL_CONTEXT");
	g_tsg_para.bridge[BRIDGE_TYPE_ALL_CONTEXT].free_cb=free_tcpall_label;

	MESA_load_profile_string_def(conffile, "SYSTEM", "GATHER_APP_RESULT_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].name, MAX_BRIDGE_NAME_LEN, "GATHER_APP_IDENTIFY_RESULT");
	g_tsg_para.bridge[BRIDGE_TYPE_GATHER_APP_RESULT].free_cb=free_gather_app_result;

	MESA_load_profile_string_def(conffile, "SYSTEM", "POLICY_PRIORITY_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].name, MAX_BRIDGE_NAME_LEN, "TSG_POLICY_PRIORITY");
	g_tsg_para.bridge[BRIDGE_TYPE_POLICY_PRIORITY].free_cb=free_policy_label;

	MESA_load_profile_string_def(conffile, "SYSTEM", "S_CHAINING_RESULT_BRIDGE_NAME", g_tsg_para.bridge[BRIDGE_TYPE_SERVICE_CHAINING].name, MAX_BRIDGE_NAME_LEN, "SERVICE_CHAINING_RESULT");
	g_tsg_para.bridge[BRIDGE_TYPE_SERVICE_CHAINING].free_cb=free_s_chaining_result;

	for(int i=0; i<BRIDGE_TYPE_MAX; i++)
	{
		g_tsg_para.bridge[i].id=stream_bridge_build(g_tsg_para.bridge[i].name, "w");
		if(g_tsg_para.bridge[i].id<0)
		{
			MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "INIT_BRIDGE", "stream_bridge_build is error, bridge_name: %s", g_tsg_para.bridge[i].name);
			return -1;
		}

		if(g_tsg_para.bridge[i].sync_cb)
		{	
			int ret=stream_bridge_register_data_sync_cb(g_tsg_para.bridge[i].id, g_tsg_para.bridge[i].sync_cb);
			if(ret<0)
			{		
				MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "BRIDGE_SYNC_CB", "Register callback failed, bridge_name: %d", g_tsg_para.bridge[i].name);
				return -1;
			}
		}

		if(g_tsg_para.bridge[i].free_cb)
		{
			int ret=stream_bridge_register_data_free_cb(g_tsg_para.bridge[i].id, g_tsg_para.bridge[i].free_cb);
			if(ret<0)
			{		
				MESA_handle_runtime_log(g_tsg_para.logger, RLOG_LV_FATAL, "BRIDGE_FREE_CB", "Register async free callback failed, bridge_name: %d", g_tsg_para.bridge[i].name);
				return -1;
			}
		}
	}

	return 0;
}

