#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <MESA/cJSON.h>

#include "tsg_sync_state.h"
#include "tsg_send_log.h"

// i don't need this
int set_exec_profile_ids(const struct streaminfo *a_stream, struct parse_handle *p);

const char *policy_key[ POLICY_UPDATE_MAX] =
{
    "service_chaining",
    "shaping",
};

static int tsg_send_ctrl_pkt(const struct streaminfo *a_stream, cJSON *object)
{
    if (object == NULL)
    {
        return -1;
    }

    char *payload = NULL;
    uint64_t session_id = tsg_get_stream_id((struct streaminfo *)a_stream);

    // tsg_get_stream_id maybe return -1
    if (session_id && session_id != (uint64_t)-1)
    {
        char trace_id[128]={0};
        snprintf(trace_id, sizeof(trace_id), "%lu", session_id);
        cJSON_AddStringToObject(object, "session_id", trace_id);
    }

    cJSON_AddStringToObject(object, "tsync", "1.0");

    payload = cJSON_PrintUnformatted(object);
    if (payload == NULL)
    {
        cJSON_Delete(object);
        return -1;
    }

    // send//
    sapp_inject_ctrl_pkt((struct streaminfo *)a_stream, SIO_DEFAULT, payload, strlen(payload)+1, a_stream->routedir);

    cJSON_free(payload);
    cJSON_Delete(object);

    return 0;
}

int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state)
{
    if (a_stream == NULL)
    {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    
    if (state== OP_STATE_PENDING)
    {
        cJSON_AddStringToObject(object, "state", "opening");
    }
    else if (state == OP_STATE_CLOSE)
    {
        cJSON_AddStringToObject(object, "state", "closing");
    }
    else
    {
        cJSON_Delete(object);
        return -1;
    }

    return tsg_send_ctrl_pkt(a_stream, object);
}

int tsg_sync_resetall_state(const struct streaminfo *a_stream)
{
    if (a_stream == NULL)
    {
        return -1;
    }

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "state", "resetall");

    return tsg_send_ctrl_pkt(a_stream, object);
}

int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_array, int policy_array_num)
{
    if (a_stream == NULL || policy_array == NULL || policy_array_num > (int) POLICY_UPDATE_MAX || policy_array_num <= 0)
    {
        return -1;
    }

    cJSON *params_object = NULL;
    cJSON *policy_arr = NULL;
    cJSON *object = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "state", "active");
    cJSON_AddStringToObject(object, "method", "policy_update");
    params_object = cJSON_AddObjectToObject(object, "params");

    for (int i = 0; i < policy_array_num; i ++)
    {
        policy_arr = cJSON_CreateIntArray(policy_array[i].ids, policy_array[i].id_num);
        if (policy_arr == NULL || policy_array[i].type >=  POLICY_UPDATE_MAX)
        {
            cJSON_Delete(object);
            return -1;
        }

        cJSON_AddItemToObject(params_object, policy_key[policy_array[i].type], policy_arr);
        policy_arr = NULL;
    }

    return tsg_send_ctrl_pkt(a_stream, object);
}

int tsg_recv_control_pkt(const struct streaminfo *a_stream, const void *payload, int payload_len)
{
    if (a_stream == NULL || payload == NULL || payload_len == 0)
    {
        return -1;
    }

    char *state = NULL;
    char *method = NULL;
    char *tsync = NULL;
    cJSON *params_object = NULL;
    cJSON *sf_ids_array = NULL;
    struct parse_handle result = {0};

    cJSON *object = cJSON_Parse((char *)payload);
    if (object == NULL)
    {
        return -1;
    }  
    
    tsync = cJSON_GetObjectItem(object, "tsync")->valuestring;
    memcpy(result.tsync, tsync, strlen(tsync));

    //result.session_id = (uint64_t)atoll(cJSON_GetObjectItem(object, "session_id")->string);

    state = cJSON_GetObjectItem(object, "state")->valuestring;
    memcpy(result.state, state, strlen(state));

    method = cJSON_GetObjectItem(object, "method")->valuestring;
    memcpy(result.method, method, strlen(method));

    params_object = cJSON_GetObjectItem(object, "params");
    sf_ids_array = cJSON_GetObjectItem(params_object, "sf_profile_ids");
    result.sf_ids.id_num = cJSON_GetArraySize(sf_ids_array);
    for (int i = 0; i < result.sf_ids.id_num; i ++)
    {
        result.sf_ids.ids[i] = cJSON_GetArrayItem(sf_ids_array, i)->valueint;
    }

    //set_exec_profile_ids(a_stream, &result);

    cJSON_Delete(object);
    return 0;
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

