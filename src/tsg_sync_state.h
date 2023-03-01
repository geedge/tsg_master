#ifndef TSG_SESSION_STATE_H
#define TSG_SESSION_STATE_H

#include <stdint.h>
#include <MESA/stream.h>

enum policy_type
{
    POLICY_UPDATE_SERVICE_CHAINING = 0, 
    POLICY_UPDATE_SHAPING,
    POLICY_UPDATE_MAX
};

struct update_policy
{
	enum policy_type type; 
	int id_num;
	int ids[8];
};

// i don't need this 
struct parse_handle 
{
    char tsync[8];
    uint64_t session_id;
    char state[8];
    char method[16];
    struct update_policy sf_ids;
};

int tsg_sync_resetall_state(const struct streaminfo *a_stream);
int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_opening_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_closing_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_array, int policy_array_num);

int tsg_recv_control_pkt(const struct streaminfo *a_stream, const void *payload, int payload_len);


#endif //TSG_SESSION_STATE_H
