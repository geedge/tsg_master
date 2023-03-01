#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <gtest/gtest.h>
#include <MESA/cJSON.h>
#include "tsg_sync_state.h"

extern int get_ctrl_pkt(char *buf, int len);

struct parse_handle test_handle;

unsigned long long tsg_get_stream_id(struct streaminfo * a_stream)
{
	return 10;
}

int set_exec_profile_ids( struct streaminfo *a_stream, struct parse_handle *p)
{
    memcpy(&test_handle, p, sizeof(struct parse_handle));
    return 0;
}

TEST(SESSION_STATE, IllegalPara)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array[2];
    memset(policy_array, 0, sizeof(struct update_policy) * 2);

    EXPECT_EQ(-1, tsg_send_session_state(NULL, 0));
    a_stream.opstate = OP_STATE_DATA;
    EXPECT_EQ(-1, tsg_send_session_state(&a_stream, OP_STATE_DATA));

    EXPECT_EQ(-1, tsg_sync_resetall_state(NULL));
    EXPECT_EQ(0, tsg_sync_resetall_state(&a_stream));

    EXPECT_EQ(-1, tsg_sync_policy_update(&a_stream, policy_array, 0));
    EXPECT_EQ(-1, tsg_sync_policy_update(&a_stream, NULL, 2));
    EXPECT_EQ(-1, tsg_sync_policy_update(NULL, policy_array, 2));
    policy_array[0].type = POLICY_UPDATE_MAX;
    EXPECT_EQ(-1, tsg_sync_policy_update(&a_stream, policy_array, 2));
}

TEST(SESSION_STATE, OpeningState)
{
    struct streaminfo a_stream = {0};
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    a_stream.opstate = OP_STATE_PENDING;
    EXPECT_EQ(0, tsg_send_session_state(&a_stream, OP_STATE_PENDING));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"opening\",\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, CloseState)
{
    struct streaminfo a_stream = {0};
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    a_stream.opstate = OP_STATE_CLOSE;
    EXPECT_EQ(0, tsg_send_session_state(&a_stream, OP_STATE_CLOSE));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"closing\",\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, ResetAllState)
{
    struct streaminfo a_stream = {0};
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    EXPECT_EQ(0, tsg_sync_resetall_state(&a_stream));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"resetall\",\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, ActiveStateOnlyServiceChaining)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array;
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy));
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, &policy_array, 1));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"active\",\"method\":\"policy_update\",\"params\":{\"service_chaining\":[]},\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, ActiveStateOnlyShaping)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array;
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy));
    policy_array.type = POLICY_UPDATE_SHAPING;
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, &policy_array, 1));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"active\",\"method\":\"policy_update\",\"params\":{\"shaping\":[]},\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, ActiveStateServiceChainingAndShaping0)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array[2];
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy) * 2);
    policy_array[0].type = POLICY_UPDATE_SHAPING;
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, policy_array, 2));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"active\",\"method\":\"policy_update\",\"params\":{\"shaping\":[],\"service_chaining\":[]},\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(SESSION_STATE, ActiveStateServiceChainingAndShaping1)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array[2];
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy) * 2);
    policy_array[0].type = POLICY_UPDATE_SHAPING;
    policy_array[0].id_num = 3;
    policy_array[0].ids[0] = 1;
    policy_array[0].ids[1] = 2;
    policy_array[0].ids[2] = 3;
    policy_array[1].id_num = 3;
    policy_array[1].ids[0] = 4;
    policy_array[1].ids[1] = 5;
    policy_array[1].ids[2] = 6;
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, policy_array, 2));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, 1024);
    EXPECT_EQ(ctrl_pkt_len, strlen(ctrl_pkt_buf)+1);
    EXPECT_STREQ("{\"state\":\"active\",\"method\":\"policy_update\",\"params\":{\"shaping\":[1,2,3],\"service_chaining\":[4,5,6]},\"session_id\":\"10\",\"tsync\":\"1.0\"}", ctrl_pkt_buf);
}

TEST(RECEIVE, IllegalPara)
{
    struct streaminfo a_stream = {0};
    const char *payload = "{\"tsync\":\"1.0\",\"session_id\":\"123456789\",\"state\":\"active\",\"method\":\"log_update\",\"params\":{\"sf_profile_ids\":}}";
    const char *payload_ = "{\"tsync\":\"1.0\",\"session_id\":\"123456789\",\"state\":\"active\",\"method\":\"log_update\",\"params\":{\"sf_profile_ids\":[2,3,4,5,6,7]}}";

    EXPECT_EQ(-1, tsg_recv_control_pkt(&a_stream, payload, strlen(payload)));
    EXPECT_EQ(-1, tsg_recv_control_pkt(&a_stream, NULL, strlen(payload)));
    EXPECT_EQ(-1, tsg_recv_control_pkt(&a_stream, payload, 0));
    EXPECT_EQ(-1, tsg_recv_control_pkt(NULL, payload_, strlen(payload_)));
    EXPECT_EQ(0, tsg_recv_control_pkt(&a_stream, payload_, strlen(payload_)));
}

#if 0
TEST(RECEIVE, JsonParse)
{
    struct streaminfo a_stream = {0};
    const char *payload_ = "{\"tsync\":\"1.0\",\"session_id\":\"123456789\",\"state\":\"active\",\"method\":\"log_update\",\"params\":{\"sf_profile_ids\":[2,3,4,5,6,7]}}";

    EXPECT_EQ(0, tsg_recv_control_pkt(&a_stream, payload_, strlen(payload_)));

    EXPECT_STREQ("1.0", test_handle.tsync);
    EXPECT_EQ(123456789, test_handle.session_id);
    EXPECT_STREQ("log_update", test_handle.method);
    EXPECT_STREQ("active", test_handle.state);
    EXPECT_EQ(6, test_handle.sf_ids.id_num);
    for (int i = 0; i < 6; i++)
    {
        EXPECT_EQ(i+2, test_handle.sf_ids.ids[i]);
    }
}
#endif

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}