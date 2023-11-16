#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <gtest/gtest.h>
#include <MESA/cJSON.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_stat.h"
#include "tsg_sync_state.h"
#include "tsg_variable.h"
#include "mpack.h"

struct tsg_rt_para g_tsg_para;

extern int get_ctrl_pkt(char *buf, int len);

unsigned long long tsg_get_stream_trace_id(const struct streaminfo *a_stream)
{
    return 10;
}

void *session_log_update_data_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
    switch (service)
    {
    case TSG_SERVICE_INTERCEPT:
        return stream_bridge_async_data_get(a_stream, BRIDGE_TYPE_LOG_UPDATE_PROXY);

    case TSG_SERVICE_CHAINING:
        return stream_bridge_async_data_get(a_stream, BRIDGE_TYPE_LOG_UPDATE_SCE);

    case TSG_SERVICE_SHAPING:
        return stream_bridge_async_data_get(a_stream, BRIDGE_TYPE_LOG_UPDATE_SHAPER);
    default:
        return NULL;
    }
}

int session_log_update_data_put(const struct streaminfo *a_stream, enum TSG_SERVICE service, void *data)
{
    switch (service)
    {
    case TSG_SERVICE_INTERCEPT:
        return stream_bridge_async_data_put(a_stream, BRIDGE_TYPE_LOG_UPDATE_PROXY, data);

    case TSG_SERVICE_CHAINING:
        return stream_bridge_async_data_put(a_stream, BRIDGE_TYPE_LOG_UPDATE_SCE, data);

    case TSG_SERVICE_SHAPING:
        return stream_bridge_async_data_put(a_stream, BRIDGE_TYPE_LOG_UPDATE_SHAPER, data);

    default:
        return 0;
    }
}

int FS_operate(screen_stat_handle_t handle,int id,int column_id,enum field_op op,long long value)
{
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
    char test_str[256] = {0};
    int ctrl_pkt_len = 0;
    a_stream.opstate = OP_STATE_PENDING;
    EXPECT_EQ(0, tsg_send_session_state(&a_stream, OP_STATE_PENDING));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));

    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    // tsync:2.0
    EXPECT_EQ(mpack_type_str, mpack_node_type(mpack_node_map_cstr(root, "tsync")));
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "tsync")), mpack_node_strlen(mpack_node_map_cstr(root, "tsync")));
    EXPECT_STREQ("2.0", test_str);
    memset(test_str, 0, sizeof(test_str));

    // session_id
    EXPECT_EQ(10, mpack_node_u64(mpack_node_map_cstr(root, "session_id")));

    // state:opening
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "state")), mpack_node_strlen(mpack_node_map_cstr(root, "state")));
    EXPECT_STREQ("opening", test_str);
    memset(test_str, 0, sizeof(test_str));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(SESSION_STATE, CloseState)
{
    struct streaminfo a_stream = {0};
    char ctrl_pkt_buf[1024];
    char test_str[256] = {0};
    int ctrl_pkt_len = 0;
    a_stream.opstate = OP_STATE_CLOSE;
    EXPECT_EQ(0, tsg_send_session_state(&a_stream, OP_STATE_CLOSE));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));

    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    // tsync:2.0
    EXPECT_EQ(mpack_type_str, mpack_node_type(mpack_node_map_cstr(root, "tsync")));
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "tsync")), mpack_node_strlen(mpack_node_map_cstr(root, "tsync")));
    EXPECT_STREQ("2.0", test_str);
    memset(test_str, 0, sizeof(test_str));

    // session_id
    EXPECT_EQ(10, mpack_node_u64(mpack_node_map_cstr(root, "session_id")));

    // state:colse
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "state")), mpack_node_strlen(mpack_node_map_cstr(root, "state")));
    EXPECT_STREQ("closing", test_str);
    memset(test_str, 0, sizeof(test_str));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(SESSION_STATE, ResetAllState)
{
    struct streaminfo a_stream = {0};
    char ctrl_pkt_buf[1024];
    char test_str[256] = {0};
    int ctrl_pkt_len = 0;
    EXPECT_EQ(0, tsg_sync_resetall_state(&a_stream));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    // state:resetall
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "state")), mpack_node_strlen(mpack_node_map_cstr(root, "state")));
    EXPECT_STREQ("resetall", test_str);
    memset(test_str, 0, sizeof(test_str));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, Sce)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    test.type = POLICY_UPDATE_SERVICE_CHAINING;
    test.n_ids = 4;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 100 + i;
    }
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t sce_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "sce");
    for (int i = 0; i < 4; i++)
    {
        EXPECT_EQ(100 + i, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(sce_map, "rule_ids"), i)));
    }

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, SceOverLimitIds)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    test.type = POLICY_UPDATE_SERVICE_CHAINING;
    test.n_ids = 4;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 100 + i;
    }
    test.n_ids += UPDATE_POLICY_RULE_IDS;
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t sce_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "sce");
    EXPECT_EQ(mpack_node_array_length(mpack_node_map_cstr(sce_map, "rule_ids")), UPDATE_POLICY_RULE_IDS);
    EXPECT_EQ(0, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(sce_map, "rule_ids"), 5)));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, Shaper)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    test.type = POLICY_UPDATE_SHAPING;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t shaper_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "shaper");
    for (int i = 0; i < 6; i++)
    {
        EXPECT_EQ(10000 + i, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(shaper_map, "rule_ids"), i)));
    }

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, ShaperOverLimitIds)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    test.type = POLICY_UPDATE_SHAPING;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }
    test.n_ids += UPDATE_POLICY_RULE_IDS;
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    mpack_node_t shaper_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "shaper");
    EXPECT_EQ(mpack_node_array_length(mpack_node_map_cstr(shaper_map, "rule_ids")), UPDATE_POLICY_RULE_IDS);
    EXPECT_EQ(0, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(shaper_map, "rule_ids"), 7)));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, ActiveStateServiceChainingAndShaping0)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array[POLICY_UPDATE_MAX];
    char test_str[256] = {0};
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy) * 2);
    policy_array[0].type = POLICY_UPDATE_SERVICE_CHAINING;
    policy_array[1].type = POLICY_UPDATE_SHAPING;
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, policy_array, 2));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    // tsync:2.0
    EXPECT_EQ(mpack_type_str, mpack_node_type(mpack_node_map_cstr(root, "tsync")));
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "tsync")), mpack_node_strlen(mpack_node_map_cstr(root, "tsync")));
    EXPECT_STREQ("2.0", test_str);
    memset(test_str, 0, sizeof(test_str));

    // session_id
    EXPECT_EQ(10, mpack_node_u64(mpack_node_map_cstr(root, "session_id")));

    // state:active
    EXPECT_EQ(mpack_type_str, mpack_node_type(mpack_node_map_cstr(root, "state")));
    memcpy(test_str, mpack_node_str(mpack_node_map_cstr(root, "state")), mpack_node_strlen(mpack_node_map_cstr(root, "state")));
    EXPECT_STREQ("active", test_str);
    memset(test_str, 0, sizeof(test_str));

    // sce
    mpack_node_t policy_sce = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "sce");
    EXPECT_EQ(mpack_type_map, mpack_node_type(policy_sce));
    EXPECT_EQ(1, mpack_node_map_count(policy_sce));
    EXPECT_EQ(mpack_type_nil, mpack_node_type(mpack_node_map_cstr(policy_sce, "rule_ids")));

    // shaper
    mpack_node_t policy_shaper = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "shaper");
    EXPECT_EQ(mpack_type_map, mpack_node_type(policy_shaper));
    EXPECT_EQ(1, mpack_node_map_count(policy_shaper));
    EXPECT_EQ(mpack_type_nil, mpack_node_type(mpack_node_map_cstr(policy_shaper, "rule_ids")));

    // // proxy
    // EXPECT_EQ(mpack_type_nil, mpack_node_type(mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "proxy")));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

TEST(POLICY_UPDATE, ActiveStateServiceChainingAndShaping1)
{
    struct streaminfo a_stream = {0};
    struct update_policy policy_array[2];
    char ctrl_pkt_buf[1024];
    int ctrl_pkt_len = 0;
    memset(&policy_array, 0, sizeof(struct update_policy) * 2);
    policy_array[0].type = POLICY_UPDATE_SHAPING;
    policy_array[0].n_ids = 3;
    policy_array[0].ids[0] = 1;
    policy_array[0].ids[1] = 2;
    policy_array[0].ids[2] = 3;
    policy_array[1].type = POLICY_UPDATE_SERVICE_CHAINING;
    policy_array[1].n_ids = 3;
    policy_array[1].ids[0] = 4;
    policy_array[1].ids[1] = 5;
    policy_array[1].ids[2] = 6;
    EXPECT_EQ(0, tsg_sync_policy_update(&a_stream, policy_array, 2));

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);

    // sce
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "sce")));
    mpack_node_t sce_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "sce");
    EXPECT_EQ(3, mpack_node_array_length(mpack_node_map_cstr(sce_map, "rule_ids")));
    for (int i = 0; i < 3; i++)
    {
        EXPECT_EQ(4 + i, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(sce_map, "rule_ids"), i)));
    }

    // shaper
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "shaper")));
    mpack_node_t shaper_map = mpack_node_map_cstr(mpack_node_map_cstr(root, "params"), "shaper");
    EXPECT_EQ(3, mpack_node_array_length(mpack_node_map_cstr(shaper_map, "rule_ids")));
    for (int i = 0; i < 3; i++)
    {
        EXPECT_EQ(1 + i, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(shaper_map, "rule_ids"), i)));
    }

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
}

static void gtest_cmsg_init(struct proxy_cmsg *cmsg)
{
    cmsg->tcp_wsacle_set_client = 1;
    cmsg->tcp_wsacle_set_server = 1;
    cmsg->tcp_seq = 1;
    cmsg->tcp_ack = 2;
    cmsg->tcp_mss_client = 3;
    cmsg->tcp_mss_server = 4;
    cmsg->tcp_wsacle_client = 6;
    cmsg->tcp_wsacle_server = 7;
    cmsg->tcp_sack_client = 8;
    cmsg->tcp_sack_server = 9;
    cmsg->tcp_ts_client = 10;
    cmsg->tcp_ts_server = 11;
    cmsg->tcp_protocol = 12;
    cmsg->tcp_window_client = 13;
    cmsg->tcp_window_server = 14;
    cmsg->tcp_ts_client_val = 15;
    cmsg->tcp_ts_server_val = 16;
    cmsg->tcp_info_packet_cur_dir = 17;

    cmsg->src_sub_id = (char *)calloc(1, 256);
    snprintf(cmsg->src_sub_id, 256, "thisistest=%d", 1);

    cmsg->dst_sub_id = (char *)calloc(1, 256);
    snprintf(cmsg->dst_sub_id, 256, "thisistest=%d", 2);

    cmsg->src_asn = (char *)calloc(1, 256);
    snprintf(cmsg->src_asn, 256, "thisistest=%d", 3);

    cmsg->dst_asn = (char *)calloc(1, 256);
    snprintf(cmsg->dst_asn, 256, "thisistest=%d", 4);

    cmsg->src_organization = (char *)calloc(1, 256);
    snprintf(cmsg->src_organization, 256, "thisistest=%d", 5);

    cmsg->dst_organization = (char *)calloc(1, 256);
    snprintf(cmsg->dst_organization, 256, "thisistest=%d", 6);

    cmsg->src_ip_full_location = (char *)calloc(1, 256);
    snprintf(cmsg->src_ip_full_location, 256, "thisistest=%d", 7);

    cmsg->dst_ip_full_location = (char *)calloc(1, 256);
    snprintf(cmsg->dst_ip_full_location, 256, "thisistest=%d", 8);

    cmsg->ssl_client_ja3_fingerprint = (char *)calloc(1, 256);
    snprintf(cmsg->ssl_client_ja3_fingerprint, 256, "thisistest=%d", 9);

    cmsg->fqdn_cat_ids.num = 4;
    for (size_t i = 0; i < 4; i++)
    {
        cmsg->fqdn_cat_ids.value[i] = i + 1;
    }

    cmsg->tcp_seq_sids.num = 5;
    for (size_t i = 0; i < 5; i++)
    {
        cmsg->tcp_seq_sids.value[i] = i + 2;
    }

    cmsg->tcp_ack_sids.num = 6;
    for (size_t i = 0; i < 6; i++)
    {
        cmsg->tcp_ack_sids.value[i] = i + 3;
    }

    cmsg->tcp_seq_route_ctx.buff = (char *)calloc(1, 256);
    snprintf(cmsg->tcp_seq_route_ctx.buff, 256, "test: tcp_seq_route_ctx");
    cmsg->tcp_seq_route_ctx.len = strlen("test: tcp_seq_route_ctx");

    cmsg->tcp_ack_route_ctx.buff = (char *)calloc(1, 256);
    snprintf(cmsg->tcp_ack_route_ctx.buff, 256, "test: tcp_ack_route_ctx");
    cmsg->tcp_ack_route_ctx.len = strlen("test: tcp_ack_route_ctx");

    cmsg->tcp_s2c_rpkt_header.buff = (char *)calloc(1, 256);
    snprintf(cmsg->tcp_s2c_rpkt_header.buff, 256, "test: s2c_rawpkt_header");
    cmsg->tcp_s2c_rpkt_header.len = strlen("test: s2c_rawpkt_header");

    cmsg->tcp_c2s_rpkt_header.buff = (char *)calloc(1, 256);
    snprintf(cmsg->tcp_c2s_rpkt_header.buff, 256, "test: c2s_rawpkt_header");
    cmsg->tcp_c2s_rpkt_header.len = strlen("test: c2s_rawpkt_header");

    return;
}

static void gtest_cmsg_destroy(struct proxy_cmsg *cmsg)
{
    free(cmsg->src_sub_id);
    free(cmsg->dst_sub_id);
    free(cmsg->src_asn);
    free(cmsg->dst_asn);
    free(cmsg->src_organization);
    free(cmsg->dst_organization);
    free(cmsg->src_ip_full_location);
    free(cmsg->dst_ip_full_location);
    free(cmsg->ssl_client_ja3_fingerprint);
    
    if (cmsg->tcp_seq_route_ctx.buff)
    {
        free(cmsg->tcp_seq_route_ctx.buff);
    }

    if (cmsg->tcp_ack_route_ctx.buff)
    {
        free(cmsg->tcp_ack_route_ctx.buff);
    }

    if (cmsg->tcp_s2c_rpkt_header.buff)
    {
        free(cmsg->tcp_s2c_rpkt_header.buff);
    }

    if (cmsg->tcp_c2s_rpkt_header.buff)
    {
        free(cmsg->tcp_c2s_rpkt_header.buff);
    }
        
    return;
}

TEST(POLICY_UPDATE, Proxy)
{
    char ctrl_pkt_buf[1024] = {0};
    char test_str[256] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");
    EXPECT_EQ(6, mpack_node_array_length(mpack_node_map_cstr(proxy_map, "rule_ids")));

    // proxy.rule_ids
    for (int i = 0; i < test.n_ids; i++)
    {
        EXPECT_EQ(10000 + i, mpack_node_i64(mpack_node_array_at(mpack_node_map_cstr(proxy_map, "rule_ids"), i)));
    }

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    EXPECT_EQ(1, mpack_node_u32(mpack_node_array_at(tcp_handshake, 0)));
    EXPECT_EQ(16, mpack_node_u32(mpack_node_array_at(tcp_handshake, 16)));

    memcpy(test_str, mpack_node_str(mpack_node_array_at(tcp_handshake, 19)), mpack_node_strlen(mpack_node_array_at(tcp_handshake, 19)));
    EXPECT_STREQ("thisistest=2", test_str);
    memset(test_str, 0, sizeof(test_str));

    memcpy(test_str, mpack_node_str(mpack_node_array_at(tcp_handshake, 24)), mpack_node_strlen(mpack_node_array_at(tcp_handshake, 24)));
    EXPECT_STREQ("thisistest=7", test_str);
    memset(test_str, 0, sizeof(test_str));

    mpack_node_t fqdn_cat_id_vals = mpack_node_array_at(tcp_handshake, 27);
    EXPECT_EQ(4, mpack_node_array_length(fqdn_cat_id_vals));
    for (int i = 0; i < 4; i++)
    {
        EXPECT_EQ(i + 1, mpack_node_u32(mpack_node_array_at(fqdn_cat_id_vals, i)));
    }

    mpack_node_t tcp_ack_route_ctxs = mpack_node_array_at(tcp_handshake, 31);
    EXPECT_EQ(mpack_type_bin, mpack_node_type(tcp_ack_route_ctxs));
    memcpy(test_str, mpack_node_bin_data(tcp_ack_route_ctxs), mpack_node_bin_size(tcp_ack_route_ctxs));
    EXPECT_STREQ("test: tcp_ack_route_ctx", test_str);
    memset(test_str, 0, sizeof(test_str));

    mpack_node_t tcp_seq_pkg_header = mpack_node_array_at(tcp_handshake, 32);
    EXPECT_EQ(mpack_type_bin, mpack_node_type(tcp_seq_pkg_header));
    memcpy(test_str, mpack_node_bin_data(tcp_seq_pkg_header), mpack_node_bin_size(tcp_seq_pkg_header));
    EXPECT_STREQ("test: c2s_rawpkt_header", test_str);
    memset(test_str, 0, sizeof(test_str));

    mpack_node_t tcp_ack_pkg_header = mpack_node_array_at(tcp_handshake, 33);
    EXPECT_EQ(mpack_type_bin, mpack_node_type(tcp_ack_pkg_header));
    memcpy(test_str, mpack_node_bin_data(tcp_ack_pkg_header), mpack_node_bin_size(tcp_ack_pkg_header));
    EXPECT_STREQ("test: s2c_rawpkt_header", test_str);
    memset(test_str, 0, sizeof(test_str));

    mpack_node_t tcp_is_intercept = mpack_node_array_at(tcp_handshake, 34);
    EXPECT_EQ(0, mpack_node_u8(tcp_is_intercept));
    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}

TEST(POLICY_UPDATE, ProxyTcpIsIntercept)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.tcp_is_intercept |=TCP_IS_INTERCEPT_SINGLE;
    cmsg.tcp_is_intercept |=TCP_IS_INTERCEPT_TUNNEL;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    mpack_node_t tcp_is_intercept = mpack_node_array_at(tcp_handshake, 34);
    EXPECT_EQ(3, mpack_node_u8(tcp_is_intercept));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}

TEST(POLICY_UPDATE, ProxyPkgHeader0)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.tcp_s2c_rpkt_header.len = 0;
    cmsg.tcp_c2s_rpkt_header.len = 0;
    cmsg.tcp_wsacle_set_client = 0;
    cmsg.tcp_wsacle_set_server = 0;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    EXPECT_EQ(1, mpack_node_u32(mpack_node_array_at(tcp_handshake, 0)));
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 4))); // tcp_wsacle_set_client
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 5))); // tcp_wsacle_set_server
    EXPECT_EQ(6, mpack_node_u32(mpack_node_array_at(tcp_handshake, 6))); // tcp_wsacle_client
    EXPECT_EQ(7, mpack_node_u32(mpack_node_array_at(tcp_handshake, 7))); // tcp_wsacle_server
    EXPECT_EQ(0, mpack_node_bin_size(mpack_node_array_at(tcp_handshake, 32)));
    EXPECT_NE(nullptr, mpack_node_bin_data(mpack_node_array_at(tcp_handshake, 33)));
    EXPECT_EQ(0, mpack_node_bin_size(mpack_node_array_at(tcp_handshake, 32)));
    EXPECT_NE(nullptr, mpack_node_bin_data(mpack_node_array_at(tcp_handshake, 33)));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}


TEST(POLICY_UPDATE, ProxyTcpWsacleExist0)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.tcp_wsacle_set_client = 0;
    cmsg.tcp_wsacle_set_server = 0;
    cmsg.tcp_wsacle_client = 0;
    cmsg.tcp_wsacle_server = 0;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    EXPECT_EQ(1, mpack_node_u32(mpack_node_array_at(tcp_handshake, 0)));
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 4))); // tcp_wsacle_set_client
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 5))); // tcp_wsacle_set_server
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 6))); // tcp_wsacle_client
    EXPECT_EQ(0, mpack_node_u32(mpack_node_array_at(tcp_handshake, 7))); // tcp_wsacle_server

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}


TEST(POLICY_UPDATE, ProxyFqdnCatIds0)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.fqdn_cat_ids.num = 0;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    mpack_node_t fqdn_cat_id_vals = mpack_node_array_at(tcp_handshake, 27);
    EXPECT_EQ(0, mpack_node_array_length(fqdn_cat_id_vals));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}


TEST(POLICY_UPDATE, ProxyTcpAckRouteCtxs0)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.tcp_ack_route_ctx.len = 0;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    mpack_node_t tcp_ack_route_ctxs = mpack_node_array_at(tcp_handshake, 31);
    EXPECT_EQ(0, mpack_node_bin_size(tcp_ack_route_ctxs));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}


TEST(POLICY_UPDATE, ProxyTcpSeqSids0)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    memset(&test, 0, sizeof(test));
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    cmsg.tcp_seq_sids.num = 0;
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");
    mpack_node_t tcp_seq_sids = mpack_node_array_at(tcp_handshake, 28);
    EXPECT_EQ(0, mpack_node_array_length(tcp_seq_sids));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}

TEST(POLICY_UPDATE, ProxyOverLimit)
{
    char ctrl_pkt_buf[1024] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    struct proxy_cmsg cmsg = {0};
    test.type = POLICY_UPDATE_INTERCEPT;
    test.n_ids = 6;
    for (int i = 0; i < test.n_ids; i++)
    {
        test.ids[i] = 10000 + i;
    }

    gtest_cmsg_init(&cmsg);
    memcpy(&test.cmsg, &cmsg, sizeof(struct proxy_cmsg));
    test.cmsg.fqdn_cat_ids.num += FQDN_CAT_ID_VALS;
    test.cmsg.tcp_ack_sids.num += TCP_XXX_SIDS;
    test.cmsg.tcp_seq_sids.num += TCP_XXX_SIDS;
    tsg_sync_policy_update(&a_stream, &test, 1);

    ctrl_pkt_len = get_ctrl_pkt(ctrl_pkt_buf, sizeof(ctrl_pkt_buf));
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, ctrl_pkt_buf, ctrl_pkt_len);
    mpack_tree_parse(&tree);
    mpack_node_t root = mpack_tree_root(&tree);
    mpack_node_t params = mpack_node_map_cstr(root, "params");

    // proxy
    EXPECT_EQ(mpack_type_map, mpack_node_type(mpack_node_map_cstr(params, "proxy")));
    mpack_node_t proxy_map = mpack_node_map_cstr(params, "proxy");

    mpack_node_t tcp_handshake = mpack_node_map_cstr(proxy_map, "tcp_handshake");

    mpack_node_t fqdn_cat_id_vals = mpack_node_array_at(tcp_handshake, 27);
    EXPECT_EQ(FQDN_CAT_ID_VALS, mpack_node_array_length(fqdn_cat_id_vals));

    mpack_node_t tcp_seq_sids = mpack_node_array_at(tcp_handshake, 28);
    EXPECT_EQ(TCP_XXX_SIDS, mpack_node_array_length(tcp_seq_sids));

    mpack_node_t tcp_ack_sids = mpack_node_array_at(tcp_handshake, 29);
    EXPECT_EQ(TCP_XXX_SIDS, mpack_node_array_length(tcp_ack_sids));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}

void gtest_get_sce_mpack_date(char **mpack_data, size_t *mpack_size, uint64_t session_id, char *method, int n_ids, const char *sce)
{
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, mpack_data, mpack_size);
    mpack_build_map(&writer);

    // tsync : 2.0
    mpack_write_cstr(&writer, "tsync");
    mpack_write_cstr(&writer, "2.0");

    // session_id
    mpack_write_cstr(&writer, "session_id");
    mpack_write_u64(&writer, session_id);

    // state
    mpack_write_cstr(&writer, "state");
    mpack_write_cstr(&writer, "active");

    // method: log_update
    mpack_write_cstr(&writer, "method");
    mpack_write_cstr(&writer, method);

    // params
    mpack_write_cstr(&writer, "params");
    mpack_build_map(&writer);
    {
        mpack_write_cstr(&writer, sce);
        mpack_build_map(&writer);
        {
            mpack_write_cstr(&writer, "sf_profile_ids");

            if (n_ids == 0)
            {
                mpack_write_nil(&writer);
            }
            else
            {
                mpack_build_array(&writer);
                for (int i = 0; i < n_ids; i++)
                {
                    mpack_write_u32(&writer, i + 1);
                }
                mpack_complete_array(&writer);
            }
        }
        mpack_complete_map(&writer);
    }
    mpack_complete_map(&writer);
    mpack_complete_map(&writer);
    // printf("mpack_size = %lu\n", (unsigned long)mpack_size);
    // for (int i = 0; i < mpack_size; i++)
    // {
    //     printf("%x ", mpack_data[i]);
    // }
    EXPECT_EQ(mpack_writer_destroy(&writer), mpack_ok);
}

TEST(LOG_UPDATE, SceIllegalLog)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    // error payload_len
    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 123456789, (char *)"log_update", 3, "sce");
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size - 1));
    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    // error session
    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 123456789, (char *)"log_update", 3, "sce");
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));
    result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    // error method
    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"policy_update", 3, "sce");
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));
    result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    // n_profile_ids = 0
    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 0, "sce");
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));
    result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

     // no sce proxy shaper
    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 0, "sce_test_no_log");
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));
    result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;
}

TEST(LOG_UPDATE, SceNormal)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 3, "sce");
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_TRUE(result);

    struct sce_log_update *sce = (struct sce_log_update *)result;
    EXPECT_EQ(3, sce->n_profile_ids);
    for (int i = 0; i < (int)sce->n_profile_ids; i++)
    {
        EXPECT_EQ(i + 1, sce->profile_ids[i]);
    }

    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING));

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, SceTwice)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 3, "sce");
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_TRUE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 5, "sce");
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result_2 = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_EQ(result_2, result);

    struct sce_log_update *sce = (struct sce_log_update *)result_2;
    EXPECT_EQ(5, sce->n_profile_ids);
    for (int i = 0; i < (int)sce->n_profile_ids; i++)
    {
        EXPECT_EQ(i + 1, sce->profile_ids[i]);
    }

    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING));

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, SceOverLimitProfileIds)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_sce_mpack_date(&mpack_data, &mpack_size, 10, (char *)"log_update", 3 + SCE_PROFILE_IDS, "sce");
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING);
    EXPECT_TRUE(result);

    struct sce_log_update *sce = (struct sce_log_update *)result;
    EXPECT_EQ(SCE_PROFILE_IDS, sce->n_profile_ids);
    for (int i = 0; i < (int)sce->n_profile_ids; i++)
    {
        EXPECT_EQ(i + 1, sce->profile_ids[i]);
    }

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_CHAINING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

void gtest_get_shaper_mpack_date(char **mpack_data, size_t *mpack_size, uint64_t session_id, int n_sh_profile_ids, long long *rules, int n_profile_ids)
{
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, mpack_data, mpack_size);
    mpack_build_map(&writer);

    // tsync : 2.0
    mpack_write_cstr(&writer, "tsync");
    mpack_write_cstr(&writer, "2.0");

    // session_id
    mpack_write_cstr(&writer, "session_id");
    mpack_write_u64(&writer, session_id);

    // state
    mpack_write_cstr(&writer, "state");
    mpack_write_cstr(&writer, "active");

    // method: log_update
    mpack_write_cstr(&writer, "method");
    mpack_write_cstr(&writer, "log_update");

    // params
    mpack_write_cstr(&writer, "params");
    mpack_build_map(&writer);
    {
        mpack_write_cstr(&writer, "shaper");
        mpack_build_array(&writer);
        for (int i = 0; i < n_sh_profile_ids; i++)
        {
            mpack_build_map(&writer);
            {
                mpack_write_cstr(&writer, "rule_id");
                mpack_write_i64(&writer, rules[i]);
                mpack_write_cstr(&writer, "profile_ids");
                mpack_build_array(&writer);
                for (int j = 0; j < n_profile_ids; j++)
                {
                    mpack_write_u32(&writer, j + 1);
                }
                mpack_complete_array(&writer);
            }
            mpack_complete_map(&writer);
        }
        mpack_complete_array(&writer);
    }
    mpack_complete_map(&writer);
    mpack_complete_map(&writer);
    // printf("mpack_size = %lu\n", (unsigned long)mpack_size);
    // for (int i = 0; i < mpack_size; i++)
    // {
    //     printf("%x ", mpack_data[i]);
    // }
    EXPECT_EQ(mpack_writer_destroy(&writer), mpack_ok);
}

TEST(LOG_UPDATE, ShaperIllegalLog)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};
    long long rule[4] = {2, 3, 4, 5};

    // n_sh_profile_ids = 0;
    gtest_get_shaper_mpack_date(&mpack_data, &mpack_size, 10, 0, rule, 3);
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));
    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;
}

TEST(LOG_UPDATE, ShaperNormal)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};
    long long rule[4] = {2, 3, 4, 5};

    gtest_get_shaper_mpack_date(&mpack_data, &mpack_size, 10, 4, rule, 3);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
    EXPECT_TRUE(result);

    struct shaper_log_update *shaper = (struct shaper_log_update *)result;
    for (int i = 0; i < (int)shaper->n_shaper_rule; i++)
    {
        EXPECT_EQ(i + 2, shaper->shaper_rules[i].rule_id);
        EXPECT_EQ(3, shaper->shaper_rules[i].n_profile_ids);
        for (int j = 0; j < (int)shaper->shaper_rules[i].n_profile_ids; j++)
        {
            EXPECT_EQ(j + 1, shaper->shaper_rules[i].profile_ids[j]);
        }
    }

    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING));

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, ShaperTwice)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};
    long long rule[4] = {2, 3, 4, 5};

    gtest_get_shaper_mpack_date(&mpack_data, &mpack_size, 10, 4, rule, 3);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
    EXPECT_TRUE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    gtest_get_shaper_mpack_date(&mpack_data, &mpack_size, 10, 3, rule, 4);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result_2 = session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
    EXPECT_EQ(result_2, result);

    struct shaper_log_update *shaper = (struct shaper_log_update *)result;
    EXPECT_EQ(3, shaper->n_shaper_rule);
    for (int i = 0; i < (int)shaper->n_shaper_rule; i++)
    {
        EXPECT_EQ(i + 2, shaper->shaper_rules[i].rule_id);
        EXPECT_EQ(4, shaper->shaper_rules[i].n_profile_ids);
        for (int j = 0; j < (int)shaper->shaper_rules[i].n_profile_ids; j++)
        {
            EXPECT_EQ(j + 1, shaper->shaper_rules[i].profile_ids[j]);
        }
    }
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING));

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, ShaperOverLimitProfileIds)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};
    long long rule[4 + SHAPR_RULE_IDS] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};

    gtest_get_shaper_mpack_date(&mpack_data, &mpack_size, 10, 4 + SHAPR_RULE_IDS, rule, 3 + SHAPR_PROFILE_IDS);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING);
    EXPECT_TRUE(result);

    struct shaper_log_update *shaper = (struct shaper_log_update *)result;
    EXPECT_EQ(shaper->n_shaper_rule, SHAPR_RULE_IDS);
    for (int i = 0; i < (int)shaper->n_shaper_rule; i++)
    {
        EXPECT_EQ(i + 2, shaper->shaper_rules[i].rule_id);
        EXPECT_EQ(SHAPR_PROFILE_IDS, shaper->shaper_rules[i].n_profile_ids);
        for (int j = 0; j < (int)shaper->shaper_rules[i].n_profile_ids; j++)
        {
            EXPECT_EQ(j + 1, shaper->shaper_rules[i].profile_ids[j]);
        }
    }

    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_SHAPING, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

// if flag = 0 nil  flag = 1 array  flag = 2 ssl_upstream_version = thisisssl_upstream_version_for_test_twice
void gtest_get_proxy_mpack_date(char **mpack_data, size_t *mpack_size, uint64_t session_id, int flag)
{
    mpack_writer_t writer;
    mpack_writer_init_growable(&writer, mpack_data, mpack_size);
    mpack_build_map(&writer);

    // tsync : 2.0
    mpack_write_cstr(&writer, "tsync");
    mpack_write_cstr(&writer, "2.0");

    // session_id
    mpack_write_cstr(&writer, "session_id");
    mpack_write_u64(&writer, session_id);

    // state
    mpack_write_cstr(&writer, "state");
    mpack_write_cstr(&writer, "active");

    // method: log_update
    mpack_write_cstr(&writer, "method");
    mpack_write_cstr(&writer, "log_update");

    // params
    mpack_write_cstr(&writer, "params");
    mpack_build_map(&writer);
    {
        mpack_write_cstr(&writer, "proxy");
        mpack_build_map(&writer);
        mpack_write_cstr(&writer, "ssl_intercept_info");
        {
            if (flag == 0)
            {
                mpack_write_nil(&writer);
            }
            else
            {
                mpack_build_array(&writer);
                {
                    mpack_write_u8(&writer, 1);
                    mpack_write_u64(&writer, 2);
                    mpack_write_u64(&writer, 3);
                    if (flag == 2)
                    {
                        mpack_write_cstr(&writer, "thisisssl_upstream_version_for_test_twice");
                        mpack_write_cstr(&writer, "thisisssl_downstream_version_for_test_twice");
                        mpack_write_u8(&writer, 7);
                    }
                    else
                    {
                        mpack_write_cstr(&writer, "thisisssl_upstream_version");
                        mpack_write_cstr(&writer, "thisisssl_downstream_version");
                        mpack_write_u8(&writer, 4);
                    }

                    mpack_write_u8(&writer, 5);
                    mpack_write_cstr(&writer, "thisisssl_error");
                    mpack_write_cstr(&writer, "thisisssl_passthrough_reason");
                }
                mpack_complete_array(&writer);
            }
        }
        mpack_complete_map(&writer);
    }
    mpack_complete_map(&writer);
    mpack_complete_map(&writer);
    // printf("mpack_size = %lu\n", (unsigned long)mpack_size);
    // for (int i = 0; i < mpack_size; i++)
    // {
    //     printf("%x ", mpack_data[i]);
    // }
    EXPECT_EQ(mpack_writer_destroy(&writer), mpack_ok);
}

TEST(LOG_UPDATE, ProxyIllegalLog)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_proxy_mpack_date(&mpack_data, &mpack_size, 10, 0);
    EXPECT_EQ(-1, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT);
    EXPECT_FALSE(result);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, ProxyNormal)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_proxy_mpack_date(&mpack_data, &mpack_size, 10, 1);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT);
    EXPECT_TRUE(result);

    struct proxy_log_update *proxy = (struct proxy_log_update *)result;

    EXPECT_EQ(1, proxy->ssl_intercept_state);
    EXPECT_EQ(2, proxy->ssl_upstream_latency);
    EXPECT_EQ(3, proxy->ssl_downstream_latency);
    EXPECT_STREQ("thisisssl_upstream_version", proxy->ssl_upstream_version);
    EXPECT_STREQ("thisisssl_downstream_version", proxy->ssl_downstream_version);
    EXPECT_EQ(4, proxy->ssl_pinning_state);
    EXPECT_EQ(5, proxy->ssl_cert_verify);
    EXPECT_STREQ("thisisssl_error", proxy->ssl_error);
    EXPECT_STREQ("thisisssl_passthrough_reason", proxy->ssl_passthrough_reason);

    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING));

    free(proxy->ssl_downstream_version);
    free(proxy->ssl_error);
    free(proxy->ssl_passthrough_reason);
    free(proxy->ssl_upstream_version);
    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

TEST(LOG_UPDATE, ProxyTwice)
{
    char *mpack_data = NULL;
    size_t mpack_size = 0;
    const struct streaminfo a_stream = {0};

    gtest_get_proxy_mpack_date(&mpack_data, &mpack_size, 10, 1);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result = session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT);
    EXPECT_TRUE(result);
    free(mpack_data);
    mpack_data = NULL;
    mpack_size = 0;

    struct proxy_log_update *proxy = (struct proxy_log_update *)result;
    char *ssl_upstream_version = proxy->ssl_upstream_version;
    char *ssl_downstream_version = proxy->ssl_upstream_version;
    EXPECT_STREQ("thisisssl_upstream_version", proxy->ssl_upstream_version);
    EXPECT_STREQ("thisisssl_downstream_version", proxy->ssl_downstream_version);
    EXPECT_EQ(4, proxy->ssl_pinning_state);

    // second
    gtest_get_proxy_mpack_date(&mpack_data, &mpack_size, 10, 2);
    EXPECT_EQ(0, tsg_parse_log_update_payload(&a_stream, mpack_data, mpack_size));

    void *result_2 = session_log_update_data_get(&a_stream, TSG_SERVICE_INTERCEPT);
    EXPECT_EQ(result_2, result);

    proxy = (struct proxy_log_update *)result_2;
    char *ssl_upstream_version_2 = proxy->ssl_upstream_version;
    char *ssl_downstream_version_2 = proxy->ssl_upstream_version;
    EXPECT_NE(ssl_upstream_version_2, ssl_upstream_version);
    EXPECT_NE(ssl_downstream_version_2, ssl_downstream_version);

    EXPECT_STREQ("thisisssl_upstream_version_for_test_twice", proxy->ssl_upstream_version);
    EXPECT_STREQ("thisisssl_downstream_version_for_test_twice", proxy->ssl_downstream_version);
    EXPECT_EQ(7, proxy->ssl_pinning_state);

    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_CHAINING));
    EXPECT_FALSE(session_log_update_data_get(&a_stream, TSG_SERVICE_SHAPING));

    free(proxy->ssl_downstream_version);
    free(proxy->ssl_error);
    free(proxy->ssl_passthrough_reason);
    free(proxy->ssl_upstream_version);
    free(result);
    result = NULL;
    session_log_update_data_put(&a_stream, TSG_SERVICE_INTERCEPT, NULL);
    free(mpack_data);
    mpack_data = NULL;
}

int main(int argc, char *argv[])
{
	g_tsg_para.logger = MESA_create_runtime_log_handle("log/tsg_sync_state", 10);
	tsg_stat_create("./tsgconf/main.conf");
	tsg_stat_init();
	tsg_stat_start();

	testing::InitGoogleTest(&argc, argv);
	int ret = RUN_ALL_TESTS();
	MESA_destroy_runtime_log_handle(g_tsg_para.logger);
	return ret;
}
