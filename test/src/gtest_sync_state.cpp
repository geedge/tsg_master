#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <gtest/gtest.h>
#include <MESA/cJSON.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_sync_state.h"
#include "tsg_variable.h"
#include "mpack.h"

struct tsg_rt_para g_tsg_para;

extern int get_ctrl_pkt(char *buf, int len);

unsigned long long tsg_get_stream_trace_id(const struct streaminfo *a_stream)
{
    return 10;
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

TEST(SESSION_STATE, ActiveStateServiceChainingAndShaping0)
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

TEST(SESSION_STATE, ActiveStateServiceChainingAndShaping1)
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
    cmsg->tcp_wsacle_exist = 1;
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

    cmsg->src_ip_location_country = (char *)calloc(1, 256);
    snprintf(cmsg->src_ip_location_country, 256, "thisistest=%d", 7);

    cmsg->dst_ip_location_country = (char *)calloc(1, 256);
    snprintf(cmsg->dst_ip_location_country, 256, "thisistest=%d", 8);

    cmsg->src_ip_location_provine = (char *)calloc(1, 256);
    snprintf(cmsg->src_ip_location_provine, 256, "thisistest=%d", 9);

    cmsg->dst_ip_location_provine = (char *)calloc(1, 256);
    snprintf(cmsg->dst_ip_location_provine, 256, "thisistest=%d", 10);

    cmsg->src_ip_location_city = (char *)calloc(1, 256);
    snprintf(cmsg->src_ip_location_city, 256, "thisistest=%d", 11);

    cmsg->dst_ip_location_city = (char *)calloc(1, 256);
    snprintf(cmsg->dst_ip_location_city, 256, "thisistest=%d", 12);

    cmsg->src_ip_location_subdivision = (char *)calloc(1, 256);
    snprintf(cmsg->src_ip_location_subdivision, 256, "thisistest=%d", 13);

    cmsg->dst_ip_location_subdivision = (char *)calloc(1, 256);
    snprintf(cmsg->dst_ip_location_subdivision, 256, "thisistest=%d", 14);

    cmsg->ssl_client_ja3_fingerprint = (char *)calloc(1, 256);
    snprintf(cmsg->ssl_client_ja3_fingerprint, 256, "thisistest=%d", 15);

    cmsg->fqdn_cat_id_val.num = 4;
    for (size_t i = 0; i < 4; i++)
    {
        cmsg->fqdn_cat_id_val.value[i] = i + 1;
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

    cmsg->tcp_seq_route_ctx.num = 7;
    for (size_t i = 0; i < 7; i++)
    {
        cmsg->tcp_seq_route_ctx.value[i] = i + 4;
    }

    cmsg->tcp_ack_route_ctx.num = 8;
    for (size_t i = 0; i < 8; i++)
    {
        cmsg->tcp_ack_route_ctx.value[i] = i + 5;
    }

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
    free(cmsg->src_ip_location_country);
    free(cmsg->dst_ip_location_country);
    free(cmsg->src_ip_location_provine);
    free(cmsg->dst_ip_location_provine);
    free(cmsg->src_ip_location_city);
    free(cmsg->dst_ip_location_city);
    free(cmsg->src_ip_location_subdivision);
    free(cmsg->dst_ip_location_subdivision);
    free(cmsg->ssl_client_ja3_fingerprint);
}

TEST(POLICY_UPDATE, Proxy)
{
    char ctrl_pkt_buf[1024] = {0};
    char test_str[256] = {0};
    int ctrl_pkt_len = 0;
    struct streaminfo a_stream = {0};
    struct update_policy test;
    struct proxy_cmsg cmsg;
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
    EXPECT_EQ(16, mpack_node_u32(mpack_node_array_at(tcp_handshake, 14)));

    memcpy(test_str, mpack_node_str(mpack_node_array_at(tcp_handshake, 17)), mpack_node_strlen(mpack_node_array_at(tcp_handshake, 17)));
    EXPECT_STREQ("thisistest=2", test_str);
    memset(test_str, 0, sizeof(test_str));

    memcpy(test_str, mpack_node_str(mpack_node_array_at(tcp_handshake, 30)), mpack_node_strlen(mpack_node_array_at(tcp_handshake, 30)));
    EXPECT_STREQ("thisistest=15", test_str);
    memset(test_str, 0, sizeof(test_str));

    mpack_node_t fqdn_cat_id_vals = mpack_node_array_at(tcp_handshake, 31);
    EXPECT_EQ(4, mpack_node_array_length(fqdn_cat_id_vals));
    for (int i = 0; i < 4; i++)
    {
        EXPECT_EQ(i + 1, mpack_node_u32(mpack_node_array_at(fqdn_cat_id_vals, i)));
    }

    mpack_node_t tcp_ack_route_ctxs = mpack_node_array_at(tcp_handshake, 35);
    EXPECT_EQ(8, mpack_node_array_length(tcp_ack_route_ctxs));
    for (int i = 0; i < 8; i++)
    {
        EXPECT_EQ(i + 5, mpack_node_u8(mpack_node_array_at(tcp_ack_route_ctxs, i)));
    }

    // // sce
    // EXPECT_EQ(mpack_type_nil, mpack_node_type(mpack_node_map_cstr(params, "sce")));

    // // shaper
    // EXPECT_EQ(mpack_type_nil, mpack_node_type(mpack_node_map_cstr(params, "shaper")));

    EXPECT_EQ(mpack_tree_destroy(&tree), mpack_ok);
    gtest_cmsg_destroy(&cmsg);
}

int main(int argc, char *argv[])
{
    g_tsg_para.logger = MESA_create_runtime_log_handle("log/tsg_sync_state", 10);

    testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    MESA_destroy_runtime_log_handle(g_tsg_para.logger);
    return ret;
}
