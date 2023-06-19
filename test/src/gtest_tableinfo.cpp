#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "tsg_stat.h"
#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

#include <gtest/gtest.h>
const struct session_runtime_attribute *session_runtime_attribute_new(const struct streaminfo *a_stream)
{
    return NULL;
}

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo *a_stream)
{
    return 0;
}

int session_runtine_attribute_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info)
{
    return 0;
}

int session_mirror_packets_sync(const struct streaminfo *a_stream, struct maat_rule *result, struct mirrored_vlan *vlan)
{
    return 0;
}

int session_capture_packets_sync(const struct streaminfo *a_stream, struct maat_rule *result, int depth)
{
    return 0;
}

extern struct maat_runtime_para g_tsg_maat_rt_para;
extern size_t tsg_scan_string(const struct streaminfo *a_stream, struct maat *feather, const char *s_data, size_t s_data_len, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
TEST(TSG_Table, TSG_FIELD_HTTP_HOST)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "http_host_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_HTTP_HOST, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 5);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, http_host)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "http_host_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "http.host"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 5);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_HOST_CAT)
{
    const struct streaminfo a_stream = {0};
    unsigned int integer = 1003;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    struct maat_rule matched_rules[MAX_RESULT_NUM];
    EXPECT_EQ(1, tsg_scan_fqdn_category_id(&a_stream, g_tsg_maat_feather, &integer, 1, MAAT_SCAN_HTTP_HOST_CAT, mid, matched_rules, MAX_RESULT_NUM));
    EXPECT_EQ(matched_rules[0].rule_id, 6);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_URL)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "http_url_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_HTTP_URL, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 7);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_REQ_HDR)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "application/json;charset=UTF-8";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_REQ_HDR"), "Content-Type", strlen("Content-Type"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_REQ_HDR"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 8);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, http_request_header)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "application/json;charset=UTF-8";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "http.request.header"), "Content-Type", strlen("Content-Type"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "http.request.header"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 8);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_RES_HDR)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "GeoIP=HK:::22.26:114.17:v4;enwikimwuser-sessionId=d8fe6d620b7c8db3e5db;WMF-Last-Access=16-Jan-2023;WMF-Last-Access-Global=16-Jan-2023;";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_RES_HDR"), "Cookie", strlen("Cookie"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_RES_HDR"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 9);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, http_response_header)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "GeoIP=HK:::22.26:114.17:v4;enwikimwuser-sessionId=d8fe6d620b7c8db3e5db;WMF-Last-Access=16-Jan-2023;WMF-Last-Access-Global=16-Jan-2023;";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "http.response.header"), "Cookie", strlen("Cookie"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "http.response.header"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 9);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_REQ_BODY)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "TSG_FIELD_HTTP_REQ_BODY_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_REQ_BODY"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 10);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_HTTP_RES_BODY)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "TSG_FIELD_HTTP_RES_BODY_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_HTTP_RES_BODY"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 11);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_SNI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_sni_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_SSL_SNI, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 12);
    EXPECT_EQ(results[0].service_id, 3);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_extensions_server_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_sni_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.extensions_server_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 12);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_SNI_CAT)
{
    const struct streaminfo a_stream = {0};
    unsigned int integer = 1002;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    struct maat_rule matched_rules[MAX_RESULT_NUM];
    EXPECT_EQ(1, tsg_scan_fqdn_category_id(&a_stream, g_tsg_maat_feather, &integer, 1, MAAT_SCAN_SSL_SNI_CAT, mid, matched_rules, MAX_RESULT_NUM));
    EXPECT_EQ(matched_rules[0].rule_id, 13);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_CN)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_cn_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SSL_CN"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 14);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_subject_common_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_cn_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.subject_common_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 14);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_CN_CAT)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1005;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SSL_CN_CAT"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 15);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_SAN)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_san_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SSL_SAN"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 16);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SSL_SAN_CAT)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SSL_SAN_CAT"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 17);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_DNS_QNAME)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "dns_qname_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_DNS_QNAME"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 18);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, dns_qry_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "dns_qname_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "dns.qry.name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 18);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_DNS_QNAME_CAT)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1009;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_DNS_QNAME_CAT"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 19);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_QUIC_SNI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "quic_sni_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    struct maat_rule matched_rules[MAX_RESULT_NUM];
	EXPECT_EQ(1, tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_QUIC_SNI, mid, matched_rules, MAX_RESULT_NUM));
    EXPECT_EQ(matched_rules[0].rule_id, 20);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, quic_sni)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "quic_sni_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "quic.sni"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 20);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_QUIC_SNI_CAT)
{
    const struct streaminfo a_stream = {0};
    unsigned int integer = 1011;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    struct maat_rule matched_rules[MAX_RESULT_NUM];
    EXPECT_EQ(1, tsg_scan_fqdn_category_id(&a_stream, g_tsg_maat_feather, &integer, 1, MAAT_SCAN_QUIC_SNI_CAT, mid, matched_rules, MAX_RESULT_NUM));
    EXPECT_EQ(matched_rules[0].rule_id, 21);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_ACCOUNT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "username_policy_id_1@gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_ACCOUNT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 22);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_FROM)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "username_policy_id_1@gtest.com_from";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_FROM"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 23);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_TO)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "username_policy_id_1@gtest.com_to";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_TO"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 24);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_SUBJECT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_25_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_SUBJECT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 25);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_CONTENT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_26_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_CONTENT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 26);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_ATT_NAME)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_27_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_ATT_NAME"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 27);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_MAIL_ATT_CONTENT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_28_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_MAIL_ATT_CONTENT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 28);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_FTP_URI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ftp_url_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_FTP_URI"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 29);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_FTP_CONTENT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_30_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_FTP_CONTENT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 30);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_FTP_ACCOUNT)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "subjet_policy_id_31_gtest.com";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_FTP_ACCOUNT"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 31);
    maat_state_free(mid);
    mid = NULL;
}

extern size_t tsg_scan_ipv4_address(const struct streaminfo *a_stream, struct maat *feather, struct ipaddr *p_addr, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *rules, size_t n_rules);
TEST(TSG_Table, TSG_SECURITY_SOURCE_ADDR)
{
    struct streaminfo a_stream = {0};
    a_stream.type = STREAM_TYPE_TCP;
    struct ipaddr p_addr = {0};
    struct stream_tuple4_v4 tuple4_v4 = {0};
    p_addr.v4 = &tuple4_v4;
    p_addr.v4->saddr = inet_addr("255.255.255.254");
    p_addr.v4->source = htons(1);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ipv4_address((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &p_addr, MAAT_SCAN_SRC_IP_ADDR, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 32);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ip_src)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ip.src"), inet_addr("255.255.255.254"), htons(1), 6, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 32);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_srcport)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.srcport"), inet_addr("255.255.255.254"), htons(1), 6, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 32);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_srcport)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.srcport"), inet_addr("255.255.255.254"), htons(30002), 17, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 33);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_SECURITY_DESTINATION_ADDR)
{
    struct streaminfo a_stream = {0};
    a_stream.type = STREAM_TYPE_TCP;
    struct ipaddr p_addr = {0};
    struct stream_tuple4_v4 tuple4_v4 = {0};
    p_addr.v4 = &tuple4_v4;
    p_addr.v4->saddr = inet_addr("255.255.255.253");
    p_addr.v4->source = htons(1);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ipv4_address((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &p_addr, MAAT_SCAN_DST_IP_ADDR, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 34);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ip_dst)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ip.dst"), inet_addr("255.255.255.253"), htons(1), 6, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 34);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_dstport)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.dstport"), inet_addr("255.255.255.253"), htons(1), 6, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 34);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_dstport)
{
    struct streaminfo a_stream = {0};
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_ipv4(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.dstport"), inet_addr("255.255.255.253"), htons(30002), 17, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 35);
    maat_state_free(mid);
    mid = NULL;
}

extern size_t tsg_scan_ip_asn(const struct streaminfo *a_stream, struct maat *feather, struct asn_info *asn, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_result);
TEST(TSG_Table, TSG_SECURITY_SOURCE_ASN)
{
    struct streaminfo a_stream = {0};
    struct asn_info asn = {0};
    asn.asn_id = (char *)"source_asn_test";
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ip_asn((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &asn, MAAT_SCAN_SRC_ASN, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 36);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_SECURITY_DESTINATION_ASN)
{
    struct streaminfo a_stream = {0};
    struct asn_info asn = {0};
    asn.asn_id = (char *)"destination_asn_test";
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ip_asn((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &asn, MAAT_SCAN_DST_ASN, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 37);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

extern size_t tsg_scan_ip_location(const struct streaminfo *a_stream, struct maat *feather, struct location_info *location, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
TEST(TSG_Table, TSG_SECURITY_SOURCE_LOCATION)
{
    struct streaminfo a_stream = {0};
    struct location_info location = {0};
	location.full_location=(char *)"country_full_test..city_full_test..";
	location.full_location_len=strlen(location.full_location);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ip_location((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &location, MAAT_SCAN_SRC_LOCATION, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 38);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_SECURITY_DESTINATION_LOCATION)
{
    struct streaminfo a_stream = {0};
    struct location_info location = {0};
	location.full_location=(char *)"country_full_test..city_full_test..";
	location.full_location_len=strlen(location.full_location);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_ip_location((const struct streaminfo *)&a_stream, g_tsg_maat_feather, &location, MAAT_SCAN_DST_LOCATION, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 39);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SIP_ORIGINATOR_DESCRIPTION)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "sip_region_buff_SIP_ORIGINATOR_DESCRIPTION";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SIP_ORIGINATOR_DESCRIPTION"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 40);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_SIP_RESPONDER_DESCRIPTION)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "sip_region_buff_SIP_RESPONDER_DESCRIPTION";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "TSG_FIELD_SIP_RESPONDER_DESCRIPTION"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 41);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FILED_GTP_IMSI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "gtp_imsi_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_GTP_IMSI, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 42);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FILED_GTP_PHONE_NUMBER)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "13766688899";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_GTP_PHONE_NUMBER, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 43);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FILED_GTP_APN)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "gtp_apn_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_GTP_APN, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 44);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_DECYPTION_EXCLUSION_SSL_SNI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "DECYPTION_EXCLUSION_SSL_SNI_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_EXCLUSION_SSL_SNI, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 45);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

extern size_t tsg_scan_integer(const struct streaminfo *a_stream, struct maat *feather, long long s_integer, enum MAAT_SCAN_TB idx, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
TEST(TSG_Table, TSG_SECURITY_TUNNEL)
{
    const struct streaminfo a_stream = {0};
    long long s_integer = 5;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_integer(&a_stream, g_tsg_maat_feather, s_integer, MAAT_SCAN_TUNNEL_ID, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 46);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

extern size_t tsg_scan_session_flags(const struct streaminfo *a_stream, struct maat *feather, unsigned long flag, struct maat_state *s_mid, struct maat_rule *results, size_t n_results);
TEST(TSG_Table, TSG_SECURITY_FLAG)
{
    const struct streaminfo a_stream = {0};
    unsigned long flag = 8;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_session_flags(&a_stream, g_tsg_maat_feather, flag, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 47);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_DTLS_SNI)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "dtls_sni_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    struct maat_rule results[MAX_RESULT_NUM] = {0};
    EXPECT_EQ(tsg_scan_string(&a_stream, g_tsg_maat_feather, s_data, s_data_len, MAAT_SCAN_DTLS_SNI, mid, results, MAX_RESULT_NUM), 1);
    EXPECT_EQ(results[0].rule_id, 48);
    EXPECT_EQ(results[0].service_id, 2);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, TSG_FIELD_DTLS_SNI_CAT)
{
    const struct streaminfo a_stream = {0};
    unsigned int integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    struct maat_rule matched_rules[MAX_RESULT_NUM];
    EXPECT_EQ(1, tsg_scan_fqdn_category_id(&a_stream, g_tsg_maat_feather, &integer, 1, MAAT_SCAN_DTLS_SNI_CAT, mid, matched_rules, MAX_RESULT_NUM));
    EXPECT_EQ(matched_rules[0].rule_id, 49);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_payload_c2s_first_data)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_tcp_c2s_first_payload";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.payload.c2s_first_data"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 50);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_payload_s2c_first_data)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_tcp_s2c_first_payload";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.payload.s2c_first_data"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 51);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_payload_c2s_first_data_len)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.payload.c2s_first_data_len"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 52);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_payload_s2c_first_data_len)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.payload.s2c_first_data_len"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 53);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_payload)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_tcp_payload";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.payload"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 54);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_syn_fingerprint)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_tcp_syn_fingerprint";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.syn.fingerprint"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 55);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, tcp_sack_fingerprint)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_tcp_sack_fingerprint";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "tcp.sack.fingerprint"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 56);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_payload_c2s_first_data)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_udp_payload_c2s_first_data";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.payload.c2s_first_data"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 57);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_payload_s2c_first_data)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_udp_payload_s2c_first_data";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.payload.s2c_first_data"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 58);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_payload_c2s_first_data_len)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.payload.c2s_first_data_len"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 59);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_payload_s2c_first_data_len)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.payload.s2c_first_data_len"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 60);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, udp_payload)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "test_udp_payload";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "udp.payload"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 61);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_analysis_ja3)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_analysis_ja3_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.analysis.ja3"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 62);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_cert_fingerprint)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_cert_fingerprint_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.cert.fingerprint"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 63);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_cert_serial_number)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_cert_serial_number_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.cert.serial_number"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 64);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_issuer_common_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_issuer_common_name_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.issuer_common_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 65);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_issuer_organization_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_issuer_organization_name_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.issuer_organization_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 66);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_issuer_country_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_issuer_country_name_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.issuer_country_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 67);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_subject_country_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_subject_country_name_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.subject_country_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 68);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_subject_organization_name)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_subject_organization_name_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.subject_organization_name"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 69);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_not_valid_before)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_not_valid_before_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.not_valid_before"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 70);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_not_valid_after)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_not_valid_after_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.not_valid_after"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 71);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, ssl_handshake_certificate_algorithm_id)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "ssl_handshake_certificate_algorithm_id_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "ssl.handshake.certificate.algorithm_id"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 72);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, general_session_analysis_app_id)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "general.session.analysis.app_id"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 73);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, APP_SIG_SESSION_ATTRIBUTE_STRING)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "sig_session_attribute_string_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "APP_SIG_SESSION_ATTRIBUTE_STRING"), "SIG_SEESION", strlen("SIG_SEESION"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "APP_SIG_SESSION_ATTRIBUTE_STRING"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 74);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, APP_SIG_SESSION_ATTRIBUTE_FLAG)
{
    const struct streaminfo a_stream = {0};
    const char *s_data = "sig_session_attribute_flag_test";
    size_t s_data_len = strlen(s_data);
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_string(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "APP_SIG_SESSION_ATTRIBUTE_FLAG"), s_data, s_data_len, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 75);
    maat_state_free(mid);
    mid = NULL;
}

TEST(TSG_Table, APP_SIG_SESSION_ATTRIBUTE_INTEGER)
{
    const struct streaminfo a_stream = {0};
    long long integer = 1007;
    struct maat_state *mid = maat_state_new(g_tsg_maat_feather, a_stream.threadnum);
    maat_state_set_scan_district(mid, maat_get_table_id(g_tsg_maat_feather, "APP_SIG_SESSION_ATTRIBUTE_INTEGER"), "SIG_SEESION", strlen("SIG_SEESION"));

    size_t n_matched_rules = 0;
    long long matched_rules[MAX_RESULT_NUM];
    int is_hited = maat_scan_integer(g_tsg_maat_feather, maat_get_table_id(g_tsg_maat_feather, "APP_SIG_SESSION_ATTRIBUTE_INTEGER"), integer, matched_rules, MAX_RESULT_NUM, &n_matched_rules, mid);
    EXPECT_EQ(is_hited, MAAT_SCAN_HIT);
    EXPECT_EQ(n_matched_rules, 1);
    EXPECT_EQ(matched_rules[0], 76);
    maat_state_free(mid);
    mid = NULL;
}

int main(int argc, char *argv[])
{
	tsg_stat_create("./tsgconf/main.conf");
	tsg_stat_init();

	tsg_maat_rule_init("tsgconf/main.conf");
	tsg_stat_start();
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}