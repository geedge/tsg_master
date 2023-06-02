#pragma once

#include <stdint.h>
#include <MESA/stream.h>

enum policy_type
{
    POLICY_UPDATE_INTERCEPT=0,
    POLICY_UPDATE_SERVICE_CHAINING,
    POLICY_UPDATE_SHAPING,
    POLICY_UPDATE_MAX
};

enum ssl_intercept_info_index
{
    SSL_INTERCEPT_STATE = 0,
    SSL_UPSTREAM_LATENCY,
    SSL_DOWNSTREAM_LATENCY,
    SSL_UPSTREAM_VERSION,
    SSL_DOWNSTREAM_VERSION,
    SSL_PINNING_STATE,
    SSL_CERT_VERIFY,
    SSL_ERROR,
    SSL_PASSTHROUGH_REASON,
    SSL_INTERCEPT_MAX_INDEX
};

#define FQDN_CAT_ID_VALS 8

struct fqdn_cat_id_val
{
    size_t num;
    uint32_t value[FQDN_CAT_ID_VALS];
};

#define TCP_XXX_SIDS 8
struct tcp_sids
{
    size_t num;
    uint16_t value[TCP_XXX_SIDS];
};

struct cmsg_buff
{
    char *buff;
    int len;
};

#define TCP_IS_INTERCEPT_SINGLE 0X01
#define TCP_IS_INTERCEPT_TUNNEL 0X02

struct proxy_cmsg
{
    uint8_t tcp_info_packet_cur_dir;
    uint8_t tcp_wsacle_exist;
    uint8_t tcp_wsacle_client;
    uint8_t tcp_wsacle_server;
    uint8_t tcp_sack_client;
    uint8_t tcp_sack_server;
    uint8_t tcp_ts_client;
    uint8_t tcp_ts_server;
    uint8_t tcp_protocol;
    uint8_t tcp_is_intercept;  // 1: single  2: tunnel
    uint16_t tcp_mss_client;
    uint16_t tcp_mss_server;
    uint16_t tcp_window_client;
    uint16_t tcp_window_server;
    uint32_t tcp_ts_client_val;
    uint32_t tcp_ts_server_val;
    uint32_t tcp_seq;
    uint32_t tcp_ack;    

    char *src_sub_id;
    char *dst_sub_id;
    char *src_asn;
    char *dst_asn;
    char *src_organization;
    char *dst_organization;
    char *src_ip_location_country;
    char *dst_ip_location_country;
    char *src_ip_location_provine;
    char *dst_ip_location_provine;
    char *src_ip_location_city;
    char *dst_ip_location_city;
    char *src_ip_location_subdivision;
    char *dst_ip_location_subdivision;
    char *ssl_client_ja3_fingerprint;
    struct fqdn_cat_id_val fqdn_cat_ids;
    struct tcp_sids tcp_seq_sids;
    struct tcp_sids tcp_ack_sids;
    struct cmsg_buff tcp_seq_route_ctx;
    struct cmsg_buff tcp_ack_route_ctx;

    struct cmsg_buff tcp_c2s_rpkt_header;
    struct cmsg_buff tcp_s2c_rpkt_header;
};

#define UPDATE_POLICY_RULE_IDS 8

struct update_policy
{
    enum policy_type type;
    int n_ids;
    long long ids[UPDATE_POLICY_RULE_IDS];
    struct proxy_cmsg cmsg;
};

struct proxy_log_update
{
    uint8_t ssl_pinning_state;
    uint8_t ssl_cert_verify;
    uint8_t ssl_intercept_state;
    uint64_t ssl_upstream_latency;
    uint64_t ssl_downstream_latency;
    char *ssl_upstream_version;
    char *ssl_downstream_version;
    char *ssl_error;
    char *ssl_passthrough_reason;
};

#define SHAPR_PROFILE_IDS 8

struct shaper_rule
{
    long long rule_id;
    size_t n_profile_ids;
    uint32_t profile_ids[SHAPR_PROFILE_IDS];
};

#define SHAPR_RULE_IDS 8
struct shaper_log_update
{
    size_t n_shaper_rule;
    struct shaper_rule shaper_rules[SHAPR_RULE_IDS];
};

#define SCE_PROFILE_IDS 8
struct sce_log_update
{
    size_t n_profile_ids;
    uint32_t profile_ids[SCE_PROFILE_IDS];
};

int tsg_sync_resetall_state(const struct streaminfo *a_stream);
int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_opening_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_closing_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_update, size_t n_policy_update);

int tsg_parse_log_update_payload(const struct streaminfo *a_stream, const void *payload, unsigned int payload_len);
