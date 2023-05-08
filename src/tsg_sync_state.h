#pragma once

#include <stdint.h>
#include <MESA/stream.h>

enum policy_type
{
    POLICY_UPDATE_INTERCEPT = 0,
    POLICY_UPDATE_SERVICE_CHAINING,
    POLICY_UPDATE_SHAPING,
    POLICY_UPDATE_MAX
};

struct cmsg_int32_array
{
    size_t num;
    uint32_t value[8];
};

struct cmsg_int16_array
{
    size_t num;
    uint16_t value[8];
};

struct cmsg_int8_array
{
    size_t num;
    uint8_t value[64];
};

struct proxy_cmsg
{
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_mss_client;
    uint16_t tcp_mss_server;
    uint8_t tcp_wsacle_exist;
    uint8_t tcp_wsacle_client;
    uint8_t tcp_wsacle_server;
    uint8_t tcp_sack_client;
    uint8_t tcp_sack_server;
    uint8_t tcp_ts_client;
    uint8_t tcp_ts_server;
    uint8_t tcp_protocol;
    uint16_t tcp_window_client;
    uint16_t tcp_window_server;
    uint32_t tcp_ts_client_val;
    uint32_t tcp_ts_server_val;
    uint8_t tcp_info_packet_cur_dir;
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
    struct cmsg_int32_array fqdn_cat_id_val;
    struct cmsg_int16_array tcp_seq_sids;
    struct cmsg_int16_array tcp_ack_sids;
    struct cmsg_int8_array tcp_seq_route_ctx;
    struct cmsg_int8_array tcp_ack_route_ctx;
};

struct update_policy
{
    enum policy_type type;
    int n_ids;
    long long ids[8];
    struct proxy_cmsg cmsg;
};

int tsg_sync_resetall_state(const struct streaminfo *a_stream);
int tsg_send_session_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_opening_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_closing_state(const struct streaminfo *a_stream, unsigned char state);
int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_update, size_t n_policy_update);

// int tsg_recv_control_pkt(const struct streaminfo *a_stream, const void *payload, int payload_len);
