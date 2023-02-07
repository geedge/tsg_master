#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include "tsg_variable.h"

g_tsg_para_t g_tsg_para;

id2field_t g_tsg_fs2_field[TSG_FS2_MAX]={{0, TSG_FS2_TCP_LINKS, "tcp_links"},
										 {0, TSG_FS2_UDP_LINKS, "udp_links"}, 
										 {0, TSG_FS2_BYPASS, "bypass"},
										 {0, TSG_FS2_HIT_ADDR, "hit_addr"},
										 {0, TSG_FS2_HIT_SHARE, "hit_share"},
										 {0, TSG_FS2_INTERCEPT, "intercept"},
										 {0, TSG_FS2_SHAPING, "shaping"},
										 {0, TSG_FS2_EXCLUSION, "exclusion"},
										 {0, TSG_FS2_APP_DPKT_RESULT, "D_result"},
										 {0, TSG_FS2_APP_Q_RESULT, "Q_result"},
										 {0, TSG_FS2_APP_USER_RESULT, "U_result"},
										 {0, TSG_FS2_APP_BUILT_IN_RESULT, "B_result"},
										 {0, TSG_FS2_INJECT_PKT_SUCCESS, "inject_succuess"},
										 {0, TSG_FS2_INJECT_PKT_FAILED, "inject_failed"},
										 {0, TSG_FS2_MIRRORED_PKT_SUCCESS, "mirror_pkt_suc"},
										 {0, TSG_FS2_MIRRORED_BYTE_SUCCESS, "mirror_byte_suc"},
										 {0, TSG_FS2_MIRRORED_PKT_FAILED, "mirror_pkt_fai"},
										 {0, TSG_FS2_MIRRORED_BYTE_FAILED, "mirror_byte_fai"},
										 {0, TSG_FS2_SET_TIMOUT_SUCCESS, "set_timeout_suc"},
										 {0, TSG_FS2_SET_TIMOUT_FAILED, "set_timeout_fai"},
                                         {0, TSG_FS2_SUCESS_TAMPER, "tamper_sucess"},
                                         {0, TSG_FS2_TAMPER_FAILED_PLOAD_LESS_4, "tamper_nopload"},
                                         {0, TSG_FS2_TAMPER_FAILED_NOSWAP, "tamper_noswap"},
										 {0, TSG_FS2_ASN_ADD, "asn_add"},
										 {0, TSG_FS2_ASN_DEL, "asn_del"},
										 {0, TSG_FS2_GTPC_ADD, "gtpc_add"},
										 {0, TSG_FS2_GTPC_DEL, "gtpc_del"},
										 {0, TSG_FS2_LOCATION_ADD, "location_add"},
										 {0, TSG_FS2_LOCATION_DEL, "location_del"},
										 {0, TSG_FS2_FQDN_ADD, "fqdn_add"},
										 {0, TSG_FS2_FQDN_DEL, "fqdn_del"},
										 {0, TSG_FS2_SUBSCRIBER_ADD, "subscriber_add"},
										 {0, TSG_FS2_SUBSCRIBER_DEL, "subscriber_del"},
										 {0, TSG_FS2_SECURIRY_ADD, "security_add"},
										 {0, TSG_FS2_SECURIRY_DEL, "security_del"},
										 {0, TSG_FS2_MIRRORED_ADD, "mirrored_add"},
										 {0, TSG_FS2_MIRRORED_DEL, "mirrored_del"},
										 {0, TSG_FS2_HTTP_RES_ADD, "http_res_add"},
										 {0, TSG_FS2_HTTP_RES_DEL, "http_res_del"},
										 {0, TSG_FS2_DNS_RES_ADD, "dns_profile_add"},
										 {0, TSG_FS2_DNS_RES_DEL, "dns_profile_del"},
										 {0, TSG_FS2_APP_ID_ADD, "app_id_add"},
										 {0, TSG_FS2_APP_ID_DEL, "app_id_del"},
										 {0, TSG_FS2_TUNNEL_CATALOG_ADD, "t_catalog_add"},
										 {0, TSG_FS2_TUNNEL_CATALOG_DEL, "t_catalog_del"},
										 {0, TSG_FS2_TUNNEL_ENDPOINT_ADD, "t_endpoint_add"},
										 {0, TSG_FS2_TUNNEL_ENDPOINT_DEL, "t_endpoint_del"},
										 {0, TSG_FS2_TUNNEL_LABEL_ADD, "t_label_add"},
										 {0, TSG_FS2_TUNNEL_LABEL_DEL, "t_label_del"}
										};

id2field_t g_tsg_proto_name2id[PROTO_MAX]={{PROTO_UNKONWN, 0, "unknown"}, 
										 {PROTO_IPv4, 	0,	"IPV4"},
										 {PROTO_IPv6, 	0,	"IPV6"},
										 {PROTO_TCP, 	0, 	"TCP"},
										 {PROTO_UDP, 	0, 	"UDP"},
										 {PROTO_HTTP, 	0, 	"HTTP"},
										 {PROTO_MAIL, 	0, 	"MAIL"},
										 {PROTO_DNS, 	0, 	"DNS"},
										 {PROTO_FTP, 	0, 	"FTP"},
										 {PROTO_SSL, 	0, 	"SSL"},
										 {PROTO_SIP, 	0, 	"SIP"},
										 {PROTO_BGP, 	0, 	"BGP"},
										 {PROTO_STREAMING_MEDIA, 0, "STREAMING_MEDIA"},
										 {PROTO_QUIC, 	0,	 "QUIC"},
										 {PROTO_SSH, 	0, 	"SSH"},
										 {PROTO_SMTP, 	0, 	"SMTP"},
										 {PROTO_IMAP, 	0, 	"IMAP"},
										 {PROTO_POP3, 	0, 	"POP3"},
										 {PROTO_RTP, 	0, 	"RTP"},
										 {PROTO_APP, 	0,	"BASE"},
										 {PROTO_L2TP, 	0,	"L2TP"},
										 {PROTO_PPTP, 	0,	"PPTP"},
										 {PROTO_STRATUM, 	0,	"Stratum"},
										 {PROTO_RDP, 	0,	"RDP"},
										 {PROTO_DTLS, 	0,	"DTLS"}
										};

