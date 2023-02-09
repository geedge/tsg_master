#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_entry.h"
#include "gtest_common.h"

#include <gtest/gtest.h>

g_tsg_para_t g_tsg_para;
struct id2field g_tsg_proto_name2id[PROTO_MAX]={{PROTO_UNKONWN, 0, "unknown"}, 
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

int app_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	return 0;
}

int session_flags_identify_result_cb(const struct streaminfo *a_stream, int bridge_id, void *data)
{
	return 0;
}

unsigned int tsg_l7_protocol_name2id(const char *l7_protocol_name)
{
	return 0;
}

void set_session_attribute_label(const struct streaminfo *a_stream, enum TSG_ATTRIBUTE_TYPE type, void *value, int value_len, int thread_seq)
{
}

int tsg_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info)
{
	return 0;
}


TEST(MasterTest, SetVlan)
{
	//int ret=set_vlan(NULL, NULL, NULL, 0, NULL, LOG_COMMON_TUNNELS_VLAN_SRC_ID);
	//EXPECT_EQ(1, ret);
}


int main(int argc, char *argv[])
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

