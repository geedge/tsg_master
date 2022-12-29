#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../inc/app_label.h"
#include "../inc/tsg_rule.h"
#include "../inc/tsg_send_log.h"
#include "../inc/tsg_statistic.h"
//#include "../src/tsg_entry.h"
#include "../src/tsg_send_log_internal.h"
#include "../inc/tsg_ssl_utils.h"
#include "../src/tsg_ssh_utils.h"
#include "../src/tsg_protocol_common.h"

#include "tsg_master_gtest_function.h"

#include <gtest/gtest.h>

/*
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.qq_web.wechat) = openvpn.psiphon
	L7(openvpn), appSketch(psiphon), Thrid(openvpn.wechat) = openvpn.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn.wechat) = openvpn.ssl.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn) = openvpn.ssl.psiphon
	L7(openvpn.ssl), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(null), appSketch(psiphon), Thrid(openvpn.ssl.wechat) = openvpn.ssl.psiphon
	L7(null), appSketch(psiphon), Thrid(wechat) = psiphon
	L7(null), appSketch(null), Thrid(openvpn.ssl.wechat) = openvpn.ssl.wechat
	L7(null), appSketch(null), Thrid(null) = unknown
*/

TEST(MasterTest, AppFullPath)
{

}


TEST(MasterTest, SetVlan)
{
	//int ret=set_vlan(NULL, NULL, NULL, 0, NULL, LOG_COMMON_TUNNELS_VLAN_SRC_ID);
	//EXPECT_EQ(1, ret);
}


int main(int argc, char *argv[])
{
	libsapp_setup_env(argc,argv);
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

