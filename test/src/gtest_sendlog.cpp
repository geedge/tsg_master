#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gtest_common.h"

#include <gtest/gtest.h>

int tsg_app_id2name(int app_id, char *app_name, int app_name_len, int is_joint_parent)
{
	return 0;
}

int tsg_get_location_type(void)
{
	return 19;
}

char *tsg_l7_protocol_id2name(unsigned int l7_protocol_id)
{
	return NULL;
}

char get_direction_from_tcpall(const struct streaminfo *a_stream)
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

