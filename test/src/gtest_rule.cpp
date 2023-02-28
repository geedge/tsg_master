#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_entry.h"
#include "gtest_common.h"

#include <gtest/gtest.h>

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

