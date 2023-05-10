#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_rule.h"

#include "gtest_common.h"

#include <gtest/gtest.h>

struct maat *g_tsg_maat_feather;

char *tsg_device_tag_get(void)
{
	return NULL;
}

char *tsg_data_center_get(void)
{
	return NULL;
}

int tsg_location_type_get(void)
{
	return 0;
}

int tsg_session_record_switch_get(void)
{
	return 0;
}

void *session_mac_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}
void *session_log_update_data_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	return NULL;
}

void *session_gather_app_results_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_conn_sketch_notify_data_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_business_data_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_session_flags_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_application_behavior_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_mirrored_and_capture_packets_exec_result_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_lua_user_defined_attribute_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_nat_c2s_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *session_nat_s2c_linkinfo_get(const struct streaminfo * a_stream)
{
	return NULL;
}

int session_matched_rules_async(const struct streaminfo * a_stream, TSG_SERVICE service, void * data)
{
	return 0;
}

const struct matched_policy_rules *session_matched_rules_get(const struct streaminfo *a_stream, enum TSG_SERVICE service)
{
	return 0;
}

void session_matched_rules_free(const struct streaminfo * a_stream, TSG_SERVICE service, void * data)
{
}

char srt_action_context_get_direction(const struct streaminfo * a_stream)
{
	return 0;
}

int tsg_get_app_name_by_id(struct maat *feahter, int app_id, char * app_name, int app_name_len, int is_joint_parent)
{
	return 0;
}

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo * a_stream)
{
	return NULL;
}

void *matched_rule_cites_security_compile(struct maat * feather, long long compile_id)
{
	return NULL;
}

void plugin_ex_data_security_compile_free(struct maat_compile * maat_compile)
{
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

