#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

#include <gtest/gtest.h>

void tsg_maat_state_free(struct maat_state *state)
{
	
}

void destroy_bucket(struct leaky_bucket * * bucket, int thread_seq)
{
	
}

void plugin_ex_data_gtp_c_free(struct umts_user_info *user_info)
{
}

void plugin_ex_data_asn_number_free(struct asn_info *asn)
{
}

void plugin_ex_data_location_free(struct location_info *location)
{
}

void plugin_ex_data_subscriber_id_free(struct subscribe_id_info *subscriber)
{
}

void plugin_ex_data_tunnel_endpoint_free(struct tunnel_endpoint *t_enpoint)
{
}

int srt_attribute_set_ip_asn(const struct streaminfo * a_stream, struct maat *feather, struct asn_info **client_asn, struct asn_info **server_asn)
{
	return 0;
}

int  srt_attribute_set_ip_location(const struct streaminfo * a_stream, struct maat *feather, struct location_info **client_location, struct location_info **server_location)
{
	return 0;
}

int srt_attribute_set_subscriber_id(const struct streaminfo *a_stream, struct maat *feather, struct subscribe_id_info **client_subscribe_id, struct subscribe_id_info **server_subscribe_id)
{
	return 0;
}

int session_runtine_attribute_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info)
{
	return 0;
}

struct umts_user_info *tsg_get_umts_user_info_form_redis(struct maat *feather, unsigned int teid)
{
	return NULL;
}

int session_app_identify_result_cb(const struct streaminfo * a_stream, int bridge_id, void * data)
{
	return 0;
}

int session_flags_identify_result_cb(const struct streaminfo * a_stream, int bridge_id, void * data)
{
	return 0;
}

int tsg_sync_policy_update(const struct streaminfo *a_stream, struct update_policy *policy_array, int policy_array_num)
{
	return 0;
}

int matched_service_chaining_rules_deal(const struct streaminfo *a_stream, struct maat_rule *s_chaining_rules, size_t n_s_chaining_rules, int thread_seq)
{
	return 0;
}

int matched_shaping_rules_deal(const struct streaminfo * a_stream, struct maat_rule * shaping_results, size_t n_shaping_results, int thread_seq)
{
	return 0;
}

int session_packet_capture_by_rules_notify(const struct streaminfo * a_stream, struct maat_rule * rules, size_t n_rules, int thread_seq)
{
	return 0;
}

TEST(TM_Bridge, HitedSecurityPolicyResult)
{
	EXPECT_EQ(1,1);
	EXPECT_NE(nullptr, "");
	EXPECT_STREQ("460045157065560", "460045157065560");
}

int main(int argc, char *argv[])
{
	int ret=tsg_bridge_init("tsgconf/main.conf");
	if(ret<0)
	{
		return -1;
	}
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}

