#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include "tsg_rule.h"
#include "tsg_label.h"
#include "tsg_entry.h"
#include "tsg_variable.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

#include <gtest/gtest.h>

extern struct maat_runtime_para g_tsg_maat_rt_para;

const struct session_runtime_attribute *session_runtime_attribute_get(const struct streaminfo * a_stream)
{
	return 0;
}

int session_runtine_attribute_get_umts_user_info(const struct streaminfo * a_stream, struct umts_user_info * * user_info)
{
	return 0;
}

int session_mirror_packets_sync(const struct streaminfo * a_stream, struct maat_rule * result, struct mirrored_vlan * vlan)
{
	return 0;
}

int session_capture_packets_sync(const struct streaminfo * a_stream, struct maat_rule * result, int depth)
{
	return 0;
}

TEST(TM, ExDataGTPC)
{
	/******************************************************************************************************
		table name: TSG_DYN_MOBILE_IDENTITY_APN_TEID
		id teid imsi phone_number apn imei is_valid
		"1\t111039813\t460045157065560\t861440152009856\tcmiott.gxqli.mcto60g.com\t8626070583075127\t1",
		"2\t111052899\t460045157053102\t861440152041083\tcmiott.wkctf.mcto60g.com\t8626070583008402\t1"
	******************************************************************************************************/
	
	long long teid=111039813;
	struct umts_user_info *user_info=(struct umts_user_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (const char *)&teid);
	EXPECT_NE(nullptr, user_info);
	EXPECT_STREQ("460045157065560", user_info->imsi);
	EXPECT_STREQ("861440152009856", user_info->msisdn);
	EXPECT_STREQ("111039813.cmiott.gxqli.mcto60g.com", user_info->apn);
	EXPECT_STREQ("8626070583075127", user_info->imei);

	teid=111052899;
	user_info=(struct umts_user_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (const char *)&teid);
	EXPECT_NE(nullptr, user_info);
	EXPECT_STREQ("460045157053102", user_info->imsi);
	EXPECT_STREQ("861440152041083", user_info->msisdn);
	EXPECT_STREQ("111052899.cmiott.wkctf.mcto60g.com", user_info->apn);
	EXPECT_STREQ("8626070583008402", user_info->imei);
}

TEST(TM, ExDataAPPIDDictUnknown)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"4\tunknown\t0\tnull\tcategory\tsubcategory\ttechnology\trisk\tcharacteristics\tnull\tnull\tnull\t1\t3600\t3600\t1800\t1800\t1"
	**************************************************************************************************************************/
	long long ll_app_id=4;
	struct app_id_dict *dict=(struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	dict=(struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	EXPECT_NE(nullptr, dict);
	EXPECT_EQ(4, dict->app_id);
	EXPECT_STREQ("unknown", dict->app_name);
	EXPECT_EQ(0, dict->parent_app_id);
	EXPECT_STREQ(nullptr, dict->parent_app_name);
	
	EXPECT_STREQ("category", dict->category);
	EXPECT_STREQ("subcategory", dict->subcategory);
	EXPECT_STREQ("technology", dict->technology);
	EXPECT_STREQ("risk", dict->risk);
	EXPECT_STREQ("characteristics", dict->characteristics);
	//depends_on_app_ids
	//implicitly_uses_app_ids
	//  deny_action
	EXPECT_EQ(1, dict->continue_scanning);
	EXPECT_EQ(3600, dict->tcp_timeout);
	EXPECT_EQ(3600, dict->udp_timeout);
	EXPECT_EQ(1800, dict->tcp_half_close);
	EXPECT_EQ(1800, dict->tcp_time_wait);

	dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
}

TEST(TM, ExDataAPPIDDictDenyActionDrop)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"67\thttp\t0\tnull\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"drop\",\"after_n_packets\":0,\"send_icmp_unreachable\":1,\"send_tcp_reset\":1}\t0\t60\t120\t30\t30\t1",
	**************************************************************************************************************************/
	long long ll_app_id=67;
	struct app_id_dict *dict=(struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	EXPECT_NE(nullptr, dict);
	EXPECT_EQ(67, dict->app_id);
	EXPECT_STREQ("http", dict->app_name);
	EXPECT_EQ(0, dict->parent_app_id);
	EXPECT_STREQ(nullptr, dict->parent_app_name);
	
	EXPECT_STREQ("networking", dict->category);
	EXPECT_STREQ("infrastructure", dict->subcategory);
	EXPECT_STREQ("network-protocol", dict->technology);
	EXPECT_STREQ("3", dict->risk);
	EXPECT_STREQ("used-by-malware,vulnerability,widely-used", dict->characteristics);
	//depends_on_app_ids
	//implicitly_uses_app_ids

	//deny_action
	EXPECT_EQ(TSG_DENY_TYPE_APP_DROP, dict->deny_app_para.type);
	EXPECT_EQ(0, dict->deny_app_para.after_n_packets);
	EXPECT_EQ(1, dict->deny_app_para.drop_para.send_icmp_enable);
	EXPECT_EQ(1, dict->deny_app_para.drop_para.send_reset_enable);
	
	EXPECT_EQ(0, dict->continue_scanning);
	EXPECT_EQ(60, dict->tcp_timeout);
	EXPECT_EQ(120, dict->udp_timeout);
	EXPECT_EQ(30, dict->tcp_half_close);
	EXPECT_EQ(30, dict->tcp_time_wait);

	dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
}

TEST(TM, ExDataAPPIDDictDenyActionRatelimit)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"68\thttps\t0\tnull\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"rate_limit\","bps":1000}\t0\t0\t0\t0\t0\t1",
	**************************************************************************************************************************/
	long long ll_app_id=68;
	struct app_id_dict *dict=(struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	EXPECT_NE(nullptr, dict);
	EXPECT_EQ(68, dict->app_id);
	EXPECT_STREQ("https", dict->app_name);
	EXPECT_EQ(0, dict->parent_app_id);
	EXPECT_STREQ(nullptr, dict->parent_app_name);
	
	EXPECT_STREQ("networking", dict->category);
	EXPECT_STREQ("infrastructure", dict->subcategory);
	EXPECT_STREQ("network-protocol", dict->technology);
	EXPECT_STREQ("3", dict->risk);
	EXPECT_STREQ("used-by-malware,vulnerability,widely-used", dict->characteristics);
	//depends_on_app_ids
	//implicitly_uses_app_ids

	//deny_action
	EXPECT_EQ(TSG_DENY_TYPE_APP_RATELIMIT, dict->deny_app_para.type);
	EXPECT_EQ(1000, dict->deny_app_para.bps);

	EXPECT_EQ(0, dict->continue_scanning);
	EXPECT_EQ(0, dict->tcp_timeout);
	EXPECT_EQ(0, dict->udp_timeout);
	EXPECT_EQ(0, dict->tcp_half_close);
	EXPECT_EQ(0, dict->tcp_time_wait);

	dict=(struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
}

TEST(TM, ExDataASNBuiltIn)
{
	/*************************************************************************************************************************
		table name: TSG_IP_ASN_BUILT_IN
	**************************************************************************************************************************/
	EXPECT_EQ(1, 1);
}

TEST(TM, ExDataASNUserDefine)
{
	/*************************************************************************************************************************
		table name: TSG_IP_ASN_USER_DEFINED
	**************************************************************************************************************************/
	EXPECT_EQ(1, 1);
}

TEST(TM, ExDataLocationBuiltIn)
{
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_BUILT_IN
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"6777621\t1819730\t4\t124.156.128.0\t124.156.191.255\t22.25\t114.1667\t50.0\ten\tAS\tAsia\tHK\tHong\\bKong\tOther\tOther\tOther\tRoad1\tAsia/Hong_Kong\t1",
		"3716523\t1814992\t4\t192.168.50.1\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tXin\\bXi\\bGang\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("124.156.128.1");
	struct location_info *location = NULL;
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);

	EXPECT_STREQ("Other", location->city_full);
	EXPECT_STREQ("Hong Kong", location->country_full);
	EXPECT_STREQ("Other", location->province_full);
	EXPECT_STREQ(NULL, location->subdivision_addr);
	EXPECT_EQ(2, location->ref_cnt);

	temp_addr.ipv4 = inet_addr("192.168.50.2");
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);

	EXPECT_STREQ("Xin Xi Gang", location->city_full);
	EXPECT_STREQ("China", location->country_full);
	EXPECT_STREQ("Beijing", location->province_full);
	EXPECT_STREQ(NULL, location->subdivision_addr); // location_field_num == 18; not 19
	EXPECT_EQ(2, location->ref_cnt);

	location = NULL;
	temp_addr.ipv4 = inet_addr("124.156.127.1");
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);
	EXPECT_EQ(NULL, location);
}

TEST(TM, ExDataLocationUserDefine)
{
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_USER_DEFINED
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"371652\t181499\t4\t192.168.50.10\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tHua\\bYan\\bBei\\bLi\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("192.168.50.11");
	struct location_info *location = NULL;
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, &temp_addr, (void **)&location, 1);

	EXPECT_STREQ("Hua Yan Bei Li", location->city_full);
	EXPECT_STREQ("China", location->country_full);
	EXPECT_STREQ("Beijing", location->province_full);
	EXPECT_STREQ(NULL, location->subdivision_addr); // location_field_num == 18; not 19
	EXPECT_EQ(2, location->ref_cnt);

	location = NULL;
	temp_addr.ipv4 = inet_addr("124.156.127.1");
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, &temp_addr, (void **)&location, 1);
	EXPECT_EQ(NULL, location);
}

TEST(TM, ExDataFQDNCategoryBuiltIn)
{
	/*************************************************************************************************************************
		table name: TSG_FQDN_CATEGORY_BUILT_IN
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"106285681\t4\t106285681.201198.com\t1\t1",
		"106285682\t5\t106285682.201198.com\t1\t1"
	**************************************************************************************************************************/
	struct fqdn_category *category_ids[2] = {0};
	int ret = maat_fqdn_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_BUILT_IN].id, "106285681.201198.com", (void **)category_ids, 2);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(4, category_ids[0]->category_id);
	EXPECT_EQ(NULL, category_ids[1]);

	category_ids[0] = NULL;
	ret = 0;
	ret = maat_fqdn_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_BUILT_IN].id, "106285682.201198.com", (void **)category_ids, 2);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(5, category_ids[0]->category_id);
	EXPECT_EQ(NULL, category_ids[1]);

	category_ids[0] = NULL;
}

TEST(TM, ExDataFQDNCategoryUserDefine)
{
	/*************************************************************************************************************************
		table name: TSG_FQDN_CATEGORY_USER_DEFINED
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"1106285681\t4\t1106285681.201198.com\t1\t1",
		"1106285682\t5\t1106285682.201198.com\t1\t1"
	**************************************************************************************************************************/
	struct fqdn_category *category_ids[2] = {0};
	int ret = maat_fqdn_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_USER_DEFINED].id, "1106285681.201198.com", (void **)category_ids, 2);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(4, category_ids[0]->category_id);
	EXPECT_EQ(NULL, category_ids[1]);

	category_ids[0] = NULL;
	ret = 0;
	ret = maat_fqdn_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_FQDN_CAT_USER_DEFINED].id, "1106285682.201198.com", (void **)category_ids, 2);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(5, category_ids[0]->category_id);
	EXPECT_EQ(NULL, category_ids[1]);

	category_ids[0] = NULL;
}

TEST(TM, ExDataTunnelCatalog)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_CATALOG
		tunnel_id tunnel_name tunnel_type composition is_valid
		"977\t1.1.1.1-1.1.1.1\tGTP\t1367\t1",
		"978\t1.1.1.1-1.1.1.1\tGTP\t1367&1605\t1"
	**************************************************************************************************************************/
	struct tunnel_catalog *t_catalog[3] = {0};
	unsigned long long bool_id_array[2] = {1367, 1605};
	size_t n_bool_id_array = 2;
	int ret = maat_bool_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_CATALOG].id, (unsigned long long *)bool_id_array, n_bool_id_array, (void **)(&t_catalog), 3);

	EXPECT_EQ(2, ret);
	EXPECT_EQ(978, t_catalog[0]->id);
	EXPECT_STREQ("1.1.1.1-1.1.1.1", t_catalog[0]->name);
	EXPECT_STREQ("GTP", t_catalog[0]->type);
	EXPECT_STREQ("1367&1605", t_catalog[0]->composition);

	EXPECT_EQ(977, t_catalog[1]->id);
	EXPECT_STREQ("1.1.1.1-1.1.1.1", t_catalog[1]->name);
	EXPECT_STREQ("GTP", t_catalog[1]->type);
	EXPECT_STREQ("1367", t_catalog[1]->composition);

	EXPECT_EQ(NULL, t_catalog[2]);
	t_catalog[0] = NULL;
	t_catalog[1] = NULL;
}

TEST(TM, ExDataTunnelEndpoint)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_ENDPOINT
		endpoint_id endpoint_group_id addr_type addr_format ip1 ip2 description is_valid
		"989\t4\t192.50.0.0\t192.50.255.255\ttest\t1",
		"990\t4\t192.50.0.0\t192.50.255.255\ttest\t1"
	**************************************************************************************************************************/
	struct tunnel_endpoint *all_endpoint[3] = {0};
	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("192.50.0.0");
	int ret = maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (const struct ip_addr *)&temp_addr, (void **)all_endpoint, 3);

	EXPECT_EQ(2, ret);
	EXPECT_EQ(989, all_endpoint[0]->id);
	EXPECT_STREQ("test", all_endpoint[0]->description);
	EXPECT_EQ(990, all_endpoint[1]->id);
	EXPECT_STREQ("test", all_endpoint[1]->description);

	ret = 0;
	all_endpoint[0] = NULL;
	all_endpoint[1] = NULL;
	temp_addr.ipv4 = inet_addr("192.50.255.255");
	ret = maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (const struct ip_addr *)&temp_addr, (void **)all_endpoint, 3);

	EXPECT_EQ(2, ret);
	EXPECT_EQ(989, all_endpoint[0]->id);
	EXPECT_STREQ("test", all_endpoint[0]->description);
	EXPECT_EQ(990, all_endpoint[1]->id);
	EXPECT_STREQ("test", all_endpoint[1]->description);

	all_endpoint[0] = NULL;
	all_endpoint[1] = NULL;
}

TEST(TM, ExDataTunnelLabel)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_LABEL
		label_id label_group_id label is_valid
		"15560\t15560\tVLAN_ID\t1",
		"15561\t15561\tVLAN_ID\t1"
	**************************************************************************************************************************/
	void *label_id = maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_LABEL].id, "VLAN_ID");
	EXPECT_EQ(0, (long long)label_id);
}

TEST(TM, ExDataSubscriberID)
{
	/*************************************************************************************************************************
		table name: TSG_DYN_SUBSCRIBER_IP
		id addr_type ip subscriber_id is_valid
		"1299\t4\t192.168.56.28\ttest5628\t1",
		"1300\t4\t192.168.56.28\ttest5627\t1"
	**************************************************************************************************************************/
	struct subscribe_id_info *subscribe_id = (struct subscribe_id_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, "192.168.56.28");
	EXPECT_STREQ("test5628", subscribe_id->subscribe_id);

	subscribe_id = (struct subscribe_id_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, "192.168.56.27");
	EXPECT_STREQ("test5627", subscribe_id->subscribe_id);

	subscribe_id = (struct subscribe_id_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_SUBSCRIBER_IP2ID].id, "192.168.56.26");
	EXPECT_EQ(NULL, subscribe_id);
}

TEST(TM, ExDataDNSRecordsProfileA)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_DNS_RECORDS
		record_id record_name record_type record_values is_valid
		"8119\teditTypeA\tA\t[{\"value\":\"1.1.1.1\",\"priority\":null},{\"value\":\"2.2.2.2\",\"priority\":null},{\"value\":\"3.3.3.3\",\"priority\":null}]\t1",
		"7961\tFile\tAAAA\t[{\"value\":\"1030::C9B4:FF12:48AA:1A2B\",\"priority\":null},{\"value\":\"1030::C9B4:FF12:48AA:1A2C\",\"priority\":null}]\t1",
		"7701\tTypeCNAME\tCNAME\t[{\"value\":\"www.facebook.com\",\"priority\":null},{\"value\":\"www.twitter.com\",\"priority\":null}]\t1"
	**************************************************************************************************************************/
	long long profile_id = 8119;
	struct dns_profile_records *profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(8119, profile_records->record_id);
	EXPECT_EQ(1, profile_records->answer_type);
	EXPECT_EQ(3, profile_records->record_num);

	EXPECT_EQ(1, profile_records->record_val[0].answer_type);
	EXPECT_EQ(4, profile_records->record_val[0].len);
	EXPECT_EQ(0, profile_records->record_val[0].selected_flag);
	EXPECT_EQ(inet_addr("1.1.1.1"), profile_records->record_val[0].v4_addr.s_addr);

	EXPECT_EQ(1, profile_records->record_val[1].answer_type);
	EXPECT_EQ(4, profile_records->record_val[1].len);
	EXPECT_EQ(0, profile_records->record_val[1].selected_flag);
	EXPECT_EQ(inet_addr("2.2.2.2"), profile_records->record_val[1].v4_addr.s_addr);

	EXPECT_EQ(1, profile_records->record_val[2].answer_type);
	EXPECT_EQ(4, profile_records->record_val[2].len);
	EXPECT_EQ(0, profile_records->record_val[2].selected_flag);
	EXPECT_EQ(inet_addr("3.3.3.3"), profile_records->record_val[2].v4_addr.s_addr);

	profile_id = 8110;
	profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(NULL, profile_records);
}

TEST(TM, ExDataDNSRecordsProfileAAAA)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_DNS_RECORDS
		record_id record_name record_type record_values is_valid
		"8119\teditTypeA\tA\t[{\"value\":\"1.1.1.1\",\"priority\":null},{\"value\":\"2.2.2.2\",\"priority\":null},{\"value\":\"3.3.3.3\",\"priority\":null}]\t1",
		"7961\tFile\tAAAA\t[{\"value\":\"1030::C9B4:FF12:48AA:1A2B\",\"priority\":null},{\"value\":\"1030::C9B4:FF12:48AA:1A2C\",\"priority\":null}]\t1",
		"7701\tTypeCNAME\tCNAME\t[{\"value\":\"www.facebook.com\",\"priority\":null},{\"value\":\"www.twitter.com\",\"priority\":null}]\t1"
	**************************************************************************************************************************/
	long long profile_id = 7961;
	uint8_t u6_addr8[16] = {0};
	struct dns_profile_records *profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(7961, profile_records->record_id);
	EXPECT_EQ(28, profile_records->answer_type);
	EXPECT_EQ(2, profile_records->record_num);

	EXPECT_EQ(28, profile_records->record_val[0].answer_type);
	EXPECT_EQ(16, profile_records->record_val[0].len);
	EXPECT_EQ(0, profile_records->record_val[0].selected_flag);
	inet_pton(AF_INET6, "1030::C9B4:FF12:48AA:1A2B", u6_addr8);
	EXPECT_EQ(0, memcmp(u6_addr8, profile_records->record_val[0].v6_addr.__in6_u.__u6_addr8, 16));

	EXPECT_EQ(28, profile_records->record_val[1].answer_type);
	EXPECT_EQ(16, profile_records->record_val[1].len);
	EXPECT_EQ(0, profile_records->record_val[1].selected_flag);
	inet_pton(AF_INET6, "1030::C9B4:FF12:48AA:1A2C", u6_addr8);
	EXPECT_EQ(0, memcmp(u6_addr8, profile_records->record_val[1].v6_addr.__in6_u.__u6_addr8, 16));

	profile_id = 8110;
	profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(NULL, profile_records);
}

TEST(TM, ExDataDNSRecordsProfileCNAME)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_DNS_RECORDS
		record_id record_name record_type record_values is_valid
		"8119\teditTypeA\tA\t[{\"value\":\"1.1.1.1\",\"priority\":null},{\"value\":\"2.2.2.2\",\"priority\":null},{\"value\":\"3.3.3.3\",\"priority\":null}]\t1",
		"7961\tFile\tAAAA\t[{\"value\":\"1030::C9B4:FF12:48AA:1A2B\",\"priority\":null},{\"value\":\"1030::C9B4:FF12:48AA:1A2C\",\"priority\":null}]\t1",
		"7701\tTypeCNAME\tCNAME\t[{\"value\":\"www.facebook.com\",\"priority\":null},{\"value\":\"www.twitter.com\",\"priority\":null}]\t1"
	**************************************************************************************************************************/
	long long profile_id = 7701;
	struct dns_profile_records *profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(7701, profile_records->record_id);
	EXPECT_EQ(5, profile_records->answer_type);
	EXPECT_EQ(2, profile_records->record_num);

	EXPECT_EQ(5, profile_records->record_val[0].answer_type);
	EXPECT_EQ(strlen("www.facebook.com"), profile_records->record_val[0].len);
	EXPECT_EQ(0, profile_records->record_val[0].selected_flag);
	EXPECT_STREQ("www.facebook.com", profile_records->record_val[0].cname);

	EXPECT_EQ(5, profile_records->record_val[1].answer_type);
	EXPECT_EQ(strlen("www.twitter.com"), profile_records->record_val[1].len);
	EXPECT_EQ(0, profile_records->record_val[1].selected_flag);
	EXPECT_STREQ("www.twitter.com", profile_records->record_val[1].cname);

	profile_id = 8110;
	profile_records = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	EXPECT_EQ(NULL, profile_records);
}

TEST(TM, ExDataResponsePagesProfile)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_RESPONSE_PAGES
		profile_id profile_name format path is_valid
		"957\ttest-html-1\thtml\tforeign_files/TSG_PROFILE_RESPONSE_PAGES.1\t1",
		"958\ttest-html-2\thtml\tforeign_files/TSG_PROFILE_RESPONSE_PAGES.2\t1"
	**************************************************************************************************************************/
	long long profile_id = 957;
	struct http_response_pages *response_pages = (struct http_response_pages *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
	EXPECT_EQ(957, response_pages->profile_id);
	EXPECT_EQ(HTTP_RESPONSE_FORMAT_HTML, response_pages->format);
	EXPECT_EQ(strlen("test1"), response_pages->content_len);
	EXPECT_STREQ("test1", response_pages->content);

	profile_id = 958;
	response_pages = (struct http_response_pages *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
	EXPECT_EQ(958, response_pages->profile_id);
	EXPECT_EQ(HTTP_RESPONSE_FORMAT_HTML, response_pages->format);
	EXPECT_EQ(strlen("test2"), response_pages->content_len);
	EXPECT_STREQ("test2", response_pages->content);

	profile_id = 959;
	response_pages = (struct http_response_pages *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
	EXPECT_EQ(NULL, response_pages);
}

TEST(TM, ExDataTrafficMirrorProfile)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_TRAFFIC_MIRROR
		profile_id profile_name vlan_ids is_valid
		"845\t168.50.28yinyong\t[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34]\t1",
		"123\ttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest\t[66]\t1"
	**************************************************************************************************************************/
	long long profile_id = 845;
	struct traffic_mirror_profile *mirror_profile = (struct traffic_mirror_profile *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_PROFILE_MIRROR].id, (const char *)&(profile_id));
	EXPECT_EQ(845, mirror_profile->profile_id);
	EXPECT_EQ(32, mirror_profile->vlan.num);
	for (int i = 0; i < 32; i++)
	{
		EXPECT_EQ(i + 3, mirror_profile->vlan.id[i]);
	}

	profile_id = 123;
	mirror_profile = (struct traffic_mirror_profile *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_PROFILE_MIRROR].id, (const char *)&(profile_id));
	EXPECT_EQ(123, mirror_profile->profile_id);
	EXPECT_EQ(1, mirror_profile->vlan.num);
	EXPECT_EQ(66, mirror_profile->vlan.id[0]);

	profile_id = 124;
	mirror_profile = (struct traffic_mirror_profile *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_PROFILE_MIRROR].id, (const char *)&(profile_id));
	EXPECT_EQ(NULL, mirror_profile);
}

TEST(TM, ExDataSessionRecordEnable)
{
	/*************************************************************************************************************************
		table name: T_VSYS_INFO
		id is_enable_session_record is_valid
		"6\t1\t1"
	**************************************************************************************************************************/
	EXPECT_EQ(g_tsg_maat_rt_para.session_record_switch, 1);
}

TEST(TMAPI, GetUmtsUserInfoFromRedis)
{
	/******************************************************************************************************
		table name: TSG_DYN_MOBILE_IDENTITY_APN_TEID
		id teid imsi phone_number apn imei is_valid
		"1\t111039813\t460045157065560\t861440152009856\tcmiott.gxqli.mcto60g.com\t8626070583075127\t1",
		"2\t111052899\t460045157053102\t861440152041083\tcmiott.wkctf.mcto60g.com\t8626070583008402\t1"
	******************************************************************************************************/

	long long teid = 111039813;
	struct umts_user_info *user_info = (struct umts_user_info *)tsg_get_umts_user_info_form_redis(g_tsg_maat_feather, teid);
	struct umts_user_info *user_info_right = (struct umts_user_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (const char *)&teid);
	EXPECT_EQ(user_info, user_info_right);

	teid = 111052899;
	user_info = (struct umts_user_info *)tsg_get_umts_user_info_form_redis(g_tsg_maat_feather, teid);
	user_info_right = (struct umts_user_info *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_GTP_IP2SIGNALING].id, (const char *)&teid);
	EXPECT_EQ(user_info, user_info_right);

	user_info = NULL;
	user_info_right = NULL;
}

TEST(TMAPI, GetAppIdDictUnknown)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"4\tunknown\t0\tnull\tcategory\tsubcategory\ttechnology\trisk\tcharacteristics\tnull\tnull\tnull\t1\t3600\t3600\t1800\t1800\t1"
	**************************************************************************************************************************/
	long long ll_app_id = 4;
	struct app_id_dict *dict_right = (struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	struct app_id_dict *dict = (struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
	EXPECT_EQ(dict_right, dict);

	dict_right = NULL;
	dict = NULL;
}

TEST(TMAPI, GetAppIdDictDenyActionDrop)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"67\thttp\t0\tnull\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"drop\",\"after_n_packets\":0,\"send_icmp_unreachable\":1,\"send_tcp_reset\":1}\t0\t60\t120\t30\t30\t1",
	**************************************************************************************************************************/
	long long ll_app_id = 67;
	struct app_id_dict *dict_right = (struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	struct app_id_dict *dict = (struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
	EXPECT_EQ(dict_right, dict);

	dict_right = NULL;
	dict = NULL;
}

TEST(TMAPI, GetAppIdDictDenyActionRatelimit)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"68\thttps\t0\tnull\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"rate_limit\","bps":1000}\t0\t0\t0\t0\t0\t1",
	**************************************************************************************************************************/
	long long ll_app_id = 68;
	struct app_id_dict *dict_right = (struct app_id_dict *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_APP_ID_DICT].id, (const char *)&ll_app_id);
	struct app_id_dict *dict = (struct app_id_dict *)matched_rule_cites_app_id_dict(g_tsg_maat_feather, ll_app_id);
	EXPECT_EQ(dict_right, dict);

	dict_right = NULL;
	dict = NULL;
}

TEST(TMAPI, GetAppNameByIdIllegalPara)
{
	// int tsg_get_app_name_by_id(int app_id, char *app_name, int app_name_len, int is_joint_parent)
	char app_name[128] = {0};
	EXPECT_EQ(0, tsg_get_app_name_by_id(g_tsg_maat_feather, 0, app_name, 128, 1));
	EXPECT_EQ(0, tsg_get_app_name_by_id(g_tsg_maat_feather, 68, NULL, 128, 1));
	EXPECT_EQ(0, tsg_get_app_name_by_id(g_tsg_maat_feather, 68, app_name, 0, 1));
}

TEST(TMAPI, GetAppNameByIdParentAppId0)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"68\thttps\t0\tnull\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"rate_limit\","bps":1000}\t0\t0\t0\t0\t0\t1",
	**************************************************************************************************************************/
	int app_id = 68;
	char app_name[128] = {0};
	EXPECT_EQ(0, tsg_get_app_name_by_id(g_tsg_maat_feather, app_id, app_name, 2, 1));
	EXPECT_EQ(strlen("https"), tsg_get_app_name_by_id(g_tsg_maat_feather, app_id, app_name, 128, 1));
}

TEST(TMAPI, GetAppNameByIdParentAppId1)
{
	/*************************************************************************************************************************
		table name: APP_ID_DICT
		app_id app_name parent_app_id parent_app_name category subcategory technology risk characteristics depends_on_app_ids implicitly_uses_app_ids deny_action continue_scanning tcp_timeout udp_timeout tcp_half_close tcp_time_wait is_valid
		"70\thttps\t1\tssl\tnetworking\tinfrastructure\tnetwork-protocol\t3\tused-by-malware,vulnerability,widely-used\tnull\tnull\t{\"method\":\"rate_limit\","bps":1000}\t0\t0\t0\t0\t0\t1",
	**************************************************************************************************************************/
	int app_id = 70;
	char app_name[128] = {0};
	EXPECT_EQ(0, tsg_get_app_name_by_id(g_tsg_maat_feather, app_id, app_name, 2, 1));
	EXPECT_EQ(strlen("ssl.https"), tsg_get_app_name_by_id(g_tsg_maat_feather, app_id, app_name, 128, 1));
}

TEST(TMAPI, GetLocationInfoLocationBuiltIn)
{
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_BUILT_IN
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"6777621\t1819730\t4\t124.156.128.0\t124.156.191.255\t22.25\t114.1667\t50.0\ten\tAS\tAsia\tHK\tHong\\bKong\tOther\tOther\tOther\tRoad1\tAsia/Hong_Kong\t1",
		"3716523\t1814992\t4\t192.168.50.1\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tXin\\bXi\\bGang\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct location_info *client_location = NULL, *server_location = NULL;
	tuple4_v4.daddr = inet_addr("124.156.128.2");
	tuple4_v4.saddr = inet_addr("192.168.50.3");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;
	srt_attribute_set_ip_location(&a_stream, g_tsg_maat_feather, &client_location, &server_location);

	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("124.156.128.1");
	struct location_info *location = NULL;
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);
	EXPECT_EQ(server_location, location);

	temp_addr.ipv4 = inet_addr("192.168.50.2");
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);
	EXPECT_EQ(client_location, location);

	location = NULL;
	client_location = NULL;
	server_location = NULL;
	tuple4_v4.daddr = inet_addr("124.156.127.1");
	tuple4_v4.saddr = inet_addr("192.168.49.1");
	a_stream.addr.tuple4_v4 = &tuple4_v4;
	srt_attribute_set_ip_location(&a_stream, g_tsg_maat_feather, &client_location, &server_location);
	EXPECT_EQ(NULL, server_location);
	EXPECT_EQ(NULL, client_location);
}

TEST(TMAPI, GetLocationInfoLocationUserDefine)
{
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_USER_DEFINED
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"371652\t181499\t4\t192.168.50.10\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tHua\\bYan\\bBei\\bLi\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct location_info *client_location = NULL, *server_location = NULL;
	tuple4_v4.saddr = inet_addr("192.168.50.11");
	tuple4_v4.daddr = inet_addr("192.168.50.12");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;
	srt_attribute_set_ip_location(&a_stream, g_tsg_maat_feather, &client_location, &server_location);

	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("192.168.50.11");
	struct location_info *location = NULL;
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_USER_DEFINED].id, &temp_addr, (void **)&location, 1);
	EXPECT_EQ(client_location, location);
	EXPECT_EQ(server_location, location);
}

TEST(TMAPI, GetLocationInfoBoth)
{
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_USER_DEFINED
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"371652\t181499\t4\t192.168.50.10\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tHua\\bYan\\bBei\\bLi\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	/*************************************************************************************************************************
		table name: TSG_IP_LOCATION_BUILT_IN
		location_id geoname_id addr_type start_ip end_ip latitude longitude coords language continent_abbr continent_full country_abbr country_full province_abbr province_full city_full subdivision_addr time_zone is_valid
		"6777621\t1819730\t4\t124.156.128.0\t124.156.191.255\t22.25\t114.1667\t50.0\ten\tAS\tAsia\tHK\tHong\\bKong\tOther\tOther\tOther\tRoad1\tAsia/Hong_Kong\t1",
		"3716523\t1814992\t4\t192.168.50.1\t192.168.50.255\t34.7725\t113.7266\t50.0\ten\tAS\tAsia\tCN\tChina\tBeijing\tBeijing\tXin\\bXi\\bGang\tRoad1\tAsia/Shanghai\t1"
	**************************************************************************************************************************/
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct location_info *client_location = NULL, *server_location = NULL;
	tuple4_v4.saddr = inet_addr("124.156.128.11");
	tuple4_v4.daddr = inet_addr("192.168.50.12");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;
	srt_attribute_set_ip_location(&a_stream, g_tsg_maat_feather, &client_location, &server_location); // find in MAAT_PLUGIN_LOCATION_USER_DEFINED

	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("192.168.50.11");
	struct location_info *location = NULL;
	maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_LOCATION_BUILT_IN].id, &temp_addr, (void **)&location, 1);
	EXPECT_NE(server_location, client_location);
	EXPECT_NE(client_location, location);
	EXPECT_NE(server_location, location);
}

TEST(TMAPI, GetFQDNCategoryIdUserDefine)
{
	/*************************************************************************************************************************
		table name: TSG_FQDN_CATEGORY_USER_DEFINED
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"1106285683\t6\t1106285683.201198.com\t1\t1",
		"1106285684\t7\t1106285684.201198.com\t1\t1"
		"1106285685\t7\t1106285684.201198.com\t1\t1"
	**************************************************************************************************************************/
	unsigned int category_ids[3] = {0};
	int ret = tsg_get_fqdn_category_ids(g_tsg_maat_feather, (char *)"1106285683.201198.com", category_ids, MAX_CATEGORY_ID_NUM);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(6, category_ids[0]);

	category_ids[0] = 0;
	ret = 0;
	ret = tsg_get_fqdn_category_ids(g_tsg_maat_feather, (char *)"1106285684.201198.com", category_ids, MAX_CATEGORY_ID_NUM); // get_fqdn_category_id 去重
	EXPECT_EQ(1, ret);
	EXPECT_EQ(7, category_ids[0]);
	EXPECT_EQ(0, category_ids[1]);
}

TEST(TMAPI, GetFQDNCategoryIdBuiltIn)
{
	/*************************************************************************************************************************
		table name: TSG_FQDN_CATEGORY_BUILT_IN
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"106285688\t8\t106285688.201198.com\t1\t1",
		"106285689\t9\t106285689.201198.com\t1\t1"
		"106285690\t9\t106285689.201198.com\t1\t1"
		"106285691\t10\t1106285683.201198.com\t1\t1"
	**************************************************************************************************************************/
	unsigned int category_ids[3] = {0};
	int ret = tsg_get_fqdn_category_ids(g_tsg_maat_feather, (char *)"106285688.201198.com", category_ids, MAX_CATEGORY_ID_NUM);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(8, category_ids[0]);

	category_ids[0] = 0;
	ret = 0;
	ret = tsg_get_fqdn_category_ids(g_tsg_maat_feather, (char *)"106285689.201198.com", category_ids, MAX_CATEGORY_ID_NUM); // get_fqdn_category_id 去重
	EXPECT_EQ(1, ret);
	EXPECT_EQ(9, category_ids[0]);
	EXPECT_EQ(0, category_ids[1]);
}

TEST(TMAPI, GetFQDNCategoryIdBoth)
{
	/*************************************************************************************************************************
		table name: TSG_FQDN_CATEGORY_BUILT_IN
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"106285691\t10\t1106285683.201198.com\t1\t1"

		table name: TSG_FQDN_CATEGORY_USER_DEFINED
		id category_id fqdn match_method(0=complete,1=suf) is_valid
		"1106285683\t6\t1106285683.201198.com\t1\t1",
	**************************************************************************************************************************/
	unsigned int category_ids[3] = {0};
	int ret = tsg_get_fqdn_category_ids(g_tsg_maat_feather, (char *)"1106285683.201198.com", category_ids, MAX_CATEGORY_ID_NUM); // 优先get TSG_FQDN_CATEGORY_USER_DEFINED
	EXPECT_EQ(1, ret);
	EXPECT_EQ(6, category_ids[0]);
	EXPECT_EQ(0, category_ids[1]);
}

TEST(TMAPI, ScanTunnelId)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_CATALOG
		tunnel_id tunnel_name tunnel_type composition is_valid
		"977\t1.1.1.1-1.1.1.1\tGTP\t1367\t1",
		"978\t1.1.1.1-1.1.1.1\tGTP\t1367&1605\t1"
	**************************************************************************************************************************/

	// tsg_scan_tunnel_id(const struct streaminfo *a_stream, struct maat_rule *results, size_t n_results, struct maat_state *s_mid, long long *bool_id_array, size_t n_bool_id_array)
	long long bool_id_array[2] = {1367, 1605};
	size_t n_bool_id_array = 2, n_results = 2;
	struct streaminfo a_stream = {0};
	struct maat_rule results[2] = {0};
	struct maat_state *s_mid = maat_state_new(g_tsg_maat_feather, 0);
	int ret = tsg_scan_tunnel_id(&a_stream, g_tsg_maat_feather, results, n_results, s_mid, bool_id_array, n_bool_id_array);

	EXPECT_EQ(2, ret);
	EXPECT_EQ(4, results[0].rule_id);
	EXPECT_EQ(16, results[0].action);
	EXPECT_EQ(0, results[0].service_id);
	EXPECT_EQ(1, results[0].do_log);

	EXPECT_EQ(3, results[1].rule_id);
	EXPECT_EQ(1, results[1].action);
	EXPECT_EQ(0, results[1].service_id);
	EXPECT_EQ(1, results[1].do_log);
	maat_state_free(s_mid);
	s_mid=NULL;
}

extern int tsg_get_endpoint_id(const struct streaminfo *a_stream, struct maat *feather, struct tunnel_endpoint **client_endpoint, struct tunnel_endpoint **server_endpoint, long long *endpoint_id_array, int endpoint_id_array_num);
TEST(TMAPI, GetEndPointId)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_ENDPOINT
		endpoint_id endpoint_group_id addr_type addr_format ip1 ip2 description is_valid
		"991\t4\t192.40.128.0\t192.40.255.255\ttest\t1",
		"992\t4\t192.40.0.0\t192.40.127.255\ttest\t1"
	**************************************************************************************************************************/

	// int tsg_get_endpoint_id(const struct streaminfo *a_stream, struct maat *feather, struct tunnel_endpoint **client_endpoint, struct tunnel_endpoint **server_endpoint, long long *endpoint_id_array, int endpoint_id_array_num)
	long long endpoint_id_array[128] = {0};
	int endpoint_id_array_num = 128;
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct tunnel_endpoint *client_endpoint = NULL, *server_endpoint = NULL;
	tuple4_v4.daddr = inet_addr("192.40.128.1");
	tuple4_v4.saddr = inet_addr("192.40.0.1");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;

	int ret = tsg_get_endpoint_id(&a_stream, g_tsg_maat_feather, &client_endpoint, &server_endpoint, endpoint_id_array, endpoint_id_array_num);
	EXPECT_EQ(2, ret);
	EXPECT_EQ(992, endpoint_id_array[0]);
	EXPECT_EQ(991, endpoint_id_array[1]);

	ret = 0;
	struct tunnel_endpoint *all_endpoint[2] = {0};
	struct ip_addr temp_addr = {0};
	temp_addr.ip_type = 4;
	temp_addr.ipv4 = inet_addr("192.40.128.1");
	ret = maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (const struct ip_addr *)&temp_addr, (void **)all_endpoint, 2);

	EXPECT_EQ(1, ret);
	EXPECT_EQ(server_endpoint, all_endpoint[0]);

	ret = 0;
	all_endpoint[0] = NULL;
	all_endpoint[1] = NULL;
	temp_addr.ipv4 = inet_addr("192.40.0.1");
	ret = maat_ip_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_TUNNEL_ENDPOINT].id, (const struct ip_addr *)&temp_addr, (void **)all_endpoint, 2);

	EXPECT_EQ(1, ret);
	EXPECT_EQ(client_endpoint, all_endpoint[0]);

	all_endpoint[0] = NULL;
	all_endpoint[1] = NULL;
}

TEST(TMAPI, GetEndPointIdMultipleTunnelEndpoint)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_ENDPOINT
		endpoint_id endpoint_group_id addr_type addr_format ip1 ip2 description is_valid
		"989\t4\t192.50.0.0\t192.50.255.255\ttest\t1",
		"990\t4\t192.50.0.0\t192.50.255.255\ttest\t1",
		"992\t4\t192.40.0.0\t192.40.127.255\ttest\t1"
	**************************************************************************************************************************/

	// int tsg_get_endpoint_id(const struct streaminfo *a_stream, struct maat *feather, struct tunnel_endpoint **client_endpoint, struct tunnel_endpoint **server_endpoint, long long *endpoint_id_array, int endpoint_id_array_num)
	long long endpoint_id_array[128] = {0};
	int endpoint_id_array_num = 128;
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct tunnel_endpoint *client_endpoint = NULL, *server_endpoint = NULL;
	tuple4_v4.daddr = inet_addr("192.50.128.1");
	tuple4_v4.saddr = inet_addr("192.40.0.1");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;

	int ret = tsg_get_endpoint_id(&a_stream, g_tsg_maat_feather, &client_endpoint, &server_endpoint, endpoint_id_array, endpoint_id_array_num);
	EXPECT_EQ(3, ret);
	EXPECT_EQ(992, endpoint_id_array[0]);
	EXPECT_EQ(989, endpoint_id_array[1]);
	EXPECT_EQ(990, endpoint_id_array[2]);

	EXPECT_EQ(992, client_endpoint->id);
	EXPECT_EQ(990, server_endpoint->id);
}

TEST(TMAPI, GetEndPointIdSourceIpEqualToDestIp) // 也可能在一个网段，是否可以两个不同的endpoint_id拥有相同的网段；是否有可能源ip和目的ip同时可以处于一个endpoint的网段；endpoint_id_array是否可能重复
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_ENDPOINT
		endpoint_id endpoint_group_id addr_type addr_format ip1 ip2 description is_valid
		"989\t4\t192.50.0.0\t192.50.255.255\ttest\t1",
		"990\t4\t192.50.0.0\t192.50.255.255\ttest\t1",
	**************************************************************************************************************************/

	// int tsg_get_endpoint_id(const struct streaminfo *a_stream, struct maat *feather, struct tunnel_endpoint **client_endpoint, struct tunnel_endpoint **server_endpoint, long long *endpoint_id_array, int endpoint_id_array_num)
	long long endpoint_id_array[128] = {0};
	int endpoint_id_array_num = 128;
	struct streaminfo a_stream = {0};
	struct stream_tuple4_v4 tuple4_v4 = {0};
	struct tunnel_endpoint *client_endpoint = NULL, *server_endpoint = NULL;
	tuple4_v4.daddr = inet_addr("192.50.128.1");
	tuple4_v4.saddr = inet_addr("192.50.0.1");
	a_stream.addr.addrtype = ADDR_TYPE_IPV4;
	a_stream.addr.tuple4_v4 = &tuple4_v4;

	int ret = tsg_get_endpoint_id(&a_stream, g_tsg_maat_feather, &client_endpoint, &server_endpoint, endpoint_id_array, endpoint_id_array_num);
	EXPECT_EQ(4, ret);
	EXPECT_EQ(989, endpoint_id_array[0]);
	EXPECT_EQ(990, endpoint_id_array[1]);
	EXPECT_EQ(989, endpoint_id_array[2]);
	EXPECT_EQ(990, endpoint_id_array[3]);

	EXPECT_EQ(990, client_endpoint->id);
	EXPECT_EQ(990, server_endpoint->id);
}

extern int tsg_get_vlan_label_id(struct maat *feather, struct single_layer_vlan_addr *vlan_array, int vlan_array_num, long long *label_id_array, int label_id_array_num);
TEST(TMAPI, GetVlanLabelIdIllegalPara)
{
	// int tsg_get_vlan_label_id(struct maat *feather, struct single_layer_vlan_addr *vlan_array, int vlan_array_num, long long *label_id_array, int label_id_array_num)
	struct single_layer_vlan_addr vlan_array[2] = {0};
	long long label_id_array[2] = {0};
	EXPECT_EQ(0, tsg_get_vlan_label_id(g_tsg_maat_feather, vlan_array, 2, label_id_array, 0));
	EXPECT_EQ(0, tsg_get_vlan_label_id(g_tsg_maat_feather, vlan_array, 2, NULL, 2));
	EXPECT_EQ(0, tsg_get_vlan_label_id(g_tsg_maat_feather, vlan_array, 0, label_id_array, 2));
	EXPECT_EQ(0, tsg_get_vlan_label_id(g_tsg_maat_feather, NULL, 2, label_id_array, 2));
}

TEST(TMAPI, GetVlanLabelIdFunction)
{
	/*************************************************************************************************************************
		table name: TSG_TUNNEL_LABEL
		label_id label_group_id label is_valid
		"15560\t15560\tVLAN_ID\t1",
		"15561\t15561\tVLAN_ID\t1"
	**************************************************************************************************************************/
	// int tsg_get_vlan_label_id(struct maat *feather, struct single_layer_vlan_addr *vlan_array, int vlan_array_num, long long *label_id_array, int label_id_array_num)
	EXPECT_EQ(1, 1);
}

TEST(TMAPI, GetDNSProfileRecord)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_DNS_RECORDS
		record_id record_name record_type record_values is_valid
		"8119\teditTypeA\tA\t[{\"value\":\"1.1.1.1\",\"priority\":null},{\"value\":\"2.2.2.2\",\"priority\":null},{\"value\":\"3.3.3.3\",\"priority\":null}]\t1",
		"7961\tFile\tAAAA\t[{\"value\":\"1030::C9B4:FF12:48AA:1A2B\",\"priority\":null},{\"value\":\"1030::C9B4:FF12:48AA:1A2C\",\"priority\":null}]\t1",
		"7701\tTypeCNAME\tCNAME\t[{\"value\":\"www.facebook.com\",\"priority\":null},{\"value\":\"www.twitter.com\",\"priority\":null}]\t1"
	**************************************************************************************************************************/

	// void *matched_rule_cites_dns_profile_record(struct maat * feather, long long profile_id);

	long long profile_id = 8119;
	struct dns_profile_records *profile_records_right = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	struct dns_profile_records *profile_records = (struct dns_profile_records *)matched_rule_cites_dns_profile_record(g_tsg_maat_feather, profile_id);
	EXPECT_EQ(profile_records_right, profile_records);

	profile_records = NULL;
	profile_records_right = NULL;
	profile_id = 7961;
	profile_records_right = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	profile_records = (struct dns_profile_records *)matched_rule_cites_dns_profile_record(g_tsg_maat_feather, profile_id);
	EXPECT_TRUE(profile_records_right);
	EXPECT_EQ(profile_records_right, profile_records);

	profile_records = NULL;
	profile_records_right = NULL;
	profile_id = 7701;
	profile_records_right = (struct dns_profile_records *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_DNS_PROFILE_RECORD].id, (const char *)&profile_id);
	profile_records = (struct dns_profile_records *)matched_rule_cites_dns_profile_record(g_tsg_maat_feather, profile_id);
	EXPECT_TRUE(profile_records_right);
	EXPECT_EQ(profile_records_right, profile_records);
}

TEST(TMAPI, GetHttpResponsePagesProfile)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_RESPONSE_PAGES
		profile_id profile_name format path is_valid
		"957\ttest-html-1\thtml\tforeign_files/TSG_PROFILE_RESPONSE_PAGES.1\t1",
		"958\ttest-html-2\thtml\tforeign_files/TSG_PROFILE_RESPONSE_PAGES.2\t1"
	**************************************************************************************************************************/

	// void *matched_rule_cites_http_response_pages(struct maat *feather, long long profile_id)
	long long profile_id = 957;
	struct http_response_pages *response_pages_right = (struct http_response_pages *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
	struct http_response_pages *response_pages = (struct http_response_pages *)matched_rule_cites_http_response_pages(g_tsg_maat_feather, profile_id);
	EXPECT_EQ(957, response_pages->profile_id);
	EXPECT_EQ(response_pages_right, response_pages);

	profile_id = 958;
	response_pages_right = (struct http_response_pages *)maat_plugin_table_get_ex_data(g_tsg_maat_feather, g_tsg_maat_rt_para.plugin_tb[MAAT_PLUGIN_RESPONSE_PAGES].id, (const char *)&profile_id);
	response_pages = (struct http_response_pages *)matched_rule_cites_http_response_pages(g_tsg_maat_feather, profile_id);
	EXPECT_EQ(958, response_pages->profile_id);
	EXPECT_EQ(response_pages_right, response_pages);
}

TEST(TMAPI, GetSessionRecordSwitch)
{
	/*************************************************************************************************************************
		table name: T_VSYS_INFO
		id is_enable_session_record is_valid
		"6\t1\t1"
	**************************************************************************************************************************/
	EXPECT_EQ(1, tsg_session_record_switch_get());
}

TEST(TMAPI, NotifyPacketCaptureByPolicy)
{
	/*************************************************************************************************************************
		table name: TSG_PROFILE_TRAFFIC_MIRROR
		profile_id profile_name vlan_ids is_valid
		"845\t168.50.28yinyong\t[3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34]\t1",
		"123\ttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest\t[66]\t1"
	**************************************************************************************************************************/
	// int session_packet_capture_by_rules_notify(const struct streaminfo *a_stream, struct maat_rule *rules, int n_rules, int thread_seq)
}

TEST(TMAPI, ScanNestingAddr)
{
	// int tsg_scan_nesting_addr(const struct streaminfo *a_stream, enum TSG_PROTOCOL proto, struct maat_state **s_mid, struct maat_rule *results, size_t n_results)
}

TEST(TMAPI, ScanAppPropertiesPolicy)
{
	// int tsg_scan_app_properties_policy(const struct streaminfo *a_stream, char *property, char *district, struct maat_state *s_mid, struct maat_rule *results, int n_results)
}

int main(int argc, char *argv[])
{
	tsg_maat_rule_init("tsgconf/main.conf");
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
