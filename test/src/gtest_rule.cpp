#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tsg_entry.h"
#include "gtest_common.h"
#include "tsg_variable.h"
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include <gtest/gtest.h>

int init_fs2_handle(const char *conffile)
{
	int value=0,cycle=0;
	int output_prometheus=0;
	unsigned short fs_server_port=0;
	char app_name[128]={0};
	char fs_server_ip[MAX_IPV4_LEN]={0};
	char fs_output_path[128]={0};

	MESA_load_profile_int_def(conffile, "FIELD_STAT", "CYCLE", &cycle, 30);
	MESA_load_profile_short_nodef(conffile, "FIELD_STAT","TELEGRAF_PORT", (short *)&(fs_server_port));
	MESA_load_profile_string_nodef(conffile,"FIELD_STAT","TELEGRAF_IP",fs_server_ip, sizeof(fs_server_ip));
	MESA_load_profile_string_def(conffile,"FIELD_STAT","OUTPUT_PATH",fs_output_path, sizeof(fs_output_path), "tsg_stat.log");
	MESA_load_profile_string_def(conffile,"FIELD_STAT","APP_NAME", app_name, sizeof(app_name), "tsg_master");
	MESA_load_profile_int_def(conffile, "FIELD_STAT", "PROMETHEUS", &output_prometheus, 1);

	g_tsg_para.fs2_handle=FS_create_handle();

	value=1;//Rewrite
	FS_set_para(g_tsg_para.fs2_handle, PRINT_MODE, &value, sizeof(value));
	value=1;//Do not create stat thread
	FS_set_para(g_tsg_para.fs2_handle, CREATE_THREAD, &value, sizeof(value));
	
    FS_set_para(g_tsg_para.fs2_handle, STAT_CYCLE, &cycle, sizeof(cycle));
    FS_set_para(g_tsg_para.fs2_handle, APP_NAME, app_name, strlen(app_name)+1);
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_DEVICE, fs_output_path, strlen(fs_output_path)+1);

	value=1;
	FS_set_para(g_tsg_para.fs2_handle, OUTPUT_PROMETHEUS, &output_prometheus, sizeof(output_prometheus));

    if(fs_server_port > 0 && strlen(fs_server_ip) > 0)
    {
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_IP,fs_server_ip, strlen(fs_server_ip)+1);
        FS_set_para(g_tsg_para.fs2_handle, STATS_SERVER_PORT,&(fs_server_port), sizeof(fs_server_port));
    }

	value=FS_OUTPUT_INFLUX_LINE;
	FS_set_para(g_tsg_para.fs2_handle, STATS_FORMAT, &value, sizeof(value));

	for(int i=0; i<TSG_FS2_MAX; i++)
	{
		g_tsg_para.fs2_field_id[i]=FS_register(g_tsg_para.fs2_handle, FS_STYLE_FIELD, FS_CALC_SPEED, g_tsg_fs2_field[i].name);
	}

	return 0;
}

extern int tsg_rule_init(const char *conffile, void *logger);
extern void security_compile_new(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp);
extern void security_compile_free(int idx, const struct Maat_rule_t* rule, const char* srv_def_large, MAAT_RULE_EX_DATA* ad, long argl, void *argp);

TEST(TSGMaster, SecurityDenyPolicyRatelimitSetExData)
{
	struct compile_user_region *user_region=NULL;
	const struct Maat_rule_t rule={2, 0, 1, 0, 16, 0, 0, {0}};
	const char * srv_def_large="{\"method\":\"rate_limit\",\"bps\":1024,\"packet_capture\":{\"enable\":1,\"capture_depth\":2000}}";

	security_compile_new(0, &rule, srv_def_large, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	EXPECT_NE(nullptr, user_region);
	EXPECT_EQ(1, user_region->ref_cnt);
	EXPECT_EQ(TSG_METHOD_TYPE_RATE_LIMIT, user_region->method_type);
	
	EXPECT_NE(nullptr, user_region->deny);
	EXPECT_EQ(TSG_DENY_TYPE_MAX, user_region->deny->type);
	EXPECT_EQ(1024, user_region->deny->bps);

	EXPECT_EQ(1, user_region->capture.enabled);
	EXPECT_EQ(2000, user_region->capture.depth);

	
	security_compile_free(0, &rule, srv_def_large, (MAAT_RULE_EX_DATA *)&user_region, 0, NULL);
	EXPECT_EQ(nullptr, user_region);
}

TEST(TSGMaster, SecurityDenyPolicyGetRatelimitExData)
{
	struct Maat_rule_t rule={2, 0, 1, 0, 16, 0, 0, {0}};
	struct compile_user_region *user_region=(struct compile_user_region *)Maat_rule_get_ex_data(g_tsg_maat_feather, &rule, g_tsg_para.table_id[TABLE_SECURITY_COMPILE]);
	EXPECT_NE(nullptr, user_region);
	
	EXPECT_EQ(2, user_region->ref_cnt);
	EXPECT_EQ(TSG_METHOD_TYPE_RATE_LIMIT, user_region->method_type);
	
	EXPECT_NE(nullptr, user_region->deny);
	EXPECT_EQ(TSG_DENY_TYPE_MAX, user_region->deny->type);
	EXPECT_EQ(1024, user_region->deny->bps);

	EXPECT_EQ(1, user_region->capture.enabled);
	EXPECT_EQ(2000, user_region->capture.depth);
}

int main(int argc, char *argv[])
{	
	init_fs2_handle(tsg_conffile);
	tsg_rule_init(tsg_conffile, g_tsg_para.logger);
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
