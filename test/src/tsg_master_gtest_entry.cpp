#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include "app_label.h"

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_jump_layer.h>

enum GTEST_BRIDGE
{
	GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT=0,
	GTEST_BRIDGE_TYPE_MAX
};

struct gtest_para
{
	int bridge_id[GTEST_BRIDGE_TYPE_MAX];
	char bridge_name[GTEST_BRIDGE_TYPE_MAX][64];
};


struct gtest_para g_gtest_para;

extern "C" unsigned char GTEST_APP_FULL_PATH_1_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	struct app_identify_result lpi;
	memset(&lpi, 0, sizeof(lpi));

	lpi.app_id_num=2;
	lpi.origin=ORIGIN_BASIC_PROTOCOL;
	lpi.app_id[0]=336;  //openvpn
	lpi.app_id[1]=199;  //ssl
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&lpi);

	struct app_identify_result user_define;
	memset(&user_define, 0, sizeof(user_define));

	user_define.app_id_num=1;
	user_define.origin=ORIGIN_USER_DEFINE;
	user_define.app_id[0]=3145;  //qq_web
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&user_define);

	struct app_identify_result qm;
	memset(&qm, 0, sizeof(qm));

	qm.app_id_num=4;
	qm.origin=ORIGIN_QM_ENGINE;
	qm.app_id[0]=336;  //openvpn
	qm.app_id[1]=199;  //ssl
	qm.app_id[2]=1241;  //qq_web
	qm.app_id[3]=3145;  //qq_r2
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&qm);

	return APP_STATE_DROPME;
}

extern "C" unsigned char GTEST_APP_FULL_PATH_2_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	struct app_identify_result lpi;
	memset(&lpi, 0, sizeof(lpi));

	lpi.app_id_num=2;
	lpi.origin=ORIGIN_BASIC_PROTOCOL;
	lpi.app_id[0]=336;  //openvpn
	lpi.app_id[1]=199;  //ssl
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&lpi);

	struct app_identify_result built_in;
	memset(&built_in, 0, sizeof(built_in));
	
	built_in.app_id_num=1;
	built_in.origin=ORIGIN_BUILT_IN;
	built_in.app_id[0]=3145;  //qq_web
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&built_in);

	struct app_identify_result qm;
	memset(&qm, 0, sizeof(qm));

	qm.app_id_num=3;
	qm.origin=ORIGIN_QM_ENGINE;
	qm.app_id[0]=336;  //openvpn
	qm.app_id[1]=1241;  //qq_web
	qm.app_id[2]=3145;  //qq_r2
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&qm);

	return APP_STATE_DROPME;
}

extern "C" unsigned char GTEST_APP_FULL_PATH_3_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	struct app_identify_result lpi;
	memset(&lpi, 0, sizeof(lpi));

	lpi.app_id_num=2;
	lpi.origin=ORIGIN_BASIC_PROTOCOL;
	lpi.app_id[0]=336;  //openvpn
	lpi.app_id[1]=199;  //ssl
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&lpi);

	struct app_identify_result built_in;
	memset(&built_in, 0, sizeof(built_in));
	
	built_in.app_id_num=1;
	built_in.origin=ORIGIN_BUILT_IN;
	built_in.app_id[0]=3145;  //qq_web
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&built_in);

	return APP_STATE_DROPME;
}

extern "C" unsigned char GTEST_APP_FULL_PATH_4_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	struct app_identify_result lpi;
	memset(&lpi, 0, sizeof(lpi));

	lpi.app_id_num=1;
	lpi.origin=ORIGIN_BASIC_PROTOCOL;
	lpi.app_id[0]=199;  //ssl
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&lpi);

	struct app_identify_result user_define;
	memset(&user_define, 0, sizeof(user_define));
	
	struct app_identify_result built_in;
	memset(&built_in, 0, sizeof(built_in));
	
	built_in.app_id_num=2;
	built_in.origin=ORIGIN_BUILT_IN;
	built_in.app_id[0]=3145;  //qq_web	
	built_in.app_id[1]=156;  //qq
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&built_in);


	struct app_identify_result qm;
	memset(&qm, 0, sizeof(qm));

	qm.app_id_num=4;
	qm.origin=ORIGIN_QM_ENGINE;
	qm.app_id[0]=336;  //openvpn
	qm.app_id[1]=199;  //ssl
	qm.app_id[2]=1241;  //qq_web
	qm.app_id[3]=3145;  //qq_r2
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&qm);

	return APP_STATE_DROPME;
}

extern "C" unsigned char GTEST_APP_FULL_PATH_5_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	struct app_identify_result built_in;
	memset(&built_in, 0, sizeof(built_in));
	
	built_in.app_id_num=2;
	built_in.origin=ORIGIN_BUILT_IN;
	built_in.app_id[0]=3145;  //qq_web	
	built_in.app_id[1]=156;  //qq
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&built_in);
	
	struct app_identify_result qm;
	memset(&qm, 0, sizeof(qm));

	qm.app_id_num=4;
	qm.origin=ORIGIN_QM_ENGINE;
	qm.app_id[0]=336;  //openvpn
	qm.app_id[1]=199;  //ssl
	qm.app_id[2]=1241;  //qq_web
	qm.app_id[3]=3145;  //qq_r2
	stream_bridge_sync_data_put(a_stream, g_gtest_para.bridge_id[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], (void *)&qm);

	return APP_STATE_DROPME;
}

extern "C" unsigned char GTEST_UNKNOWN_APP_ENTRY(const struct streaminfo *a_stream, void **pme, int thread_seq, const void *a_packet)
{
	return APP_STATE_DROPME;
}

extern "C" int GTEST_INIT()
{
	memset(&g_gtest_para, 0, sizeof(g_gtest_para));
	
	MESA_load_profile_string_def("tsgconf/main.conf", "SYSTEM", "APP_IDENTIFY_RESULT_BRIDGE", g_gtest_para.bridge_name[GTEST_BRIDGE_TYPE_APP_IDENTIFY_RESULT], 64, "APP_IDENTIFY_RESULT_BRIDGE");

	for(int i=0; i<GTEST_BRIDGE_TYPE_MAX; i++)
	{
		g_gtest_para.bridge_id[i]=stream_bridge_build(g_gtest_para.bridge_name[i], "w");
		if(g_gtest_para.bridge_id[i]<0)
		{
			printf("stream_bridge_build is error, bridge_name: %s", g_gtest_para.bridge_name[i]);	
			return -1;
		}
	}

	return 0;
}

extern "C" int GTEST_UNLOAD()
{
	return 0;
}

