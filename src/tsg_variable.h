#pragma once

struct reset_argv
{
	int pkt_num;
	int seed1;
	int seed2;
	int th_flags;
	int dir;
	int remedy;
};

#define	_MAX_TABLE_NAME_LEN	64
typedef	struct tsg_para
{
	int level;
	short mirror_switch;
	unsigned short timeout;
	int dynamic_maat_switch;
	int location_field_num;
	int app_dict_field_num;
	int device_seq_in_dc;
	int datacenter_id;
	int scan_signaling_switch;
	int hash_timeout;
	int hash_slot_size;
	int hash_thread_safe;
	int feature_tamper;
	enum DEPLOY_MODE deploy_mode;
	int scan_time_interval;
	int identify_app_max_pkt_num;
	int unknown_app_id;
	int hit_path_switch;
	int default_compile_id;
	int table_id[TABLE_MAX];	
	int dyn_table_id[DYN_TABLE_MAX];
	int priority_project_id;
	int shaping_project_id;
	int session_attribute_project_id;
	int context_project_id;
	int tcpall_project_id;
	int gather_app_project_id;	
	int bridge_id[BRIDGE_TYPE_MAX];
	int proto_flag; //tsg_protocol_t
	int fs2_field_id[TSG_FS2_MAX];
	char device_sn[MAX_DOMAIN_LEN/8];
	char log_path[MAX_DOMAIN_LEN/8];
	char device_id_command[MAX_DOMAIN_LEN/8];
	char data_center[_MAX_TABLE_NAME_LEN];
	char device_tag[MAX_DOMAIN_LEN/2];
	char table_name[TABLE_MAX][_MAX_TABLE_NAME_LEN];	
	char dyn_table_name[DYN_TABLE_MAX][_MAX_TABLE_NAME_LEN];
	char bridge_name[BRIDGE_TYPE_MAX][_MAX_TABLE_NAME_LEN];
	void *logger;
	void *maat_logger;
	struct reset_argv reset;
	struct mirrored_vlan default_vlan;
	screen_stat_handle_t fs2_handle;
	struct l7_protocol *name_by_id;
	struct l7_protocol *id_by_name;
	struct traffic_mirror *mirror_handle;
	ctemplate::Template *tpl_403,*tpl_404;
	ctemplate::Template *tpl_200,*tpl_204;
	ctemplate::Template *tpl_303;
}g_tsg_para_t;

extern g_tsg_para_t g_tsg_para;
extern Maat_feather_t g_tsg_dynamic_maat_feather;
extern id2field_t g_tsg_proto_name2id[PROTO_MAX];