#ifndef	__TSG_SEND_LOG_INTERNAL_H__
#define	__TSG_SEND_LOG_INTERNAL_H__

typedef	struct _tsg_logger_info
{
	int mode;
	int level;
	void *logger;
	void *cabot_handle;
	char field_file[128];
	char broker_list[128];
	char log_path[128];
	char local_ip_str[16];
}tsg_logger_info_t;

#endif

