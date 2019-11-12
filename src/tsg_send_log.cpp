#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <MESA/stream.h>
#include <MESA/cabot_send_log.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_types.h"
#include "tsg_send_log.h"
#include "tsg_send_log_internal.h"

tsg_logger_info_t tsg_logger_info;

static unsigned int get_ip_by_eth_name(const char *ifname)
{
    int sockfd;
    struct ifreq ifr;
    unsigned int ip;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sockfd) {
        goto error;
    }

    strcpy(ifr.ifr_name,ifname);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        goto error;
    }

    ip = ((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr.s_addr;
    close(sockfd);
    return ip;

error:
    close(sockfd);
    return INADDR_NONE;
}

int steaminfo2opt()
{
	return 0;
}


int tsg_sendlog_init(char *filename)
{
	int ret=0;
	unsigned int local_ip_nr=0;
	char nic_name[32];
	
	memset(&tsg_logger_info, 0, sizeof(tsg_logger_info));

	MESA_load_profile_int_def(filename, "TSG_LOG", "MODE",&(tsg_logger_info.mode), 0);	
	MESA_load_profile_string_def(filename, "TSG_LOG", "FIELD_FILE", tsg_logger_info.field_file, sizeof(tsg_logger_info.field_file), NULL);
	MESA_load_profile_string_def(filename, "TSG_LOG", "BROKER_LIST", tsg_logger_info.broker_list, sizeof(tsg_logger_info.broker_list), NULL);

	MESA_load_profile_int_def(filename, "TSG_LOG", "LEVEL",&(tsg_logger_info.level), 30);	
	MESA_load_profile_string_def(filename, "TSG_LOG", "LOG_PATH", tsg_logger_info.log_path, sizeof(tsg_logger_info.log_path), NULL);

	tsg_logger_info.logger=MESA_create_runtime_log_handle(tsg_logger_info.log_path, tsg_logger_info.level);
	if(tsg_logger_info.logger==NULL)
	{
		printf("MESA_create_runtime_log_handle failed ..., path: %s level: %d", tsg_logger_info.log_path, tsg_logger_info.level);
		return -1;
	}
	
	tsg_logger_info.cabot_handle=cabot_sendlog_create();
	cabot_sendlog_set(tsg_logger_info.cabot_handle, SENDLOG_MODE,(void *)&(tsg_logger_info.mode));
	cabot_sendlog_set(tsg_logger_info.cabot_handle, CONFIG_FILE,(void *)tsg_logger_info.field_file);
	cabot_sendlog_set(tsg_logger_info.cabot_handle, BROKER_LIST,(void *)&(tsg_logger_info.mode));

	ret=cabot_sendlog_init(tsg_logger_info.cabot_handle, tsg_logger_info.logger);
	if(ret<0)
	{
		MESA_handle_runtime_log(tsg_logger_info.logger, RLOG_LV_FATAL, "CABOT_INIT", "cabot_sendlog_init failed ...");
		return -2;
	}

	MESA_load_profile_string_def(filename, "TSG_LOG", "NIC_NAME", nic_name, sizeof(nic_name), "eth0");	
	local_ip_nr=get_ip_by_eth_name(nic_name);
	if(local_ip_nr==INADDR_NONE)
	{
		MESA_handle_runtime_log(tsg_logger_info.logger,RLOG_LV_FATAL, "GET_LOCAL_IP","get NIC_NAME: %s error.", nic_name);
		return -3;
	}
	inet_ntop(AF_INET,&(local_ip_nr),tsg_logger_info.local_ip_str,sizeof(tsg_logger_info.local_ip_str));


	//maat

	
	
	return 0;
}
void tsg_send_log(const tsg_log_t* log_msg, struct _opt_unit_t* log_opt, int opt_num, int thread_id)
{
	
		
}

