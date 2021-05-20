#include <stdio.h>
#include <string.h>

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_entry.h"
#include "tsg_gtp_signaling.h"

MESA_htable_handle g_gtp_signaling_hash_handle;


static int is_gtp_tunnel(const struct streaminfo *a_stream)
{
	int ret=0;
	unsigned short is_tunnel=0;
	int size=sizeof(unsigned short);
	
	ret=MESA_get_stream_opt(a_stream, MSO_STREAM_TUNNEL_TYPE, (void *)&is_tunnel, &size);
	if(ret>=0 && is_tunnel==STREAM_TUNNEL_GPRS_TUNNEL)
	{
		return 1;
	}

	return 0;
}

static int get_gtp_teid(const struct streaminfo *a_stream, unsigned int *uplink, unsigned int *downlink)
{
	const struct streaminfo *p=a_stream, *q=a_stream->pfather;

	while(p)
	{
		if(p->addr.addrtype==ADDR_TYPE_GPRS_TUNNEL)
		{
			*uplink=ntohl(p->addr.gtp->teid_c2s);
			*downlink=ntohl(p->addr.gtp->teid_s2c);
			
			return 1;
		}

		p=q;
		q=q->pfather;
	}

	return 0;
}

static int copy_one_field(char **dst, char *src, int src_len)
{
	if(src!=NULL && src_len>0)
	{
		*dst=(char *)calloc(1, src_len+1);
		memcpy(*dst, src, src_len);
		
		return 1;
	}

	return 0;
}


static long copy_user_info(void *data, const uchar *key, uint size, void *user_arg)
{
	int num=0;
	struct gtp_signaling_field *signal=(struct gtp_signaling_field *)data;
	struct umts_user_info *user_info=(struct umts_user_info *)user_arg;

	if(signal!=NULL)
	{
		num+=copy_one_field(&(user_info->apn), (char *)(signal->ie_unit[GTP_FIELD_APN].value), signal->ie_unit[GTP_FIELD_APN].len);
		num+=copy_one_field(&(user_info->imsi), (char *)(signal->ie_unit[GTP_FIELD_IMSI].value), signal->ie_unit[GTP_FIELD_IMSI].len);		
		num+=copy_one_field(&(user_info->imei), (char *)(signal->ie_unit[GTP_FIELD_IMEI].value), signal->ie_unit[GTP_FIELD_IMEI].len);		
		num+=copy_one_field(&(user_info->msisdn), (char *)(signal->ie_unit[GTP_FIELD_MSISDN].value), signal->ie_unit[GTP_FIELD_MSISDN].len);
	}

	return num;
}

void free_gtp_signaling_field(void *data)
{
	int i=0;
	struct gtp_signaling_field *signal=(struct gtp_signaling_field *)data;

	if(data==NULL)
	{
		return ;
	}
	
	for(i=0; i<GTP_FIELD_MAX; i++)
	{
		if(signal->ie_unit[i].value!=NULL)
		{
			free(signal->ie_unit[i].value);
			signal->ie_unit[i].value=NULL;
		}
	}

	free(data);
	data=NULL;

	return ;
}


void tsg_free_gtp_signaling_field(void *data)
{
	if(data!=NULL)
	{
		free_gtp_signaling_field(data);
		data=NULL;
	}
}


static int get_umts_user_info(struct umts_user_info **user_info, unsigned int teid, int thread_seq)
{
	long cb_ret=0;
	struct umts_user_info tmp_user_info={0};
	
	MESA_htable_search_cb(g_gtp_signaling_hash_handle, (unsigned char *)&(teid), sizeof(unsigned int), copy_user_info, (void *)&tmp_user_info, &cb_ret);
	if(cb_ret>0)
	{
		*user_info=(struct umts_user_info *)dictator_malloc(thread_seq, sizeof(struct umts_user_info));
		memcpy(*user_info, &tmp_user_info, sizeof(struct umts_user_info));
		
		return 1;
	}
	
	return 0;
}

int tsg_get_umts_user_info(const struct streaminfo *a_stream, struct umts_user_info **user_info)
{
	int ret=0;
	unsigned int uplink=0,downlink=0;

	if(*user_info!=NULL)
	{
		return 1;
	}
	
	ret=is_gtp_tunnel(a_stream);
	if(ret==0)
	{		
		return 0;
	}

	ret=get_gtp_teid(a_stream, &uplink, &downlink);
	if(ret==0)
	{
		return 0;
	}

	ret=get_umts_user_info(user_info, uplink, a_stream->threadnum);
	if(ret==1)
	{
		return 1;
	}

	ret=get_umts_user_info(user_info, downlink, a_stream->threadnum);
	if(ret==1)
	{
		return 1;
	}
		
	return 0;
}

int tsg_gtp_signaling_hash_init(const char* conffile, void *logger)
{
	MESA_htable_create_args_t args;

	MESA_load_profile_int_def(conffile, "GTP_SIGNALING", "HASH_TIMEOUT", &g_tsg_para.hash_timeout, 300);
	MESA_load_profile_int_def(conffile, "GTP_SIGNALING", "HASH_SLOT_SIZE", &g_tsg_para.hash_slot_size, 1024*1024*32);

	memset(&args, 0, sizeof(args));
	args.thread_safe=128;
	args.recursive=1;
	args.max_elem_num=0;		
	args.data_free=free_gtp_signaling_field;
	args.eliminate_type=HASH_ELIMINATE_ALGO_LRU;
	args.expire_time=g_tsg_para.hash_timeout;
	args.hash_slot_size=g_tsg_para.hash_slot_size;
	
	g_gtp_signaling_hash_handle=MESA_htable_create(&args, sizeof(MESA_htable_create_args_t));
	if(g_gtp_signaling_hash_handle==NULL)
	{
		MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "GTP_SIGNALING", "MESA_htable_create failed");
		return -1;
	}

	return 0;
}

