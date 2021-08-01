#include <marsio.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stream.h>

#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

#include "tsg_traffic_mirror.h"

#define BURST_MAX       64
#define PREDICT_FALSE(x) __builtin_expect((x),0)
#define PREDICT_TRUE(x) __builtin_expect((x),1)

struct traffic_mirror
{
  struct mr_instance * mr_instance;
  struct mr_vdev * dev_handler;
  struct mr_sendpath * to_dev_sendpath;
  char app_name[64];
  char nic_name[32];
  int nr_thread;
  int default_vlan_id;
};

struct traffic_mirror *tsg_traffic_mirror_init(const char *conffile, void *logger)
{
  int ret=0,traffic_mirror_enable=TRRAFFIC_MIRROR_DISABLE;
  struct traffic_mirror *ttm = NULL;

  ttm=(struct traffic_mirror *)calloc(1, sizeof(struct traffic_mirror));

  if (conffile == NULL)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Conffile Path Is Null !!!");
    goto init_error;
  }

  MESA_load_profile_int_def(conffile, "TRAFFIC_MIRROR", "TRAFFIC_MIRROR_ENABLE", &traffic_mirror_enable, 0);
  if (traffic_mirror_enable != TRRAFFIC_MIRROR_ENABLE)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Traffic Mirror Is Disable !!!");
    goto init_error;
  }

  MESA_load_profile_string_def(conffile, "TRAFFIC_MIRROR", "NIC_NAME", ttm->nic_name, sizeof(ttm->nic_name), "lo");
  if (ttm->nic_name == NULL)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Traffic Mirror Cfg No Setting Nic Name !!!");
    goto init_error;
  }

  MESA_load_profile_string_def(conffile, "TRAFFIC_MIRROR", "APP_NAME", ttm->app_name, sizeof(ttm->app_name),"tsg_traffic_mirror");

  MESA_load_profile_int_def(conffile, "TRAFFIC_MIRROR", "DEFAULT_VLAN_ID", &ttm->default_vlan_id, 0);

  ttm->mr_instance = marsio_create();
  if (ttm->mr_instance == NULL)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Marsion Create Error !!!");
    goto init_error;
  }

  ret = marsio_init(ttm->mr_instance, ttm->app_name);
  if (ret < 0)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Marsion Init Error !!!");
    goto init_error;
  }

  ttm->nr_thread = get_thread_count();
  if (ttm->nr_thread <= 0)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Get Thread Count Error :%d",ttm->nr_thread);
    goto init_error;
  }

  ttm->dev_handler = marsio_open_device(ttm->mr_instance, ttm->nic_name, 0, ttm->nr_thread);
  if (ttm->dev_handler == NULL)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Marsion Open Device Error :%s",ttm->nic_name);
    goto init_error;
  }

  ttm->to_dev_sendpath = marsio_sendpath_create_by_vdev(ttm->dev_handler);
  if (ttm->to_dev_sendpath == NULL)
  {
    MESA_handle_runtime_log(logger, RLOG_LV_FATAL, "TSG_TRAFFIC_MIRROR", "Marsion Create Sendpath Error !!!");
    goto init_error;
  }
  return ttm;

init_error:
  if (ttm->mr_instance != NULL)
  {
    marsio_destory(ttm->mr_instance);
  }

  free(ttm);

  return NULL;
}

int tsg_traffic_mirror_send_burst(struct traffic_mirror *ttm,char * pkt_ptr,int pkt_len,int *vlan_array,int vlan_num,int thread_seq)
{
  int i=0,ret=0,tx_buffer_num=0;
  marsio_buff_t * tx_buff[BURST_MAX];
  int *vlan_tag_array = NULL;

  if (PREDICT_FALSE((ttm == NULL) || (ttm->to_dev_sendpath == NULL)))
  {
    return SEND_ERROR_NOT_INIT;
  }
  if (PREDICT_FALSE(thread_seq >= ttm->nr_thread))
  {
    return SEND_ERROR_THREAD_SEQ_ERR;
  }
  if (PREDICT_FALSE(pkt_ptr == NULL))
  {
    return SEND_ERROR_PKT_BUFFER_IS_NULL;
  }
  if (PREDICT_FALSE(pkt_len == 0))
  {
    return SEND_ERROR_PKT_LEN_ERROR;
  }
  if (PREDICT_FALSE(vlan_num > BURST_MAX))
  {
    return SEND_ERROR_VLAN_NUM_EXCEED_BURST_MAX;
  }

  if (PREDICT_FALSE((vlan_num <= 1) || (vlan_array == NULL)))
  {
    tx_buffer_num = 1;
    vlan_tag_array = &ttm->default_vlan_id;
  }
  else
  {
    tx_buffer_num = vlan_num;
    vlan_tag_array = vlan_array;
  }

  ret = marsio_buff_malloc_global(ttm->mr_instance, tx_buff, tx_buffer_num, MARSIO_SOCKET_ID_ANY, MARSIO_LCORE_ID_ANY);
  if (PREDICT_FALSE(ret < 0 ))
  {
    return SEND_ERROR_BUFF_MALLOC_ERROR;
  }

  for (i = 0; i < tx_buffer_num; i++)
  {
    unsigned int vlan_id = vlan_tag_array[i];
    marsio_buff_t * tx_buff_ptr = tx_buff[i];
    char * tx_buff_begin = marsio_buff_append(tx_buff_ptr, pkt_len);
    memcpy(tx_buff_begin, pkt_ptr, pkt_len);
    marsio_buff_set_metadata(tx_buff_ptr,MR_BUFF_METADATA_VLAN_TCI,&vlan_id,sizeof(vlan_id));
  }

  ret = marsio_send_burst_with_options(ttm->to_dev_sendpath, thread_seq, tx_buff, tx_buffer_num, MARSIO_SEND_OPT_FAST);
  if (PREDICT_FALSE(ret < 0))
  {
    return TRRAFFIC_MIRROR_SEND_ERROR_DROP;
  }

  return TRRAFFIC_MIRROR_SEND_SUCCESS;
}