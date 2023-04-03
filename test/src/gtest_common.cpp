#include <MESA/stream.h>
#include "tsg_entry.h"

const char *gtest_addrlist="127.0.0.1.37690>127.0.0.1.443";

struct gtest_ctrl_pkt
{
	char buf[1024];
	int len;
}ctrl_pkt;

void dictator_free(int thread_seq, void * pbuf)
{
	free(pbuf);
	pbuf=NULL;
}

void *dictator_malloc(int thread_seq,size_t size)
{
	return calloc(1, size);
}

const char *printaddr (const struct layer_addr *paddrinfo, int threadindex)
{
	return gtest_addrlist;
}

int get_thread_count(void)
{
	return 8;
}

int MESA_rst_tcp(struct streaminfo * stream, struct rst_tcp_para * paras, int para_len)
{
	return 0;
}

int sapp_inject_pkt(struct streaminfo * stream, enum sapp_inject_opt sio, const void * payload, int payload_len, unsigned char snd_routedir)
{
	return 0;
}

int sapp_inject_ctrl_pkt(struct streaminfo * stream, enum sapp_inject_opt sio, const void * payload, int payload_len, unsigned char snd_routedir)
{
    memset(&ctrl_pkt, 0, 1024);
    memcpy(ctrl_pkt.buf, payload, payload_len);
    ctrl_pkt.len = payload_len;

    return 0;
}

int get_ctrl_pkt(char *buf, int len)
{
	memcpy(buf, ctrl_pkt.buf, MIN(len, ctrl_pkt.len));
	return MIN(len, ctrl_pkt.len);
}

unsigned char MESA_dir_reverse(unsigned char raw_route_dir)
{
	return 0;
}

extern "C" int MESA_get_dev_ipv4(const char * device, int * ip_add)
{
	return 0;
}


extern "C" int sendpacket_do_checksum(unsigned char *buf, int protocol, int len)
{
	return 0;
}

char *layer_addr_ntop_r(const struct streaminfo * pstream, char * out_buf, int out_buf_len)
{
	return NULL;
}


const char *layer_addr_prefix_ntop(const struct streaminfo * pstream)
{
	return NULL;
}

int stream_addr_list_ntop(const struct streaminfo * pstream, char * dst, int size)
{
	return 0;
}

int MESA_dir_link_to_human(int link_route_dir)
{
	return 0;
}


int MESA_set_stream_opt(const struct streaminfo * pstream, enum MESA_stream_opt opt, void * opt_val, int opt_val_len)
{
	return 0;
}

int MESA_get_stream_opt(const struct streaminfo * pstream, enum MESA_stream_opt opt, void * opt_val, int * opt_val_len)
{
	if (*opt_val_len == 2)
	{
		*(u_short *)opt_val = 2;
	}

	if (*opt_val_len == 8)
	{
		*(long long *)opt_val = 5;
	}

	return 0;
}


int sapp_get_platform_opt(enum sapp_platform_opt opt, void * opt_val, int * opt_val_len)
{
	return 0;
}

int get_rawpkt_opt_from_streaminfo(const struct streaminfo * pstream, int type, void * out_value)
{
	return 0;
}

#define	MAX_BRIDGE_NUM	32
void *g_bridge_async_data[MAX_BRIDGE_NUM]={0};
stream_bridge_free_cb_t *g_bridge_async_free[MAX_BRIDGE_NUM]={0};
stream_bridge_sync_cb_t *g_bridge_sync_cb[MAX_BRIDGE_NUM]={0};

int stream_bridge_register_data_free_cb(int bridge_id, stream_bridge_free_cb_t * free_cb_fun)
{
	g_bridge_async_free[bridge_id]=free_cb_fun;

	return 0;
}

int stream_bridge_register_data_sync_cb(int bridge_id, stream_bridge_sync_cb_t * sync_cb_fun)
{
	g_bridge_sync_cb[bridge_id]=*(stream_bridge_sync_cb_t *)sync_cb_fun;
	
	return 0;
}

int stream_bridge_sync_data_put(const struct streaminfo *stream, int bridge_id, void *data)
{
	if(g_bridge_sync_cb[bridge_id])
	{
		g_bridge_sync_cb[bridge_id](stream, bridge_id, data);
	}
	
	return 0;
}

void *stream_bridge_async_data_get(const struct streaminfo *stream, int bridge_id)
{
	return g_bridge_async_data[bridge_id];
}

int stream_bridge_async_data_put(const struct streaminfo * stream, int bridge_id, void * data)
{
	g_bridge_async_data[bridge_id]=data;
	return 0;
}

int stream_bridge_build(const char * bridge_name, const char * rw_mode)
{
	static int bridge_id=0;
	assert(bridge_id<MAX_BRIDGE_NUM);
	return bridge_id++;
}

#define	MAX_PROJECT_NUM	16
static int project_id=0;
const void *g_project_data[MAX_PROJECT_NUM]={0};
project_req_free_t *g_project_free[MAX_PROJECT_NUM]={0};
char g_project_label[MAX_PROJECT_NUM][32]={0};

int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value)
{
	g_project_data[project_req_id]=project_req_value;
	return 0;
}

const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id)
{
	return g_project_data[project_req_id];
}

int project_customer_register(const char * project_req_name, const char * project_req_val_type)
{
	for(int i=0; i<project_id; i++)
	{
		if(memcmp(g_project_label[i], project_req_name, strlen(project_req_name))==0)
		{
			return i;
		}
	}

	return -1;
}

int project_producer_register(const char * project_req_name, const char * project_req_val_type, project_req_free_t * free_cb)
{
	assert(project_id<MAX_PROJECT_NUM);
	for(int i=0; i<project_id; i++)
	{
		if(memcmp(g_project_label[i], project_req_name, strlen(project_req_name))==0)
		{
			return project_id;
		}
	}

	g_project_free[project_id]=free_cb;
	memcpy(g_project_label[project_id], project_req_name, strlen(project_req_name));
	return project_id++;
}

extern "C" void *http_field_parser(const char* buf, unsigned int buflen, int http_dir)
{
	return NULL;
}

extern "C" int http_get_filed_result(void *result, long long field_flag, char **field_value)
{
	return 0;
}

extern "C" void http_free_filed_result(void *result)
{
}

extern "C" int ftp_control_identify(struct streaminfo *a_tcp)
{
	return 0;
}

extern "C" int ftp_data_identify(struct streaminfo *a_tcp)
{
	return 0;
}

extern "C" int mail_protocol_identify_by_first_payload(struct streaminfo *a_tcp, char *payload, int payload_len, int thread_seq)
{
	return 0;
}

extern "C" char stratum_identify(struct streaminfo* pstream,void** pme,int thread_seq,const void* a_packet)
{
	return 0;
}

extern "C" int rdp_protocol_identify(const char *payload, unsigned int payload_len, int thread_seq)
{
	return 0;
}

extern "C" int rdpudp_protocol_identify(const char *payload, unsigned int payload_len, int thread_seq)
{
	return 0;
}

int quic_version_int2string(unsigned int version, char *buff, int buff_len)
{
	return 0;
}

unsigned int quic_protocol_identify(struct streaminfo *a_stream, void *a_packet, char *out_sni, int *out_sni_len, char *out_ua, int *out_ua_len)
{
	return 0;
}

extern "C" unsigned char sip_identify_from_to(char* buff,UINT32 buflen,char** from,UINT32* from_len,char** to,UINT32* to_len)
{
	return 0;
}

extern "C" int dtls_parse_sni(const char *udp_payload, int udp_payload_len, char *servername, int servername_len)
{
	return 0;
}

extern "C" bool dtls_identifyStream(struct streaminfo *a_udp)
{
	return 0;
}

extern "C" struct _ssl_ja3_info_t *ssl_get_ja3_fingerprint(struct streaminfo *stream, unsigned char *payload, int payload_len, int thread_seq)
{
	return NULL;
}
