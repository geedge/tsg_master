#include <MESA/stream.h>
#include "tsg_entry.h"

const char *gtest_addrlist="127.0.0.1.37690>127.0.0.1.443";

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
	return 1;
}

int MESA_rst_tcp(struct streaminfo * stream, struct rst_tcp_para * paras, int para_len)
{
	return 0;
}

int sapp_inject_pkt(struct streaminfo * stream, enum sapp_inject_opt sio, const void * payload, int payload_len, unsigned char snd_routedir)
{
	return 0;
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

#define	MAX_BRIDGE_NUM	16
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
	if(g_bridge_sync_cb[bridge_id])
	{
		g_bridge_sync_cb[bridge_id]=sync_cb_fun;
	}
	
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

int project_req_add_struct(struct streaminfo *stream, int project_req_id, const void *project_req_value)
{
	return 0;
}

const void *project_req_get_struct(const struct streaminfo *stream, int project_req_id)
{
	return NULL;
}

int project_customer_register(const char * project_req_name, const char * project_req_val_type)
{
	return 0;
}

int project_producer_register(const char * project_req_name, const char * project_req_val_type, project_req_free_t * free_cb)
{
	return 0;
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
