#include <MESA/stream.h>

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
