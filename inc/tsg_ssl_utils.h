#pragma once 

struct cipher_suite
{
	int value;
	const char* name;
};

enum chello_parse_result
{
	CHELLO_PARSE_SUCCESS = 0,
	CHELLO_PARSE_INVALID_FORMAT = -1,
	CHELLO_PARSE_NOT_ENOUGH_BUFF = -2
};

struct ssl_version
{
	uint8_t minor;	
	uint8_t major;
	uint16_t ossl_format;
};

struct ssl_chello
{
	struct ssl_version min_version;
	struct ssl_version max_version;

	char* sni;
	char* alpn;
	char* cipher_suites;
	char* cipher_suites_tls13;
};
struct ssl_chello* ssl_chello_parse(const unsigned char* buff, size_t buff_len, enum chello_parse_result* result);

void ssl_chello_free(struct ssl_chello* chello);