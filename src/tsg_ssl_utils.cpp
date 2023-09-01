#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "tsg_ssl_utils.h"

#define ALLOC(type, number) ((type *)calloc(sizeof(type), number))
#define	FREE(p)	{free(*p);*p=NULL;}
#define KNI_STRING_MAX	2048

struct cipher_suite cipher_suite_list[] =
{
	{0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
	{0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"},
	{0xC028, "ECDHE-RSA-AES256-SHA384"},
	{0xC024, "ECDHE-ECDSA-AES256-SHA384"},
	{0xC014, "ECDHE-RSA-AES256-SHA"},
	{0xC00A, "ECDHE-ECDSA-AES256-SHA"},
	{0x00A5, "DH-DSS-AES256-GCM-SHA384"},
	{0x00A3, "DHE-DSS-AES256-GCM-SHA384"},
	{0x00A1, "DH-RSA-AES256-GCM-SHA384"},
	{0x009F, "DHE-RSA-AES256-GCM-SHA384"},
	{0x006B, "DHE-RSA-AES256-SHA256"},
	{0x006A, "DHE-DSS-AES256-SHA256"},
	{0x0069, "DH-RSA-AES256-SHA256"},
	{0x0068, "DH-DSS-AES256-SHA256"},
	{0x0039, "DHE-RSA-AES256-SHA"},
	{0x0038, "DHE-DSS-AES256-SHA"},
	{0x0037, "DH-RSA-AES256-SHA"},
	{0x0036, "DH-DSS-AES256-SHA"},
	{0x0088, "DHE-RSA-CAMELLIA256-SHA"},
	{0x0087, "DHE-DSS-CAMELLIA256-SHA"},
	{0x0086, "DH-RSA-CAMELLIA256-SHA"},
	{0x0085, "DH-DSS-CAMELLIA256-SHA"},
	{0xC019, "AECDH-AES256-SHA"},
	{0x00A7, "ADH-AES256-GCM-SHA384"},
	{0x006D, "ADH-AES256-SHA256"},
	{0x003A, "ADH-AES256-SHA"},
	{0x0089, "ADH-CAMELLIA256-SHA"},
	{0xC032, "ECDH-RSA-AES256-GCM-SHA384"},
	{0xC02E, "ECDH-ECDSA-AES256-GCM-SHA384"},
	{0xC02A, "ECDH-RSA-AES256-SHA384"},
	{0xC026, "ECDH-ECDSA-AES256-SHA384"},
	{0xC00F, "ECDH-RSA-AES256-SHA"},
	{0xC005, "ECDH-ECDSA-AES256-SHA"},
	{0x009D, "AES256-GCM-SHA384"},
	{0x003D, "AES256-SHA256"},
	{0x0035, "AES256-SHA"},
	{0x0084, "CAMELLIA256-SHA"},
	{0x008D, "PSK-AES256-CBC-SHA"},
	{0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
	{0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
	{0xC027, "ECDHE-RSA-AES128-SHA256"},
	{0xC023, "ECDHE-ECDSA-AES128-SHA256"},
	{0xC013, "ECDHE-RSA-AES128-SHA"},
	{0xC009, "ECDHE-ECDSA-AES128-SHA"},
	{0x00A4, "DH-DSS-AES128-GCM-SHA256"},
	{0x00A2, "DHE-DSS-AES128-GCM-SHA256"},
	{0x00A0, "DH-RSA-AES128-GCM-SHA256"},
	{0x009E, "DHE-RSA-AES128-GCM-SHA256"},
	{0x0067, "DHE-RSA-AES128-SHA256"},
	{0x0040, "DHE-DSS-AES128-SHA256"},
	{0x003F, "DH-RSA-AES128-SHA256"},
	{0x003E, "DH-DSS-AES128-SHA256"},
	{0x0033, "DHE-RSA-AES128-SHA"},
	{0x0032, "DHE-DSS-AES128-SHA"},
	{0x0031, "DH-RSA-AES128-SHA"},
	{0x0030, "DH-DSS-AES128-SHA"},
	{0x009A, "DHE-RSA-SEED-SHA"},
	{0x0099, "DHE-DSS-SEED-SHA"},
	{0x0098, "DH-RSA-SEED-SHA"},
	{0x0097, "DH-DSS-SEED-SHA"},
	{0x0045, "DHE-RSA-CAMELLIA128-SHA"},
	{0x0044, "DHE-DSS-CAMELLIA128-SHA"},
	{0x0043, "DH-RSA-CAMELLIA128-SHA"},
	{0x0042, "DH-DSS-CAMELLIA128-SHA"},
	{0xC018, "AECDH-AES128-SHA"},
	{0x00A6, "ADH-AES128-GCM-SHA256"},
	{0x006C, "ADH-AES128-SHA256"},
	{0x0034, "ADH-AES128-SHA"},
	{0x009B, "ADH-SEED-SHA"},
	{0x0046, "ADH-CAMELLIA128-SHA"},
	{0xC031, "ECDH-RSA-AES128-GCM-SHA256"},
	{0xC02D, "ECDH-ECDSA-AES128-GCM-SHA256"},
	{0xC029, "ECDH-RSA-AES128-SHA256"},
	{0xC025, "ECDH-ECDSA-AES128-SHA256"},
	{0xC00E, "ECDH-RSA-AES128-SHA"},
	{0xC004, "ECDH-ECDSA-AES128-SHA"},
	{0x009C, "AES128-GCM-SHA256"},
	{0x003C, "AES128-SHA256"},
	{0x002F, "AES128-SHA"},
	{0x0096, "SEED-SHA"},
	{0x0041, "CAMELLIA128-SHA"},
	{0x008C, "PSK-AES128-CBC-SHA"},
	{0xC012, "ECDHE-RSA-DES-CBC3-SHA"},
	{0xC008, "ECDHE-ECDSA-DES-CBC3-SHA"},
	{0x0016, "EDH-RSA-DES-CBC3-SHA"},
	{0x0013, "EDH-DSS-DES-CBC3-SHA"},
	{0x0010, "DH-RSA-DES-CBC3-SHA"},
	{0x000D, "DH-DSS-DES-CBC3-SHA"},
	{0xC017, "AECDH-DES-CBC3-SHA"},
	{0x001B, "ADH-DES-CBC3-SHA"},
	{0xC00D, "ECDH-RSA-DES-CBC3-SHA"},
	{0xC003, "ECDH-ECDSA-DES-CBC3-SHA"},
	{0x000A, "DES-CBC3-SHA"},
	{0x0007, "IDEA-CBC-SHA"},
	{0x008B, "PSK-3DES-EDE-CBC-SHA"},
	{0x0021, "KRB5-IDEA-CBC-SHA"},
	{0x001F, "KRB5-DES-CBC3-SHA"},
	{0x0025, "KRB5-IDEA-CBC-MD5"},
	{0x0023, "KRB5-DES-CBC3-MD5"},
	{0xC011, "ECDHE-RSA-RC4-SHA"},
	{0xC007, "ECDHE-ECDSA-RC4-SHA"},
	{0xC016, "AECDH-RC4-SHA"},
	{0x0018, "ADH-RC4-MD5"},
	{0xC00C, "ECDH-RSA-RC4-SHA"},
	{0xC002, "ECDH-ECDSA-RC4-SHA"},
	{0x0005, "RC4-SHA"},
	{0x0004, "RC4-MD5"},
	{0x008A, "PSK-RC4-SHA"},
	{0x0020, "KRB5-RC4-SHA"},
	{0x0024, "KRB5-RC4-MD5"},
	{0xC010, "ECDHE-RSA-NULL-SHA"},
	{0xC006, "ECDHE-ECDSA-NULL-SHA"},
	{0xC015, "AECDH-NULL-SHA"},
	{0xC00B, "ECDH-RSA-NULL-SHA"},
	{0xC001, "ECDH-ECDSA-NULL-SHA"},
	{0x003B, "NULL-SHA256"},
	{0x0002, "NULL-SHA"},
	{0x0001, "NULL-MD5"}
};

struct cipher_suite cipher_suite_list_tls13[] =
{
	{0x1301, "TLS_AES_128_GCM_SHA256"},
	{0x1302, "TLS_AES_256_GCM_SHA384"},
	{0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
	{0x1304, "TLS_AES_128_CCM_SHA256"},
	{0x1305, "TLS_AES_128_CCM_8_SHA256"}
};

void ssl_chello_free(struct ssl_chello* chello)
{
	if(chello==NULL)
	{
		return;
	}
	free(chello->sni);
	chello->sni = NULL;
	free(chello);
}

static char*  parse_server_name_extension(const unsigned char* buff, size_t buff_len, enum chello_parse_result* result)
{
	size_t pos = 2; /* skip server name list length */
	char* sni = NULL;
	while (pos + 3 < buff_len)
	{
		size_t len = ((size_t)buff[pos + 1] << 8) + (size_t)buff[pos + 2];
		if (len == 0 || pos + 3 + len > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
			return NULL;
		}
        switch (buff[pos])
		{
            case 0x00: /* host_name */
				sni = (char*)malloc(len + 1);
                strncpy(sni, (const char*)buff + pos + 3, len);
                sni[len] = '\0';
				*result = CHELLO_PARSE_SUCCESS;
			default:
				break;
        }
        pos += 3 + len;
    }
    if (pos != buff_len)
	{
		if(sni!=NULL)
		{
			free(sni);
			sni = NULL;
		}
		*result = CHELLO_PARSE_INVALID_FORMAT;
	}
	return sni;
}

static enum chello_parse_result parse_extensions(const unsigned char* buff, size_t buff_len, struct ssl_chello* chello) {
    size_t pos = 0;
	char *p_buff=NULL;
    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= buff_len)
	{
        size_t len = ((size_t)buff[pos + 2] << 8) + (size_t)buff[pos + 3];
        /* Check if it's a server name extension */
        if (buff[pos] == 0x00 && buff[pos + 1] == 0x00)
		{
            if (pos + 4 + len > buff_len)
			{
				return CHELLO_PARSE_INVALID_FORMAT;
			}
			enum chello_parse_result result = CHELLO_PARSE_SUCCESS;
            p_buff=parse_server_name_extension(buff + pos + 4, len, &result);
			if(chello->sni == NULL)
			{
				chello->sni = p_buff;
			}
			else
			{
				free(p_buff);
				p_buff=NULL;
			}
			if(result != CHELLO_PARSE_SUCCESS)
			{
				return result;
			}
        }
		/* Check if it's a alpn extension */
		if (buff[pos] == 0x00 && buff[pos + 1] == 0x10)
		{
			if (pos + 4 + len > buff_len)
			{
				return CHELLO_PARSE_INVALID_FORMAT;
			}
		}
		if (buff[pos] == 0xff && buff[pos + 1] == 0xce)//identify encrypt sni
        {
            chello->is_encrypt_sni = 1;
        }
		if (buff[pos] == 0xfe && buff[pos + 1] == 0x0d)//identify encrypt chello
        {
            chello->is_encrypt_chello = 1;
        }		
        pos += (4 + len);
    }
    /* Check we ended where we expected to */
    if (pos != buff_len)
	{
		return CHELLO_PARSE_INVALID_FORMAT;
	}
	return CHELLO_PARSE_SUCCESS;
}

struct ssl_chello* ssl_chello_parse(const unsigned char* buff, size_t buff_len, enum chello_parse_result* result)
{
	if(buff == NULL)
	{
		*result = CHELLO_PARSE_INVALID_FORMAT;
		return NULL;
	}
	if(buff_len < 1)
	{
		*result = CHELLO_PARSE_NOT_ENOUGH_BUFF;
		return NULL;
	}
	if(buff[0] != 0x80 && buff[0] != 0x16)
	{
		*result = CHELLO_PARSE_INVALID_FORMAT;
		return NULL;
	}
	 /* SSL 2.0 compatible Client Hello
     * High bit of first byte (length) and content type is Client Hello
     * See RFC5246 Appendix E.2
	 * if it is SSL 2.0, only parse version
     */
	if(buff[0] == 0x80)
	{
		struct ssl_chello* _chello = (struct ssl_chello*)ALLOC(struct ssl_chello, 1);
		_chello->min_version.major = 0x02;
		if(buff_len < 2)
		{
			*result = CHELLO_PARSE_NOT_ENOUGH_BUFF;
			return _chello;
		}
		size_t len = (size_t)buff[1];
		if (buff_len < len + 2)
		{
			*result = CHELLO_PARSE_NOT_ENOUGH_BUFF;
        	return _chello;
		}
		buff_len = len + 2;
		size_t pos = 2;
		/* Handshark Message Type: Client Hello */
		if (pos + 1 > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
    	}
		if (buff[pos] != 0x01)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
    	}
		pos += 1;
		/*  Version */
		if(pos + 2 > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
		_chello->max_version.major = buff[pos];
		_chello->max_version.minor = buff[pos + 1];
		_chello->max_version.ossl_format=(uint16_t)_chello->max_version.major<<8|_chello->max_version.minor;
		*result = CHELLO_PARSE_SUCCESS;
		return _chello;
	}
	else
	{
		if (buff_len < 5)
		{
        	*result = CHELLO_PARSE_NOT_ENOUGH_BUFF;
			return NULL;
		}
		if(buff[1] != 3 || buff[2] > 4)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return NULL;
		}
		struct ssl_chello* _chello = (struct ssl_chello*)ALLOC(struct ssl_chello, 1);
		_chello->min_version.major = buff[1];
		_chello->min_version.minor = buff[2];
		_chello->min_version.ossl_format=(uint16_t)_chello->min_version.major<<8|_chello->min_version.minor;
		_chello->max_version.major = (uint8_t)(-1);
		_chello->max_version.minor =  (uint8_t)(-1);
		_chello->sni = NULL;

		/* TLS record length */
    	size_t len = ((size_t)buff[3] << 8) + (size_t)buff[4] + 5;
		if (buff_len < len)
		{
			*result = CHELLO_PARSE_NOT_ENOUGH_BUFF;
        	return _chello;
		}
		buff_len = len;
		size_t pos = 5;
    	if (pos + 1 > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
    	}
		if (buff[pos] != 0x01)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
    	}
		pos += 4;
		if(pos + 2 > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
		_chello->max_version.major = buff[pos];
		_chello->max_version.minor = buff[pos+1];
		_chello->max_version.ossl_format=(uint16_t)_chello->max_version.major<<8|_chello->max_version.minor;

		pos += 34;
		/* Session ID */
    	if (pos + 1 > buff_len)
		{
        	*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
    	len = (size_t)buff[pos];
    	pos += 1 + len;
		/* Cipher Suites */
    	if (pos + 2 > buff_len)
		{
        	*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
    	len = ((size_t)buff[pos] << 8) + (size_t)buff[pos + 1];
		pos += 2;
		if(pos + len > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
		pos += len;
		/* Compression Methods */
    	if (pos >= buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
    	len = (size_t)buff[pos];
    	pos += 1 + len;
		/* no extensions */
		if(pos == buff_len)
		{
			*result = CHELLO_PARSE_SUCCESS;
			return _chello;
		}
		/* Extensions */
    	if (pos + 2 > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
    	len = ((size_t)buff[pos] << 8) + (size_t)buff[pos + 1];
    	pos += 2;
		if (pos + len > buff_len)
		{
			*result = CHELLO_PARSE_INVALID_FORMAT;
        	return _chello;
		}
		enum chello_parse_result ret = parse_extensions(buff + pos, len, _chello);
		*result = ret;
		return _chello;
	}
}
