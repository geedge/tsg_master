#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <MESA/ssl.h>
#include <MESA/stream.h>

int tm_get_ssl_ja3_fingerprint(const struct streaminfo *a_stream, char **ja3_fingerprint)
{
	struct _ssl_ja3_info_t *ja3_info=ssl_get_ja3_fingerprint((struct streaminfo *)a_stream, (unsigned char *)a_stream->ptcpdetail->pdata, (unsigned int)a_stream->ptcpdetail->datalen, a_stream->threadnum);
	if(ja3_info!=NULL)
	{
		if(ja3_info->fp!=NULL && ja3_info->fp_len>0)
		{
			*ja3_fingerprint=(char *)dictator_malloc(a_stream->threadnum, ja3_info->fp_len+1);
			memset(*ja3_fingerprint, 0, ja3_info->fp_len+1);
			memcpy(*ja3_fingerprint, ja3_info->fp, ja3_info->fp_len);
			return 1;
		}
	}

	return 0;
}

