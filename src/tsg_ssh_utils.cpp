#include <stdio.h>
#include <stdlib.h>
#include "tsg_ssh_utils.h"


#define SSH_PROTOCOL_FIELD "SSH"
#define SSH_PROTOCOL_FIELD_LEN 3


int ssh_protocol_identify(const unsigned char* buff, size_t buff_len, void* argp)
{
	if(buff == NULL || buff_len < SSH_PROTOCOL_FIELD_LEN)
	{
		return -1;
	}
	if(memcmp((void *)buff,SSH_PROTOCOL_FIELD, SSH_PROTOCOL_FIELD_LEN) == 0)
		return 1;
	else
		return 0;
}

