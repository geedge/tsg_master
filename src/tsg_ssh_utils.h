#ifndef	__TSG_SSH_UTILS_H__
#define	__TSG_SSH_UTILS_H__
#include <string.h>
#include <MESA/MESA_handle_logger.h>
int ssh_protocol_identify(const unsigned char* buff, size_t buff_len, void* argp);

#endif
