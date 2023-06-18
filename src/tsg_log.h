#pragma once

#define	LOG_MODULE_ACTION	"DO_ACTION"
#define	LOG_MODULE_BRIDGE	"BRIDGE"
#define	LOG_MODULE_SID		"SID"
#define	LOG_MODULE_SYNC_APP	"SYN_APP"
#define	LOG_MODULE_PENDING	"PENDING"
#define	LOG_MODULE_INIT		"INIT"
#define	LOG_MODULE_PROXY	"PROXY"
#define	LOG_MODULE_MAAT		"MAAT"
#define	LOG_MODULE_SENDLOG	"SENDLOG"
#define	LOG_MODULE_MPACK	"MPACK"
#define	LOG_MODULE_METRICS	"METRICS"

#define MASTER_LOG(handle, level, module, format, ...)								\
do																					\
{																					\
	if (MESA_handle_runtime_log_level_enabled(handle, level))						\
	{																				\
		MESA_handle_runtime_log(handle, level, module, "file %s, line %d, " format,	\
								__FILE__, __LINE__, ##__VA_ARGS__);					\
	}																				\
} while (0)

