#ifndef	__TSG_SEND_LOG_H__
#define	__TSG_SEND_LOG_H__

#include <MESA/Maat_rule.h>

#ifdef __cplusplus
extern "C"
{
#endif


struct _opt_unit_t
{
	int opt_type;
	int opt_len;
	char *opt_value;
};

typedef	struct _tsg_log
{
	int result_num;
	Maat_rule_t *result;
	struct streaminfo *a_stream;
}tsg_log_t;


int tsg_sendlog_init(char *filename);
void tsg_send_log(const tsg_log_t* log_msg, struct _opt_unit_t* log_opt, int opt_num, int thread_id);


#ifdef __cplusplus
}
#endif

#endif
