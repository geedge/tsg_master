#pragma once

#include "tsg_send_log.h"

extern "C" int TSG_MASTER_INIT();
void session_matched_rules_free(const struct streaminfo *stream, int bridge_id, void *data);

int TLD_convert_json(struct TLD_handle_t *_handle, char *buff, unsigned int buff_len);
int set_app_id(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream);
int set_shaping_rule_ids(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, const struct streaminfo *a_stream);


