#pragma once

extern int rd_kafka_get_sendlog_cnt(void);
extern void rd_kafka_clean_sendlog_cnt(void);
extern const char *rd_kafka_get_sendlog_payload(int idx);

