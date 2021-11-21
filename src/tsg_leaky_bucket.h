#ifndef	__TSG_LEAK_BUCKET_H__
#define	__TSG_LEAK_BUCKET_H__

struct leaky_bucket;

struct leaky_bucket *create_bucket(int bucket_size, int thread_seq);
void destroy_bucket(struct leaky_bucket **bucket, int thread_seq);
int is_permit_pass(int pkt_size, struct leaky_bucket * bucket, int thread_seq);

#endif
