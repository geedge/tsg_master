#include<stdio.h>
#include<sys/time.h>
#include<stdlib.h>
#include <time.h>

#include <MESA/stream.h>

struct leaky_bucket
{
    double rate;
    int used_size;
    int bucket_size;
	struct timespec refresh_time;
};

void refresh_bucket(struct leaky_bucket * bucket, int thread_seq)
{
	long interval_us=0;
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	interval_us = (end.tv_sec - bucket->refresh_time.tv_sec)*1000000 + (end.tv_nsec - bucket->refresh_time.tv_nsec)/1000;

    bucket->used_size=bucket->used_size - interval_us*(bucket->rate);
    bucket->used_size=(bucket->used_size<0) ? 0 : bucket->used_size;

    bucket->refresh_time=end;

	return ;
}

int is_permit_pass(int pkt_size, struct leaky_bucket * bucket, int thread_seq)
{
    refresh_bucket(bucket, thread_seq);
    if ((bucket->used_size+pkt_size) < bucket->bucket_size)
    {
        bucket->used_size += pkt_size;
        return 1;
    }
   
	return 0;
}

struct leaky_bucket * create_bucket(double rate, int bucket_size, int thread_seq)
{
    struct leaky_bucket * bucket = (struct leaky_bucket *)dictator_malloc(thread_seq, sizeof(struct leaky_bucket));
	
    bucket->rate = rate;
    bucket->used_size = 0;
    bucket->bucket_size = bucket_size;

	clock_gettime(CLOCK_MONOTONIC, &(bucket->refresh_time));

    return bucket;
}

void destroy_bucket(struct leaky_bucket **bucket, int thread_seq)
{
	if(*bucket!=NULL)
	{
    	dictator_free(thread_seq, *bucket);
    	bucket = NULL;
	}

	return ;
}

