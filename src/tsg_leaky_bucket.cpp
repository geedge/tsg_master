#include<stdio.h>
#include<sys/time.h>
#include<stdlib.h>
#include <time.h>

#include <MESA/stream.h>

enum BUCKET_UNIT
{
	BUCKET_UNIT_S=0,
	BUCKET_UNIT_MS,
	BUCKET_UNIT_US,
	BUCKET_UNIT_MAX,
};

struct leaky_bucket
{
    double rate;
    int used_size;
    int bucket_size;
	enum BUCKET_UNIT unit;
	struct timespec refresh_time;
};

#define	BUCKET_UNIT_S_LIMIT_MAX_BIT		32*8*1024
#define	BUCKET_UNIT_MS_LIMIT_MAX_BIT	64*8*1024

void refresh_bucket(struct leaky_bucket * bucket, int thread_seq)
{
	long interval_us=0;
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);

	switch(bucket->unit)
	{
		case	BUCKET_UNIT_S:			
			interval_us=(end.tv_sec-bucket->refresh_time.tv_sec)+(end.tv_nsec-bucket->refresh_time.tv_nsec)/1000000000;
			break;
		case	BUCKET_UNIT_MS:			
			interval_us=(end.tv_sec-bucket->refresh_time.tv_sec)*1000 + (end.tv_nsec-bucket->refresh_time.tv_nsec)/1000000;
			break;
		case	BUCKET_UNIT_US:			
			interval_us=(end.tv_sec-bucket->refresh_time.tv_sec)*1000000 + (end.tv_nsec-bucket->refresh_time.tv_nsec)/1000;
			break;
		default:
			bucket->used_size=bucket->bucket_size;
			return ;
	}
	

    bucket->used_size=bucket->used_size-interval_us*(bucket->rate);
    bucket->used_size=(bucket->used_size<0) ? 0 : bucket->used_size;

	if(interval_us>=1)
	{				
		bucket->refresh_time=end;
	}
	
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

struct leaky_bucket * create_bucket(int bucket_size, int thread_seq)
{
	if(bucket_size<0)
	{
		return NULL;
	}
	
    struct leaky_bucket * bucket = (struct leaky_bucket *)dictator_malloc(thread_seq, sizeof(struct leaky_bucket));

	if(bucket_size<BUCKET_UNIT_S_LIMIT_MAX_BIT)
	{
	    bucket->rate=(double)bucket_size;		
		bucket->unit=BUCKET_UNIT_S;
	}
	else if(bucket_size<BUCKET_UNIT_MS_LIMIT_MAX_BIT)
	{
		bucket->rate=(double)bucket_size/(double)1000;		
		bucket->unit=BUCKET_UNIT_MS;
	}
	else
	{
		bucket->rate=(double)bucket_size/(double)1000000;		
		bucket->unit=BUCKET_UNIT_US;
	}
	
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

