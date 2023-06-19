#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <MESA/dns.h>

#include "tsg_entry.h"
#include "tsg_rule_internal.h"
#include "tsg_protocol_common.h"

static int random_integer(int max, int min)
{
	if(max>min)
	{
		return (rand()%(max-min+1));
	}

	return 0;
}

static int record_set_uint32(char *payload, unsigned int value)
{
	*(unsigned int *)payload=(unsigned int)(value);
	return 4;
}

static int record_hton_uint16(char *payload, unsigned short value)
{
	*(unsigned short *)payload=(unsigned short)htons(value);
	return 2;
}

static int record_hton_uint32(char *payload, unsigned int value)
{
	*(unsigned int *)payload=(unsigned int)htonl(value);
	return 4;
}

static int compress_domain_record(const unsigned char *domain, int domain_len, u_char *result)
{
	int result_pos = 1;
	int domain_pos = 0;

    if(domain_len < 0 || domain_len > DNS_MAX_NAME+1 ||  '.' == domain[0] || '.' == domain[domain_len - 1])
    {
        return -1;
    }

	while((domain[domain_pos] != '\n') && (domain[domain_pos] != '\0'))
	{
		int section_len = 0;
		while((domain[domain_pos] != '.') &&(domain[domain_pos] != '\n')&&(domain[domain_pos] != '\0'))
		{
			result[result_pos] = domain[domain_pos];
			result_pos++;
			domain_pos++;
			section_len++;
		}
		result[result_pos - section_len -1] = section_len;

		if((domain[domain_pos] == '\n')||(domain[domain_pos] == '\0'))
			break;
		result_pos++;
		domain_pos++;
	}

	result[result_pos]= '\0';

	if(result_pos >= domain_len)
	{
    	return result_pos+1;
	}
	else
	{
		return  result_pos;
	}

	return 0;
}

int dns_set_response_header(dns_hdr_t *dns_hdr)
{
	dns_hdr->qr = 1;        // 1bit: Response
	dns_hdr->opcode = 0;    // 4bits: Query
	dns_hdr->aa = 0;        // 1bit: authoritative answer
	dns_hdr->tc = 0;        // 1bit: Not truncated
	dns_hdr->rd = 1;        // 1bit: Recursion Desired
	dns_hdr->ra = 1;        // 1bit: Recursion Available
	dns_hdr->z = 0;         // 3bits: Reserved for future use: Must be zero in all queries and responses
	dns_hdr->rcode = 0;     // 4bits: 0: No error condition

	dns_hdr->id = htons(dns_hdr->id);
	dns_hdr->qdcount = htons(dns_hdr->qdcount);  // 16bits: QDCOUNT: number of questions
	dns_hdr->ancount = htons(dns_hdr->ancount);  // 16bits: ANCOUNT: number of answer resource records
	dns_hdr->aucount = htons(dns_hdr->aucount);  // 16bits: NSCOUNT: number of authority resource records
	dns_hdr->adcount = htons(dns_hdr->adcount);  // 16bits: ARCOUNT: number of additional resource records

	return 0;
}


int dns_set_response_question(char *payload, int payload_len, dns_query_question_t *query_question)
{
	int compress_len=0, used_len=0;
	u_char compress_name[DNS_MAX_NAME+1];

	/* ֻ����һ������ */
	
	memset(compress_name, 0, sizeof(compress_name));
	compress_len=compress_domain_record(query_question->qname,strlen((char *)(query_question->qname)), compress_name);
	if(compress_len<=0)
	{
		return -1;
	}

	memcpy(payload, compress_name, compress_len);
	used_len+=compress_len;
	used_len+=record_hton_uint16(payload+used_len, query_question->qtype);
	used_len+=record_hton_uint16(payload+used_len, query_question->qclass);

	return used_len;
}

int dns_set_response_records(char *payload, int payload_len, struct dns_record_val *record_val, int record_val_num, int max_ttl, int min_ttl)
{
	int used_len=0;
	unsigned short compress_len=0;
	unsigned char compress_name[DNS_MAX_NAME+1]={0};

	for(int i=0; i<record_val_num; i++)
	{
		used_len+=record_hton_uint16(payload+used_len, (unsigned short)0xc00c);
		used_len+=record_hton_uint16(payload+used_len, (unsigned short)(record_val[i].answer_type));//type
		used_len+=record_hton_uint16(payload+used_len, (unsigned short)1); //class
		
		int ttl=random_integer(max_ttl, min_ttl)+min_ttl;
		used_len+=record_hton_uint32(payload+used_len, (unsigned int)ttl);//ttl

		switch(record_val[i].answer_type)
		{
			case DNS_TYPE_A:
				used_len+=record_hton_uint16(payload+used_len, (unsigned short)(record_val[i].len));	//len
				used_len+=record_set_uint32(payload+used_len, (unsigned int)(record_val[i].v4_addr.s_addr));	//IPv4
				break;
			case DNS_TYPE_AAAA:
				used_len+=record_hton_uint16(payload+used_len, (unsigned short)(record_val[i].len));	//len
				memcpy(payload+used_len, record_val[i].v6_addr.s6_addr, record_val[i].len);	//IPv6
				used_len+=record_val[i].len;
				break;
			case DNS_TYPE_CNAME:
				compress_len=compress_domain_record((unsigned char *)record_val[i].cname, record_val[i].len, compress_name);
				used_len+=record_hton_uint16(payload+used_len, (unsigned short)(compress_len));	//len
				memcpy(payload+used_len, compress_name, compress_len);
				used_len+=compress_len;
				break;
			default:
				break;
		}
	}

	return used_len;
}


static int dns_set_header(struct _dns_info *dns_info, struct _dns_hdr *dns_hdr, int record_num)
{
	dns_hdr->id = dns_info->hdr_info.id;
	dns_hdr->qdcount = 1;
	dns_hdr->ancount = record_num;
	dns_set_response_header(dns_hdr);

	return 0;
}

static struct dns_user_region *dns_get_user_records(struct dns_user_region *user_region_records, int user_region_records_num, int qtype)
{
	int i=0;
	for(i=0; i<user_region_records_num; i++)
	{
		if(user_region_records[i].query_type==qtype)
		{
			return &(user_region_records[i]);
		}
	}

	return NULL;
}

static int dns_set_answer_records(char *payload, int payload_len, struct dns_answer_records *answer_records, int *answer_record_num)
{
	if(answer_records==NULL)
	{
		return 0;
	}

	int used_len=0;
	if(answer_records->record_val.selected_flag==1)
	{	
		struct dns_profile_records *profile_records=(struct dns_profile_records *)matched_rule_cites_dns_profile_record(g_tsg_maat_feather, (long long)answer_records->record_val.selected.profile_id);
		if(profile_records==NULL)
		{
			return 0;
		}

		int record_num=MIN(answer_records->record_val.selected.selected_num, profile_records->record_num);
		int idx=random_integer(profile_records->record_num, record_num);
		used_len+=dns_set_response_records(payload+used_len, payload_len-used_len, profile_records->record_val+idx, record_num, answer_records->max_ttl, answer_records->min_ttl);

		(*answer_record_num)+=record_num;
	}
	else
	{		
		(*answer_record_num)++;
		used_len+=dns_set_response_records(payload+used_len, payload_len-used_len, &(answer_records->record_val), 1, answer_records->max_ttl, answer_records->min_ttl);
	}
	
	return used_len;
}

unsigned char do_action_redirect_dns(const struct streaminfo *a_stream, struct maat_rule *p_result, struct compile_user_region *user_region, const void *user_data)
{
	int opt_value=0;
	int ret=0,used_len=0,record_num=0;	
	unsigned char raw_route_dir=0;
	char payload[1024]={0};
	int payload_len=sizeof(payload);
	int header_len=sizeof(struct _dns_hdr);
	struct dns_user_region *user_region_record=NULL;
	struct _dns_info *dns_info=(struct _dns_info *)user_data;

	if(dns_info==NULL)
	{
		return STATE_GIVEME;
	}
	
	if(dns_info->hdr_info.qr==1 && g_tsg_para.deploy_mode==DEPLOY_MODE_MIRROR) //mirror
	{
		return STATE_GIVEME;
	}

	if(dns_info->hdr_info.qr==0 && (g_tsg_para.deploy_mode==DEPLOY_MODE_INLINE || g_tsg_para.deploy_mode==DEPLOY_MODE_TRANSPARENT)) //inline or transparent
	{
		return STATE_GIVEME;
	}
	
	user_region_record=dns_get_user_records(user_region->deny->records, user_region->deny->records_num, dns_info->query_question.qtype);
	if(user_region_record==NULL)
	{
		return STATE_GIVEME;
	}
	
	used_len+=header_len;
	ret=dns_set_response_question(payload+used_len, payload_len-used_len, &(dns_info->query_question));
	if(ret==-1)
	{
		MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
		return STATE_GIVEME;
	}
	
	used_len+=ret;
	used_len+=dns_set_answer_records(payload+used_len, payload_len-used_len, user_region_record->a, &record_num);
	used_len+=dns_set_answer_records(payload+used_len, payload_len-used_len, user_region_record->aaaa, &record_num);
	used_len+=dns_set_answer_records(payload+used_len, payload_len-used_len, user_region_record->cname, &record_num);
	if(record_num<=0)
	{
		return STATE_GIVEME;
	}
	
	dns_set_header(dns_info, (struct _dns_hdr *)payload, record_num);
	raw_route_dir=(dns_info->hdr_info.qr==0) ? MESA_dir_reverse(a_stream->routedir) : a_stream->routedir;
	tsg_send_inject_packet(a_stream, SIO_DEFAULT, payload, used_len, raw_route_dir);
	
	MESA_set_stream_opt(a_stream, MSO_DROP_CURRENT_PKT, (void *)&opt_value, sizeof(opt_value));
	
	return STATE_GIVEME;
}

