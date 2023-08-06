#pragma once

enum STATISTICS_DIMENSION
{
	DIMENSION_MAAT_RULE=0,
	DIMENSION_MAAT_STATE,
	DIMENSION_FQDN,
	DIMENSION_CATEGORY_ID,
	DIMENSION_APPLICATION,
	DIMENSION_MAX
};

#ifndef MAX_CATEGORY_ID_NUM
#define	MAX_CATEGORY_ID_NUM	8
#endif
struct server_fqdn_category
{
	int n_ids;
	unsigned int ids[MAX_CATEGORY_ID_NUM];
};

struct statistics_dimensions
{
    enum STATISTICS_DIMENSION type;
    union
    {
		char *server_fqdn;
		char *application;
		struct maat_state *maat_state;
        struct matched_policy_rules *policy;
		struct server_fqdn_category *category;
    };
};

int session_dimension_server_fqdn_sync(const struct streaminfo *a_stream, char *server_fqdn);
int session_dimension_application_sync(const struct streaminfo *a_stream, char *application);
int session_dimension_maat_state_sync(const struct streaminfo *a_stream, struct maat_state *state);
int session_dimension_maat_rule_sync(const struct streaminfo *a_stream, struct matched_policy_rules *policy);
int session_dimension_category_id_sync(const struct streaminfo *a_stream, unsigned int *category_id, int n_category_id);
