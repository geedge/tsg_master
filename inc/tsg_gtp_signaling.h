#ifndef	__TSG_GTP_SIGNALING_H__
#define	__TSG_GTP_SIGNALING_H__

#include <MESA/gtp.h>
#include <MESA/MESA_htable.h>

enum GTP_FIELD_IDX
{
	GTP_FIELD_APN,
	GTP_FIELD_IMEI,
	GTP_FIELD_IMSI,
	GTP_FIELD_MSISDN,	//phone number
	GTP_FIELD_END_USER_IP,
	GTP_FIELD_PAA,
	GTP_FIELD_TEID_CP,
	GTP_FIELD_TEID_II,
	GTP_FIELD_MAX
};

struct gtp_signaling_field
{
	char type;
	char version;
	unsigned int uplink_teid;
	unsigned int downlink_teid;
	struct IE_unit ie_unit[GTP_FIELD_MAX];
};

extern MESA_htable_handle g_gtp_signaling_hash_handle;

void tsg_free_gtp_signaling_field(void *data);

#endif
