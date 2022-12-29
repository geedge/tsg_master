#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <MESA/stream.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>
#include <MESA/MESA_jump_layer.h>

#include "../inc/app_label.h"
#include "../inc/tsg_rule.h"
#include "../inc/tsg_send_log.h"
#include "../inc/tsg_statistic.h"
#include "../src/tsg_entry.h"
#include "../src/tsg_send_log_internal.h"
#include "../inc/tsg_ssl_utils.h"
#include "../src/tsg_ssh_utils.h"
#include "../src/tsg_protocol_common.h"

#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h"

using namespace rapidjson;
using namespace std;

extern "C" int TSG_MASTER_INIT();
int set_vlan(struct tsg_log_instance_t *_instance, struct TLD_handle_t *_handle, struct single_layer_vlan_addr *vlan_addr, int layer_num, Value *tunnel_object, tsg_log_field_id_t id);
int set_app_full_path(struct TLD_handle_t *_handle, char *field_name, struct gather_app_result *result);

