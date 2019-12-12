#!/bin/sh
DST=${RPM_INSTALL_PREFIX}
mkdir -p ${DST}/plug/platform/
sed -i '/tsg_master.inf/d' ${DST}/plug/conflist.inf
sed -i '/POLICY_PRIORITY/d' ${DST}/etc/project_list.conf
