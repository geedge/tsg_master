
if [ $1 == 0 ]; then
	echo "uninstall: $1"

	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/platform/
	sed -i '/tsg_master.inf/d' ${DST}/plug/conflist.inf
	sed -i '/POLICY_PRIORITY/d' ${DST}/etc/project_list.conf
	sed -i '/ESTABLISH_LATENCY/d' ${DST}/etc/project_list.conf
fi

