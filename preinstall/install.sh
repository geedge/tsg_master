
	echo " pre install: $1"

	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/platform/
	mkdir -p ${DST}/etc/
	touch ${DST}/plug/conflist.inf
	touch ${DST}/etc/project_list.conf

	if [[ -z `grep -rn 'POLICY_PRIORITY' ${DST}/etc/project_list.conf` ]];then
		echo 'POLICY_PRIORITY	struct' >> ${DST}/etc/project_list.conf
	fi

	if [[ -z `grep -rn 'ESTABLISH_LATENCY' ${DST}/etc/project_list.conf` ]];then
		echo 'ESTABLISH_LATENCY	long' >> ${DST}/etc/project_list.conf
	fi

	if [[ -z `grep -rn 'tsg_master.inf' ${DST}/plug/conflist.inf` ]];then
		sed -i '/\[platform\]/a\./plug/platform/tsg_master/tsg_master.inf' ${DST}/plug/conflist.inf
	fi

