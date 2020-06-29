if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}

	mkdir -p ${DST}/plug/platform/
	sed -i '/tsg_master.inf/d' ${DST}/plug/conflist.inf
	sed -i '/POLICY_PRIORITY/d' ${DST}/etc/project_list.conf
	sed -i '/TSG_MASTER_INTERNAL_LABEL/d' ${DST}/etc/project_list.conf
fi

