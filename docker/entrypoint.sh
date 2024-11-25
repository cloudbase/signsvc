#!/bin/bash
set -e
set -o pipefail

init(){
	local pcscd_running
	pcscd_running=$(pgrep pcscd) || true
	if [ -z "$pcscd_running" ]; then
		echo "starting pcscd in backgroud"
		pcscd --debug --apdu
		pcscd --hotplug
	else
		echo "pcscd is running in already: ${pcscd_running}"
	fi
}

init

/usr/bin/ykman piv info || true # Yubikey might not be inserted at that time
/root/signsvc
