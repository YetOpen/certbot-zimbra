#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# author: Jernej Jakob <jernej.jakob@gmail.com>
# GPLv3 license

PROGNAME="certbot-zimbra"
VERSION="0.7.8"
GITHUB_URL="https://github.com/YetOpen/certbot-zimbra"
# paths
ZMPATH="/opt/zimbra"
ZMWEBROOT="$ZMPATH/data/nginx/html"
LE_LIVE_PATH="/etc/letsencrypt/live" # the domain will be appended to this path
TEMPPATH="/run/$PROGNAME"
# other options
ZMPROV_OPTS="-l" # use ldap (faster)
# Do NOT modify anything after this line.
WEBROOT=""
CERTPATH=""
LE_PARAMS=""
LE_AGREE_TOS=false
LE_NONIACT=false
EXTRA_DOMAINS=()
NO_NGINX=false
DEPLOY_ONLY=false
NEW_CERT=false
SERVICES=all
PATCH_ONLY=false
RESTART_ZIMBRA=true
PROMPT_CONFIRM=false
DETECT_PUBLIC_HOSTNAMES=true
SKIP_PORT_CHECK=false
PORT=""
QUIET=false

# set up a trap on exit
exitfunc(){
	e="$?"
	if [ "$e" -ne 0 ] && ! "$QUIET"; then
		echo
		echo "An error seems to have occurred. Please read the output above for clues and try to rectify the situation."
		echo "If you believe this is an error with the script, please file an issue at $GITHUB_URL."
	fi

	# close fd used for locking, workaround for issue #89
	exec 200>&-
	rm "$TEMPPATH/$PROGNAME.lck"

	exit "$e"
}
trap exitfunc EXIT

## functions begin ##

check_user () {
	if [ "$EUID" -ne 0 ]; then
		echo "Error: This script must be run as root" 1>&2
		exit 1
	fi
}

make_temp() {
	! mkdir --mode=750 -p "$TEMPPATH" && echo "Error: Can't create temporary directory $TEMPPATH" && exit 1
	chown root:zimbra "$TEMPPATH"
}

get_lock(){
	exec 200> "$TEMPPATH/$PROGNAME.lck"
	! flock -n 200 && echo "Error: can't get exclusive lock. Another instance of this script may be running.
If you are sure there is no other instance of this script running (check with \"ps afx\") you can remove $TEMPPATH/$PROGNAME.lck and try again." && exit 1
}

prompt(){
	while read -p "$1 " yn; do
		case "$yn" in
			[Yy]* ) return 0;;
			[Nn]* ) return 1;;
			* ) echo "Please answer yes or no.";;
		esac
	done
}

check_depends_ca() {
	# Debian/Ubuntu provided by ca-certificates
	[ -f /etc/ssl/certs/ca-certificates.crt ] && return
	# RHEL/CentOS provided by pki-base
	[ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ] && return

	echo "Installed CA certificates not found. Please check if you have installed:"
	echo "Debian/Ubuntu: ca-certificates (if you do, you might have to run \"update-ca-certificates\")"
	echo "RHEL/CentOS: pki-base (if you do, you might have to run \"update-ca-trust\")"
	exit 1
}

check_depends() {
	# check for dependencies
	! $QUIET && echo "Checking for dependencies..."

	# do not check for lsof or ss here as we'll do that later
	for name in su openssl grep head cut sed chmod chown cat cp $ZMPATH/bin/zmcertmgr $ZMPATH/bin/zmcontrol $ZMPATH/bin/zmprov $ZMPATH/libexec/get_plat_tag.sh; do
		! which "$name" >/dev/null && echo "Error: \"$name\" not found or executable" && exit 1
	done
}

# version compare from  http://stackoverflow.com/a/24067243/738852
version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

bootstrap() {
	check_user
	make_temp
	get_lock

	check_depends
	check_depends_ca

	# Detect OS and Zimbra version

	# use zimbra's get_plat_tag.sh to find OS and version (this is only for display and not used elsewhere in the script)
	# returns $OS$ver for 32-bit or $OS$ver_64 for 64-bit, where OS is the os name (UBUNTU,DEBIAN,RHEL,CentOS,F,FC,SLES,openSUSE,UCS,MANDRIVA,SOLARIS,MACOSx)
	PLATFORM="$($ZMPATH/libexec/get_plat_tag.sh)"

	DETECTED_ZIMBRA_VERSION="$(su - zimbra -c "$ZMPATH/bin/zmcontrol -v" | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)"
	[ -z "$DETECTED_ZIMBRA_VERSION" ] && echo "Error: Unable to detect zimbra version" && exit 1
	! "$QUIET" && echo "Detected Zimbra $DETECTED_ZIMBRA_VERSION on $PLATFORM"

	return 0
}

check_zimbra_proxy() {
	# must be run after get_domain
	[ -z "$DOMAIN" ] && echo "Unexpected error (check_zimbra_proxy DOMAIN not set)" && exit 1

	! "$QUIET" && echo "Checking zimbra-proxy is running and enabled"

	# no need if we check if it's running later
	#su - zimbra -c "$ZMPATH/bin/zmprov $ZMPROV_OPTS gs $DOMAIN zimbraServiceEnabled | grep -q proxy" || ( echo "Error: zimbra-proxy is not enabled" && exit 1 )

	# TODO: check if path to zmproxyctl is different on <8.7
	! su - zimbra -c "$ZMPATH/bin/zmproxyctl status > /dev/null" && echo "Error: zimbra-proxy is not running" && exit 1
	! su - zimbra -c "$ZMPATH/bin/zmprov $ZMPROV_OPTS gs $DOMAIN zimbraReverseProxyHttpEnabled | grep -q TRUE" && echo "Error: http reverse proxy not enabled (zimbraReverseProxyHttpEnabled: FALSE)" && exit 1

	if [ -z "$PORT" ]; then
		! "$QUIET" && echo "Detecting port from zimbraMailProxyPort"
		PORT="$(su - zimbra -c "$ZMPATH/bin/zmprov $ZMPROV_OPTS gs $DOMAIN zimbraMailProxyPort | sed -n 's/zimbraMailProxyPort: //p'")"
		[ -z "$PORT" ] && echo "Error: zimbraMailProxyPort not found" && exit 1
	else
		echo "Skipping port detection from zimbraMailProxyPort due to --port override"
	fi
}

# Check if process is listening on port $1 (optionally with name $2 and/or user $3) or return an error
check_port () {
	if "$SKIP_PORT_CHECK"; then
		! "$QUIET" && echo "Skipping port check"
		return 0
	fi

	[ -z "$1" ] && echo 'Unexpected error: check_port empty $1 (port)' && exit 1

	! "$QUIET" && echo "Checking if process is listening on port $1 ${2:+"with name \"$2\" "}${3:+"user \"$3\""}"

	# check with lsof if available, or fall back to ss
	LSOF_BIN="$(which lsof 2>/dev/null)"
	SS_BIN="$(which ss 2>/dev/null)"
	CHECK_BIN=""
	GREP_FILTER=""
	if [ -x "$LSOF_BIN" ]; then
		CHECK_BIN="$LSOF_BIN -i :$1 -s TCP:LISTEN -a -n"
		GREP_FILTER="$2.*$3"
	elif [ -x "$SS_BIN" ]; then
		CHECK_BIN="$SS_BIN -lptn sport eq :$1"
		# ss doesn't return process user, so don't use it for count
		GREP_FILTER="$2"
	else
		echo 'Error: Neither "lsof" nor "ss" were found in PATH. Unable to continue, exiting.'
		exit 1
	fi

	# return false if count of matched processes is 0
	# optionally $2 and $3 are process name and process user
	(( "$($CHECK_BIN | grep -c "$GREP_FILTER")" == 0 )) && return 1

	return 0
}


# Patch zimbra proxy nginx and restart it if successful
# zimbra-proxy must be running (checked with check_zimbra_proxy) or zmproxyctl restart will fail
# returns true if patch was applied or was already present, exits script if encountered an error
patch_nginx() {
	[ ! -d $ZMPATH/conf/nginx/includes ] && echo "Error: $ZMPATH/conf/nginx/includes not found, exiting" && exit 1

	# Return if patch is already applied
	if grep -r -q 'acme-challenge' "$ZMPATH/conf/nginx/includes"; then
		! "$QUIET" && echo "Nginx templates already patched."
		return
	fi

	[ -z $WEBROOT ] && echo "Unexpected error: patch_nginx WEbROOT not set. Exiting." && exit 1

	! "$QUIET" && echo "Patching nginx templates."

	set -e

	# Let's make a backup of zimbra's original templates
	BKDATE="$(date +'%Y%m%d_%H%M%S')"
	! "$QUIET" && echo "Making a backup of nginx templates in $ZMPATH/conf/nginx/templates.$BKDATE"
	cp -a "$ZMPATH/conf/nginx/templates" "$ZMPATH/conf/nginx/templates.$BKDATE"

	# do patch
	for file in http.default https.default http https ; do
		sed -i "s#^}#\n    \# patched by certbot-zimbra.sh\n    location ^~ /.well-known/acme-challenge {\n        root $WEBROOT;\n    }\n}#" "$ZMPATH/conf/nginx/templates/nginx.conf.web.$file.template"
	done

	set +e

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
                prompt "Restart zmproxy?"
                (( $? == 1 )) && echo "Cannot continue. Exiting." && exit 1
        fi

	! "$QUIET" && echo "Running zmproxyctl restart."
	# reload nginx config
	su - zimbra -c 'zmproxyctl restart'; e="$?"
	if [ "$e" -ne 0 ]; then
		echo "Error restarting zmproxy (zmproxyctl exit status $e). Exiting."
		exit 1
	fi
	return 0
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
find_additional_public_hostnames() {
	# If already set, leave them alone
	[ -n "$EXTRA_DOMAINS" ] && return

	# If it has been requested NOT to perform the search
	if ! "$DETECT_PUBLIC_HOSTNAMES"; then
		! "$QUIET" && echo "Skipping additional public service hostname detection"
		return
	fi

	! "$QUIET" && echo -n "Detecting additional public service hostnames..."
	for i in $($ZMPATH/bin/zmprov $ZMPROV_OPTS gad); do
		getdomain="$($ZMPATH/bin/zmprov $ZMPROV_OPTS gd $i zimbraPublicServiceHostname | grep zimbraPublicServiceHostname | cut -f 2 -d ' ')"
		[ -z "$getdomain" ] && continue
		# Skip our primary domain
		[ "$getdomain" == "$DOMAIN" ] && continue
		EXTRA_DOMAINS=("${EXTRA_DOMAINS[@]}" "$getdomain")
		! "$QUIET" && echo -n " $getdomain"
	done
	! "$QUIET" && echo
	return 0
}

get_domain () {
	# If we got no domain from command line try using zimbra hostname
	if [ -z "$DOMAIN" ]; then
		! "$QUIET" && echo "Using zmhostname to detect domain."
		DOMAIN="$($ZMPATH/bin/zmhostname)"
		# Find additional domains
		"$DEPLOY_ONLY" || find_additional_public_hostnames
	fi

	[ -z "$DOMAIN" ] && echo "Error: No domain found! Please run with -d/--hostname or check why zmhostname is not working" && exit 1

	! "$QUIET" && echo "Using domain $DOMAIN (as certificate DN)"
	[ -n "$EXTRA_DOMAINS" ] && ! "$QUIET" && echo "Found domains to use as certificate SANs: ${EXTRA_DOMAINS[@]}"

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		prompt "Is this correct?"
		(( $? == 1 )) && echo "Error: Please call $(basename $0) --hostname your.host.name" && exit 1
	fi
	return 0
}

set_certpath() {
	# must be run after get_domain
	[ -z "$DOMAIN" ] && echo "Unexpected error (set_certpath DOMAIN not set)" && exit 1

	# when run as --deploy-hook, check if any of RENEWED_DOMAINS match zimbra's domain.
	# RENEWED_DOMAINS and RENEWED_LINEAGE are passed by certbot as env vars to --deploy-hook
	if [ -n "$RENEWED_DOMAINS" ]; then
		# we were run as --deploy-hook
		for renewed_domain in $RENEWED_DOMAINS; do
			[ "$renewed_domain" == "$DOMAIN" ] && CERTPATH="$RENEWED_LINEAGE"
		done
		# exit gracefully if no matching domains were found. We must be running for some other cert, not ours.
		if [ -z "$CERTPATH" ]; then
			! "$QUIET" && echo "Detected --deploy-hook but no matching domain found. Nothing to do."
			exit 0
		else
			! "$QUIET" && echo "Detected --deploy-hook and matching domain found"
		fi
	else
		# we were run standalone
		CERTPATH="$LE_LIVE_PATH/$DOMAIN"
	fi
}

check_webroot () {
	[ -z "$WEBROOT" ] && echo "Unexpected error: check_webroot WEBROOT not set. Exiting." && exit 1
	
	# <8.7 didn't have nginx webroot
	if [ ! -d "$WEBROOT" ]; then
		if ! "$QUIET" && "$PROMPT_CONFIRM"; then
			prompt "Create $WEBROOT?"
			if (( $? == 0 )); then
				mkdir -p "$WEBROOT"
				return 0
			else
				echo "Cannot proceed, exiting."
				exit 1
			fi
		fi
		echo "Error: $WEBROOT does not exist, cannot proceed. Please create it manually or rerun this script with -c/--prompt-confirm and without -q/--quiet. Exiting."
		exit 1
	fi
}

find_certbot () {
	# check for executable certbot-auto / certbot / letsencrypt
	LE_BIN="$(which certbot-auto certbot letsencrypt 2>/dev/null | head -n 1)"
	[ -z "$LE_BIN" ] && echo "Error: No letsencrypt/certbot binary found in $PATH" && exit 1
	return 0
}

# perform the letsencrypt request
request_cert() {
	check_webroot

	#TODO: dry-run

	"$LE_NONIACT" && LE_PARAMS="--non-interactive"
	"$QUIET" && LE_PARAMS="$LE_PARAMS --quiet"
	"$LE_AGREE_TOS" && LE_PARAMS="$LE_PARAMS --agree-tos"
	# use --cert-name instead of --expand as it allows also removing domains? https://github.com/certbot/certbot/issues/4275
	LE_PARAMS="$LE_PARAMS --webroot -w $WEBROOT --expand -d $DOMAIN"
	for d in ${EXTRA_DOMAINS[@]}; do
		[ -z "$d" ] && continue
		LE_PARAMS="$LE_PARAMS -d $d"
	done

	! "$QUIET" && echo "Running $LE_BIN certonly $LE_PARAMS"
	"$QUIET" && exec > /dev/null
	# Request our cert
	$LE_BIN certonly $LE_PARAMS
	e=$?
	"$QUIET" && exec > /dev/tty
	[ "$e" -ne 0 ] && echo "Error: $LE_BIN exit status $e. Cannot proceed, exiting." && exit 1
	return 0
}

# copies stuff ready for zimbra deployment and test them
prepare_cert() {
	! "$QUIET" && echo "Preparing certificates for deployment."

	[ -z "$CERTPATH" ] && echo "Unexpected error (prepare_cert CERTPATH not set). Exiting." && exit 1
	[ -z "$DOMAIN" ] && echo "Unexpected error (prepare_cert DOMAIN not set). Exiting." && exit 1

	# Make zimbra accessible files
	# save old umask
	oldumask="$(umask -p)"
	# make files u=rwx g=rx o=
	umask 0027

	# exit on error
	set -e

	tmpcerts="$(mktemp -d --tmpdir="$TEMPPATH" certs-XXXXXXXX)"

	cp "$CERTPATH"/{privkey.pem,cert.pem} "$tmpcerts/"

	# Create the "patched" chain suitable for Zimbra
	cat "$CERTPATH/chain.pem" > "$tmpcerts/zimbra_chain.pem"
	if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
	        # Debian/Ubuntu
		# use the issuer_hash of the LE chain cert to find the root CA in /etc/ssl/certs
		cat "/etc/ssl/certs/$(openssl x509 -in $CERTPATH/chain.pem -noout -issuer_hash).0" >> $tmpcerts/zimbra_chain.pem
	elif [ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]; then
		# RHEL/CentOS
		# extract CA by CN in tls-ca-bundle.pem
		issuer="$(openssl x509 -in $CERTPATH/chain.pem -noout -issuer | sed -n 's/.*CN=//;s/\/.*$//;p')"
		[ -z "$issuer" ] && exit 1
		# the following awk script extracts the CA cert from the bundle or exits 1 if not found
		awk "BEGIN {e=1}; /^# $issuer$/{e=0} /^# $issuer$/,/END CERTIFICATE/; END {exit e}" /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem >> $tmpcerts/zimbra_chain.pem
	else
		# we shouldn't be here
		echo "Unexpected error (problem in check_depends_ca)" && exit 1
	fi

	$oldumask

	# set permissions so that zimbra can read the certs
	chown -R root:zimbra "$tmpcerts"
	chmod 550 "$tmpcerts"
	chmod 440 $tmpcerts/*

	! "$QUIET" && echo "Testing with zmcertmgr."

	# redirect stdout to /dev/null if quiet
	"$QUIET" && exec > /dev/null

	# Test cert. 8.6 and below must use root
	if version_gt "$DETECTED_ZIMBRA_VERSION" "8.7"; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr verifycrt comm $tmpcerts/privkey.pem $tmpcerts/cert.pem $tmpcerts/zimbra_chain.pem"
	else
		$ZMPATH/bin/zmcertmgr verifycrt comm "$tmpcerts/privkey.pem" "$tmpcerts/cert.pem" "$tmpcerts/zimbra_chain.pem"
	fi

	# undo quiet
	"$QUIET" && exec > /dev/tty

	# undo set -e
	set +e

	return 0
}

# deploys certificate and restarts zimbra. ASSUMES prepare_certificate has been called already
deploy_cert() {
	# exit on error
	set -e
	! "$QUIET" && echo "Deploying certificates."

	# Backup old stuff
	cp -a "$ZMPATH/ssl/zimbra" "$ZMPATH/ssl/zimbra.$(date +'%Y%m%d_%H%M%S')"

	# copy privkey
	cp -a "$tmpcerts/privkey.pem" "$ZMPATH/ssl/zimbra/commercial/commercial.key"

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		prompt "Deploy certificates to Zimbra?"
		(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 1
	fi

	"$QUIET" && exec > /dev/null
	# this is it, deploy the cert.
	if version_gt "$DETECTED_ZIMBRA_VERSION" "8.7"; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr deploycrt comm $tmpcerts/cert.pem $tmpcerts/zimbra_chain.pem -deploy ${SERVICES}"
	else
		$ZMPATH/bin/zmcertmgr deploycrt comm "$tmpcerts/cert.pem" "$tmpcerts/zimbra_chain.pem"
	fi
	"$QUIET" && exec > /dev/tty

	! "$QUIET" && echo "Removing temporary files in $tmpcerts"
	# this is kind of sketchy
	[ -n "$tmpcerts" ] && rm -r "$tmpcerts"

	if "$RESTART_ZIMBRA"; then
		if ! "$QUIET" && "$PROMPT_CONFIRM"; then
			prompt "Restart Zimbra?"
			(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 1
		fi

		! "$QUIET" && echo "Restarting Zimbra."

		"$QUIET" && exec > /dev/null
		# Finally apply cert!
		su - zimbra -c 'zmcontrol restart'
		# FIXME And hope that everything started fine! :)
		"$QUIET" && exec > /dev/tty
	fi

	set +e

	return 0
}

usage () {
	cat <<EOF
USAGE: $(basename $0) < -d | -n | -p > [-aNuzjxcq] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port] [-L "--extra-le-parameters ..."]
  Only one option at a time can be supplied. Options cannot be chained.
  Mandatory options (only one can be specified):
	 -d | --deploy-only: Just deploys certificates. Can be run as --deploy-hook. If run standalone, assumes valid certificates are in $LE_LIVE_PATH. Incompatible with -n/--new, -p/--patch-only.
	 -n | --new: performs a request for a new certificate ("certonly"). Can be used to update the domains in an existing certificate. Incompatible with -d/--deploy-only, -p/--patch-only.
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade. Incompatible with -d/--deploy-only, -n/--new, -x/--no-nginx.

  Options only used with -n/--new:
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -L | --letsencrypt-params "--extra-le-parameters ...": Additional parameters to pass to certbot/letsencrypt
	 -N | --noninteractive: Pass --noninteractive to certbot/letsencrypt.
  Domain options:
	 -e | --extra-domain <extra.domain.tld>: additional domains being requested. Can be used multiple times. Implies -u/--no-public-hostname-detection.
	 -H | --hostname <my.host.name>: hostname being requested. If not passed it's automatically detected using "zmhostname".
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraServicePublicHostname.
  Deploy options:
	 -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
	 -z | --no-zimbra-restart: do not restart zimbra after a certificate deployment
  Port check:
	 -j | --no-port-check: disable port check. Incompatible with -P/--port.
	 -P | --port <port>: HTTP port the web server to use for letsencrypt authentication is listening on. Is detected from zimbraMailProxyPort. Mandatory with -x/--no-nginx.
  Nginx options:
	 -w | --webroot "/path/to/www": path to the webroot of alternate webserver. Valid only with -x/--no-nginx.
	 -x | --no-nginx: Alternate webserver mode. Don't check and patch zimbra-proxy's nginx. Must also specify -P/--port and -w/--webroot. Incompatible with -p/--patch-only.
  Output options:
	 -c | --prompt-confirm: ask for confirmation. Incompatible with -q/--quiet.
	 -q | --quiet: Do not output on stdout. Useful for scripts. Implies -N/--noninteractive, incompatible with -c/--prompt-confirm.

Authors: Lorenzo Milesi <maxxer@yetopen.it>, Jernej Jakob <jernej.jakob@gmail.com> @jjakob
Feedback, bugs and PR are welcome on GitHub: https://github.com/yetopen/certbot-zimbra.

Disclaimer:
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
EOF
}
## functions end ##

# main flow


# parameters parsing http://stackoverflow.com/a/14203146/738852
while [[ $# -gt 0 ]]; do
	case "$1" in
		# flow-modifying parameters
		-d|--deploy-only)
			DEPLOY_ONLY=true
			;;
		-n|--new)
			NEW_CERT=true
			;;
		-p|--patch-only)
			PATCH_ONLY=true
			;;
		# optional parameters
		# letsencrypt
		-a|--agree-tos)
			AGREE_TOS=true
			;;
		-L|--letsencrypt-params)
			[ -z "$2" ] && echo "missing letsencrypt-params argument" && exit 1
			LE_PARAMS="$LE_PARAMS $2"
			shift
			;;
		-N|--noninteractive)
			LE_NONIACT=true
			;;
		# domain
		-e|--extra-domain)
			[ -z "$2" ] && echo "missing extra domain argument" && exit 1
			EXTRA_DOMAINS=("${EXTRA_DOMAINS[@]}" "$2")
			DETECT_PUBLIC_HOSTNAMES=false
			shift
			;;
		-H|--hostname)
			[ -z "$2" ] && echo "missing hostname argument" && exit 1
			DOMAIN="$2"
			DETECT_PUBLIC_HOSTNAMES=false
			shift
			;;
		-u|--no-public-hostname-detection)
			DETECT_PUBLIC_HOSTNAMES=false
			;;
		# port check
		-j|--no-port-check)
			SKIP_PORT_CHECK=true
			;;
		-P|--port)
			[ -z "$2" ] && echo "missing port argument" && exit 1
			PORT="$2"
			shift
			;;
		# nginx
		-w|--webroot)
			[ -z "$2" ] && echo "missing webroot argument" && exit 1
			WEBROOT="$2"
			shift
			;;
		-x|--no-nginx)
			NO_NGINX=true
			;;
		# zimbra
		-s|--services)
			[ -z "$2" ] && echo "missing services argument" && exit 1
			SERVICES="$2"
			shift
			;;
		-z|--no-zimbra-restart)
			RESTART_ZIMBRA=false
			;;
		# other
		-c|--prompt-confirm)
			PROMPT_CONFIRM=true
			;;
		-q|--quiet)
			QUIET=true
			LE_NONIACT=true
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1. Try --help for usage." >& 2
			exit 1
			;;
	esac
	shift
done

# exit if an invalid option combination was passed
"$QUIET" && "$PROMPT_CONFIRM" && echo "Incompatible parameters: -q -c" && exit 1
"$LE_NONIACT" && "$PROMPT_CONFIRM" && echo "Incompatible parameters: -N -c" && exit 1

"$DEPLOY_ONLY" && ("$NEW_CERT" || "$PATCH_ONLY") && echo "Incompatible option combination" && exit 1
"$NEW_CERT" && ("$DEPLOY_ONLY" || "$PATCH_ONLY") && echo "Incompatible option combination" && exit 1
"$PATCH_ONLY" && ("$DEPLOY_ONLY" || "$NEW_CERT" || "$NO_NGINX") && echo "Incompatible option combination" && exit 1
! ("$DEPLOY_ONLY" || "$NEW_CERT" || "$PATCH_ONLY") && echo "Nothing to do. Please specify one of: -d -n -p. Exiting." && exit 1

"$NO_NGINX" && [ -z "$WEBROOT" -o \( -z "$PORT" -a ! "$SKIP_PORT_CHECK" \) ] && echo "Error: --no-nginx requires --webroot and --port or --no-port-check. Exiting." && exit 1
! "$NO_NGINX" && [ -n "$WEBROOT" ] && echo "Error: -w/--webroot can't be used in zimbra-proxy mode. Please use -x/--no-nginx (alternate webserver mode). Exiting." && exit 1
"$SKIP_PORT_CHECK" && [ -n "$PORT" ] && echo "Error: -j/--no-port-check can't be used with -P/--port. Exiting." && exit 1

! "$QUIET" && echo "$PROGNAME v$VERSION - $GITHUB_URL"

## actions
bootstrap
get_domain

if ! "$DEPLOY_ONLY"; then
	if "$NO_NGINX"; then
		! check_port "$PORT" && echo "Error: port check failed. A web server to use for letsencrypt authentication of the domain $DOMAIN must be listening on the port specified with --port." && exit 1
	else
		WEBROOT="$ZMWEBROOT"
		check_zimbra_proxy
		! check_port "$PORT" nginx zimbra && echo "Error: port check failed. If you have overridden the port with --port, a web server to use for letsencrypt authentication of the domain $DOMAIN must be listening on it." && exit 1
		patch_nginx
	fi

	"$PATCH_ONLY" && exit 0

	find_certbot
	request_cert
fi

set_certpath
prepare_cert
deploy_cert

exit 0
