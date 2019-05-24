#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# contributions: Jernej Jakob <jernej.jakob@gmail.com>
# GPLv3 license

PROGNAME="certbot-zimbra"
VERSION="0.7"
GITHUB_URL="https://github.com/YetOpen/certbot-zimbra"
# paths
ZMPATH="/opt/zimbra"
WEBROOT="$ZMPATH/data/nginx/html"
CERTPATH="/etc/letsencrypt/live" # the domain will be appended to this path so the full path is $CERTPATH/$DOMAIN
# Do not modify anything after this line.
LE_PARAMS=""
LE_AGREE_TOS=false
LE_NONIACT=false
EXTRA_DOMAINS=""
NO_NGINX=false
DEPLOY_ONLY=false
NEW_CERT=false
SERVICES=all
PATCH_ONLY=false
RESTART_ZIMBRA=true
PROMPT_CONFIRM=false
DETECT_PUBLIC_HOSTNAMES=true
SKIP_PORT_CHECK=false
PORT=80
QUIET=false

# set up a trap on exit
exitfunc(){
	e="$?"
	if [ "$e" -ne 0 ] && ! "$QUIET"; then
		echo
		echo "An error seems to have occurred. Please read the output above for clues and try to rectify the situation."
		echo "If you believe this is an error with the script, please file an issue at $GITHUB_URL."
	fi
	exit "$e"
}
trap exitfunc EXIT

## functions begin ##

prompt(){
	while read -p "$1 " yn; do
		case "$yn" in
			[Yy]* ) return 0;;
			[Nn]* ) return 1;;
			* ) echo "Please answer yes or no.";;
		esac
	done
}

# version compare from  http://stackoverflow.com/a/24067243/738852
version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

bootstrap() {
	# check for dependencies
	# do not check for lsof or ss here as we'll do that later
	for name in "su openssl grep head cut sed chmod chown cat cp $ZMPATH/bin/zmcertmgr $ZMPATH/bin/zmcontrol $ZMPATH/bin/zmprov"; do
		! which "$name" >/dev/null && echo "$name not found or executable" && exit 1
	done

	DETECTED_ZIMBRA_VERSION="$(su - zimbra -c "$ZMPATH/bin/zmcontrol -v" | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)"
	[ -z "$DETECTED_ZIMBRA_VERSION" ] && echo "Unable to detect zimbra version" && exit 1
	! "$QUIET" && echo "Detected Zimbra $DETECTED_ZIMBRA_VERSION"

	if ! check_nginx_port; then
		echo "Zimbra's nginx doesn't seem to be listening on port $PORT."
		echo "This script uses nginx to verify the letsencrypt certificate retrieval so it needs Zimbra to be publically accessible from port 80."
		echo "Please pass --port or -j to skip if you're sure this is okay."
		exit 1
	fi
	return 0
}

# Check if nginx is listening on port 80 or return an error
check_nginx_port () {
	if "$SKIP_PORT_CHECK"; then
		! "$QUIET" && echo "Skipping port check"
		return
	fi
	
	! "$QUIET" && echo "Checking if nginx is listening on port $PORT"

	# Better check with lsof, if available
	LSOF_BIN="$(which lsof 2>/dev/null)"
	if [ -x "$LSOF_BIN" ]; then
		NGINX_CNT="$($LSOF_BIN -i :$PORT -u zimbra -a | grep -v COMMAND | wc -l)"
		(( "$NGINX_CNT" < 1 )) && return 1
		return 0
	fi

	# Fallback to ss
	SS_BIN=$(which ss 2>/dev/null)
	if [ -x "$SS_BIN" ]; then
		NGINX_CNT="$($SS_BIN -lptn sport eq $PORT | grep nginx | wc -l)"
		(( "$NGINX_CNT" < 1 )) && return 1
		return 0
	fi

	echo 'Neither "lsof" nor "ss" were found in PATH. Unable to continue, exiting.'
	exit 1
}


# Check if nginx is installed and patch it
# returns true if patch was applied or was already present, exits script if encountered an error
patch_nginx() {
	if version_gt "$DETECTED_ZIMBRA_VERSION" 8.7; then
		NGINX_BIN="$ZMPATH/common/sbin/nginx"
	else
		NGINX_BIN="$ZMPATH/nginx/sbin/nginx"
	fi

	# Exit if nginx is not installed
	[ ! -x "$NGINX_BIN" ] && echo "$NGINX_BIN not found or executable (zimbra-proxy package not installed?), exiting." && exit 1
	[ ! -d $ZMPATH/conf/nginx/includes ] && echo "$ZMPATH/conf/nginx/includes not found, exiting" && exit 1

	# Return if patch is already applied
	if grep -q 'acme-challenge' "$ZMPATH/conf/nginx/includes/nginx.conf.web.http.default"; then
		! "$QUIET" && echo "Nginx templates already patched."
		return
	fi

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
		echo "Error restarting zmproxy (zmproxydctl exit status $e). Exiting."
		exit 1
	fi
	return 0
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
find_additional_public_hostnames() {
	# If already set, leave them alone
	[ ! -z "$EXTRA_DOMAINS" ] && return

	# If it has been requested NOT to perform the search
	"$DETECT_PUBLIC_HOSTNAMES" || return

	for i in $($ZMPATH/bin/zmprov gad); do
		getdomain="$($ZMPATH/bin/zmprov gd $i zimbraPublicServiceHostname | grep zimbraPublicServiceHostname | cut -f 2 -d ' ')"
		[ -z "$getdomain" ] && continue
		# Skip our primary domain
		[ "$getdomain" == "$DOMAIN" ] && continue
		EXTRA_DOMAINS="${EXTRA_DOMAIN} $getdomain"
	done
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

	[ -z "$DOMAIN" ] && echo "No domain found! Please run with -d/--hostname or check why zmhostname is not working" && exit 1
	
	! "$QUIET" && echo "Using domain $DOMAIN (as certificate DN)"
	[ ! -z "$EXTRA_DOMAINS" ] && ! "$QUIET" && echo "Found domains to use as certificate SANs: $EXTRA_DOMAINS"

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		prompt "Is this correct?"
		(( $? == 1 )) && echo "Please call $(basename $0) --hostname your.host.name" && exit 1
	fi
	return 0
}

check_webroot () {
	[ -z "$WEBROOT" ] && echo "WEBROOT not set. Exiting." && exit 1
		
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
		echo "$WEBROOT does not exist, cannot proceed. Please create it manually or rerun this script with -c and without -q. Exiting."
		exit 1
	fi
}

find_certbot () {
	# check for executable certbot-auto / certbot / letsencrypt
	LE_BIN="$(which certbot-auto certbot letsencrypt 2>/dev/null | head -n 1)"
	[ -z "$LE_BIN" ] && echo "No letsencrypt/certbot binary found in $PATH" && exit 1
	return 0
}

# perform the letsencrypt request
request_cert() {
	check_webroot
	
	#TODO: dry-run
	
	"$LE_NONIACT" && LE_PARAMS="--non-interactive"
	"$QUIET" && LE_PARAMS="$LE_PARAMS --quiet"
	"$LE_AGREE_TOS" && LE_PARAMS="$LE_PARAMS --agree-tos"
	LE_PARAMS="$LE_PARAMS --webroot -w $WEBROOT --expand -d $DOMAIN"
	for d in "$EXTRA_DOMAINS"; do
		[ -z "$d" ] && continue
		LE_PARAMS="$LE_PARAMS -d $d"
	done

	! "$QUIET" && echo "Running $LE_BIN certonly $LE_PARAMS"
	"$QUIET" && exec > /dev/null
	# Request our cert
	# use --cert-name instead of --expand as it allows also removing domains? https://github.com/certbot/certbot/issues/4275
	$LE_BIN certonly $LE_PARAMS
	e=$?
	"$QUIET" && exec > /dev/tty
	[ "$e" -ne 0 ] && echo "Error: $LE_BIN exit status $e. Cannot proceed, exiting." && exit 1
	return 0
}

# copies stuff ready for zimbra deployment and test them
prepare_cert() {
	! "$QUIET" && echo "Preparing certificates."

	[ -z "$CERTPATH" ] && echo "CERTPATH not set. Exiting." && exit 1
	[ -z "$DOMAIN" ] && echo "DOMAIN not set. Exiting." && exit 1

	# When run as --post-hook, RENEWED_LINEAGE will contain the actual path as used by certbot
	if [ ! -z "$RENEWED_LINEAGE" ]; then
		CERTPATH="$RENEWED_LINEAGE"
	else
		CERTPATH="$CERTPATH/$DOMAIN"
	fi
	
	# Make zimbra accessible files
	# save old umask
	oldumask="$(umask -p)"
	# make files u=rwx g=rx o=
	umask 0027
	
	# this will complain if the dir already exists so send stderr to /dev/null	
	mkdir "$ZMPATH/ssl/letsencrypt" 2>/dev/null
	
	# exit on error
	set -e

	cp "$CERTPATH"/{privkey.pem,cert.pem} "$ZMPATH/ssl/letsencrypt/"
	chown -R zimbra:root "$ZMPATH/ssl/letsencrypt"
	chmod 550 "$ZMPATH/ssl/letsencrypt"
	

	# Create the "patched" chain suitable for Zimbra
	cat "$CERTPATH/chain.pem" > $ZMPATH/ssl/letsencrypt/zimbra_chain.pem
	# use the issuer_hash of the LE chain cert to find the root CA in /etc/ssl/certs
	cat "/etc/ssl/certs/$(openssl x509 -in $CERTPATH/chain.pem -noout -issuer_hash).0" >> $ZMPATH/ssl/letsencrypt/zimbra_chain.pem

	chmod 440 $ZMPATH/ssl/letsencrypt/*
	$oldumask
	
	! "$QUIET" && echo "Testing with zmcertmgr."

	"$QUIET" && exec > /dev/null
	# Test cert. 8.6 and below must use root
	if version_gt "$DETECTED_ZIMBRA_VERSION" "8.7"; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr verifycrt comm $ZMPATH/ssl/letsencrypt/privkey.pem $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem"
	else
		$ZMPATH/bin/zmcertmgr verifycrt comm "$ZMPATH/ssl/letsencrypt/privkey.pem" "$ZMPATH/ssl/letsencrypt/cert.pem" "$ZMPATH/ssl/letsencrypt/zimbra_chain.pem"
	fi
	"$QUIET" && exec > /dev/tty

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

	cp "$ZMPATH/ssl/letsencrypt/privkey.pem" "$ZMPATH/ssl/zimbra/commercial/commercial.key"
	
	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		prompt "Deploy certificates to Zimbra?"
		(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 1
	fi
	
	"$QUIET" && exec > /dev/null
	# this is it, deploy the cert.
	if version_gt "$DETECTED_ZIMBRA_VERSION" "8.7"; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr deploycrt comm $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem -deploy ${SERVICES}"
	else
		$ZMPATH/bin/zmcertmgr deploycrt comm "$ZMPATH/ssl/letsencrypt/cert.pem" "$ZMPATH/ssl/letsencrypt/zimbra_chain.pem"
	fi
	"$QUIET" && exec > /dev/tty	

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		prompt "Restart Zimbra?"
		(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 1
	fi

	! "$QUIET" && echo "Restarting Zimbra."
	"$QUIET" && exec > /dev/null	
	# Finally apply cert!
	"$RESTART_ZIMBRA" && su - zimbra -c 'zmcontrol restart'
	# FIXME And hope that everything started fine! :)
	"$QUIET" && exec > /dev/tty
	set +e
	return 0
}

check_user () {
	if [ "$EUID" -ne 0 ]; then
		echo "This script must be run as root" 1>&2
		exit 1
	fi
}

usage () {
	cat <<EOF
USAGE: $(basename $0) < -d | -n | -p > [-acjNquxz] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port] [-L "--letsencrypt-parameters ..."] 
  Only one option at a time can be supplied. Options cannot be chained.
  Mandatory options (only one can be specified):
	 -d | --deploy-only: Just deploys certificates. Assumes valid certificates are in $CERTPATH. Incompatible with -n, -p.
	 -n | --new: performs a request for a new certificate ("certonly"). Can be used to update the domains in an existing certificate. Incompatible with -d, -p.
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade. Incompatible with -d, -n, -x.

  Options only used with -n/--new:
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -L | --letsencrypt-params: Additional parameters to pass to certbot/letsencrypt
	 -N | --noninteractive: Pass --noninteractive to certbot/letsencrypt.
  Domain options:
	 -e | --extra-domain: additional domains being requested. Can be used multiple times. Implies -u.
	 -H | --hostname: hostname being requested. If not passed it's automatically detected using "zmhostname".
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraServicePublicHostname.
  Deploy options:
	 -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
	 -z | --no-zimbra-restart: do not restart zimbra after a certificate deployment
  Port check:
	 -j | --no-port-check: disable nginx port check
	 -P | --port: HTTP port web server is listening on (default 80)
  Nginx options:
	 -w | --webroot: if there's another webserver on port 80 specify its webroot
	 -x | --no-nginx: doesn't check and patch zimbra's nginx. Incompatible with -p.
  Output options:
	 -c | --prompt-confirm: ask for confirmation. Incompatible with -q.
	 -q | --quiet: Do not output on stdout. Useful for scripts. Implies -N, incompatible with -c.

Author: Lorenzo Milesi <maxxer@yetopen.it>
Contributors: Jernej Jakob <jernej.jakob@gmail.com> @jjakob
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
			EXTRA_DOMAIN="${EXTRA_DOMAIN} -d $2"
			EXTRA_DOMAIN_OUTPUT="${EXTRA_DOMAIN_OUTPUT} $2"
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
		*)
			echo "Unknown option: $1" >& 2
			usage
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

! "$QUIET" && echo "$PROGNAME v$VERSION - $GITHUB_URL"

# actions
check_user
bootstrap
"$NO_NGINX" || "$DEPLOY_ONLY" || patch_nginx
"$PATCH_ONLY" && exit 0
get_domain
"$DEPLOY_ONLY" || find_certbot 
"$DEPLOY_ONLY" || request_cert
prepare_cert
deploy_cert

exit 0
