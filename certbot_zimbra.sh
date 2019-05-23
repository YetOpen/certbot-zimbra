#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# contributions: Jernej Jakob <jernej.jakob@gmail.com>
# GPLv3 license

PROGNAME="certbot-zimbra"
VERSION="0.7"
GITHUB_URL="https://github.com/YetOpen/certbot-zimbra"
AGREE_TOS=""
NO_NGINX=false
RENEW_ONLY=false
NEW_CERT=false
ZMPATH="/opt/zimbra"
WEBROOT="$ZMPATH/data/nginx/html"
SERVICES=all
PATCH_ONLY=false
RESTART_ZIMBRA=true
EXTRA_DOMAIN=""
PROMPT_CONFIRM=true
DETECT_PUBLIC_HOSTNAMES=true
SKIP_PORT_CHECK=false
PORT=80
QUIET=false
IACT=false
CERTPATH="/etc/letsencrypt/live" # the domain will be appended to this path so the full path is $CERTPATH/$DOMAIN

## functions begin ##

# version compare from  http://stackoverflow.com/a/24067243/738852
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

function bootstrap() {
	set -e

	for name in su $ZMPATH/bin/zmcontrol; do
		! which "$name" >/dev/null && echo "$name not found or executable" && exit 1
	done

	DETECTED_ZIMBRA_VERSION=$(su - zimbra -c "$ZMPATH/bin/zmcontrol -v" | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)
	[ -z "$DETECTED_ZIMBRA_VERSION" ] && echo "Unable to detect zimbra version" && exit 1
	echo "Detected Zimbra $DETECTED_ZIMBRA_VERSION"

	if ! check_nginx_port; then
		echo "Zimbra's nginx doesn't seem to be listening on port $PORT."
		echo "This script uses nginx to verify the letsencrypt certificate retrieval so it needs Zimbra to be publically accessible from port 80."
		echo "Please pass --port or -j to skip if you're sure this is okay."
		exit 1
	fi
}

# Check if nginx is listening on port 80 or return an error
function check_nginx_port () {
	"$SKIP_PORT_CHECK" && echo "Skipping port check" && return

	# Better check with lsof, if available
	LSOF_BIN=$(which lsof 2>/dev/null)
	if [ -x "$LSOF_BIN" ]; then
		NGINX_CNT=$($LSOF_BIN -i :$PORT -u zimbra -a | grep -v COMMAND | wc -l)
		if [ "$NGINX_CNT" -lt 1 ]; then
			false
			return
		fi
	fi

	# Fallback to ss
	SS_BIN=$(which ss 2>/dev/null)
	if [ -x "$SS_BIN" ]; then
		NGINX_CNT=$($SS_BIN -lptn sport eq $PORT | grep nginx | wc -l)
		if [ "$NGINX_CNT" -lt 1 ]; then
			false
			return
		fi
	fi

	echo 'Neither "lsof" nor "ss" were found in PATH. Unable to continue, exiting.'
	exit 1
}

# Check if nginx is installed and patch it
# returns true if patch was applied or was already present, exits script if encountered an error
function patch_nginx() {
	set -e

	if version_gt "$DETECTED_ZIMBRA_VERSION" 8.7; then
		NGINX_BIN="$ZMPATH/common/sbin/nginx"
	else
		NGINX_BIN="$ZMPATH/nginx/sbin/nginx"
	fi

	# Exit if nginx is not installed
	[ ! -x $NGINX_BIN ] && echo "$NGINX_BIN not found or executable (zimbra-proxy package not installed?)" && exit 1
	[ ! -d $ZMPATH/conf/nginx/includes ] && echo "$ZMPATH/conf/nginx/includes not found, exiting" && exit 1

	# Return if patch is already applied
	grep -q 'acme-challenge' $ZMPATH/conf/nginx/includes/nginx.conf.web.http.default && return

	# Let's make a backup of zimbra's original templates
	BKDATE=$(date +"%Y%m%d_%H%M%S")
	echo "Making a backup of nginx templates in $ZMPATH/conf/nginx/templates.$BKDATE"
	cp -a $ZMPATH/conf/nginx/templates $ZMPATH/conf/nginx/templates.$BKDATE

	# do patch
	for file in http.default https.default http https ; do
		sed -i "s#^}#\n    \# patched by certbot-zimbra.sh\n    location ^~ /.well-known/acme-challenge {\n        root $WEBROOT;\n    }\n}#" $ZMPATH/conf/nginx/templates/nginx.conf.web.$file.template
	done

	set +e
	# reload nginx config
	su - zimbra -c 'zmproxyctl restart'; e=$?
	if [ $e -ne 0 ]; then
		echo "Error restarting zmproxy (zmproxydctl exit status $e). Please see $GITHUB_URL/issues if this issue has already been reported or file a new one including the output above."
		exit 1
	fi
}

function find_certbot () {
	# check for executable certbot-auto / certbot / letsencrypt
	LEB_BIN=$(which certbot-auto certbot letsencrypt 2>/dev/null | head -n 1)
	[ -z "$LEB_BIN" ] && echo "No letsencrypt/certbot binary found in $PATH" && exit 1
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
function find_additional_public_hostnames() {
	# If already set, leave them alone
	[ ! -z "$EXTRA_DOMAIN" ] && return

	# If it has been requested NOT to perform the search
	"$DETECT_PUBLIC_HOSTNAME" || return

	for i in $($ZMPATH/bin/zmprov gad); do
		ADDITIONAL_DOMAIN=$($ZMPATH/bin/zmprov gd $i zimbraPublicServiceHostname | grep zimbraPublicServiceHostname | cut -f 2 -d ' ')
		[ -z "$ADDITIONAL_DOMAIN" ] && continue
		# Skip our primary domain
		[ "$ADDITIONAL_DOMAIN" == "$DOMAIN" ] && continue
		EXTRA_DOMAIN="${EXTRA_DOMAIN} -d $ADDITIONAL_DOMAIN"
		# to be used at prompt
		EXTRA_DOMAIN_OUTPUT="${EXTRA_DOMAIN_OUTPUT} $ADDITIONAL_DOMAIN"
	done
}

function get_domain () {
	# If we got no domain from command line try using zimbra hostname
	if [ -z "$DOMAIN" ]; then
		DOMAIN=$($ZMPATH/bin/zmhostname)
		! "$QUIET" && echo "Using $ZMHOSTNAME ('zmhostname') as domain for certificate."
		# Detect additional hostnames
		"$RENEW_ONLY" || find_additional_public_hostnames
	fi

	if [ -z "$DOMAIN" ]; then
		! "$QUIET" && echo "No domain detected! Please run with -d/--hostname or check why zmhostname is not working"
		exit 1
	fi

	! "$QUIET" && echo "Main certificate domain: $DOMAIN"
	[ ! -z "$EXTRA_DOMAIN_OUTPUT" ] && ! "$QUIET" && echo "Additional certificate domains: $EXTRA_DOMAIN_OUTPUT"

	if ! "$QUIET" && "$PROMPT_CONFIRM"; then
		while read -p "Is this correct? " yn; do
			case "$yn" in
				[Yy]* ) break;;
				[Nn]* ) echo "Please call $(basename $0) --hostname your.host.name"; exit 1;;
				* ) echo "Please answer yes or no.";;
			esac
		done
	fi
}

# perform the letsencrypt request and prepares the certs
function request_certificate() {
	[ -z "$CERTPATH" ] && echo "CERTPATH not set. Exiting." && exit 1
	[ -z "$DOMAIN" ] && echo "DOMAIN not set. Exiting." && exit 1
	# Set variable for use in prepare_certificate
	CERTPATH="$CERTPATH/$DOMAIN"

	# <8.7 didn't have nginx webroot
	if [ ! -d "$WEBROOT" ]; then
		if ! "$QUIET" && "$PROMPT_CONFIRM"; then
			while read -p "Create $WEBROOT? " yn; do
                        case "$yn" in
                                [Yy]* ) mkdir -p "$WEBROOT";;
                                [Nn]* ) echo "Cannot proceed."; exit 1;;
                                * ) echo "Please answer yes or no.";;
                        esac
                done
		fi
		echo "$WEBROOT does not exist, cannot proceed. Please create it manually or rerun this script with -c." && exit 1
	fi
	
	#TODO: dry-run
	
	LE_PARAMS=""
	"$NONIACT" && LE_PARAMS="--non-interactive"
	"$QUIET" && LE_PARAMS="$LE_PARAMS --quiet"
	LE_PARAMS="$LE_PARAMS $AGREE_TOS"

	# Request our cert
	if "$NEW_CERT"; then
		$LE_BIN certonly $LE_PARAMS --expand -a webroot -w $WEBROOT -d $DOMAIN $EXTRA_DOMAIN
	else
		$LE_BIN renew $LE_PARAMS -a webroot -w $WEBROOT
	fi
	if [ $? -ne 0 ] ; then
		echo "letsencrypt returned an error"
		exit 1
	fi
}



# copies stuff ready for zimbra deployment and test them
function prepare_certificate () {
	[ -z "$CERTPATH" ] && echo "Empty CERTPATH" && exit 1
	
	# Make zimbra accessible files
	mkdir $ZMPATH/ssl/letsencrypt 2>/dev/null
	cp $CERTPATH/{privkey.pem,cert.pem} $ZMPATH/ssl/letsencrypt/
	chown -R zimbra:root $ZMPATH/ssl/letsencrypt
	chmod 550 $ZMPATH/ssl/letsencrypt
	
	# Create the "patched" chain suitable for Zimbra
	cat $CERTPATH/chain.pem > $ZMPATH/ssl/letsencrypt/zimbra_chain.pem
	# use the issuer_hash of the LE chain cert to find the root CA in /etc/ssl/certs
	cat /etc/ssl/certs/$(openssl x509 -in $CERTPATH/chain.pem -noout -issuer_hash).0 >> $ZMPATH/ssl/letsencrypt/zimbra_chain.pem
	[ $? -ne 0 ] && echo ""

	chmod 440 $ZMPATH/ssl/letsencrypt/*

	# Test cert. 8.6 and below must use root
	if version_gt "$DETECTED_ZIMBRA_VERSION" 8.7; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr verifycrt comm $ZMPATH/ssl/letsencrypt/privkey.pem $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem"
	else
		$ZMPATH/bin/zmcertmgr verifycrt comm $ZMPATH/ssl/letsencrypt/privkey.pem $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem
	fi
	if [ $? -eq 1 ]; then
		echo "Unable to verify cert!"
		exit 1;
	fi

}

# deploys certificate and restarts zimbra. ASSUMES prepare_certificate has been called already
function deploy_certificate() {
	# Backup old stuff
	cp -a $ZMPATH/ssl/zimbra $ZMPATH/ssl/zimbra.$(date "+%Y.%m.%d-%H.%M")

	cp $ZMPATH/ssl/letsencrypt/privkey.pem $ZMPATH/ssl/zimbra/commercial/commercial.key
	chown zimbra:zimbra $ZMPATH/ssl/zimbra/commercial/commercial.key
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c "$ZMPATH/bin/zmcertmgr deploycrt comm $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem -deploy ${SERVICES}"
	else
		$ZMPATH/bin/zmcertmgr deploycrt comm $ZMPATH/ssl/letsencrypt/cert.pem $ZMPATH/ssl/letsencrypt/zimbra_chain.pem
	fi

	# Set ownership of nginx config template
	chown zimbra:zimbra $ZMPATH/conf/nginx/includes/nginx.conf.web.http.default

	# Finally apply cert!
	"$RESTART_ZIMBRA" && su - zimbra -c 'zmcontrol restart'
	# FIXME And hope that everything started fine! :)

}

function check_user () {
	if [ "$EUID" -ne 0 ]; then
		echo "This script must be run as root" 1>&2
		exit 1
	fi
}

function usage () {
	cat <<EOF
USAGE: $(basename $0) < -d | -n | -p > [-xaczuj] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port]
  Options:
	 -d | --deploy-only: Just deploys certificates. Assumes valid certificates are in $CERTPATH. Incompatible with -n, -p.
	 -n | --new: performs a request for a new certificate. The default is to renew. Incompatible with -d, -p.
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade. Incompatible with -d, -n, -x.
	 -x | --no-nginx: doesn't check and patch zimbra's nginx. Incompatible with -p.
	 
	 -H | --hostname: hostname being requested. If not passed it's automatically detected using "zmhostname".
	 -e | --extra-domain: additional domains being requested. Can be used multiple times. Implies -u.
	 -w | --webroot: if there's another webserver on port 80 specify its webroot
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -c | --prompt-confirmation: ask for confirmation before proceding with cert request showing detected hostnames. Incompatible with -q.
	 -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
	 -z | --no-zimbra-restart: do not restart zimbra after a certificate deployment
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraServicePublicHostname.
	 -j | --no-port-check: disable nginx port check
	 -P | --port: HTTP port nginx is listening on (default 80)
	 -q | --quiet: Do not output on stdout. Useful for scripts. Incompatible with -c.
	 -i | --interactive: Pass --interactive to certbot/letsencrypt. Implies -c, incompatible with -q.

Author: Lorenzo Milesi <maxxer@yetopen.it>
Feedback, bugs and PR are welcome on GitHub: https://github.com/yetopen/certbot-zimbra.

Disclaimer:
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
EOF
}
## functions end ##

# main flow

echo "$PROGNAME v$VERSION - $GITHUB_URL"

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
			AGREE_TOS="--text --agree-tos --non-interactive"
			;;
		-c|--prompt-confirm)
			PROMPT_CONFIRM=true
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
		-x|--no-nginx)
			NO_NGINX=true
			
			;;
		-w|--webroot)
			[ -z "$2" ] && echo "missing webroot argument" && exit 1
			WEBROOT="$2"
			shift
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
		-N|--non-interactive)
			NONIACT=true
			;;
		-q|--quiet)
			QUIET=true
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
"$QUIET" && ("$IACT" || "$PROMPT_CONFIRM") && echo "Incompatible parameters: -q -c" && exit 1

"$DEPLOY_ONLY" && ("$NEW_CERT" || "$PATCH_ONLY") && echo "Incompatible option combination" && exit 1
"$NEW_CERT" && ("$DEPLOY_ONLY" || "$PATCH_ONLY") && echo "Incompatible option combination" && exit 1
"$PATCH_ONLY" && ("$DEPLOY_ONLY" || "$NEW_CERT" || "$NO_NGINX") && echo "Incompatible option combination" && exit 1


# If passed by --renew-hook, contains the path of the renewed cert which may differ from the default /etc/letsencrypt/live/$DOMAIN
#CERTPATH=$RENEWED_LINEAGE
#if [ -z "$CERTPATH" ]; then
#CERTPATH="/etc/letsencrypt/live/$DOMAIN"
#fi

# actions
check_user
bootstrap
"$NO_NGINX" || "$DEPLOY_ONLY" || patch_nginx
"$PATCH_ONLY" && exit 0
get_domain
"$DEPLOY_ONLY" || find_certbot && request_cert
prepare_cert
deploy_cert

exit 0
