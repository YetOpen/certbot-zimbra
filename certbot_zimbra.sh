#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# GPLv3 license

AGREE_TOS=""
NO_NGINX="no"
RENEW_ONLY="no"
NEW_CERT="no"
WEBROOT="/opt/zimbra/data/nginx/html"
SERVICES=all
PATCH_ONLY="no"
RESTART_ZIMBRA="yes"
EXTRA_DOMAIN=""
PROMPT_CONFIRM="no"
DETECT_PUBLIC_HOSTNAMES="yes"
SKIP_PORT_CHECK="no"

## functions
# check executable certbot-auto / certbot / letsencrypt
function check_executable() {
	LEB_BIN=$(which certbot-auto certbot letsencrypt 2>/dev/null | head -n 1)
	# No way
	if [ -z "$LEB_BIN" ]; then
		echo "No letsencrypt/certbot binary found in $PATH";
		exit 1;
	fi
}

# version compare from  http://stackoverflow.com/a/24067243/738852
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

function bootstrap() {
    echo "Certbot-Zimbra v0.5 - https://github.com/YetOpen/certbot-zimbra"

	if [ ! -x "/opt/zimbra/bin/zmcontrol" ]; then
		echo "/opt/zimbra/bin/zmcontrol not found"
		exit 1;
	fi
	DETECTED_ZIMBRA_VERSION=$(su - zimbra -c '/opt/zimbra/bin/zmcontrol -v' | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)
	if [ -z "$DETECTED_ZIMBRA_VERSION" ]; then
		echo "Unable to detect zimbra version"
		exit 1;
	fi
	echo "Detected Zimbra $DETECTED_ZIMBRA_VERSION"
	check_executable

	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		NGINX_BIN="/opt/zimbra/common/sbin/nginx"
	else
		NGINX_BIN="/opt/zimbra/nginx/sbin/nginx"
	fi

	if ! is_zimbra_on_port_80 ; then
		echo "Zimbra's nginx doesn't seem to be listening on port 80"
		echo "This script applies a patch to nginx, so it wouldn't work. Please check your config or pass -j"
		exit 1;
	fi
}

# Check if nginx is listening on port 80 or return an error
function is_zimbra_on_port_80 () {
	if [ "$SKIP_PORT_CHECK" == "yes" ]; then
		echo "Skipping port check"
		return
	fi

	# Better check with lsof, if available
	LSOF_BIN=$(which lsof 2>/dev/null)
	if [ ! -z "$LSOF_BIN" ]; then
		NGINX_CNT=$($LSOF_BIN -i :80 -u zimbra -a | grep -v COMMAND | wc -l)
		if [ $NGINX_CNT -lt 1 ]; then
			false
			return
		fi
	fi

	# Fallback to ss
	SS_BIN=$(which ss 2>/dev/null)
	if [ ! -z "$SS_BIN" ]; then
		NGINX_CNT=$($SS_BIN -lptn sport eq 80 | grep nginx | wc -l)
		if [ $NGINX_CNT -lt 1 ]; then
			false
			return
		fi
	fi

	# If no tool is available just return true
	true
}

# Patch nginx, and check if it's installed
function patch_nginx() {
	if [ "$NO_NGINX" == "yes" ]; then
		return
	fi

	# check if nginx is installed
	if [ ! -x $NGINX_BIN ]; then
		echo "zimbra-proxy package not present"
		exit 1;
	fi

	# Check if patch is already present
	grep -q 'acme-challenge' /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
	if [ $? -eq 0 ]; then
		# No need to patch
		return
	fi

	# Let's make a backup of zimbra's original templates
	BKDATE=$(date +"%Y%m%d_%H%M%S")
	echo "Making a backup of nginx templates in /opt/zimbra/conf/nginx/templates.$BKDATE"
	cp -r /opt/zimbra/conf/nginx/templates /opt/zimbra/conf/nginx/templates.$BKDATE

	# DO patch
	for patchfile in nginx.conf.web.http.default.template nginx.conf.web.https.default.template nginx.conf.web.http.template nginx.conf.web.https.template ; do
		sed -i "s#^}#\n    \# patched by certbot-zimbra.sh\n    location ^~ /.well-known/acme-challenge {\n root $WEBROOT;\n    }\n}#" /opt/zimbra/conf/nginx/templates/$patchfile
	done;

	# reload nginx config
	su - zimbra -c 'zmproxyctl restart'
	if [ $? -ne 0 ]; then
		echo "Something went wrong while restarting zimbra proxy component. Please file a bug with the output above to https://github.com/YetOpen/certbot-zimbra/issues/new"
		exit 1;
	fi
}

# perform the letsencrypt request and prepares the certs
function request_certificate() {
	# If we got no domain from command line try using zimbra hostname
	if [ -z "$DOMAIN" ]; then
		DOMAIN=$(/opt/zimbra/bin/zmhostname)
        # Detect additional hostnames
        find_additional_public_hostnames
    fi
    if [ -z "$DOMAIN" ]; then
        echo "No domain detected! Please run with --hostname or check why zmhostname is not working"
        exit 1;
    fi
	echo "Detected $DOMAIN as Zimbra hostname"
    [ ! -z "$EXTRA_DOMAIN_OUTPUT" ] && echo "These additional domains will be part of the requested certificate: $EXTRA_DOMAIN_OUTPUT"
    if [ "$PROMPT_CONFIRM" == "yes" ]; then
		while true; do
			read -p "Is this correct? " yn
		    	case $yn in
				[Yy]* ) break;;
				[Nn]* ) echo "Please call $(basename $0) --hostname your.host.name"; exit;;
				* ) echo "Please answer yes or no.";;
		    	esac
		done
	fi

	# Set variable for use in prepare_certificate
	CERTPATH="/etc/letsencrypt/live/$DOMAIN"
	if [ "$RENEW_ONLY" == "yes" ]; then
		return
	fi

	# <8.7 didn't have nginx webroot
	if [ ! -d "$WEBROOT" ]; then
		mkdir -p $WEBROOT
		chown -R zimbra:zimbra $WEBROOT
	fi

	# Request our cert
    # If Zimbra is in https only we can use port 80 for ourselves, otherwise go through nginx
	$LEB_BIN certonly $AGREE_TOS --expand -a webroot -w $WEBROOT -d $DOMAIN $EXTRA_DOMAIN
	if [ $? -ne 0 ] ; then
		echo "letsencrypt returned an error";
		exit 1;
	fi
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
function find_additional_public_hostnames() {
    # Useless during renew
    [ "$RENEW_ONLY" == "yes" ] && return;
    # If we already have them set leave alone
    [ ! -z "$EXTRA_DOMAIN" ] && return;
    # If it has been requested NOT to perform the search
    [ "$DETECT_PUBLIC_HOSTNAME" == "no" ] && return;
    for i in $(/opt/zimbra/bin/zmprov gad); do
        ADDITIONAL_DOMAIN=$(/opt/zimbra/bin/zmprov gd $i zimbraPublicServiceHostname | grep zimbraPublicServiceHostname | cut -f 2 -d ' ')
        [ -z "$ADDITIONAL_DOMAIN" ] && continue
        # Skip our primary domain
        [ "$ADDITIONAL_DOMAIN" == "$DOMAIN" ] && continue;
        EXTRA_DOMAIN="${EXTRA_DOMAIN} -d $ADDITIONAL_DOMAIN"
        # to be used at prompt
        EXTRA_DOMAIN_OUTPUT="${EXTRA_DOMAIN_OUTPUT} $ADDITIONAL_DOMAIN"
    done
}

# copies stuff ready for zimbra deployment and test them
function prepare_certificate () {
	if [ -z "$CERTPATH" ] ; then
		echo "Empty CERTPATH"
		exit 1;
	fi
	# Make zimbra accessible files
	mkdir /opt/zimbra/ssl/letsencrypt 2>/dev/null
	cp $CERTPATH/* /opt/zimbra/ssl/letsencrypt/
	chown -R zimbra:zimbra /opt/zimbra/ssl/letsencrypt/

	# Now we should have the chain. Let's create the "patched" chain suitable for Zimbra
	cat $CERTPATH/chain.pem > /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	# The cert below comes from https://www.identrust.com/certificates/trustid/root-download-x3.html. It should be better to let the user fetch it?
	cat << EOF >> /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
-----BEGIN CERTIFICATE-----
MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow
PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD
Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O
rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq
OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b
xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw
7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD
aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG
SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69
ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr
AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz
R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5
JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo
Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ
-----END CERTIFICATE-----
EOF

	# Test cert. 8.6 and below must use root
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'
	else
		/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	fi
	if [ $? -eq 1 ]; then
		echo "Unable to verify cert!"
		exit 1;
	fi

}

# deploys certificate and restarts zimbra. ASSUMES prepare_certificate has been called already
function deploy_certificate() {
	# Backup old stuff
	cp -a /opt/zimbra/ssl/zimbra /opt/zimbra/ssl/zimbra.$(date "+%Y.%m.%d-%H.%M")

	cp /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c "/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem -deploy ${SERVICES}"
	else
		/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	fi

	# Set ownership of nginx config template
        chown zimbra:zimbra /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default

	# Finally apply cert!
	[[ "${RESTART_ZIMBRA}" == "yes" ]] && su - zimbra -c 'zmcontrol restart'
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
USAGE: $(basename $0) < -n | -r | -p > [-d my.host.name] [-e extra.domain.tld] [-x] [-w /var/www]
  Options:
	 -n | --new: performs a request for a new certificate
	 -r | --renew: deploys certificate, assuming it has just been renewed
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade

	Optional arguments:
	 -d | --hostname: hostname being requested. If not passed uses \`zmhostname\`
	 -e | --extra-domain: additional domains being requested. Can be used multiple times
	 -x | --no-nginx: doesn't check and patch zimbra's nginx. Assumes some other webserver is listening on port 80
	 -w | --webroot: if there's another webserver on port 80 specify its webroot
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -c | --prompt-confirmation: ask for confirmation before proceding with cert request showing detected hostname
	 -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
	 -z | --no-zimbra-restart: do not restart zimbra after a certificate deployment
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraServicePublicHostname. Enabled when -e is passed
	 -j | --no-port-check: disable port 80 check

Author: Lorenzo Milesi <maxxer@yetopen.it>
Feedback, bugs and PR are welcome on GitHub: https://github.com/yetopen/certbot-zimbra.

Disclaimer:
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
EOF
}
## end functions

# main flow
# parameters parsing http://stackoverflow.com/a/14203146/738852
while [[ $# -gt 0 ]]; do
	key="$1"

	case $key in
	    -d|--hostname)
	    DOMAIN="$2"
        DETECT_PUBLIC_HOSTNAMES="no"
	    shift # past argument
	    ;;
        -e|--extra-domain)
        EXTRA_DOMAIN="${EXTRA_DOMAIN} -d $2"
        EXTRA_DOMAIN_OUTPUT="${EXTRA_DOMAIN_OUTPUT} $2"
        DETECT_PUBLIC_HOSTNAMES="no"
        shift # past argument
        ;;
	    -u|--no-public-hostname-detection)
        DETECT_PUBLIC_HOSTNAMES="no"
	    ;;
	    -x|--no-nginx)
	    NO_NGINX="yes"
	    ;;
	    -p|--patch-only)
	    PATCH_ONLY="yes"
	    ;;
		-n|--new)
	  	NEW_CERT="yes"
	    ;;
		-r|--renew)
	  	RENEW_ONLY="yes"
	    ;;
		-w|--webroot)
	  	WEBROOT="$2"
		shift
	    ;;
		-a|--agree-tos)
	  	AGREE_TOS="--text --agree-tos --non-interactive"
        ;;
		-s|--services)
	  	SERVICES="$2"
		shift
	    ;;
		-z|--no-zimbra-restart)
	  	RESTART_ZIMBRA="no"
	    ;;
		-c|--prompt-confirmation)
	  	PROMPT_CONFIRM="yes"
	    ;;
		-j|--no-port-check)
	  	SKIP_PORT_CHECK="yes"
	    ;;
	    *)
	  	# unknown option
			usage
			exit 0
	    ;;
	esac
	shift # past argument or value
done

if [ "$NEW_CERT" == "no" ] && [ "$RENEW_ONLY" == "no" ] && [ "$PATCH_ONLY" == "no" ]; then
	usage
	exit 0
fi

if [ "$PATCH_ONLY" == "yes" ] && [ "$NO_NGINX" == "yes" ]; then
	echo "Incompatible nginx parameters"
	exit 0
fi

# If passed by --renew-hook, contains the path of the renewed cert which may differ from the default /etc/letsencrypt/live/$DOMAIN
#CERTPATH=$RENEWED_LINEAGE
#if [ -z "$CERTPATH" ]; then
CERTPATH="/etc/letsencrypt/live/$DOMAIN"
#fi

# actions
bootstrap
check_user
patch_nginx
if [ "$PATCH_ONLY" == "yes" ]; then
    exit 0;
fi
request_certificate
prepare_certificate
deploy_certificate

exit 0;
