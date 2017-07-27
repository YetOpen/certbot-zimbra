#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# GPLv3 license

NO_NGINX="no"
RENEW_ONLY="no"
NEW_CERT="no"
WEBROOT="/opt/zimbra/data/nginx/html"

## functions
# check executable certbot-auto / certbot / letsencrypt
check_executable () {
	LEB_BIN=$(which certbot-auto)
	if [ -z "$LEB_BIN" ]; then 
		LEB_BIN=$(which certbot)
	fi
	if [ -z "$LEB_BIN" ]; then 
		LEB_BIN=$(which letsencrypt)
	fi

	# No way
	if [ -z "$LEB_BIN" ]; then
		echo "No letsencrypt/certbot binary found in $PATH";
		exit 1;
	fi
}

# version compare from  http://stackoverflow.com/a/24067243/738852
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

function bootstrap() {
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

	# zimbraReverseProxyMailMode
	ZMODE=$(/opt/zimbra/bin/zmprov gs $(/opt/zimbra/bin/zmhostname) zimbraReverseProxyMailMode | grep Mode | cut -f 2 -d " ")

	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		NGINX_BIN="/opt/zimbra/common/sbin/nginx"
	else
		NGINX_BIN="/opt/zimbra/nginx/sbin/nginx"
	fi
}

# Patch nginx, and check if it's installed
function patch_nginx() {
	if [ "$NO_NGINX" == "yes" ]; then
		return
	fi
	# In https mode patching nginx is not required
	if [ "$ZMODE" == "https" ]; then
		echo "Detected zimbraReverseProxyMailMode in https only, requesting certificate in standalone mode. Make sure your firewall has port 80 open"
		return
	fi

	# check if nginx is installed
	if [ ! -x $NGINX_BIN ]; then
		echo "zimbra-proxy package not present"
		exit 1;
	fi

    # check if patch binary is present
	PATCH_BIN=$(which patch)
	if [ -z "$PATCH_BIN" ]; then
		echo "No patch binary found. Please install OS 'patch' package";
		exit 1;
	fi

	PATCHFILE=$(dirname $0)"/patches/zimbra_${DETECTED_ZIMBRA_VERSION}_letsencrypt_nginx.patch"

	if [ ! -f "$PATCHFILE" ]; then
		echo "Your Zimbra version is not currently supported (or patch subdir was not copied)"
		exit 1;
	fi

	# Test if we need to patch nginx.conf.web.http.default
	grep -Fxq '\\.well-known' /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
	if [ $? -eq 1 ]; then
		echo "Patching /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default";
		$PATCH_BIN /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default < $PATCHFILE
		if [ $? -ne 0 ]; then
			echo "Patching failed! File a bug with the output above"
			exit 1;
		fi
		# reload nginx config
		$NGINX_BIN -c /opt/zimbra/conf/nginx.conf -s reload
	fi
}

# perform the letsencrypt request and prepares the certs
function request_certificate() {
	# If we got no domain from command line try using zimbra hostname
	# FIXME the prompt should be avoided in cron!
	if [ -z "$DOMAIN" ]; then
		ZMHOSTNAME=$(/opt/zimbra/bin/zmhostname)
		while true; do
			read -p "Detected $ZMHOSTNAME as Zimbra domain: use this hostname for certificate request? " yn
		    	case $yn in
				[Yy]* ) DOMAIN=$ZMHOSTNAME; break;;
				[Nn]* ) echo "Please call $(basename $0) --hostname your.host.name"; exit;;
				* ) echo "Please answer yes or no.";;
		    	esac
		done
	fi

	if [ "$RENEW_ONLY" == "yes" ]; then
		return
	fi

	# <8.7 didn't have nginx webroot
	if [ ! -d "$WEBROOT" ]; then
		mkdir -p $WEBROOT
		chown -R zimbra:zimbra $WEBROOT
	fi

	# Request our cert
	case $ZMODE in
		https)
			$LEB_BIN certonly -a standalone --preferred-challenges http -d $DOMAIN
			;;
		*)
			$LEB_BIN certonly -a webroot -w $WEBROOT -d $DOMAIN
			;;
	esac
	if [ $? -ne 0 ] ; then
		echo "letsencrypt returned an error";
		exit 1;
	fi
}

# copies stuff ready for zimbra deployment and test them
function prepare_certificate () {
	# Make zimbra accessible files
	mkdir /opt/zimbra/ssl/letsencrypt 2>/dev/null
	cp /etc/letsencrypt/live/$DOMAIN/* /opt/zimbra/ssl/letsencrypt/
	chown -R zimbra:zimbra /opt/zimbra/ssl/letsencrypt/

	# Now we should have the chain. Let's create the "patched" chain suitable for Zimbra
	cat /etc/letsencrypt/live/$DOMAIN/chain.pem > /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
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
	cp -a /opt/zimbra/ssl/zimbra /opt/zimbra/ssl/zimbra.$(date "+%Y%.m%.d-%H.%M")

	cp /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'
	else
		/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem
	fi
	
	# Set ownership of nginx config template
        chown zimbra:zimbra /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
	
	# Finally apply cert!
	su - zimbra -c 'zmcontrol restart'
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
USAGE: $(basename $0) < -n | -r > [-d my.host.name] [-x] [-w /var/www]
  Options:
	 -n | --new: performs a request for a new certificate
	 -r | --renew: deploys certificate, assuming it has just been renewed

	Optional arguments:"
	 -d | --hostname: hostname being requested. If not passed uses \`zmhostname\`
	 -x | --no-nginx: doesn't check and patch zimbra's nginx. Assumes some other webserver is listening on port 80
	 -w | --webroot: if there's another webserver on port 80 specify its webroot

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
	    shift # past argument
	    ;;
	    -x|--no-nginx)
	    NO_NGINX="yes"
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
	    *)
	  	# unknown option
			usage
			exit 0
	    ;;
	esac
	shift # past argument or value
done

if [ "$NEW_CERT" == "no" ] && [ "$RENEW_ONLY" == "no" ]; then
	usage
	exit 0
fi

# actions
bootstrap
check_user
patch_nginx
request_certificate
prepare_certificate
deploy_certificate
