#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# GPLv3 license

NO_NGINX="no"
RENEW_ONLY="no"
NEW_CERT="no"
WEBROOT="/opt/zimbra/data/nginx/html"

## patches
read -r -d '' PATCH_Z87 <<'EOF'
diff -Naur templates_orig/nginx.conf.web.http.default.template templates/nginx.conf.web.http.default.template
--- templates_orig/nginx.conf.web.http.default.template	2017-10-01 20:30:23.022776735 +0200
+++ templates/nginx.conf.web.http.default.template	2017-10-01 20:39:04.619034013 +0200
@@ -65,6 +65,9 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
diff -Naur templates_orig/nginx.conf.web.https.default.template templates/nginx.conf.web.https.default.template
--- templates_orig/nginx.conf.web.https.default.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.https.default.template	2017-10-01 20:38:47.583025551 +0200
@@ -94,6 +94,9 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
diff -Naur templates_orig/nginx.conf.web.https.template templates/nginx.conf.web.https.template
--- templates_orig/nginx.conf.web.https.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.https.template	2017-10-01 20:35:34.062929705 +0200
@@ -95,6 +95,9 @@
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }

+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }
+
     location /
     {
         # Begin stray redirect hack
diff -Naur templates_orig/nginx.conf.web.http.template templates/nginx.conf.web.http.template
--- templates_orig/nginx.conf.web.http.template	2017-10-01 20:30:23.034776741 +0200
+++ templates/nginx.conf.web.http.template	2017-10-01 20:33:26.550866829 +0200
@@ -67,6 +67,9 @@
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }

+    # patched by certbot-zimbra.sh
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }
+
     location /
     {
         # Begin stray redirect hack
EOF

read -r -d '' PATCH_Z86 <<'EOF'
+++ templates/nginx.conf.web.http.default.template	2017-09-10 09:57:59.420380580 +0200
@@ -39,6 +39,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.https.default.template templates/nginx.conf.web.https.default.template
--- templates_ORIG/nginx.conf.web.https.default.template	2015-12-16 09:51:45.196584572 +0100
+++ templates/nginx.conf.web.https.default.template	2017-09-10 09:58:23.839441900 +0200
@@ -55,6 +55,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.https.template templates/nginx.conf.web.https.template
--- templates_ORIG/nginx.conf.web.https.template	2015-12-02 15:36:35.322922195 +0100
+++ templates/nginx.conf.web.https.template	2017-09-10 09:59:17.917577714 +0200
@@ -56,6 +56,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ https://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     ${web.login.upstream.disable} location = /
     ${web.login.upstream.disable} {
diff -Naur templates_ORIG/nginx.conf.web.http.template templates/nginx.conf.web.http.template
--- templates_ORIG/nginx.conf.web.http.template	2014-12-15 22:18:51.000000000 +0100
+++ templates/nginx.conf.web.http.template	2017-09-10 10:00:10.216709079 +0200
@@ -66,6 +66,8 @@
     ${web.login.upstream.disable}     # Fudge inter-mailbox redirects (kludge)
     ${web.login.upstream.disable}     proxy_redirect http://$relhost/ http://$http_host/;
     ${web.login.upstream.disable} }
+
+    location ^~ /.well-known/acme-challenge { root /opt/zimbra/data/nginx/html; }

     location /
     {
EOF

## end patches

## functions
# check executable certbot-auto / certbot / letsencrypt
function check_executable() {
	LEB_BIN=$(which certbot-auto certbot letsencrypt | head -n 1)
	# No way
	if [ -z "$LEB_BIN" ]; then
		echo "No letsencrypt/certbot binary found in $PATH";
		exit 1;
	fi
}

# version compare from  http://stackoverflow.com/a/24067243/738852
function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

function bootstrap() {
    echo "Certbot-Zimbra v0.2 - https://github.com/YetOpen/certbot-zimbra"

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

	# check if nginx is installed
	if [ ! -x $NGINX_BIN ]; then
		echo "zimbra-proxy package not present"
		exit 1;
	fi

	grep -Fxq 'acme-challenge' /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
	if [ $? -eq 0 ]; then
		# No need to patch
		return
	fi

    # check if patch binary is present
	PATCH_BIN=$(which patch)
	if [ -z "$PATCH_BIN" ]; then
		echo "No patch binary found. Please install OS 'patch' package";
		exit 1;
	fi

	# Let's make a backup of zimbra's original templates
	BKDATE=$(date +"%Y%m%d_%H%M%S")
	echo "Making a backup of nginx templates in /opt/zimbra/conf/nginx/templates.$BKDATE"
	cp -r /opt/zimbra/conf/nginx/templates /opt/zimbra/conf/nginx/templates.$BKDATE

	# Simulate patching
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		echo "$PATCH_Z87" | $PATCH_BIN --dry-run -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.6; then
		echo "$PATCH_Z86" | $PATCH_BIN --dry-run -l -p1 -d /opt/zimbra/conf/nginx/templates/
	else
		echo "Your Zimbra version is not currently supported"
		exit 1;
	fi
	if [ $? -ne 0 ]; then
		echo "Patching test failed! Please file a bug with the output above to https://github.com/YetOpen/certbot-zimbra/issues/new"
		exit 1;
	fi

	# DO patch
	if version_gt $DETECTED_ZIMBRA_VERSION 8.7; then
		echo "$PATCH_Z87" | $PATCH_BIN -l -p1 -d /opt/zimbra/conf/nginx/templates/
	elif version_gt $DETECTED_ZIMBRA_VERSION 8.6; then
		echo "$PATCH_Z86" | $PATCH_BIN -l -p1 -d /opt/zimbra/conf/nginx/templates/
	fi
	if [ $? -ne 0 ]; then
		echo "Patching zimbra's nginx failed! File a bug with the output above to https://github.com/YetOpen/certbot-zimbra/issues/new"
		# Restore the backups
		cp /opt/zimbra/conf/nginx/templates.$BKDATE/* /opt/zimbra/conf/nginx/templates/
		echo "The original templates has been restored from /opt/zimbra/conf/nginx/templates.$BKDATE"
		exit 1;
	fi

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
    # If Zimbra is in https only we can use port 80 for ourselves, otherwise go through nginx
	$LEB_BIN certonly --text --agree-tos --non-interactive -a webroot -w $WEBROOT -d $DOMAIN
	if [ $? -ne 0 ] ; then
		echo "letsencrypt returned an error";
		exit 1;
	fi
}

# copies stuff ready for zimbra deployment and test them
function prepare_certificate () {
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

	Optional arguments:
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

# If passed by --renew-hook, contains the path of the renewed cert which may differ from the default /etc/letsencrypt/live/$DOMAIN
CERTPATH=$RENEWED_LINEAGE
if [ -z "$CERTPATH" ]; then
    CERTPATH="/etc/letsencrypt/live/${DOMAIN%%,*}"
fi

# actions
bootstrap
check_user
patch_nginx
request_certificate
prepare_certificate
deploy_certificate

exit 0;
