#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# GPLv3 license

# Optional first argument: hostname (otherwise detected by zmhostname)
DOMAIN="$1"

LEB_BIN=$(which letsencrypt)
if [ -z "$LEB_BIN" ]; then
	# try with certbot
	LEB_BIN=$(which certbot)
fi
# No way
if [ -z "$LEB_BIN" ]; then
	echo "No letsencrypt/certbot binary found in $PATH";
	exit 1;
fi

DETECTED_ZIMBRA_VERSION=$(su - zimbra -c /opt/zimbra/bin/zmcontrol | grep -Po '\d.\d.\d')
PATCHFILE="patches/zimbra_${DETECTED_ZIMBRA_VERSION}_letsencrypt_nginx.patch"

# If we got no domain from command line try using zimbra hostname
if [ -z "$DOMAIN" ]; then
	ZMHOSTNAME=$(/opt/zimbra/bin/zmhostname)
	while true; do
		read -p "Detected $ZMHOSTNAME as Zimbra domain: use this hostname for certificate request?" yn
	    	case $yn in
			[Yy]* ) DOMAIN=$ZMHOSTNAME; break;;
			[Nn]* ) echo "Please call $(basename $0) your.host.name"; exit;;
			* ) echo "Please answer yes or no.";;
	    	esac
	done
fi

if [ ! -f "$PATCHFILE" ]; then
	echo "Your Zimbra version $DETECTED_ZIMBRA_VERSION is not currently supported"
	exit 1;
fi

# Test if we need to patch nginx.conf.web.http.default
grep -Fxq '/\.well-known' /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default
if [ $? -eq 0 ]; then
	echo "Patching /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default";
	patch /opt/zimbra/conf/nginx/includes/nginx.conf.web.http.default < $PATCHFILE
	# reload nginx config
	/opt/zimbra/common/sbin/nginx -c /opt/zimbra/conf/nginx.conf -s reload
fi

# Request our cert
$LEB_BIN certonly -a webroot -w /opt/zimbra/data/nginx/html -d $DOMAIN
if [ $? -ne 0 ] ; then
	echo "letsencrypt returned an error";
	exit 1;
fi

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

# Test cert
# FIXME use root for 8.6 https://wiki.zimbra.com/wiki/Installing_a_LetsEncrypt_SSL_Certificate#Zimbra_Collaboration_8.6_and_previous
su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'
if [ $? -eq 1 ]; then
	echo "Unable to verify cert!"
	exit 1;
fi

# Backup
cp -a /opt/zimbra/ssl/zimbra /opt/zimbra/ssl/zimbra.$(date "+%Y%m%d")

cp /opt/zimbra/ssl/letsencrypt/privkey.pem /opt/zimbra/ssl/zimbra/commercial/commercial.key
# FIXME use root for 8.6
su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm /opt/zimbra/ssl/letsencrypt/cert.pem /opt/zimbra/ssl/letsencrypt/zimbra_chain.pem'

# Finally apply cert!
su - zimbra -c 'zmcontrol restart'
# FIXME And hope that everything started fine! :)
