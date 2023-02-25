#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# author: Jernej Jakob <jernej.jakob@gmail.com>
# GPLv3 license

readonly progname="certbot-zimbra"
readonly version="0.7.13 (unreleased)"
readonly github_url="https://github.com/YetOpen/certbot-zimbra"
# paths
readonly zmpath="/opt/zimbra"
readonly zmwebroot="$zmpath/data/nginx/html"
readonly le_live_path="/etc/letsencrypt/live" # the domain will be appended to this path
readonly temppath="/run/$progname"
# other options
readonly zmprov_opts="-l" # use ldap (faster)
# used to extract the CA for the letsencrypt certs
readonly ca_certificates_file="/etc/ssl/certs/ca-certificates.crt"
readonly pki_ca_bundle_file="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
# Do NOT modify anything after this line.
webroot=""
certpath=""
le_bin=""
le_params=()
le_agree_tos=false
le_noniact=false
agree_tos=false
extra_domains=()
no_nginx=false
deploy_only=false
new_cert=false
services=all
patch_only=false
restart_zimbra=true
prompt_confirm=false
detect_public_hostnames=true
skip_port_check=false
port=""
quiet=false
readonly min_certbot_version="0.19.0"
locked=false
platform=""
detected_zimbra_version=""

# set up a trap on exit
exitfunc(){
	e="$?"
	if [ "$e" -ne 0 ] && ! "$quiet"; then
		echo
		echo "An error seems to have occurred. Please read the output above for clues and try to rectify the situation."
		echo "If you believe this is an error with the script, please file an issue at $github_url."
	fi

	# close fd used for locking
	exec 200>&-
	if "$locked"; then
		rm "$temppath/$progname.lck"
	fi

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
	! mkdir --mode=750 -p "$temppath" && echo "Error: Can't create temporary directory $temppath" && exit 1
	chown root:zimbra "$temppath"
}

get_lock(){
	exec 200> "$temppath/$progname.lck"
	! flock -n 200 && echo "Error: can't get exclusive lock. Another instance of this script may be running.
If you are sure there is no other instance of this script running (check with \"ps afx\") you can remove $temppath/$progname.lck and try again." && exit 1
	locked=true
	readonly locked
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
	[ -r $ca_certificates_file ] && return
	# RHEL/CentOS provided by pki-base
	[ -r $pki_ca_bundle_file ] && return

	echo "Error: Installed CA certificates not found or files not readable. Please check if you have installed:"
	echo "Debian/Ubuntu: ca-certificates (if you do, you might have to run \"update-ca-certificates\")"
	echo "RHEL/CentOS: pki-base (if you do, you might have to run \"update-ca-trust\")"
	exit 1
}

check_depends() {
	# check for dependencies
	! $quiet && echo "Checking for dependencies..."

	# do not check for lsof or ss here as we'll do that later
	for name in su openssl grep head cut sed chmod chown cat cp gawk $zmpath/bin/zmhostname $zmpath/bin/zmcertmgr $zmpath/bin/zmcontrol $zmpath/bin/zmprov $zmpath/libexec/get_plat_tag.sh; do
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
	platform="$($zmpath/libexec/get_plat_tag.sh)"
	readonly platform

	detected_zimbra_version="$(su - zimbra -c "$zmpath/bin/zmcontrol -v" | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)"
	readonly detected_zimbra_version
	[ -z "$detected_zimbra_version" ] && echo "Error: Unable to detect zimbra version" && exit 1
	! "$quiet" && echo "Detected Zimbra $detected_zimbra_version on $platform"

	get_domain

	return 0
}

check_zimbra_proxy() {
	# must be run after get_domain
	[ -z "$domain" ] && echo "Unexpected error (check_zimbra_proxy domain not set)" && exit 1

	! "$quiet" && echo "Checking zimbra-proxy is running and enabled"

	# TODO: check if path to zmproxyctl is different on <8.7
	! su - zimbra -c "$zmpath/bin/zmproxyctl status > /dev/null" && echo "Error: zimbra-proxy is not running" && exit 1
	! su - zimbra -c "$zmpath/bin/zmprov $zmprov_opts gs $domain zimbraReverseProxyHttpEnabled | grep -q TRUE" \
			&& echo "Error: http reverse proxy not enabled (zimbraReverseProxyHttpEnabled: FALSE)" && exit 1

	if [ -z "$port" ]; then
		! "$quiet" && echo "Detecting port from zimbraMailProxyPort"
		port="$(su - zimbra -c "$zmpath/bin/zmprov $zmprov_opts gs $domain zimbraMailProxyPort | sed -n 's/zimbraMailProxyPort: //p'")"
		[ -z "$port" ] && echo "Error: zimbraMailProxyPort not found" && exit 1
	else
		echo "Skipping port detection from zimbraMailProxyPort due to --port override"
	fi

	if [ "$port" != "80" ] && ! "$quiet"; then
		echo "WARNING: non-standard zimbraMailProxyPort $port. 
This needs to be 80 from the internet for Let's Encrypt (certbot) to work. 
If you have NAT set up to do the translation this is likely fine. 
If not, your Zimbra proxy is misconfigured and certbot will fail."
		if "$prompt_confirm"; then
			prompt "Proceed?"
			(( $? == 1 )) && echo "Cannot continue. Exiting." && exit 0
		else
			echo "WARNING: Prompt disabled, proceeding anyway."
		fi
	fi
}

# Check if process is listening on port $1 (optionally with name $2 and/or user $3) or return an error
check_port () {
	if "$skip_port_check"; then
		! "$quiet" && echo "Skipping port check"
		return 0
	fi

	[ -z "$1" ] && echo 'Unexpected error: check_port empty $1 (port)' && exit 1

	! "$quiet" && echo "Checking if process is listening on port $1 ${2:+"with name \"$2\" "}${3:+"user \"$3\""}"

	# check with lsof if available, or fall back to ss
	local lsof_bin="$(which lsof 2>/dev/null)"
	local ss_bin="$(which ss 2>/dev/null)"
	local check_bin=""
	local grep_filter=""
	if [ -x "$lsof_bin" ]; then
		check_bin="$lsof_bin -i :$1 -s TCP:LISTEN -a -n"
		grep_filter="$2.*$3"
	elif [ -x "$ss_bin" ]; then
		check_bin="$ss_bin -lptn sport eq :$1"
		# ss doesn't return process user, so don't use it for count
		grep_filter="$2"
	else
		echo 'Error: Neither "lsof" nor "ss" were found in PATH. Unable to continue, exiting.'
		exit 1
	fi

	# return false if count of matched processes is 0
	# optionally $2 and $3 are process name and process user
	(( "$($check_bin | grep -c "$grep_filter")" == 0 )) && return 1

	unset lsof_bin ss_bin check_bin grep_filter
	return 0
}


# Patch zimbra proxy nginx and restart it if successful
# zimbra-proxy must be running (checked with check_zimbra_proxy) or zmproxyctl restart will fail
# returns true if patch was applied or was already present, exits script if encountered an error
patch_nginx() {
	[ ! -d "$zmpath/conf/nginx/includes" ] && echo "Error: $zmpath/conf/nginx/includes not found, exiting" && exit 1

	# Don't patch if patch is already applied
	if grep -r -q 'acme-challenge' "$zmpath/conf/nginx/templates"; then
		! "$quiet" && echo "Nginx templates already patched."
	else
		[ -z $webroot ] && echo "Unexpected error: patch_nginx WEBROOT not set. Exiting." && exit 1

		# Let's make a backup of zimbra's original templates
		set -e
		local bkdate="$(date +'%Y%m%d_%H%M%S')"
		! "$quiet" && echo "Making a backup of nginx templates in $zmpath/conf/nginx/templates.$bkdate"
		cp -a "$zmpath/conf/nginx/templates" "$zmpath/conf/nginx/templates.$bkdate"
		set +e

		# do patch
		! "$quiet" && echo -n "Patching nginx templates... "
		e=0
		for file in http.default https.default http https ; do
			# Find the } that matches the first { after the server directive and add our location block before it,
			# ignoring all curly braces and anything else between them. If there are multiple server blocks
			# it adds the directives to all of them. It breaks in special cases of one-liner server blocks (rare)
			# and unbalanced curly brace count (missing braces aka broken formatting).
			# Exits 0 (success) if at least 1 substitution was made, 1 (failure) if 0 substitutions were made.
			gawk \
"BEGIN {e = 1}
/^#/ {print; next}
/^server[[:space:]{]*.*$/ {found++}
/{/ && found {
  b++
  if (first == 0) first = NR
}
/}/ && found {b--}
{ if (found && b == 0 && first != 0) {
    print gensub(/}[^}]*/, \"\n    # patched by certbot-zimbra.sh\n    location ^~ /.well-known/acme-challenge {\n        root $webroot;\n    }\n&\", 1)
    found = 0
    first = 0
    e = 0
  }
  else print
}
END {exit e}" "$zmpath/conf/nginx/templates.$bkdate/nginx.conf.web.$file.template" > "$zmpath/conf/nginx/templates/nginx.conf.web.$file.template"
			e="$?"
			[ "$e" -ne 0 ] && break
		done

		if [ "$e" -ne 0 ]; then
			! "$quiet" && echo -ne "Error!\nRestoring old templates... "
			cp -a $zmpath/conf/nginx/templates.$bkdate/* "$zmpath/conf/nginx/templates/"
			if [ "$?" -ne 0 ]; then
				! "$quiet" && echo "Error!"
			else
				! "$quiet" && echo "Success."
			fi
			! "$quiet" && echo "Exiting." && exit 1
		else
			! "$quiet" && echo "Success."
		fi

		unset bkdate
	fi

	# Don't restart if includes show nginx has already been restarted
	if grep -r -q 'acme-challenge' "$zmpath/conf/nginx/includes"; then
		! "$quiet" && echo "Nginx includes already patched, skipping zmproxy restart."
	else
		if "$prompt_confirm"; then
			prompt "Restart zmproxy?"
			(( $? == 1 )) && echo "Cannot continue. Exiting." && exit 0
		fi

		! "$quiet" && echo "Running zmproxyctl restart."
		# reload nginx config
		su - zimbra -c 'zmproxyctl restart' 200>&-; e="$?"
		if [ "$e" -ne 0 ]; then
			! "$quiet" && echo "Error restarting zmproxy (\"zmproxyctl restart\" exit status $e). Exiting."
			exit 1
		else
			! "$quiet" && echo "Success."
		fi
	fi

	return 0
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
find_additional_public_hostnames() {
	# If already set, leave them alone
	[ -n "$extra_domains" ] && return

	# If it has been requested NOT to perform the search
	if ! "$detect_public_hostnames"; then
		! "$quiet" && echo "Skipping additional public service hostname detection"
		return
	fi

	! "$quiet" && echo -n "Detecting additional public service hostnames... "
	
	extra_domains=($(su - zimbra -c "zmprov $zmprov_opts gad" \
			| gawk '{printf "gd %s zimbraPublicServiceHostname\ngd %s zimbraVirtualHostname\n", $0, $0}' \
			| su - zimbra -c "zmprov $zmprov_opts -" \
			| sed "/prov>/d;/# name/d;/$domain/d;/^$/d;s/\(\(zimbraPublicServiceHostname\)\|\(zimbraVirtualHostname\)\): \(.*\)/\4/g" \
			| sort -u | tr '\n' ' ' \
			))
	! "$quiet" && echo "Found ${#extra_domains[@]} through auto-detection (zimbraPublicServiceHostname, zimbraVirtualHostname)"

	return 0
}

get_domain () {
	# If we got no domain from command line try using zimbra hostname
	if [ -z "$domain" ]; then
		! "$quiet" && echo "Using zmhostname to detect domain."
		domain="$($zmpath/bin/zmhostname)"
	fi

	[ -z "$domain" ] && echo "Error: No domain found! Please run with -d/--hostname or check why zmhostname is not working" && exit 1

	! "$quiet" && echo "Using domain $domain (as certificate DN)"

	if "$prompt_confirm"; then
		prompt "Is this correct?"
		(( $? == 1 )) && echo "Error: Please manually specify your hostname with \"--hostname your.host.name\"" && exit 0
	fi

	# Find additional domains
	"$new_cert" && find_additional_public_hostnames

	if [ -n "$extra_domains" ] && ! "$quiet"; then
		echo "Got ${#extra_domains[@]} domains to use as certificate SANs: ${extra_domains[@]}"
		if "$prompt_confirm"; then
			prompt "Include these in the certificate?"
			(( $? == 1 )) && unset extra_domains
		fi
	fi

	return 0
}

set_certpath() {
	# must be run after get_domain
	[ -z "$domain" ] && echo "Unexpected error (set_certpath domain not set)" && exit 1

	# when run as --deploy-hook, check if any of RENEWED_DOMAINS match zimbra's domain.
	# RENEWED_DOMAINS and RENEWED_LINEAGE are passed by certbot as env vars to --deploy-hook
	if [ -n "$RENEWED_DOMAINS" ]; then
		# we were run as --deploy-hook
		for renewed_domain in $RENEWED_DOMAINS; do
			[ "$renewed_domain" == "$domain" ] && certpath="$RENEWED_LINEAGE"
		done
		# exit gracefully if no matching domains were found. We must be running for some other cert, not ours.
		if [ -z "$certpath" ]; then
			! "$quiet" && echo "Detected --deploy-hook but no matching domain found. Nothing to do."
			exit 0
		else
			! "$quiet" && echo "Detected --deploy-hook and matching domain found"
		fi
	else
		# we were run standalone
		certpath="$le_live_path/$domain"
	fi
}

check_webroot () {
	[ -z "$webroot" ] && echo "Unexpected error: check_webroot WEBROOT not set. Exiting." && exit 1
	
	# <8.7 didn't have nginx webroot
	if [ ! -d "$webroot" ]; then
		if "$prompt_confirm"; then
			prompt "Webroot $webroot doesn't exist, create it?"
			(( $? == 1 )) && echo "Cannot proceed, exiting." && exit 0
		fi
		echo "Creating webroot $webroot"
		set -e
		mkdir -p "$webroot"
		set +e
	fi
}

find_certbot () {
	# check for executable certbot-auto / certbot / letsencrypt
	# TODO: remove dead certbot-auto
	le_bin="$(which certbot letsencrypt certbot-auto 2>/dev/null | head -n 1)"
	[ -z "$le_bin" ] && echo "Error: No letsencrypt/certbot binary found in $PATH" && exit 1

	! "$quiet" && echo "Detecting certbot version..."

	# get certbot version, we need to use some trickery here in case certbot is bootstrapping (1st run) and expects user input
	# if run with --prompt-confirm, show the output of certbot on stderr and allow the user to answer yes/no
	# otherwise add --no-bootstrap and exit in case of error
	local certbot_version_params=""
	! "$prompt_confirm" && certbot_version_params="--no-bootstrap "
	"$le_noniact" && certbot_version_params+="--non-interactive "
	certbot_version_params+="--version"

	local detected_certbot_version="$($le_bin ${certbot_version_params} 2>&1 | $( "$prompt_confirm" && echo 'tee /dev/stderr |') grep '^certbot .*$')"
	certbot_version_exit=${PIPESTATUS[0]}
	if [ "$certbot_version_exit" -ne 0 ]; then
		! "$quiet" && echo "Error: \"$le_bin ${certbot_version_params}\" exit status $certbot_version_exit.
Try running $le_bin by itself on the command line and see if it works (it may need to bootstrap itself).
Exiting."
		exit 1
	fi

	unset certbot_version_params

	if [ -z "$detected_certbot_version" ]; then
		! "$quiet" && echo "Error: unable to parse certbot version. Exiting."
		exit 1
	fi

	! "$quiet" && ! "$prompt_confirm" && echo "Detected $detected_certbot_version"

	if ! version_gt "$(echo "$detected_certbot_version" | grep -Po '(\d+).(\d+).(\d+)')" "$min_certbot_version"; then
		! "$quiet" && echo "Error: certbot is too old, please upgrade to certbot >=$min_certbot_version. Exiting."
		exit 1
	fi

	return 0
}

# perform the letsencrypt request
request_cert() {
	check_webroot

	if "$prompt_confirm"; then
		prompt "We will now run certbot to request the certificate. Proceed?"
		(( $? == 1 )) && echo "Exiting." && exit 0
	fi

	#TODO: dry-run

	"$le_noniact" && le_params+=("--non-interactive")
	"$quiet" && le_params+=("--quiet")
	"$le_agree_tos" && le_params+=("--agree-tos")
	le_params+=("--webroot" "-w" "$webroot" "--cert-name" "$domain" "-d" "$domain")
	for d in ${extra_domains[@]}; do
		[ -z "$d" ] && continue
		le_params+=("-d" "$d")
	done

	! "$quiet" && echo "Running $le_bin certonly ${le_params[@]}"
	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null
	# Request our cert
	"$le_bin" certonly "${le_params[@]}"
	e=$?
	"$quiet" && exec > /dev/stdout
	"$quiet" && exec 2> /dev/stderr
	[ "$e" -ne 0 ] && echo "Error: $le_bin exit status $e. Cannot proceed, exiting." && exit 1
	return 0
}

# copies stuff ready for zimbra deployment and test them
prepare_cert() {
	! "$quiet" && echo "Preparing certificates for deployment."

	[ -z "$certpath" ] && echo "Unexpected error (prepare_cert certpath not set). Exiting." && exit 1
	[ -z "$domain" ] && echo "Unexpected error (prepare_cert domain not set). Exiting." && exit 1

	# Make zimbra accessible files
	# save old umask
	oldumask="$(umask -p)"
	# make files u=rwx g=rx o=
	umask 0027

	# exit on error
	set -e

	tmpcerts="$(mktemp -d --tmpdir="$temppath" certs-XXXXXXXX)"

	cp "$certpath"/{privkey.pem,cert.pem} "$tmpcerts/"

	# Create the "patched" chain suitable for Zimbra
	cat "$certpath/chain.pem" > "$tmpcerts/zimbra_chain.pem"

	# get the last cert in chain.pem (topmost in the intermediates chain)
	local chaincerts="$(cat $certpath/chain.pem)"
	local topchaincert="-----BEGIN CERTIFICATE${chaincerts##*BEGIN CERTIFICATE}"
	unset chaincerts

	if [ -r "$ca_certificates_file" ]; then
	        # Debian/Ubuntu
		# use the issuer_hash of the LE chain cert to find the root CA in /etc/ssl/certs
		cat "/etc/ssl/certs/$(echo "${topchaincert}" | openssl x509 -noout -issuer_hash).0" >> "$tmpcerts/zimbra_chain.pem"
	elif [ -r "$pki_ca_bundle_file" ]; then
		# RHEL/CentOS
		# extract CA by CN in tls-ca-bundle.pem
		issuer="$(echo "${topchaincert}" | openssl x509 -noout -issuer | sed -n 's/.*CN\s\?=\s\?//;s/\/.*$//;p')"
		[ -z "$issuer" ] && echo "Error: can't find issuer of topmost certificate in \"$certpath/chain.pem\". Exiting." && exit 1
		# if we can't find the issuer in the bundle file, it may have spaces removed, hopefully we'll find it without spaces
		grep -q "^# $issuer\$" "$pki_ca_bundle_file" || issuer="${issuer//' '}"
		# the following awk script extracts the CA cert from the bundle or exits 1 if not found
		! gawk "BEGIN {e=1}; /^# $issuer$/{e=0} /^# $issuer$/,/END CERTIFICATE/; END {exit e}" "$pki_ca_bundle_file" >> "$tmpcerts/zimbra_chain.pem"\
			&& echo "Error: Can't find \"$issuer\" in \"$pki_ca_bundle_file\". Exiting." && exit 1
	else
		# we shouldn't be here
		echo "Error in prepare_cert: can't find installed CA certificates (check_depends_ca should have caught this). Exiting." && exit 1
	fi

	unset topchaincert issuer
	$oldumask
	unset oldumask

	# set permissions so that zimbra can read the certs
	chown -R root:zimbra "$tmpcerts"
	chmod 550 "$tmpcerts"
	chmod 440 $tmpcerts/*

	! "$quiet" && echo "Testing with zmcertmgr."

	# redirect stdout to /dev/null if quiet
	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null

	# Test cert. 8.6 and below must use root
	if version_gt "$detected_zimbra_version" "8.7"; then
		su - zimbra -c "$zmpath/bin/zmcertmgr verifycrt comm $tmpcerts/privkey.pem $tmpcerts/cert.pem $tmpcerts/zimbra_chain.pem"
	else
		"$zmpath/bin/zmcertmgr" verifycrt comm "$tmpcerts/privkey.pem" "$tmpcerts/cert.pem" "$tmpcerts/zimbra_chain.pem"
	fi

	# undo quiet
	"$quiet" && exec > /dev/stdout
	"$quiet" && exec 2> /dev/stderr

	# undo set -e
	set +e

	return 0
}

# deploys certificate and restarts zimbra. ASSUMES prepare_certificate has been called already
deploy_cert() {
	if "$prompt_confirm"; then
		prompt "Deploy certificates to Zimbra? This may restart some services."
		(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 0
	fi

	# exit on error
	set -e
	! "$quiet" && echo "Deploying certificates."

	# Backup old stuff
	cp -a "$zmpath/ssl/zimbra" "$zmpath/ssl/zimbra.$(date +'%Y%m%d_%H%M%S')"

	# copy privkey
	cp -a "$tmpcerts/privkey.pem" "$zmpath/ssl/zimbra/commercial/commercial.key"

	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null
	# this is it, deploy the cert.
	if version_gt "$detected_zimbra_version" "8.7"; then
		su - zimbra -c "$zmpath/bin/zmcertmgr deploycrt comm $tmpcerts/cert.pem $tmpcerts/zimbra_chain.pem -deploy ${services}"
	else
		"$zmpath/bin/zmcertmgr" deploycrt comm "$tmpcerts/cert.pem" "$tmpcerts/zimbra_chain.pem"
	fi
	"$quiet" && exec > /dev/stdout
	"$quiet" && exec 2> /dev/stderr

	! "$quiet" && echo "Removing temporary files in $tmpcerts"
	# this is kind of sketchy
	[ -n "$tmpcerts" ] && rm -r "$tmpcerts"
	unset tmpcerts

	set +e

	if "$restart_zimbra"; then
		if "$prompt_confirm"; then
			prompt "Restart Zimbra?"
			(( $? == 1 )) && echo "Cannot proceed. Exiting." && exit 0
		fi

		! "$quiet" && echo "Restarting Zimbra."

		"$quiet" && exec > /dev/null
		"$quiet" && exec 2> /dev/null
		# Finally apply cert!
		su - zimbra -c 'zmcontrol restart' 200>&-
		# FIXME And hope that everything started fine! :)
		"$quiet" && exec > /dev/stdout
		"$quiet" && exec 2> /dev/stderr
	fi

	return 0
}

usage () {
	cat <<EOF
USAGE: $(basename $0) < -d | -n | -p > [-aNuzjxcq] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port] [-L "--extra-le-parameters ..."]
  Only one option at a time can be supplied. Options cannot be chained.
  Mandatory options (only one can be specified):
	 -d | --deploy-only: Just deploys certificates. Can be run as --deploy-hook. If run standalone, assumes valid certificates are in $le_live_path. Incompatible with -n/--new, -p/--patch-only.
	 -n | --new: performs a request for a new certificate ("certonly"). Can be used to update the domains in an existing certificate. Incompatible with -d/--deploy-only, -p/--patch-only.
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade. Incompatible with -d/--deploy-only, -n/--new, -x/--no-nginx.

  Options only used with -n/--new:
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -L | --letsencrypt-params "--extra-le-parameter": Additional parameter to pass to certbot/letsencrypt. Must be repeated for each parameter and argument, e.g. -L "--preferred-chain" -L "ISRG Root X1"
	 -N | --noninteractive: Pass --noninteractive to certbot/letsencrypt.
  Domain options:
	 -e | --extra-domain <extra.domain.tld>: additional domains being requested. Can be used multiple times. Implies -u/--no-public-hostname-detection.
	 -H | --hostname <my.host.name>: hostname being requested. If not passed it's automatically detected using "zmhostname".
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraPublicServiceHostname.
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

Authors: Lorenzo Milesi <maxxer@yetopen.com>, Jernej Jakob <jernej.jakob@gmail.com> @jjakob
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
			deploy_only=true
			;;
		-n|--new)
			new_cert=true
			;;
		-p|--patch-only)
			patch_only=true
			;;
		# optional parameters
		# letsencrypt
		-a|--agree-tos)
			agree_tos=true
			;;
		-L|--letsencrypt-params)
			[ -z "$2" ] && echo "missing letsencrypt-params argument" && exit 1
			le_params+=("$2")
			shift
			;;
		-N|--noninteractive)
			le_noniact=true
			;;
		# domain
		-e|--extra-domain)
			[ -z "$2" ] && echo "missing extra domain argument" && exit 1
			extra_domains=("${extra_domains[@]}" "$2")
			detect_public_hostnames=false
			shift
			;;
		-H|--hostname)
			[ -z "$2" ] && echo "missing hostname argument" && exit 1
			domain="$2"
			detect_public_hostnames=false
			shift
			;;
		-u|--no-public-hostname-detection)
			detect_public_hostnames=false
			;;
		# port check
		-j|--no-port-check)
			skip_port_check=true
			;;
		-P|--port)
			[ -z "$2" ] && echo "missing port argument" && exit 1
			port="$2"
			shift
			;;
		# nginx
		-w|--webroot)
			[ -z "$2" ] && echo "missing webroot argument" && exit 1
			webroot="$2"
			shift
			;;
		-x|--no-nginx)
			no_nginx=true
			;;
		# zimbra
		-s|--services)
			[ -z "$2" ] && echo "missing services argument" && exit 1
			services="$2"
			shift
			;;
		-z|--no-zimbra-restart)
			restart_zimbra=false
			;;
		# other
		-c|--prompt-confirm)
			prompt_confirm=true
			;;
		-q|--quiet)
			quiet=true
			le_noniact=true
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

readonly deploy_only new_cert patch_only agree_tos le_noniact detect_public_hostnames skip_port_check no_nginx services restart_zimbra prompt_confirm quiet

# exit if an invalid option combination was passed
"$quiet" && "$prompt_confirm" && echo "Incompatible parameters: -q -c" && exit 1
"$le_noniact" && "$prompt_confirm" && echo "Incompatible parameters: -N -c" && exit 1

"$deploy_only" && ("$new_cert" || "$patch_only") && echo "Incompatible option combination" && exit 1
"$new_cert" && ("$deploy_only" || "$patch_only") && echo "Incompatible option combination" && exit 1
"$patch_only" && ("$deploy_only" || "$new_cert" || "$no_nginx") && echo "Incompatible option combination" && exit 1
! ("$deploy_only" || "$new_cert" || "$patch_only") && echo "Nothing to do. Please specify one of: -d -n -p. Exiting." && exit 1

"$no_nginx" && [ -z "$webroot" -o \( -z "$port" -a ! "$skip_port_check" \) ] && echo "Error: --no-nginx requires --webroot and --port or --no-port-check. Exiting." && exit 1
! "$no_nginx" && [ -n "$webroot" ] && echo "Error: -w/--webroot can't be used in zimbra-proxy mode. Please use -x/--no-nginx (alternate webserver mode). Exiting." && exit 1
"$skip_port_check" && [ -n "$port" ] && echo "Error: -j/--no-port-check can't be used with -P/--port. Exiting." && exit 1

! "$quiet" && echo "$progname v$version - $github_url"

## actions
bootstrap

if ! "$deploy_only"; then
	if "$no_nginx"; then
		! check_port "$port" && echo "Error: port check failed. A web server to use for letsencrypt authentication of the domain $domain must be listening on the port specified with --port." \
				&& exit 1
	else
		webroot="$zmwebroot"
		readonly webroot

		check_zimbra_proxy
		! check_port "$port" nginx zimbra && echo "Error: port check failed. If you have overridden the port with --port, a web server to use for letsencrypt authentication \
				of the domain $domain must be listening on it." && exit 1
		patch_nginx
	fi

	"$patch_only" && exit 0

	find_certbot
	request_cert
fi

set_certpath
prepare_cert
deploy_cert

exit 0
