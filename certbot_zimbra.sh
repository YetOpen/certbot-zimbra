#!/bin/bash

# author: Lorenzo Milesi <maxxer@yetopen.it>
# author: Jernej Jakob <jernej.jakob@gmail.com>
# GPLv3 license

readonly progname="certbot_zimbra.sh"
readonly version="0.7.13 (unreleased)"
readonly github_url="https://github.com/YetOpen/certbot-zimbra"
# paths
readonly zmpath="/opt/zimbra"
readonly zmwebroot="$zmpath/data/nginx/html"
readonly le_conf_path="/etc/letsencrypt"
readonly le_conf_renewal_path="$le_conf_path/renewal"
readonly le_live_path="$le_conf_path/live" # the domain will be appended to this path
readonly temppath="/run/$progname"
# other options
readonly zmprov_opts="-l" # use ldap (faster)
# used to extract the CA for the Lets Encrypt certs
readonly ca_certificates_file="/etc/ssl/certs/ca-certificates.crt"
readonly pki_ca_bundle_file="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
# Do NOT modify anything after this line.
webroot=""
certpath=""
le_bin=""
le_params=()
le_agree_tos=false
le_noniact=false
le_override_key_type_rsa=true
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
detected_certbot_version=""
locked=false
platform=""
detected_zimbra_version=""

# set up a trap on exit
exitfunc(){
	e="$?"
	if (( e != 0 )) && ! "$quiet"; then
		printf '\nAn error seems to have occurred. Please read the output above for clues and try to rectify the situation.\nIf you believe this is an error with the script, please file an issue at %s . Exiting.\n' "$github_url" >&2
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
	if (( EUID != 0 )); then
		printf 'Error: This script must be run as root.\n' >&2
		exit 1
	fi
}

make_temp() {
	! mkdir --mode=750 -p "$temppath" && printf 'Error: Cannot create temporary directory "%s".\n' "$temppath" >&2 && exit 1
	chown root:zimbra "$temppath"
}

get_lock(){
	exec 200> "$temppath/$progname.lck"
	if ! flock -n 200; then
		printf 'Error: cannot get exclusive lock. Another instance of this script may be running.\nIf you are sure there is no other instance of this script running (check with "ps afx") you can remove "%s" and try again.\n' "$temppath/$progname.lck" >&2
		exit 1
	fi
	locked=true
	readonly locked
}

prompt(){
	while read -rp "$1 " yn; do
		case "$yn" in
			[Yy]* ) return 0;;
			[Nn]* ) return 1;;
			* ) printf 'Please answer yes or no.\n' >&2 ;;
		esac
	done
}

check_depends_ca() {
	# Debian/Ubuntu provided by ca-certificates
	[[ -r "$ca_certificates_file" ]] && return
	# RHEL/CentOS provided by pki-base
	[[ -r "$pki_ca_bundle_file" ]] && return

	cat >&2 <<-'EOF'
		Error: Installed CA certificates not found or files not readable. Please check if you have installed:
		Debian/Ubuntu: ca-certificates (if you do, you might have to run "update-ca-certificates")
		RHEL/CentOS: pki-base (if you do, you might have to run "update-ca-trust")
	EOF
	exit 1
}

check_depends() {
	# check for dependencies
	! "$quiet" && printf 'Checking for dependencies...\n' >&2

	# do not check for lsof or ss here as we'll do that later
	for name in su openssl grep sort head cut sed chmod chown cat cp gawk "$zmpath/bin/zmhostname" "$zmpath/bin/zmcertmgr" "$zmpath/bin/zmcontrol" "$zmpath/bin/zmprov" "$zmpath/libexec/get_plat_tag.sh"; do
		if ! hash "$name" 2>/dev/null; then
			printf 'Error: "%s" not found or executable\n' "$name" >&2
			exit 1
		fi
	done
}

# greater than or equal to (>=) semver comparison
# pure bash solution thanks to geirha at #bash:irc.libera.chat
version_ge() {
	local a b
	IFS=. read -ra a <<< "$1"
	IFS=. read -ra b <<< "$2"
	(( a[0] > b[0] || (a[0] == b[0] && (a[1] > b[1] || a[1] == b[1] && a[2] >= b[2])) ))
}

bootstrap() {
	check_user
	make_temp
	get_lock

	check_depends
	check_depends_ca

	# Detect OS and Zimbra version

	# use Zimbra's get_plat_tag.sh to find OS and version (this is only for display and not used elsewhere in the script)
	# returns $OS$ver for 32-bit or $OS$ver_64 for 64-bit, where OS is the os name (UBUNTU,DEBIAN,RHEL,CentOS,F,FC,SLES,openSUSE,UCS,MANDRIVA,SOLARIS,MACOSx)
	platform="$("$zmpath/libexec/get_plat_tag.sh")"
	readonly platform

	detected_zimbra_version="$(su - zimbra -c "$zmpath/bin/zmcontrol -v" | grep -Po '(\d+).(\d+).(\d+)' | head -n 1)"
	readonly detected_zimbra_version
	[[ -z "$detected_zimbra_version" ]] && printf 'Error: Unable to detect Zimbra version.\n' >&2 && exit 1
	! "$quiet" && printf 'Detected Zimbra %s on %s\n' "$detected_zimbra_version" "$platform" >&2

	get_domain

	return 0
}

check_zimbra_proxy() {
	# must be run after get_domain
	[[ -z "$domain" ]] && printf 'Unexpected error (check_zimbra_proxy domain not set).\n' >&2 && exit 1

	! "$quiet" && printf 'Checking zimbra-proxy is running and enabled\n' >&2

	# TODO: check if path to zmproxyctl is different on <8.7
	! su - zimbra -c "$zmpath/bin/zmproxyctl status > /dev/null" && printf 'Error: zimbra-proxy is not running.\n' >&2 && exit 1
	! su - zimbra -c "$zmpath/bin/zmprov $zmprov_opts gs $domain zimbraReverseProxyHttpEnabled | grep -q TRUE" \
			&& printf 'Error: http reverse proxy not enabled (zimbraReverseProxyHttpEnabled: FALSE).\n' >&2 && exit 1

	if [[ -z "$port" ]]; then
		! "$quiet" && printf 'Detecting port from zimbraMailProxyPort\n' >&2
		port="$(su - zimbra -c "$zmpath/bin/zmprov $zmprov_opts gs $domain zimbraMailProxyPort | sed -n 's/zimbraMailProxyPort: //p'")"
		[[ -z "$port" ]] && printf 'Error: zimbraMailProxyPort not found.\n' >&2 && exit 1
	else
		printf 'Skipping port detection from zimbraMailProxyPort due to --port override\n' >&2
	fi

	if [[ "$port" != "80" ]] && ! "$quiet"; then
		printf 'WARNING: non-standard zimbraMailProxyPort %s. This needs to be 80 from the internet for ACME HTTP-01 to work. If you have NAT set up to do the translation this is likely fine. If not, your Zimbra proxy is misconfigured and Certbot will fail.\n' "$port" >&2
		if "$prompt_confirm"; then
			prompt "Proceed?"
			(( $? == 1 )) && printf 'Cannot continue.\n' >&2 && exit 0
		else
			printf 'WARNING: Prompt disabled, proceeding anyway.\n' >&2
		fi
	fi
}

# Check if process is listening on port $1 (optionally with name $2 and/or user $3) or return an error
check_port () {
	if "$skip_port_check"; then
		! "$quiet" && printf 'Skipping port check\n' >&2
		return 0
	fi

	[[ -z "$1" ]] && printf 'Unexpected error: check_port empty $1 (port).\n' >&2 && exit 1

	! "$quiet" && printf 'Checking if process is listening on port %s\n' "$1 ${2:+"with name \"$2\" "}${3:+"user \"$3\""}" >&2

	# check with lsof if available, or fall back to ss
	declare -a check_bin
	declare grep_filter=
	if hash lsof 2>/dev/null; then
		check_bin=("lsof" "-i" ":$1" "-s" "TCP:LISTEN" "-a" "-n")
		grep_filter="$2.*$3"
	elif hash ss 2>/dev/null; then
		check_bin=("ss" "-lptn" "sport" "eq" ":$1")
		# ss doesn't return process user, so don't use it for count
		grep_filter="$2"
	else
		printf 'Error: Neither "lsof" nor "ss" were found in PATH. Unable to continue.\n' >&2
		exit 1
	fi

	# return false if count of matched processes is 0
	# optionally $2 and $3 are process name and process user
	(( "$("${check_bin[@]}" | grep -c "$grep_filter")" == 0 )) && return 1

	return 0
}


# Patch Zimbra proxy nginx and restart it if successful
# zimbra-proxy must be running (checked with check_zimbra_proxy) or zmproxyctl restart will fail
# returns true if patch was applied or was already present, exits script if encountered an error
patch_nginx() {
	[[ ! -d "$zmpath/conf/nginx/includes" ]] && printf 'Error: "%s" not found.\n' "$zmpath/conf/nginx/includes" >&2 && exit 1

	# Don't patch if patch is already applied
	if grep -r -q 'acme-challenge' "$zmpath/conf/nginx/templates"; then
		! "$quiet" && printf 'Nginx templates already patched.\n' >&2
	else
		[[ -z $webroot ]] && printf 'Unexpected error: patch_nginx WEBROOT not set.\n' >&2 && exit 1

		# Let's make a backup of Zimbra's original templates
		set -e
		local bkdate="$(date +'%Y%m%d_%H%M%S')"
		! "$quiet" && printf 'Making a backup of nginx templates in "%s"\n' "$zmpath/conf/nginx/templates.$bkdate" >&2
		cp -a "$zmpath/conf/nginx/templates" "$zmpath/conf/nginx/templates.$bkdate"
		set +e

		# do patch
		! "$quiet" && printf 'Patching nginx templates... ' >&2
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
			(( e != 0 )) && break
		done

		if (( e != 0 )); then
			! "$quiet" && printf 'Error!\nRestoring old templates... ' >&2
			if ! cp -a "$zmpath/conf/nginx/templates.$bkdate/"* "$zmpath/conf/nginx/templates/"; then
				! "$quiet" && printf 'Error restoring templates!\n' >&2
			else
				! "$quiet" && printf 'Success.\n' >&2
			fi
			! "$quiet" && printf 'Error patching nginx templates.\n' >&2 && exit 1
		else
			! "$quiet" && printf 'Success.\n' >&2
		fi

		unset bkdate
	fi

	# Don't restart if includes show nginx has already been restarted
	if grep -r -q 'acme-challenge' "$zmpath/conf/nginx/includes"; then
		! "$quiet" && printf 'Nginx includes already patched, skipping zmproxy restart.\n' >&2
	else
		if "$prompt_confirm"; then
			prompt "Restart zmproxy?"
			(( $? == 1 )) && printf 'Cannot continue.\n' >&2 && exit 0
		fi

		! "$quiet" && printf 'Running zmproxyctl restart.\n' >&2
		# reload nginx config
		su - zimbra -c 'zmproxyctl restart' 200>&-; e="$?"
		if (( e != 0 )); then
			! "$quiet" && printf 'Error restarting zmproxy ("zmproxyctl restart" exit status %s).\n' "$e" >&2
			exit 1
		else
			! "$quiet" && printf 'Success.\n' >&2
		fi
	fi

	return 0
}

# detect additional public service hostnames from configured domains' zimbraPublicServiceHostname
find_additional_public_hostnames() {
	# If already set, leave them alone
	[[ "${extra_domains[*]}" ]] && return

	# If it has been requested NOT to perform the search
	if ! "$detect_public_hostnames"; then
		! "$quiet" && printf 'Skipping additional public service hostname detection\n' >&2
		return
	fi

	! "$quiet" && printf 'Detecting additional public service hostnames...\n' >&2

	extra_domains=($(su - zimbra -c "zmprov $zmprov_opts gad" \
			| gawk '{printf "gd %s zimbraPublicServiceHostname\ngd %s zimbraVirtualHostname\n", $0, $0}' \
			| su - zimbra -c "zmprov $zmprov_opts -" \
			| sed "/prov>/d;/# name/d;/$domain/d;/^$/d;s/\(\(zimbraPublicServiceHostname\)\|\(zimbraVirtualHostname\)\): \(.*\)/\4/g" \
			| sort -u | tr '\n' ' ' \
			))
	! "$quiet" && printf 'Found %s extra domains through auto-detection (zimbraPublicServiceHostname, zimbraVirtualHostname)\n' "${#extra_domains[*]}" >&2

	return 0
}

get_domain () {
	# If we got no domain from command line try using Zimbra hostname
	if [[ -z "$domain" ]]; then
		! "$quiet" && printf 'Using zmhostname to detect domain.\n' >&2
		domain="$("$zmpath/bin/zmhostname")"
	fi

	[[ -z "$domain" ]] && printf 'Error: No domain found! Please run with -d/--hostname or check why zmhostname is not working.\n' >&2 && exit 1

	! "$quiet" && printf 'Using domain %s (as certificate DN)\n' "$domain" >&2

	if "$prompt_confirm"; then
		prompt "Is this correct?"
		(( $? == 1 )) && printf 'Error: Please manually specify your hostname with "--hostname your.host.name".\n' >&2 && exit 0
	fi

	# Find additional domains
	"$new_cert" && find_additional_public_hostnames

	if [[ "${extra_domains[*]}" ]] && ! "$quiet"; then
		printf 'Got %s domains to use as certificate SANs: %s\n' "${#extra_domains[@]}" "${extra_domains[*]}" >&2
		if "$prompt_confirm"; then
			prompt "Include these in the certificate?"
			(( $? == 1 )) && unset extra_domains
		fi
	fi

	return 0
}

set_certpath() {
	# must be run after get_domain
	[[ -z "$domain" ]] && printf 'Unexpected error (set_certpath domain not set).\n' >&2 && exit 1

	# when run as --deploy-hook, check if any of RENEWED_DOMAINS match Zimbra's domain.
	# RENEWED_DOMAINS and RENEWED_LINEAGE are passed by Certbot as env vars to --deploy-hook
	if [[ -n "$RENEWED_DOMAINS" ]]; then
		# we were run as --deploy-hook
		for renewed_domain in $RENEWED_DOMAINS; do
			[[ "$renewed_domain" == "$domain" ]] && certpath="$RENEWED_LINEAGE"
		done
		# exit gracefully if no matching domains were found. We must be running for some other cert, not ours.
		if [[ -z "$certpath" ]]; then
			! "$quiet" && printf 'Detected --deploy-hook but no matching domain found. Nothing to do.\n' >&2
			exit 0
		else
			! "$quiet" && printf 'Detected --deploy-hook and matching domain found\n' >&2
		fi
	else
		# we were run standalone
		certpath="$le_live_path/$domain"
	fi
}

check_webroot () {
	[[ -z "$webroot" ]] && printf 'Unexpected error: check_webroot webroot not set.\n' >&2 && exit 1
	
	# <8.7 didn't have nginx webroot
	if ! [[ -d "$webroot" ]]; then
		if "$prompt_confirm"; then
			prompt "Webroot $webroot doesn't exist, create it?"
			(( $? == 1 )) && printf 'Cannot proceed.\n' >&2 && exit 0
		fi
		printf 'Creating webroot %s\n' "$webroot" >&2
		set -e
		mkdir -p "$webroot"
		set +e
	fi
}

find_certbot () {
	# check for executable certbot-auto / certbot / letsencrypt
	# TODO: remove dead certbot-auto
	le_bin="$(command -v certbot letsencrypt certbot-auto 2>/dev/null | head -n 1)"
	[[ -z "$le_bin" ]] && printf 'Error: No letsencrypt/certbot binary found in PATH.\n' >&2 && exit 1

	! "$quiet" && printf 'Detecting Certbot version...\n' >&2

	# get Certbot version, we need to use some trickery here in case Certbot is bootstrapping (1st run) and expects user input
	# if run with --prompt-confirm, show the output of Certbot on stderr and allow the user to answer yes/no
	# otherwise add --no-bootstrap and exit in case of error
	# TODO: --no-bootstrap is not used in Certbot, deprecated in Certbot >=1.13.0, and certbot-auto is already dead,
	# so no point in keeping it, Certbot does not need to bootstrap (but may ask for accepting the TOS)
	local certbot_version_params=()
	! "$prompt_confirm" && certbot_version_params=("--no-bootstrap")
	"$le_noniact" && certbot_version_params+=("--non-interactive")
	certbot_version_params+=("--version")

	detected_certbot_version="$($le_bin "${certbot_version_params[@]}" 2>&1 | $( "$prompt_confirm" && printf 'tee /dev/stderr |') | grep -oP '^certbot \K(\d+).(\d+).(\d+)$')"
	local certbot_version_exit="${PIPESTATUS[0]}"
	if (( certbot_version_exit != 0 )); then
		! "$quiet" && printf 'Error: "%s" exit status %s.\nTry running "%s" by itself on the command line and see if it works.\n' "$le_bin ${certbot_version_params[*]}" "$certbot_version_exit" "$le_bin" >&2
		exit 1
	fi

	if [[ -z "$detected_certbot_version" ]]; then
		! "$quiet" && printf 'Error: unable to parse Certbot version.\n' >&2
		exit 1
	fi

	! "$quiet" && ! "$prompt_confirm" && printf 'Detected Certbot %s\n' "$detected_certbot_version" >&2

	if ! version_ge "$detected_certbot_version" "$min_certbot_version"; then
		! "$quiet" && printf 'Error: Certbot is too old, please upgrade to Certbot >=%s.\n' "$min_certbot_version" >&2
		exit 1
	fi

	return 0
}

# perform the Lets Encrypt request
request_cert() {
	check_webroot

	if "$prompt_confirm"; then
		prompt "We will now run Certbot to request the certificate. Proceed?"
		(( $? == 1 )) && printf 'Unable to proceed.\n' >&2 && exit 0
	fi

	#TODO: dry-run

	"$le_noniact" && le_params+=("--non-interactive")
	"$quiet" && le_params+=("--quiet")
	"$le_agree_tos" && le_params+=("--agree-tos")

	version_ge "$detected_certbot_version" "2.0.0" &&
		"$le_override_key_type_rsa" &&
		le_params+=("--key-type" "rsa" "--rsa-key-size" "4096")

	le_params+=("--webroot" "-w" "$webroot" "--cert-name" "$domain" "-d" "$domain")
	for d in "${extra_domains[@]}"; do
		[[ -z "$d" ]] && continue
		le_params+=("-d" "$d")
	done

	! "$quiet" && printf 'Running %s\n' "$le_bin certonly ${le_params[*]}" >&2
	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null
	# Request our cert
	"$le_bin" certonly "${le_params[@]}"
	e="$?"
	"$quiet" && exec > /dev/stdout
	"$quiet" && exec 2> /dev/stderr
	(( e != 0 )) && printf 'Error: "%s" exit status %s. Cannot proceed.\n' "$le_bin" "$e" >&2 && exit 1
	return 0
}

# adds pre and deploy hooks to the Certbot certificate configuration
add_certbot_hooks() {
        if "$prompt_confirm" && ! prompt "Do you wish to add pre and deploy hooks to Certbot certificate configuration? (unless you manually wish to do so, answer yes)"; then
		printf 'Please manually add Certbot hooks as described in the README.\n' >&2
		return
        fi

	declare -i e=0

	if ! hash "$progname" 2>/dev/null; then
		printf 'Error: could not find "%s" in PATH!\n' "$progname" >&2
		e=1
	else
		! "$quiet" && printf 'Adding pre and deploy hooks to Certbot certificate configuration\n' >&2

		if version_ge "$detected_certbot_version" "2.3.0"; then
			# Certbot >=2.3.0 has "reconfigure"
			local le_reconfigure_params=("--cert-name" "$domain" "--pre-hook" "$progname -p" "--deploy-hook" "$progname -d")
			! "$quiet" && printf 'Running "%s"\n' "$le_bin reconfigure ${le_reconfigure_params[*]}" >&2
			"$le_bin" reconfigure "${le_reconfigure_params[@]}"
			e="$?"
		else
			# manually change hooks in Certbot renewal config file
			! "$quiet" && printf 'Certbot does not have reconfigure, manually editing renewal config file...\n'

			# make backup of conf file
			local le_domain_conf="$le_conf_renewal_path/$domain.conf"
			local le_domain_conf_temp="$temppath/$domain.conf"

			if ! cp --preserve=all "$le_domain_conf" "$le_domain_conf_temp"; then
				printf 'Error: cannot read "%s"!\n' "$le_domain_conf" >&2
				e=1
			fi

			if ! cp -f --preserve=all --backup=numbered "$le_domain_conf" "$le_domain_conf"; then
				printf 'Error: cannot write to "%s"!\n' "$le_conf_renewal_path" >&2
				e=1
			fi

			if (( e != 0 )); then
				# awk program works if [renewalparams] does or doesn't already exist
				# (it would be very odd if they didn't!)
				# Certbot stores --deploy-hook as "renew_hook" in the config file
				# https://github.com/certbot/certbot/issues/5935
				gawk -v progname="$progname" -f - "$le_domain_conf" > "$le_domain_conf_temp" <<- "EOF"
					function print_hooks() {
					        print "pre_hook =", progname, "-p"
					        print "renew_hook =", progname, "-d"
					}
					BEGIN {e=1}
					/^(pre|renew)_hook.*/ {next}
					{print}
					/^\[renewalparams\]$/ {
						print "# hooks modified by", progname
					        print_hooks()
					        e=0
					}
					END {
					        if (e) {
							print "# renewalparams added by", progname
					                print "[renewalparams]"
					                print_hooks()
					        }
					}
				EOF
				e="$?"
				if (( e != 0 )); then
					printf 'Error: awk exit %s!\n' "$e" >&2
				else
					if ! cp -f --preserve=all "$le_domain_conf_temp" "$le_domain_conf"; then
						printf 'Error: cannot write to "%s"!\n' "$le_domain_conf" >&2
						e+=1
					fi
				fi
			fi
		fi
	fi

	if (( e != 0 )); then
		printf 'Error while adding hooks to "%s"! Please do so manually as described in the README.\n' "$le_domain_conf" >&2
	fi
}

# copies stuff ready for Zimbra deployment and test them
prepare_cert() {
	! "$quiet" && printf 'Preparing certificates for deployment.\n' >&2

	[[ -z "$certpath" ]] && printf 'Unexpected error (prepare_cert certpath not set).\n' >&2 && exit 1
	[[ -z "$domain" ]] && printf 'Unexpected error (prepare_cert domain not set).\n' >&2 && exit 1

	# Make Zimbra accessible files
	# save old umask
	oldumask="$(umask -p)"
	# make files u=rwx g=rx o=
	umask 0027

	# exit on error
	set -e

	tmpcerts="$(mktemp -d --tmpdir="$temppath" certs-XXXXXXXX)"

	cp "$certpath"/{privkey.pem,cert.pem} "$tmpcerts/"

	# Create the "patched" chain suitable for Zimbra

	# find the first valid chain by iterating through chain.pem one certificate at a time
	local chaincerts="$(cat "$certpath/chain.pem")"
	local chaincert="${chaincerts%%END CERTIFICATE*}END CERTIFICATE-----"
	local issuerhash=
	local issuercn=

	while [[ "$chaincert" != "${chaincert##*BEGIN CERTIFICATE}" ]]; do
		if printf '%s\n' "$chaincert" | openssl verify >/dev/null 2>&1; then
			issuerhash="$(printf '%s' "${chaincert}" | openssl x509 -noout -issuer_hash)"
			issuercn="$(printf '%s' "${chaincert}" | openssl x509 -noout -issuer -nameopt sep_multiline,utf8 | grep -oP '\sCN=\K.*')"
			break
		else
			# get next cert
			chaincerts="${chaincerts##"$chaincert"}"
			chaincert="${chaincerts%%END CERTIFICATE*}END CERTIFICATE-----"
		fi
	done

	unset chaincerts chaincert

	if [[ -z "$issuerhash" ]]; then
		printf 'Error: No valid chain found in "%s"!\n' "$certpath/chain.pem" >&2
		exit 1
	fi

	if [[ -r "$ca_certificates_file" ]]; then
	        # Debian/Ubuntu
		# use the issuer_hash of the LE chain cert to find the root CA in /etc/ssl/certs
		cat "/etc/ssl/certs/$issuerhash.0" >> "$tmpcerts/zimbra_chain.pem"
	elif [[ -r "$pki_ca_bundle_file" ]]; then
		# RHEL/CentOS
		# extract CA by CN in tls-ca-bundle.pem

		# if we can't find the issuer CN in the bundle file, it may have spaces removed, hopefully we'll find it without spaces
		grep -q "^# $issuercn\$" "$pki_ca_bundle_file" || issuercn="${issuercn//' '}"
		# the following awk script extracts the CA cert from the bundle or exits 1 if not found
		! gawk "BEGIN {e=1}; /^# $issuercn$/{e=0} /^# $issuercn$/,/END CERTIFICATE/; END {exit e}" "$pki_ca_bundle_file" >> "$tmpcerts/zimbra_chain.pem"\
			&& printf 'Error: Cannot find "%s" in "%s".\n' "$issuercn" "$pki_ca_bundle_file" && exit 1
	else
		# we shouldn't be here
		printf 'Error in prepare_cert: cannot find installed CA certificates (check_depends_ca should have caught this).\n' >&2 && exit 1
	fi

	cat "$certpath/chain.pem" >> "$tmpcerts/zimbra_chain.pem"

	$oldumask
	unset oldumask

	# set permissions so that Zimbra can read the certs
	chown -R root:zimbra "$tmpcerts"
	chmod 550 "$tmpcerts"
	chmod 440 "$tmpcerts"/*

	! "$quiet" && printf 'Testing with zmcertmgr.\n' >&2

	# redirect stdout to /dev/null if quiet
	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null

	# Test cert. 8.6 and below must use root
	if version_ge "$detected_zimbra_version" "8.7"; then
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

# deploys certificate and restarts Zimbra. ASSUMES prepare_certificate has been called already
deploy_cert() {
	if "$prompt_confirm"; then
		prompt "Deploy certificates to Zimbra? This may restart some services."
		(( $? == 1 )) && printf 'Cannot proceed.\n' >&2 && exit 0
	fi

	# exit on error
	set -e
	! "$quiet" && printf 'Deploying certificates.\n' >&2

	# Backup old stuff
	cp -a "$zmpath/ssl/zimbra" "$zmpath/ssl/zimbra.$(date +'%Y%m%d_%H%M%S')"

	# copy privkey
	cp -a "$tmpcerts/privkey.pem" "$zmpath/ssl/zimbra/commercial/commercial.key"

	"$quiet" && exec > /dev/null
	"$quiet" && exec 2>/dev/null
	# this is it, deploy the cert.
	if version_ge "$detected_zimbra_version" "8.7"; then
		su - zimbra -c "$zmpath/bin/zmcertmgr deploycrt comm $tmpcerts/cert.pem $tmpcerts/zimbra_chain.pem -deploy ${services}"
	else
		"$zmpath/bin/zmcertmgr" deploycrt comm "$tmpcerts/cert.pem" "$tmpcerts/zimbra_chain.pem"
	fi
	"$quiet" && exec > /dev/stdout
	"$quiet" && exec 2> /dev/stderr

	! "$quiet" && printf 'Removing temporary files in "%s"\n' "$tmpcerts" >&2
	# this is kind of sketchy
	[[ -n "$tmpcerts" ]] && rm -r "$tmpcerts"
	unset tmpcerts

	set +e

	if "$restart_zimbra"; then
		if "$prompt_confirm"; then
			prompt "Restart Zimbra?"
			(( $? == 1 )) && printf 'Cannot proceed.\n' >&2 && exit 0
		fi

		! "$quiet" && printf 'Restarting Zimbra.\n' >&2

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
USAGE: $progname < -d | -n | -p > [-aNuzjxcq] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port] [-L "--extra-le-parameter"]...
  Only one option at a time can be supplied. Options cannot be chained.
  Mandatory options (only one can be specified):
	 -d | --deploy-only: Just deploys certificates. Will detect if it's being run from Certbot renew_hook or --deploy-hook and only deploy if env variable RENEWED_DOMAINS matches the hostname. If run standalone, assumes valid certificates are in $le_live_path. Incompatible with -n/--new, -p/--patch-only.
	 -n | --new: performs a request for a new certificate ("certonly"). Can be used to update the domains in an existing certificate. Incompatible with -d/--deploy-only, -p/--patch-only.
	 -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade. Incompatible with -d/--deploy-only, -n/--new, -x/--no-nginx.

  Options only used with -n/--new:
	 -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
	 -L | --letsencrypt-params "--extra-le-parameter": Additional parameter to pass to certbot/letsencrypt. Must be repeated for each parameter and argument, e.g. -L "--preferred-chain" -L "ISRG Root X1"
	 -N | --noninteractive: Pass --noninteractive to certbot/letsencrypt.
	 --no-override-key-type-rsa: if Certbot >=v2.0.0 has been detected, do not override ECDSA to RSA with "--key-type rsa" (use this to get the default ECDSA key type, Zimbra does NOT support it!)

  Domain options:
	 -e | --extra-domain <extra.domain.tld>: additional domains being requested. Can be used multiple times. Implies -u/--no-public-hostname-detection.
	 -H | --hostname <my.host.name>: hostname being requested. If not passed it's automatically detected using "zmhostname".
	 -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraPublicServiceHostname and zimbraVirtualHostname.

  Deploy options:
	 -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
	 -z | --no-zimbra-restart: do not restart Zimbra after a certificate deployment

  Port check:
	 -j | --no-port-check: disable port check. Incompatible with -P/--port.
	 -P | --port <port>: HTTP port the web server to use for Lets Encrypt authentication is listening on. Is detected from zimbraMailProxyPort. Mandatory with -x/--no-nginx.

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
while (( $# > 0 )); do
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
		# Lets Encrypt
		-a|--agree-tos)
			le_agree_tos=true
			;;
		-L|--letsencrypt-params)
			[[ -z "$2" ]] && printf 'Error: missing --letsencrypt-params argument\n' >&2 && exit 1
			le_params+=("$2")
			shift
			;;
		-N|--noninteractive)
			le_noniact=true
			;;
		--no-override-key-type-rsa)
			le_override_key_type_rsa=false
			;;
		# domain
		-e|--extra-domain)
			[[ -z "$2" ]] && printf 'Error: missing --extra-domain argument\n' >&2 && exit 1
			extra_domains+=("$2")
			detect_public_hostnames=false
			shift
			;;
		-H|--hostname)
			[[ -z "$2" ]] && printf 'Error: missing --hostname argument\n' >&2 && exit 1
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
			[[ -z "$2" ]] && printf 'Error: missing --port argument\n' >&2 && exit 1
			port="$2"
			shift
			;;
		# nginx
		-w|--webroot)
			[[ -z "$2" ]] && printf 'Error: missing --webroot argument\n' >&2 && exit 1
			webroot="$2"
			shift
			;;
		-x|--no-nginx)
			no_nginx=true
			;;
		# zimbra
		-s|--services)
			[[ -z "$2" ]] && printf 'Error: missing --services argument\n' >&2 && exit 1
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
			printf 'Unknown option: "%s". Try --help for usage.\n' "$1" >&2
			exit 1
			;;
	esac
	shift
done

readonly deploy_only new_cert patch_only le_agree_tos le_noniact le_override_key_type_rsa detect_public_hostnames skip_port_check no_nginx services restart_zimbra prompt_confirm quiet

# exit if an invalid option combination was passed
"$quiet" && "$prompt_confirm" && printf 'Incompatible parameters: -q -c\n' >&2 && exit 1
"$le_noniact" && "$prompt_confirm" && printf 'Incompatible parameters: -N -c\n' >&2 && exit 1

"$deploy_only" && ("$new_cert" || "$patch_only") && printf 'Incompatible option combination\n' >&2 && exit 1
"$new_cert" && ("$deploy_only" || "$patch_only") && printf 'Incompatible option combination\n' >&2 && exit 1
"$patch_only" && ("$deploy_only" || "$new_cert" || "$no_nginx") && printf 'Incompatible option combination\n' >&2 && exit 1
! ("$deploy_only" || "$new_cert" || "$patch_only") && printf 'Nothing to do. Please specify one of: -d -n -p.\n' >&2 && exit 1

"$no_nginx" && [[ -z "$webroot" || ( -z "$port" && ! "$skip_port_check" ) ]] && printf 'Error: --no-nginx requires --webroot and --port or --no-port-check.\n' >&2 && exit 1
! "$no_nginx" && [[ -n "$webroot" ]] && printf 'Error: -w/--webroot cannot be used in zimbra-proxy mode. Please use -x/--no-nginx (alternate webserver mode).\n' >&2 && exit 1
"$skip_port_check" && [[ -n "$port" ]] && printf 'Error: -j/--no-port-check cannot be used with -P/--port.\n' >&2 && exit 1

! "$quiet" && printf '%s\n' "$progname v$version - $github_url" >&2

## actions
bootstrap

if ! "$deploy_only"; then
	if "$no_nginx"; then
		! check_port "$port" && printf 'Error: port check failed. A web server to use for the HTTP-01 ACME challenge must be listening on the port specified with --port.\n' >&2 \
				&& exit 1
	else
		webroot="$zmwebroot"
		readonly webroot

		check_zimbra_proxy
		! check_port "$port" nginx zimbra && printf 'Error: port check failed. If you have overridden the port with --port, a web server to use for the HTTP-01 ACME challenge must be listening on it.\n' >&2 && exit 1
		patch_nginx
	fi

	"$patch_only" && exit 0

	find_certbot
	request_cert
	add_certbot_hooks
fi

set_certpath
prepare_cert
deploy_cert

exit 0
