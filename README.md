# certbot-zimbra
Automated letsencrypt/certbot certificate deploy script for Zimbra hosts.

[![asciicast](https://asciinema.org/a/219713.svg)](https://asciinema.org/a/219713)

The script tweaks zimbra's nginx config to allow access of *.well-known* webserver location from local files instead of redirecting upstream to jsp. So it **may not be used if there's no *zimbra-nginx* package installed**.

Letsencrypt by default tries to verify a domain using http, so the script should work fine if [*zimbraReverseProxyMailMode*](https://wiki.zimbra.com/wiki/Enabling_Zimbra_Proxy_and_memcached#Protocol_Requirements_Including_HTTPS_Redirect) is set to *http*, *both* or *redirect*. It won't work if set to *https* only. This is due to certbot deprecating the *tls-sni-01* authentication method and switching to *HTTP-01*. https://letsencrypt.org/docs/challenge-types/

This is still a BETA script. Partially tested on:
* 8.8.8_UBUNTU16
* 8.8.12_UBUNTU16

# WARNING - Breaking changes ahead

Thanks to the awesome job of @jjakob the script has undergone a considerable rewrite. 
Some things changed, some parameters have been renamed, so **if you're upgrading please read the [WARNING chapter](https://github.com/YetOpen/certbot-zimbra/tree/master#warning) below**.
If you're not upgrading then we encourage you in testing the script and report back any issue you might encounter.

If you're in a hurry and cannot wait our feedback on an issue you can download the last *stable* version from [0.5.0 tag](https://github.com/YetOpen/certbot-zimbra/tree/0.5.0-beta).

If you encounter any problem please [open an issue](https://github.com/YetOpen/certbot-zimbra/issues/new).

Things explicitly not tested are in the [TESTING](TESTING) file.

USE AT YOUR OWN RISK.

## WARNING

The command line parameters were changed with v0.7. `-r/--renew-only` was renamed to `-d/--deploy-only`, and `-d` was changed to `-H`. This is a BREAKING change so please update your crontabs and any other places they are used. Some new parameters were added, though they won't break backwards-compatibility, they add new features. Refer to the usage and/or the changelog for more information.

### Limitations

The script doesn't handle multiple domains configured with SNI (see #8). You can still request a single certificate for multiple hostnames.

# Installation

## Requirements

- bash, su, patch, which, lsof or ss, openssl, grep, sed (GNU)
- Zimbra: zmhostname, zmcontrol, zmproxyctrl, zmprov, zmcertmgr
- zimbra-proxy installed and working
- either certbot, certbot-auto or letsencrypt binary in PATH. These three may be used interchangeably in the rest of the document, depending on what is installed on your system.

## Certbot installation

The preferred way is to install it is by using the wizard [at certbot's home](https://certbot.eff.org/). Choose *None of the above* as software and your operating system. This will allow you to install easily upgradable system packages.

By installing Certbot via packages it automatically creates a cron schedule to renew certificates (at least on Ubuntu). 
We must **disable this schedule** because after the renew we must deploy it in Zimbra. 
So open `/etc/cron.d/certbot` with your favourite editor and **comment the last line**.

## certbot_zimbra installation

Download the latest release and install it (copy the latest URL from the Releases tab):

```
wget https://github.com/YetOpen/certbot-zimbra/archive/0.4.0-beta.tar.gz
tar xzf 0.4.0-beta.tar.gz certbot_zimbra.sh
mv certbot_zimbra.sh /usr/local/bin/
chmod +x /usr/local/bin/certbot_zimbra.sh
```

# Usage

```bash
USAGE: certbot_zimbra.sh < -d | -n | -p > [-xaczuj] [-H my.host.name] [-e extra.domain.tld] [-w /var/www] [-s <service_names>] [-P port]
  Mandatory options (only one may be specified):
	 -d | --deploy-only: Just deploys certificates. Assumes valid certificates are in /etc/letsencrypt/live. Incompatible with -n, -p.
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

```


If no `-e` is given, the script will figure out the domain(s) to request certificate for via the following commands:
* `zmhostname` 
* `zmprov gd $domain zimbraPublicServiceHostname`

Only one certificate will be issued including all the found hostnames. The primary host will always be `zmhostname`.


## Zimbra 8.6+ single server example

### First run

If you don't yet have a letsencrypt certificate, you'll need to obtain one first. The script can do everything for you, including deploying the certificate and restarting zimbra.

Run
`./certbot_zimbra.sh -n -c`

This will do all pre-run checks, patch zimbra's nginx, run certbot to obtain the certificate, test it, deploy it and restart zimbra. Passing -c means the script will prompt you for confirmation before restarting zimbra's nginx, running certbot/letsencrypt, deploying the certificate and restarting zimbra.

Certbot will also ask you some information about the certificate interactively, including an e-mail to use for expiry notifications. Please use a valid e-mail for this as should the automatic renewal fail for any reason, this is the way you'll get notified.

The domain of the certificate is obtained automatically using `zmhostname`. If you want to request a specific hostname use the `-H/--hostname` option. This domain will be the DN of the certificate.

The certificate can be requested with additional hostnames/SANs. By default the script loops though all Zimbra domains, fetches 
the `zimbraPublicServiceHostname` attribute and if present, adds it to the certificate SANs to be requested. This automatic detection may take several minutes depending on the number of domains you have. If you want to disable this behavior use the `-u/--no-public-hostname-detection` option. 

To indicate additional domains explicitly use the `-e/--extra-domain` option (can be specified multiple times). Note that `-e` also disables additional hostname detection. 

Additional options can be passed directly to certbot/letsencrypt with `-L | --letsencrypt-params`. For example, if you want 4096-bit certificates, add `-L "--rsa-key-size 4096"`. Refer to certbot's documentation for more information.

### Running noninteractively

When retrieving a new certificate using -n, certbot runs interactively. If you want to run it noninteractively, you can pass `-N/--noninteractive` which will be passed on to certbot. Also passing `-q/--quiet` will suppress the status output of the script.
Only do this if you're absolutely sure what you're doing, as this leaves you with no option to verify the detected hostnames, specify the certificate e-mail etc. `-N/--noninteractive` may be combined with `-q | --quiet` and/or `-L | --letsencrypt-params` to pass all the parameters to certbot directly, e.g. in scripts to do automated testing with staging certificates. 

## Renewal

EFF suggest to run *renew* twice a day. Since this would imply restarting zimbra, once a day outside workhours should be fine. So in your favourite place (like `/etc/cron.d/zimbracrontab` or with `sudo crontab -e`) schedule the command below, as suitable for your setup:

```
12 5 * * * root /usr/bin/certbot renew --pre-hook "/usr/local/bin/certbot_zimbra.sh -p" --renew-hook "/usr/local/bin/certbot_zimbra.sh -d"
```
Replace `/usr/bin/certbot` with the location of your certbot binary, use this to find it: `which certbot-auto certbot letsencrypt`.

The `--pre-hook` ensures Zimbra's nginx is patched to allow certificate verification. You can omit it if you remember to manually execute that command after an upgrade or a reinstall which may restore nginx's templates to their default.

The `--renew-hook` parameter is only run if a renewal was successful, this will run certbot-zimbra.sh with `-d` to deploy the renewed certificates and restart zimbra.

It has been added since certbot 0.7.0, so check your version before using it. If it's not supported you should get a workaround, but probably the easiest way is to upgrade certbot. If you installed certbot manually instead of via the package manager, it should auto-upgrade on every invocation. Just run `certbot-auto` (or the equivalent on your system) without any parameters to auto-upgrade.

The domain to renew is automatically obtained with `zmhostname`. If you need customized domain name pass the `-H` parameter after `-d`.

## Renewal using Systemd
The example below uses the renew-hook which will only rerun the script if a renewal was successful and thus only reloading zimbra when needed.

Create a service file eg: /etc/systemd/system/renew-letsencrypt.service

```
[Unit]
Description=Renew Let's Encrypt certificates
After=network-online.target

[Service]
Type=oneshot
# check for renewal, only start/stop nginx if certs need to be renewed
ExecStart=/usr/bin/certbot renew --quiet --pre-hook "/usr/local/bin/certbot_zimbra.sh -p" --renew-hook "/usr/local/bin/certbot_zimbra.sh -d"
```

Create a timer file to run the above once a day at 2am: /etc/systemd/system/renew-letsencrypt.timer

```
[Unit]
Description=Daily renewal of Let's Encrypt's certificates

[Timer]
# once a day, at 2AM
OnCalendar=*-*-* 02:00:00
# Be kind to the Let's Encrypt servers: add a random delay of 0–3600 seconds
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

Then reload the unit file with
```
systemctl daemon-reload
systemctl start renew-letsencrypt.timer
systemctl enable renew-letsencrypt.timer
```

Check the timers status:
```
systemctl list-timers renew-letsencrypt.timer
```


## If you have another webserver in front

*(It may happen even in the best families)*

Say you have apache in front of zimbra (or listening on port 80 only) just run `certbot-auto` to request the certificate for apache, and when done run
```
/usr/local/bin/certbot_zimbra.sh --deploy --no-nginx
```
so that it will deploy the certificate in zimbra without patching nginx.



## Upgrade from v0.1

If you originally requested the certificate with the first version of the script, which used *standalone* method, newer version will fail to renew. This because it
now uses *webroot* mode by patching Zimbra's nginx, making it more simple to work and to mantain.

To check if you have the old method, run `grep authenticator /etc/letsencrypt/renewal/YOURDOMAIN.conf`. If it says *standalone* it uses the old method.

To update to the new "webroot" method you can simply run `certbot-zimbra.sh -n -c -L "--cert-name [yourcertname] --force-renewal"`. This will force renew your existing certificate and save the new authentication method. It'll also ask you for deploying the new certificate in Zimbra. You can also manually modify the config file in /etc/letsencrypt/renewal/, while not recommended, is detailed here: https://community.letsencrypt.org/t/how-to-change-certbot-verification-method/56735

# How it works
TODO: explain the nginx patching mathod, etc.

# Certbot notes

Certbot preserves the gid and the g:rwx and o:r permissions from old privkey files to the renewed ones. This is described in 
https://github.com/certbot/certbot/blob/8b684e9b9543c015669844222b8960e1b9a71e97/certbot/storage.py#L1107

If you have some old certificates you've been renewing for a long time, it may be possible your privkey is created with other read permissions. This may be bad if all the containing directories are also other-readable. In my case they were not (the archive dir was mode 700) so the contained private keys were also not readable. Still, you may consider checking your situation and chmod'ing the privkeys to something more sensible like 640:

`chmod 640 /etc/letsencrypt/archive/*/privkey*.pem`

The default for new privkeys is 600.

If you want the keys in /etc/letsencrypt to be readable by some other programs, adjust the folder and file permissions as necessary, for example:
```
addgroup --system ssl-cert
chmod g+rx /etc/letsencrypt/{live,archive}
chgrp -R ssl-cert /etc/letsencrypt
addgroup ssl-cert <user that needs key access>
```

# License

See [LICENSE](LICENSE).

### Disclaimer of Warranty

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

# Author

&copy; Lorenzo Milesi <maxxer@yetopen.it>

## Contributors
- Jernej Jakob <jernej.jakob@gmail.com>
- @eN0RM
- Pavel Pulec @pulecp
- Antonio Prado
- @afrimberger
- @mauriziomarini

*if you are a contributor, add yourself here (and in the code)*


Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
