# certbot-zimbra
Automated letsencrypt/certbot certificate deploy script for Zimbra hosts.

The script tweaks zimbra's nginx config to allow access of *.well-known* webserver location from local files instead of redirecting upstream to jsp. So it **may not be used if there's no *zimbra-nginx* package installed**.

Letsencrypt by default tries to verify a domain using https, so the script should work fine if [*zimbraReverseProxyMailMode*](https://wiki.zimbra.com/wiki/Enabling_Zimbra_Proxy_and_memcached#Protocol_Requirements_Including_HTTPS_Redirect)s is set to *both* or *https*. May not work for *http* only.

This is still a BETA script. Tested on:
* 8.8.8_UBUNTU16
* 8.7.11_RHEL7
* 8.6_RHEL7
* 8.6_UBUNTU12

# Requirements

* zimbra-proxy package is required
* either `certbot` or `letsencrypt` binary is required

## Certbot installation

The preferred way is to install it is by using the wizard [at certbot's home](https://certbot.eff.org/). Choose *None of the above* as software and your operating system. This will allow you to install easily upgradable system packages.

By installing Certbot via packages it automatically creates a cron schedule to renew certificates (at least on Ubuntu). 
We must **disable this schedule** because after the renew we must deploy it in Zimbra. 
So open `/etc/cron.d/certbot` with your favourite editor and **comment the last line**.

# Limitations

* The script doesn't handle multiple domains configured with SNI (see #8). You can still request a single certificate for multiple hostnames.

# Usage

```bash
USAGE: certbot_zimbra.sh < -n | -r | -p > [-d my.host.name] [-e extra.domain.tld] [-x] [-w /var/www]
```

## Command options

Either one of these action is mandatory:

* -n | --new: performs a request for a new certificate
* -r | --renew: deploys certificate, assuming it has just been renewed
* -p | --patch-only: does only nginx patching. Useful to be called before renew, in case nginx templates have been overwritten by an upgrade

Optional arguments:

* -d | --hostname: hostname being requested. If not passed uses `zmhostname`
* -e | --extra-domain: additional domains being requested. Can be used multiple times
* -x | --no-nginx: doesn't check and patch zimbra's nginx. Assumes some other webserver is listening on port 80
* -w | --webroot: if there's another webserver on port 80/443 specify its webroot
* -a | --agree-tos: agree with the Terms of Service of Let's Encrypt (avoids prompt)
* -c | --prompt-confirmation: ask for confirmation before proceding with cert request showing detected hostname
* -s | --services <service_names>: the set of services to be used for a certificate. Valid services are 'all' or any of: ldap,mailboxd,mta,proxy. Default: 'all'
* -z | --no-zimbra-restart: do not restart zimbra after a certificate deployment
* -u | --no-public-hostname-detection: do not detect additional hostnames from domains' zimbraServicePublicHostname. Enabled when -e is passed
* -j | --no-port-check: disable port 80 check

## Zimbra 8.6+ single server example

Run
`./certbot_zimbra.sh -n`
it should do everything by itself, including **restarting zimbra**. 

The domain of the certificate is obtained automatically by running `zmhostname`. If you want do request a specific hostname use the `-d/--hostname` option.

The certificate can be requested with additional hostnames. By default the script loops though all Zimbra domains, fetches 
the `zimbraPublicServiceHostname` attribute and adds the value to the request. If you want to disable this behavior use the `-u/--no-public-hostname-detection` option. 
To indicate additional domains explicitly use the `-e/--extra-domain` option (can be specified multiple times). Note that `-e` disables additional hostname detection. 

## Renewal

EFF suggest to run *renew* twice a day. Since this would imply restarting zimbra, once a day outside workhours should be fine. So in your favourite place (like `/etc/cron.d/zimbracrontab`) schedule the commands below, as suitable for your setup:

```
12 5 * * * root /usr/bin/certbot renew --pre-hook "/usr/local/bin/certbot_zimbra.sh -p" --renew-hook "/usr/local/bin/certbot_zimbra.sh -r "
```
The `--pre-hook` ensures Zimbra's nginx is patched to allow certificate verification. You can omit it if you remember to manually execute that command after an upgrade or
a reinstall which may restore nginx's templates to their default.

The `--renew-hook` parameter has been added since certbot 0.7.0, so check your version before using it. If it's not supported you should get a workaround, but probably the easiest way is to upgrade certbot.

The domain to renew is automatically obtained with `zmhostname`. If you need customized domain name pass the `-d` parameter after `-r`.

## Renewal using Systemd
The example below uses the renew-hook which will only rerun the script if a renewal was successfull and thus only reloading zimbra when needed.

Create a service file eg: /etc/systemd/system/renew-letsencrypt.service

```
[Unit]
Description=Renew Let's Encrypt certificates
After=network-online.target

[Service]
Type=oneshot
# check for renewal, only start/stop nginx if certs need to be renewed
ExecStart=/usr/bin/certbot renew --quiet --agree-tos --pre-hook "/usr/local/bin/certbot_zimbra.sh -p" --renew-hook "/usr/local/bin/certbot_zimbra.sh -r"
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
/usr/local/bin/certbot_zimbra.sh --renew --no-nginx
```
so that it will deploy the certificate in zimbra without patching nginx.

## Creating a patch

**This is now obsolete** 

Since v0.2 patches are embedded into the script. To produce a patch:

1. make a fresh zimbra installation
1. make a copy of the vanilla `/opt/zimbra/conf/nginx/templates` location (i.e. `cp -r /opt/zimbra/conf/nginx/templates /opt/zimbra/conf/nginx/templates_ORIG`)
1. patch the templates file by adding the `.well-known/acme-challenge` location with a webroot (see existing patches)
1. produce a patchfile, making sure to have only one directory below: `cd /opt/zimbra/conf/nginx/ ; diff -Naur templates_ORIG templates > /tmp/zimbra_YOURVERSION.patch`
1. embed the patch in the *patches* section
1. add the version condition in `patch_nginx` function

## Upgrade from v0.1

If you originally requested the certificate with the first version of the script, which used *standalone* method, newer version will fail to renew. This because it
now uses *webroot* mode by patching Zimbra's nginx, making it more simple to work and to mantain.

To check if you have the old method, run `grep authenticator /etc/letsencrypt/renewal/YOURDOMAIN.conf`. If it says *standalone* you got it!

To get it back working, @andrewmur on [issue #43](https://github.com/YetOpen/certbot-zimbra/issues/43#issuecomment-400018603) suggests to stop (and kill, to make sure) nginx
before renewal. This is proven to work (by  him).

A more *definitive* solution would be to try forcing the issue of a new certificate in *webroot* mode, so that it will work with newver versions of the scripts. But this is
untested. ;)


# License

See [LICENSE](LICENSE).

### Disclaimer of Warranty

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

# Author

&copy; Lorenzo Milesi <maxxer@yetopen.it>

Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
