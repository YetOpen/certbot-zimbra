# certbot-zimbra
Automated letsencrypt/certbot certificate deploy script for Zimbra hosts.

The script tweaks zimbra's nginx config to allow access of *.well-known* webserver location from local files instead of redirecting upstream to jsp. So it **may not be used if there's no *zimbra-nginx* package installed**.

Letsencrypt by default tries to verify a domain using https, so the script should work fine if [*zimbraReverseProxyMailMode*](https://wiki.zimbra.com/wiki/Enabling_Zimbra_Proxy_and_memcached#Protocol_Requirements_Including_HTTPS_Redirect)s is set to *both* or *https*. May not work for *http* only.

This is still a BETA script. Tested on:
* 8.7.11_UBUNTU16
* 8.6_RHEL7
* 8.6_UBUNTU12

# Requirements

* zimbra-proxy package is required (for !*https* mode)
* of course either `certbot` or `letsencrypt` binary is required

## Certbot/Letsencrypt installation

The preferred way is to install it is by using the wizard [at certbot's home](https://certbot.eff.org/). Choose *None of the above* as software and your operating system. This will allow you to install easily upgradable system packages.

By installing Certbot via packages it automatically creates a cron schedule to renew certificates. We must **disable this schedule** because after the renew we must deploy it in Zimbra. So open `/etc/cron.d/certbot` with your favourite editor and **comment the last line**.

# Limitations

* The script doesn't handle multiple certificates on the same server. See #8 and #17

# Usage

## Zimbra 8.7 single server

Run
`./certbot_zimbra.sh -n`
it should do everything by itself, including **restarting zimbra**.

## Renewal

EFF suggest to run *renew* twice a day. Since this would imply restarting zimbra, once a day outside workhours should be fine. So in your favourite place (like `/etc/cron.d/zimbracrontab`) schedule the commands below, as suitable for your setup:

```
12 5 * * * root /usr/bin/certbot renew --renew-hook "/usr/local/bin/certbot_zimbra.sh -r -d $(/opt/zimbra/bin/zmhostname)"
```
The `--renew-hook` parameter has been added since certbot 0.7.0, so check your version before using it. If it's not supported you should get a workaround, but probably the easiest way is to upgrade it.

The `-d` option is required in order to avoid domain confirmation prompt by the script.

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
ExecStart=/usr/bin/certbot renew --quiet --agree-tos --renew-hook "/usr/local/bin/certbot_zimbra.sh -r -d $(/opt/zimbra/bin/zmhostname)"
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

Since v0.2 patches are embedded into the script. To produce a patch:

1. make a fresh zimbra installation
1. make a copy of the vanilla `/opt/zimbra/conf/nginx/templates` location (i.e. `cp -r /opt/zimbra/conf/nginx/templates /opt/zimbra/conf/nginx/templates_ORIG`)
1. patch the templates file by adding the `.well-known` location with a webroot, and removing it from the location which must go upstream to jsp (see existing patches)
1. produce a patchfile, making sure to have only one directory below and escape $: `cd /opt/zimbra/conf/nginx/ ; diff -Naur templates_ORIG templates > /tmp/zimbra_YOURVERSION.patch`
1. embed the patch in the *patches* section
1. add the version condition in `patch_nginx` function

# License

See [LICENSE](LICENSE).

### Disclaimer of Warranty

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

# Author

&copy; Lorenzo Milesi <maxxer@yetopen.it>

Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
