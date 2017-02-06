# certbot-zimbra
Automated letsencrypt/certbot certificate deploy script for Zimbra hosts.

The script tweaks zimbra's nginx config to allow access of *.well-known* webserver location from local files instead of redirecting upstream to jsp. So it **may not be used if there's no *zimbra-nginx* package installed**.

This is still a BETA script, currently working and tested on 8.7.2_UBUNTU16 only.

# Usage

## Zimbra 8.7 single server

Run
`./certbot_zimbra.sh -n`
it should do everything by itself, including **restarting zimbra**.

## Renewal

EFF suggest to run *renew* twice a day. Since this would imply restarting zimbra, once a day should be fine. So in your favourite place schedule
the commands below, as suitable for your setup:

```
12 5 * * * root /usr/bin/certbot renew --post-hook "/usr/local/bin/certbot_zimbra.sh -r -d $(zmhostname)"
```
The `--post-hook` parameter has been added since certbot 0.7.0, so check your version before using it. If it's not supported you should get a workaround, but probably the easiest way is to upgrade it.

The `-d` option is required in order to avoid domain confirmation prompt.

## If you have another webserver in front

*(It may happen even in the best families)*

Say you have apache in front of zimbra (or listening on port 80 only) just run `certbot-auto` to request the certificate for apache, and when done run
```
/usr/local/bin/certbot_zimbra.sh --renew --no-nginx
```
so that it will deploy the certificate in zimbra without patching nginx.

# License

See [LICENSE](LICENSE).

# Author

&copy; Lorenzo Milesi <maxxer@yetopen.it>

Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
