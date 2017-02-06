# certbot-zimbra
Automated letsencrypt/certbot certificate deploy script for Zimbra hosts.

The script tweaks zimbra's nginx config to allow access of *.well-known* webserver location from local files instead of redirecting upstream to jsp. So it **may not be used if there's no *zimbra-nginx* package installed**.

This is still a BETA script, currently working and tested on 8.7.2_UBUNTU16 only.

# Requirements

* zimbra-proxy package is required
* currently working only if [*zimbraMailMode*](https://wiki.zimbra.com/wiki/CLI_zmtlsctl_to_set_Web_Server_Mode) is set to *both*

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

### Disclaimer of Warranty

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

# Author

&copy; Lorenzo Milesi <maxxer@yetopen.it>

Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
