# certbot-zimbra
Automated Certbot (ACME) certificate script for Zimbra.

[![asciicast](https://asciinema.org/a/219713.svg)](https://asciinema.org/a/219713)

## Warning: when upgrading from Certbot 1.x to 2.x
[Read this](#zmcertmgr-certificate-and-private-key-do-not-match-expecting-an-rsa-key)

# Installation

## Requirements

- bash, capsh, lsof or ss, openssl, grep, sed (GNU), gawk (GNU)
- ca-certificates (Debian/Ubuntu) or pki-base (RHEL/CentOS)
- Zimbra: zmhostname, zmcontrol, zmproxyctl, zmprov, zmcertmgr
- zimbra-proxy installed and working or an alternate webserver configured for ACME webroot
- Certbot >=0.19.0 in PATH

## Certbot installation

The preferred way is to install it is by using the wizard [at Certbot's home](https://certbot.eff.org/). Select "Other" as software. This will allow you to install easily upgradable system packages.

## certbot-zimbra installation

Download the latest release and install it (copy the latest URL from the Releases tab):

```
wget --content-disposition https://github.com/YetOpen/certbot-zimbra/archive/0.7.13.tar.gz
tar xf certbot-zimbra-0.7.13.tar.gz
cd certbot-zimbra-0.7.13
./install all
```
Or from the master branch (unstable): [certbot-zimbra-master.tar.gz](https://github.com/YetOpen/certbot-zimbra/archive/master.tar.gz)

# Usage

[docs/cli-help.txt](docs/cli-help.txt)

## Automatic hostname detection
If no `-e` is given, the script will figure out the additional domain(s) to add to the certificate as SANs via `zmprov gd $domain zimbraPublicServiceHostname zimbraVirtualHostname`.
This can be skipped with `-u/--no-public-hostname-detection`, in which case only the CN from `zmhostname` or `-H/--hostname` will be used.

Only one certificate will be issued including all the found hostnames. The primary host will always be `zmhostname` or the one passed via `-H|--hostname`.


# Zimbra 8.6+ single server example

## Preparation

The script needs some prerequisites. They are listed under Installation/Requirements. The script will run a prerequisite check on startup and exit if anthing is missing.

In addition, there are different modes of operation, depending on your environment (proxy server):

### Zimbra-proxy mode (the default)

Uses zimbra-proxy for the ACME HTTP-01 challenge. Zimbra-proxy must be enabled and running. This is the preferred mode.

When starting, the script checks the status of zmproxyctl and checks if a process with the name "nginx" and user "zimbra" is listening on port zimbraMailProxyPort (obtained via zmprov).

The port can optionally be overridden with `-P/--port` or the port check skipped entirely with `-j/--no-port-check` if you are absolutely sure everything is set up correctly. The zmproxyctl status check can't be skipped.

Patches are applied to nginx's templates to serve .well-known from the webroot, after which nginx is restarted.

Everything, including new certificate requests, can be done via certbot-zimbra in this mode.

### Alternate webserver mode

Is selected with `-x/--no-nginx`. Requires `-P/--port` and `-w/--webroot`. `--port` is checked for listening status. All zimbra-proxy checks are skipped.

Can be used in case you don't have zimbra-proxy enabled but have a different webserver as a reverse proxy in front of Zimbra. 

You'll have to configure the webserver to serve `/.well-known/acme-challenge` from a webroot somewhere in the filesystem, some examples for this can be found [here.](https://www.hiawatha-webserver.org/forum/topic/2275)

Renewal can be done as per instructions below, but `--pre-hook` can be omitted.

## First run (obtaining a new certificate)

If you don't yet have a ACME certificate, you'll need to obtain one first. The script can do everything for you, including deploying the certificate and restarting Zimbra.

Run
`./certbot_zimbra.sh --new --prompt-confirm`

This will do all pre-run checks, patch Zimbra's nginx, run Certbot to obtain the certificate, test it, deploy it and restart Zimbra. Passing `-c|--prompt-confirm` means the script will prompt you for confirmation before actions (restarting Zimbra's nginx, running Certbot, deploying the certificate, restarting Zimbra,...).

Certbot will also ask you some information about the certificate interactively, including an e-mail to use for expiry notifications. Please use a valid e-mail for this as should the automatic renewal fail for any reason, this is the way you'll get notified.

The domain of the certificate is obtained automatically using `zmhostname`. If you want to request a specific hostname use the `-H/--hostname` option. This domain will be the DN of the certificate.

The certificate can be requested with additional hostnames/SANs. By default the script fetches `zimbraPublicServiceHostname` and `zimbraVirtualHostname` attributes from all domains and if present, adds those to the certificate SANs to be requested. If you want to disable this behavior use the `-u/--no-public-hostname-detection` option.

**Note:** Let's Encrypt has a limit of a maximum of 100 domains per certificate at the time of this writing: [Rate Limits](https://letsencrypt.org/docs/rate-limits/)

To indicate additional domains explicitly use the `-e/--extra-domain` option (can be specified multiple times). Note that `-e` also disables additional hostname detection. 

Additional options can be passed directly to Certbot with `-L | --letsencrypt-params`. The option must be repeated for each Certbot option. For example, if you want 4096-bit certificates, add `-L "--rsa-key-size" -L "4096"`. Refer to Certbot's documentation for more information.

Note: the naming of `-L|--letsencrypt-params` dates to when Certbot was still a script named "letsencrypt", it would make more sense to name it e.g. `--certbot-params` but changing it would break backwards compatibility.

## Running noninteractively

When retrieving a new certificate using `-n|--new`, Certbot runs interactively. If you want to run it noninteractively, you can pass `-N/--noninteractive` which will be passed on to Certbot. Also passing `-q/--quiet` will suppress the status output of the script.
Only do this if you're absolutely sure what you're doing, as this leaves you with no option to verify the detected hostnames, specify the certificate e-mail etc. `-N/--noninteractive` may be combined with `-q | --quiet` and/or `-L | --letsencrypt-params` to pass all the parameters to Certbot directly, e.g. in scripts to do automated testing with staging certificates.

## Renewal

When obtaining a new certificate with `certbot-zimbra.sh --new`, the script will add itself as `pre_hook` and `renew_hook` (equivalent to `--pre-hook` and `--deploy-hook`) to Certbot's certificate renewal configuration. Certbot will then automatically run hooks when renewing the certificate, the hooks will deploy the certificate and restart Zimbra.

Certbot will install a crontab or systemd timer to automatically renew certificates close to expiring. You will likely want to modify the time at which it runs, or else Certbot might restart Zimbra at a random time during the day, which might mean downtime when you don't want it! Read Certbot's documentation to see how to do this (modify the default Certbot crontab or systemd timer).

Note: previously this readme instructed to disable Certbot's crontab or timer and install a script-specific one. This is not required, if you are still using the custom cronjob or timer, you can remove it, reenable stock Certbot ones (though you will probably want to modify the time at which they execute) and [manually add hooks to Certbot](#manually-adding-hooks-to-certbot).

### Renewal failure notifications

Make sure you have a working mail setup (valid alias for root or similar). Cron can send script output to mail if the crontab is correctly configured. Configuring systemd timers to send mail is harder but possible.

### Manually adding hooks to Certbot

If adding hooks fails during script execution, or if you requested a new certificate without using the script, you can add hooks manually.

#### Certbot >=2.3.0:
```
certbot reconfigure --cert-name "cert.name" --pre-hook "/usr/local/bin/certbot_zimbra.sh -p" --deploy-hook "/usr/local/bin/certbot_zimbra.sh -d"
```
Replace `cert.name` with the name of the certificate, you can see it using `certbot certificates`.
If you changed the path where the script is installed, change the path here accordingly.

#### Older certbot versions:
Edit `/etc/letsencrypt/renewal/cert.name.conf` (replace cert.name with the name of your certificate) and modify section `[renewalparams]` to contain:
```
pre_hook = /usr/local/bin/certbot_zimbra.sh -p
renew_hook = /usr/local/bin/certbot_zimbra.sh -d
```
If you changed the path where the script is installed, change the path here accordingly.

## Alternate webserver mode

See [Preparation](#preparation): [Alternate webserver](#alternate-webserver)

### Alternate webserver, manual Certbot new certificate request

As above, but the first certificate can be obtained manually with Certbot outside of this script with the authenticator plugin of your choice. Refer to Certbot documentation for first certificate request information.

After the certificate has been obtained, `-d/--deploy-only` can be used to deploy the certificate in Zimbra (to use it in services other than HTTP also) and renewal can be done as usual with `--deploy-hook`.

### No proxy server (manual certificate request with alternate authentication method)

Since the HTTP authentication method can't be used, an alternate method like DNS will have to be used. Refer to Certbot documentation on obtaining certificates without HTTP.

Deployment and renewal can be done as in the [Alternate webserver manual mode](#alternate-webserver-manual-certbot-new-certificate-request).

### Manual certificate request example

Say you have Apache in front of Zimbra (or listening on port 80 only) just run Certbot by hand with appropriate options to request the certificate for Apache, and when done run
```
/usr/local/bin/certbot_zimbra.sh --deploy-only
```
so that it will deploy the certificate in Zimbra.

Set up renewal hooks as above, but without `--pre-hook`.

# Troubleshooting

## Error: port check failed

This usually means zimbra-proxy is misconfigured. In the default case (without port overrides) the script checks if zimbra-proxy's nginx is listening on "zimbraMailProxyPort" (can be read with zmprov, port 80 in most cases). If this check fails, zimbra-proxy is misconfigured, not enabled, not started or you have a custom port configuration and didn't tell the script via port override parameters.

Zimbra's proxy guide ([Zimbra Proxy Guide](https://wiki.zimbra.com/wiki/Zimbra_Proxy_Guide)) is usually quite confusing for a novice and may be difficult to learn. For this we have a quick [Zimbra proxy configuration for certbot-zimbra guide](https://github.com/YetOpen/certbot-zimbra/wiki/Zimbra-proxy-configuration-for-Certbot-Zimbra) to get you up and running quickly. Still, you should get to know zimbra-proxy and configure it according to your own needs.

## Error: unable to parse certbot version

This is caused by Certbot expecting user input when the script tried to run it to detect its version. To fix this, run `certbot` on the command line manually and answer any questions it has or fix any errors. After this the script should work fine.

Newer versions of the script print a more descriptive error message if ran with `-c|--prompt-confirm`.

## Certbot failures

## General Certbot troubleshooting

Check that you have an updated version of Certbot installed. If you have installed Certbot from your operating system's repositories, they may be out of date, especially on non-rolling distributions. If your distribution's Certbot is outdated, remove the system packages and install it the way that Certbot recommends for your operating system on their installation page, or a different way that you prefer.

Check certificate statuses with `certbot certificates`. Remove any duplicate or outdated certificates for the same domain names.

Check that ports 80 and 443 are open and accessible from the outside and check that your domain points to the server's IP. Basically troubleshoot Certbot as if you weren't using certbot-zimbra.

## `cat: /etc/ssl/certs/2e5ac55d.0: No such file or directory` OR `Can't find "DSTRootCAX3"` OR `Unable to validate certificate chain: O = Digital Signature Trust Co., CN = DST Root CA X3`

Let's Encrypt's "DST Root CA X3" expired in September 2021. Already issued certificates were cross-signed with both the old "DST Root CA X3" and new "ISRG Root X1" chains. Due to the way certbot-zimbra parses certificate files, it may cause certbot-zimbra to use the wrong chain's CA certificate when deploying the certificate. See issue #140.

Procedure to fix it:

- make sure you have latest ca-certificates (Debian/Ubuntu) or pki-base (RHEL/CentOS) package (do a apt-get dist-upgrade/upgrade/install ca-certificates or equivalent yum/dnf command), this will make sure you have the "ISRG Root X1" CA in the system-wide CA store
- install `certbot_zimbra.sh` >=0.7.13
- run `/usr/local/bin/certbot_zimbra.sh -d` to redeploy the certificate
- if unsuccessful, force a renewal with `certbot renew --force-renewal --preferred-chain "ISRG Root X1" --cert-name "zimbra-cert-name"` Replace zimbra-cert-name with the name of your existing cert, you can find it with `certbot certificates`.
- if successful, run `/usr/local/bin/certbot_zimbra.sh -d` to deploy the new cert.

`certbot_zimbra.sh` >=0.7.13 includes a fix for parsing the chain and should work better. If simply redeploying the certificate doesn't work, please open a new issue with your problem. `--preferred-chain` is a workaround but should not be required, if it fixes your problem, there is still an issue with the script.

## zmcertmgr certificate and private key do not match ("expecting an rsa key")

Certbot v2.0.0 switched to ECDSA private keys by default for newly issued certificates, which Zimbra's zmcertmgr doesn't support. See [Certbot docs](https://github.com/certbot/certbot/blob/caad4d93d048d77ede6508dd42da1d23cde524eb/certbot/docs/using.rst#id34)

It may be possible to [patch zmcertmgr](https://forums.zimbra.org/viewtopic.php?f=15&t=69645&p=301580) to support ECDSA keys, but this is not officially supported or widely tested.

Certbot-zimbra >=0.7.13 will auto-detect if Certbot is >=2.0.0 and apply options while requesting a new certificate to obtain a RSA key.

Existing certificates will continue to be renewed with their current key type, **unless `certbot renew` is ran with `--force-renewal`**, in which case it will switch to ECDSA, which will cause this issue.

### Already renewed with ECDSA key, which failed to deploy
If you used Certbot >=2 with certbot-zimbra <0.7.13, or upgraded Certbot from 1.x to 2.x, and Certbot has already renewed with an ECDSA key, there are two options:

- `certbot renew --key-type rsa --rsa-key-size 4096 --cert-name "zimbra-cert-name" --force-renewal` replace zimbra-cert-name with the name of the existing certificate, you can find it with `certbot certificates`. You can also change the key size to one that you prefer. If renewal is successful, redeploy the certificate with `/usr/local/bin/certbot_zimbra.sh -d`.
- update to certbot-zimbra >=0.7.13 and rerequest the certificate with `certbot-zimbra --new`, and add all the options you used with the original `--new` invocation, else your certificate may get replaced with one with different CN and SANs.

### Just upgraded Certbot 1.x to 2.x, not renewed yet, still using RSA key
If you have just upgraded to Certbot >=2.0.0 but the certificate has not yet renewed (is still RSA) you can set it to force a RSA key on renewal. This is not required if you're not going to run `certbot renew --force-renewal` but is good to have just to be safe.

Certbot >=2.3.0: `certbot reconfigure --cert-name "zimbra-cert-name" --key-type rsa`

Certbot <2.3.0: edit `/etc/letsencrypt/renewal/zimbra-cert-name.conf`, under `[renewalparams]` add `key_type = rsa`

On next scheduled renewal the set key type will be honored.

# Notes

## Notes on zimbraReverseProxyMailMode 

Let's Encrypt by default tries to verify a domain using http, so the script should work fine if [zimbraReverseProxyMailMode](https://wiki.zimbra.com/wiki/Enabling_Zimbra_Proxy_and_memcached#Protocol_Requirements_Including_HTTPS_Redirect) is set to http, both, redirect or mixed. It won't work if set to https only. This is due to Certbot deprecating the tls-sni-01 authentication method and switching to HTTP-01. https://letsencrypt.org/docs/challenge-types/

## Limitations

The script doesn't handle multiple domains configured with SNI (see #8). You can still request a single certificate for multiple hostnames.

## Upgrade from v0.1

If you originally requested the certificate with the first version of the script, which used *standalone* method, newer version will fail to renew. This because it
now uses *webroot* mode by patching Zimbra's nginx, making it more simple to work and to mantain.

To check if you have the old method, run `grep authenticator /etc/letsencrypt/renewal/YOURDOMAIN.conf`. If it says *standalone* it uses the old method.

To update to the new "webroot" method you can simply run `certbot-zimbra.sh -n -c -L "--force-renewal"`. This will force renew your existing certificate and save the new authentication method. It'll also ask you for deploying the new certificate in Zimbra. You can also manually modify the config file in /etc/letsencrypt/renewal/, while not recommended, is detailed here: https://community.letsencrypt.org/t/how-to-change-certbot-verification-method/56735

## How it works
This script uses zimbra-proxy's nginx to intercept requests to `.well-known/acme-challenge` and pass them to a custom webroot folder. To do this, we patch the templates Zimbra uses to build nginx's configuration files.
The patch is simple, we add this new section to the end of the templates:
```
    # patched by certbot-zimbra.sh
    location ^~ /.well-known/acme-challenge {
        root $WEBROOT;
    }
```
`$WEBROOT` is either `/opt/zimbra/data/nginx/html` (default) or the path specified by the command line option.
After this we restart zmproxy to apply the patches.

We then pass this webroot to Certbot with the webroot plugin to obtain the certificate.

After the certificate has been obtained successfully we stage the certificates in a temporary directory, find the correct CA certificates from the system's certificate store and build the certificate files in a way Zimbra expects them. If verification with zmcertmgr succeeds we deploy the new certificates, restart Zimbra and clean up the temporary files.

After the first patching the script will check if the templates have been already patched and if so, it skips the patching and zmproxy restart steps. This is useful in cron jobs where even if we upgrade Zimbra and wipe out the patched templates they'll be repatched automatically.

The use of `--deploy-only` from `--deploy-hook` in cron jobs will only deploy the certificates if a renewal was successful. Thus Zimbra won't be unnecessarily restarted if no renewal was done.

## Certbot certificate privacy/security notes

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

&copy; Lorenzo Milesi <maxxer@yetopen.com>

## Contributors
- Jernej Jakob @jjakob
- @eN0RM
- Pavel Pulec @pulecp
- Antonio Prado
- @afrimberger
- @mauriziomarini

*if you are a contributor, add yourself here (and in the code)*


Feedback, bugs, PR are welcome on [GitHub](https://github.com/yetopen/certbot-zimbra).
