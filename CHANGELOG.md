## v0.7.8-beta

* Close fd used for locking on exit, workaround for issue #89
* Remove lock file too (#89)
* Tell user he can remove the lockfile
* Custom ss check, as it doesn't contain the user. Fix #91
* Add troubleshooting section to readme
* Add issue template
* Fix formatting of issue template
* Add "how it works" explanation
* Add certbot version check
* Remove lock file only if we successfully obtained a lock (#89)
* On quiet redirect to /dev/stdout instead of /dev/tty, also redirect stderr
* Rewrite find_additional_public_hostnames to be much faster (#95)
* README: update section describing additional hostname detection
* Some extra quoting where possible
* Close locking fd when running zmproxyctl/zmcontrol restart (fix #89)
* Remove unneeded commented proxy service check
* Add nonstandard zimbraMailProxyPort warning with prompt (issue #90)
* Wrap very long lines
* Update TESTING: moved -e to tested
* certbot: use --cert-name instead of --expand (issue #97)
* Change exit status for prompts, fix typos
* Changed prompt to allow not including detected SANs
* Add prompt before running certbot
* Remove redundant QUIET check before prompts
* Fix prompts exit status in deploy stage
* Create webroot even without prompt confirm enabled

## v0.7.7-beta

* fix --extra-domain parsing and additional domain detection (#87)

## v0.7.6-beta

* fix file perms being lost when copying privkey to commercial.key (#84)
* make tempdir in /run, obtain exclusive lock, move init funcs into bootstrap
* Add more comprehensive checks for zimbra-proxy (#83)
* add platform detection to bootstrap using zimbra's get_plat_tag.sh
* use ZMPROV_OPTS for all zmprov with "-l" (LDAP is faster than SOAP)
* prefix all error messages with "Error:"
* Add additional constraint checks for --port, --no-port-check and --no-nginx
* show long and short options in all messages
* Update README.md
* move certificate staging to TEMPDIR, don't prompt for zimbra restart if -z is set
* add some status output when run as --deploy-hook
* fix #85
* add more status output during public service hostname detection

## v0.7.5-beta

* fix #84, further fixes to CentOS

## v0.7.4-beta

* fix #84, add missing quotes around $issuer

## v0.7.3-beta

* Fix typo, --deploy tested working on Ubuntu
* Update README.md, TESTING
* Implement proper deploy hook domain env var checking (#17, jjakob#4), fix --extra-domain typos, update usage, add --help
* fix #79: support RHEL/CentOS pki-base, add dependency check

## v0.7.2-alpha

* Improve cron and systemd documentation
* Fix dependency check not working (#8)
* Fix ss syntax (#74), limit lsof check to listening state only

## v0.7.0-alpha

* This is a HUGE rewrite! The most notably changes are two parameters rename: `-r/--renew-only` has become `-d/--deploy-only`, 
and `-d` is now `-H`. Features should be the same

## v0.5.0-beta

* Patch nginx using sed instead of patch strings! Thanks to @eN0RM
* Added a check for port 80 being used by nginx #58

## v0.4.0-beta

* Added ability to request certificate for more than one domain thanks to @pulecp #53 
* Automatically get zimbraPublicServiceHostname hosts from domain and add them to the cert #54
* Removed domain confirmation prompt for new requests. Just use `zmhostname` by default

## v0.3.0-alpha

* Fix *prepare certificate*, thanks to Antonio Prado (#44)
* Added patches for Zimbra 8.8.8

## v0.2.2-alpha

* Added --patch-only option to only patch nginx, to be called before renewal
* Added --no-zimbra-restart option, thanks to Pavel Pulec
* Added --services options, thanks to Pavel Pulec
* (hopefully) Finally fixed patch detection, thanks to Pavel Pulec
* Added --agree-tos option, thanks to Pavel Pulec

## v0.2.1-alpha

* Less invasive patches (taken from @afrimberger's 619f6e0) #22
* Fixed patch already applied test (thanks to @mauriziomarini) #24 

## v0.2-alpha

Half rewrite of the first version:
* patches are now embedded: less problems
* patching is done via if/elif, so if there's no newer patch assume the previous is good. Less problems
* now patching templates instead of *current* nginx files, so patches survives zimbra restart. Less problems
* now patching all nginx templates instead of just http/https: all cert requests goes straight to nginx. Less variations, less problems
* improved README documentation

## v0.1

Initial version
