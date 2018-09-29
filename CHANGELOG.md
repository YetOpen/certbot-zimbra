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
