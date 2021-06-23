* If the error is "ERROR: Unable to validate certificate chain" please update to latest 0.7.12, that will fix it

* Read the [troubleshooting section of the readme](https://github.com/YetOpen/certbot-zimbra#troubleshooting) if any section applies.

* If you have upgraded to v0.7+ from older versions, please check that you have also changed your command line options in crontabs or systemd units and that you are using the correct post-0.7 options if running manually (read the [readme](https://github.com/YetOpen/certbot-zimbra)).

* If the error is "port check failed":

  Please check your zimbra-proxy configuration first: [Troubleshooting/Error:_port_check_failed](https://github.com/YetOpen/certbot-zimbra#error-port-check-failed)
  If you believe zimbra-proxy is configured correctly, please include the output of the following commands:

  ```
  (as zimbra)
  zmprov gs $(zmhostname) zimbraServiceEnabled | grep proxy
  zmprov gs $(zmhostname) zimbraReverseProxyHttpEnabled
  zmprov gs $(zmhostname) | grep Port
  (as root)
  lsof -i -s TCP:LISTEN -a -n | grep zimbra
  ss -nlpt | grep nginx
  ```

* If none of the above has fixed your issue, copy-paste the complete output of the failing command and put it into a code block:
  ```
  place command output here
  ```

  List the versions of your operating system, Zimbra and Certbot-zimbra if not included in the output of certbot-zimbra you copy-pasted.

