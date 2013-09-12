HTTP Proxy via Cisco telnet session
===================================

This tool was created by unknown russian engineer who worked with Cisco VOIP gateways in restricted
corporate environment (i.e. little or no internet access on workplaces). These Cisco gateways were
typically connected to fast internet uplinks to provide good connectivity, so he decided to use them
for internet browsing.

This tool can establish telnet session with Cisco gateway with specified credentials and then act as
HTTP proxy, listening on local IP and proxying all requests via Cisco WAN interface.

Author is unknown for me, so I decided to upload the code as-is.

Compilation
-----------

1. On Linux:

        gcc telnet2http.c -o testnet2http

2. On Solaris:

        gcc telnet2http.c -lsocket -o testnet2http


Usage
-----

To run this proxy you need Linux or Solaris machine (possibly virtual one).

1. Launch telnet2http:

        ./telnet2http <linux_pc ip> <cisco ip> Loopback0 <AudioCodes_ip> 8080 1 0

2. Enter login credentials:

        login:
        password:
        enable (optional)

3. Set http proxy in the browser:

        http://<linux_ip>:8080
