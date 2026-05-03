# whm-root-ip-guard
## Block WHM root logins from non-allowlisted IPs

A daemon that watches cPanel's WHM login log and blocks any root login
attempt from an IP not in /etc/whm-root-ip-guard/allowed_ips. Blocks are
applied via CSF temp-deny on the WHM port. Cleans up cPanel session
residue from blocked IPs.

Designed to run alongside cPHulk and lfd as defense-in-depth for WHM
root access on shared cPanel hosting servers.

## Install (for EL8)

``yum install ``

Edit ``/etc/whm-root-ip-guard/allowed_ips`` and add your admin IPs (one per line, CIDR supported).
