# whm-root-ip-guard
## Block WHM root logins from non-allowlisted IPs

A daemon that watches cPanel's WHM login log and blocks any root login
attempt from an IP not in /etc/whm-root-ip-guard/allowed_ips. Blocks are
applied via CSF temp-deny on the WHM port. Cleans up cPanel session
residue from blocked IPs.

Designed to run alongside cPHulk and lfd as defense-in-depth for WHM
root access on shared cPanel hosting servers.

## Install (for EL8)

``yum install https://github.com/wbdv/whm-root-ip-guard/releases/download/v1.0.0/whm-root-ip-guard-1.0.0-2.el8.noarch.rpm``

Edit ``/etc/whm-root-ip-guard/allowed_ips`` and add your admin IPs (one per line, CIDR supported).

``
chmod 600 /etc/whm-root-ip-guard/allowed_ips
systemctl enable --now whm-root-ip-guard
``

The service will REFUSE to start with an empty allowlist to prevent locking yourself out of WHM.

Watch it with ``journalctl -u whm-root-ip-guard.service -f``
