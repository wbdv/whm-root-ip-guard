Name:           whm-root-ip-guard
Version:        1.0.0
Release:        2%{?dist}
Summary:        Block WHM root logins from non-allowlisted IPs

License:        MIT
URL:            https://reqad.net/whm-root-ip-guard
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

# Build-time only
BuildRequires:  systemd-rpm-macros

# Runtime requirements
Requires:       python3 >= 3.6
Requires:       python3-inotify_simple
Requires:       systemd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
A daemon that watches cPanel's WHM login log and blocks any root login
attempt from an IP not in /etc/whm-root-ip-guard/allowed_ips. Blocks are
applied via CSF temp-deny on the WHM port. Cleans up cPanel session
residue from blocked IPs.

Designed to run alongside cPHulk and lfd as defense-in-depth for WHM
root access on shared cPanel hosting servers.

%prep
%setup -q

%build
# noarch, nothing to build

%install
rm -rf %{buildroot}

# Daemon
install -D -m 0755 whm_root_ip_guard.py %{buildroot}%{_sbindir}/whm_root_ip_guard.py

# Config
install -d -m 0755 %{buildroot}%{_sysconfdir}/whm-root-ip-guard
install -D -m 0600 allowed_ips.example %{buildroot}%{_sysconfdir}/whm-root-ip-guard/allowed_ips.example

# systemd units
install -D -m 0644 whm-root-ip-guard.service %{buildroot}%{_unitdir}/whm-root-ip-guard.service
install -D -m 0644 whm-root-ip-guard-alert.service %{buildroot}%{_unitdir}/whm-root-ip-guard-alert.service

# Documentation
install -D -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md

%files
%{_sbindir}/whm_root_ip_guard.py
%{_unitdir}/whm-root-ip-guard.service
%{_unitdir}/whm-root-ip-guard-alert.service
%dir %{_sysconfdir}/whm-root-ip-guard
%config(noreplace) %{_sysconfdir}/whm-root-ip-guard/allowed_ips.example
%doc %{_docdir}/%{name}/README.md

%post
%systemd_post whm-root-ip-guard.service

if ! command -v csf >/dev/null 2>&1; then
    echo "WARNING: csf binary not found. The daemon requires CSF." >&2
fi

# First-install message — don't auto-start because the allowlist isn't configured yet
if [ $1 -eq 1 ]; then
    echo ""
    echo "==========================================================="
    echo " whm-root-ip-guard installed."
    echo ""
    echo " Before starting the service:"
    echo "   1. cp /etc/whm-root-ip-guard/allowed_ips.example \\"
    echo "         /etc/whm-root-ip-guard/allowed_ips"
    echo "   2. Edit /etc/whm-root-ip-guard/allowed_ips and add"
    echo "      your admin IPs (one per line, CIDR supported)."
    echo "   3. chmod 600 /etc/whm-root-ip-guard/allowed_ips"
    echo "   4. systemctl enable --now whm-root-ip-guard"
    echo ""
    echo " The service will REFUSE to start with an empty allowlist"
    echo " to prevent locking yourself out of WHM."
    echo "==========================================================="
fi

%preun
%systemd_preun whm-root-ip-guard.service

%postun
%systemd_postun_with_restart whm-root-ip-guard.service

%changelog
* Sat May 02 2026 Daniel Toma <dt@webdev.ro> - 1.0.0-1
- Initial package
