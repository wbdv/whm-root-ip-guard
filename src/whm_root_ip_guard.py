#!/usr/bin/env python3
"""
WHM root login IP guard.

Watches /usr/local/cpanel/logs/login_log for root login attempts.
If an attempt (success or failure) comes from an IP not in the allowlist,
blocks the IP via CSF and removes any session residue.

Allowlist: /etc/whm_root_allowed_ips (one IP or CIDR per line, # comments)
Reload allowlist with: kill -HUP <pid>

Requires: inotify_simple (pip3 install inotify_simple or better
          /usr/bin/python3 -m pip install inotify_simple)
Tested on: Python 3.6.8 (Rocky Linux 8 system python)
"""

import re
import os
import sys
import time
import json
import signal
import logging
import logging.handlers
import subprocess
import ipaddress
from pathlib import Path
import argparse

try:
    from inotify_simple import INotify, flags
except ImportError:
    sys.stderr.write("install inotify_simple: pip3 install inotify_simple\n")
    sys.exit(1)

# ---- Config ----------------------------------------------------------------

LOG_FILE        = "/usr/local/cpanel/logs/login_log"
ALLOWLIST_FILE  = "/etc/whm-root-ip-guard/allowed_ips"
SESSIONS_DIR    = "/var/cpanel/sessions/raw"
CSF_BIN         = "/usr/sbin/csf"
BLOCK_DURATION  = 3600                     # seconds; 0 = permanent
WHM_PORT        = 2087
SYSLOG_TAG      = "whm-root-ip-guard"

# Regex MUST be verified against your cPanel version's login_log format.
# Run: tail -f /usr/local/cpanel/logs/login_log
# while logging in (success and failure) as root and confirm fields match.
LOGIN_RE = re.compile(
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'\S+\s+'                              # log level
    r'\[(?P<service>\w+)\]\s+'             # whostmgrd / cpaneld / etc.
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+'  # source IP
    r'-\s+'
    r'(?P<user>\S+)\s+'                    # username
    r'.*?'
    r'\b(?P<result>SUCCESS|FAILED|DEFERRED)\b',
    re.IGNORECASE,
)

# ---- Logging ---------------------------------------------------------------

log = logging.getLogger(SYSLOG_TAG)
log.setLevel(logging.INFO)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
log.addHandler(sh)

# ---- Allowlist -------------------------------------------------------------

class Allowlist:
    """Reloadable IP/CIDR allowlist. Refuses to be empty."""

    def __init__(self, path):
        self.path = path
        self.networks = []
        # Initial load must succeed and be non-empty, or we exit.
        if not self._load_strict():
            log.error(f"allowlist {path} missing or empty - refusing to start")
            sys.exit(2)

    def _load_strict(self):
        """Try to load. Return True on success (file exists, has valid entries)."""
        try:
            with open(self.path) as f:
                content = f.read()
        except FileNotFoundError:
            return False
        except (IOError, OSError) as e:
            log.error(f"cannot read {self.path}: {e}")
            return False

        new = []
        for n, line in enumerate(content.splitlines(), 1):
            entry = line.split('#', 1)[0].strip()
            if not entry:
                continue
            try:
                new.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log.warning(f"{self.path}:{n}: bad entry: {entry!r}")

        if not new:
            return False

        self.networks = new
        return True

    def reload(self):
        """SIGHUP-triggered reload. Keeps existing list on failure."""
        old_count = len(self.networks)
        old_networks = list(self.networks)

        if self._load_strict():
            log.info(f"reloaded {self.path}: {old_count} -> {len(self.networks)} networks")
        else:
            self.networks = old_networks  # restore (paranoid; _load_strict shouldn't have mutated)
            log.error(
                f"refused to reload {self.path} (missing or empty) - "
                f"keeping existing {old_count} networks in memory"
            )

    def contains(self, ip_str):
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip in n for n in self.networks)


# ---- CSF + session helpers -------------------------------------------------

def is_already_blocked(ip):
    """Check whether IP is already known to CSF (any list)."""
    try:
        result = subprocess.run(
            [CSF_BIN, "-g", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        log.error(f"csf -g failed for {ip}: {e}")
        return False

    output = (result.stdout + result.stderr).decode('utf-8', errors='replace')

    # Positive signals that the IP is currently blocked:
    # - "Temporary Blocks: IP:<ip>"  -> in tempban
    # - "DENYIN" or "DENYOUT" chain entries -> in iptables deny chains
    #   (covers both temp and permanent blocks)
    if f"Temporary Blocks: IP:{ip}" in output:
        return True
    if "DENYIN" in output or "DENYOUT" in output:
        return True

    return False


def block_ip(ip, reason):
    """Block an IP via CSF temp deny on the WHM port."""
    if is_already_blocked(ip):
        log.info(f"{ip} already blocked, skipping")
        return

    cmd = [CSF_BIN, "-td", ip, str(BLOCK_DURATION), "-p", str(WHM_PORT), reason]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        log.error(f"csf timed out for {ip}")
        return
    except OSError as e:
        log.error(f"csf failed to execute for {ip}: {e}")
        return

    stdout = result.stdout.decode('utf-8', errors='replace').strip()
    stderr = result.stderr.decode('utf-8', errors='replace').strip()

    if result.returncode != 0:
        log.error(
            f"csf failed for {ip}: rc={result.returncode} "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
        return

    log.warning(f"blocked {ip} for {BLOCK_DURATION}s ({reason})")


def kill_sessions_from_ip(ip):
    """Remove session files that originated from this IP."""
    sd = Path(SESSIONS_DIR)
    if not sd.is_dir():
        return
    needle = f"ip_address={ip}"
    killed = 0
    for p in sd.iterdir():
        if not p.is_file():
            continue
        try:
            with open(p) as f:
                content = f.read()
        except (IOError, OSError):
            continue
        # Sessions are key=value, one per line
        if any(line.strip() == needle for line in content.splitlines()):
            try:
                p.unlink()
                killed += 1
            except OSError as e:
                log.error(f"can't remove {p}: {e}")
    if killed:
        log.warning(f"removed {killed} session file(s) for {ip}")

# ---- Login event handling --------------------------------------------------

def handle_event(user, ip, result, allowlist):
    if user != 'root':
        return
    if allowlist.contains(ip):
        log.info(f"root {result} from {ip} (allowed)")
        return

    log.warning(f"root {result} login from non-allowed {ip} - blocking")
    block_ip(ip, f"WHM root {result} from non-allowed IP")
    # Remove session residue regardless of success/fail; if attacker did
    # get a token, this kills it. If they didn't, this is harmless cleanup.
    kill_sessions_from_ip(ip)

# ---- Log tailer with rotation handling -------------------------------------

def tail(path):
    """Yield new lines from path, surviving rotation."""
    inotify = INotify()
    while True:
        try:
            f = open(path, 'r', errors='replace')
        except FileNotFoundError:
            log.error(f"{path} not found, retrying in 5s")
            time.sleep(5)
            continue

        f.seek(0, os.SEEK_END)
        try:
            inode = os.fstat(f.fileno()).st_ino
        except OSError:
            f.close()
            continue

        try:
            wd = inotify.add_watch(path, flags.MODIFY | flags.MOVE_SELF | flags.DELETE_SELF)
        except OSError as e:
            log.error(f"inotify add_watch failed: {e}")
            f.close()
            time.sleep(5)
            continue

        try:
            buf = ""
            while True:
                chunk = f.read()
                if chunk:
                    buf += chunk
                    *lines, buf = buf.split('\n')
                    for line in lines:
                        yield line
                    continue

                events = inotify.read(timeout=1000)
                rotated = any(e.mask & (flags.MOVE_SELF | flags.DELETE_SELF) for e in events)
                if rotated:
                    log.info(f"{path} rotated, reopening")
                    break
                # Sanity check inode (handles copytruncate-style rotation)
                try:
                    if os.stat(path).st_ino != inode:
                        log.info(f"{path} inode changed, reopening")
                        break
                except FileNotFoundError:
                    log.info(f"{path} disappeared, reopening")
                    break
        finally:
            try:
                inotify.rm_watch(wd)
            except Exception:
                pass
            f.close()

# ---- Main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='Validate config and exit')
    args = parser.parse_args()

    if args.check:
        # Just try to load; the constructor exits on failure
        Allowlist(ALLOWLIST_FILE)
        log.info("config check passed")
        sys.exit(0)

    allowlist = Allowlist(ALLOWLIST_FILE)

    def on_sighup(signum, frame):
        log.info("SIGHUP received, reloading allowlist")
        allowlist.reload()
    signal.signal(signal.SIGHUP, on_sighup)

    def on_term(signum, frame):
        log.info("shutting down")
        sys.exit(0)
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    log.info(f"watching {LOG_FILE}")
    for line in tail(LOG_FILE):
        m = LOGIN_RE.search(line)
        if not m:
            continue
        try:
            handle_event(
                user=m.group('user'),
                ip=m.group('ip'),
                result=m.group('result').upper(),
                allowlist=allowlist,
            )
        except Exception as e:
            log.error(f"handler error on line {line!r}: {e}")


if __name__ == '__main__':
    main()
