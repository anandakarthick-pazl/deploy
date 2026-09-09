"""Remote /proc reader.

One SSH call gathers everything the live server-monitor view needs and we parse
it back into the same dict shape that the local psutil snapshot produces, so
the template + JS don't need to know which side they're looking at.
"""

import shlex
import time
from datetime import datetime


def _human(n: float) -> str:
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} {u}"
        n /= 1024


# Single bash one-liner gathering everything in one SSH round-trip.
# We `sleep 0.4` between two /proc/stat reads so we can compute CPU%.
_REMOTE_SCRIPT = r"""
echo "===HOSTNAME==="; hostname
echo "===UPTIME==="; cat /proc/uptime
echo "===LOAD==="; cat /proc/loadavg
echo "===CPU_BEFORE==="; head -n1 /proc/stat
echo "===CPU_BEFORE_PERCORE==="; awk '/^cpu[0-9]/' /proc/stat
sleep 0.4
echo "===CPU_AFTER==="; head -n1 /proc/stat
echo "===CPU_AFTER_PERCORE==="; awk '/^cpu[0-9]/' /proc/stat
echo "===NPROC==="; nproc 2>/dev/null || true
echo "===MEMINFO==="; cat /proc/meminfo
echo "===DF==="; df -B1 -T -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null
echo "===NET==="; cat /proc/net/dev
echo "===PROCS==="; ps -eo pid,user,pcpu,rss,etime,comm --sort=-pcpu --no-headers 2>/dev/null | head -30
"""


def _split_sections(blob: str) -> dict[str, list[str]]:
    out, cur, key = {}, [], None
    for line in blob.splitlines():
        line = line.rstrip("\r")
        if line.startswith("===") and line.endswith("==="):
            if key is not None:
                out[key] = cur
            key, cur = line.strip("="), []
        else:
            cur.append(line)
    if key is not None:
        out[key] = cur
    return out


def _cpu_pct(before: str, after: str) -> float:
    """Each line: 'cpu user nice system idle iowait irq softirq steal guest guest_nice'"""
    try:
        b = [int(x) for x in before.split()[1:]]
        a = [int(x) for x in after.split()[1:]]
        idle_b   = b[3] + (b[4] if len(b) > 4 else 0)
        idle_a   = a[3] + (a[4] if len(a) > 4 else 0)
        total_b  = sum(b)
        total_a  = sum(a)
        td, id_ = total_a - total_b, idle_a - idle_b
        if td <= 0: return 0.0
        return round(100.0 * (td - id_) / td, 1)
    except Exception:
        return 0.0


def _parse_meminfo(lines):
    info = {}
    for ln in lines:
        if ":" in ln:
            k, v = ln.split(":", 1)
            parts = v.strip().split()
            try:
                kb = int(parts[0])
            except ValueError:
                continue
            info[k.strip()] = kb * 1024
    return info


def _parse_df(lines):
    """df -B1 -T -x tmpfs ... — columns: Filesystem Type 1B-blocks Used Available Use% Mounted on"""
    disks = []
    for ln in lines[1:]:                  # skip header
        parts = ln.split()
        if len(parts) < 7:
            continue
        try:
            dev, fstype, total, used, free, _pct, mount = parts[:7]
            total, used, free = int(total), int(used), int(free)
            pct = round(100.0 * used / total, 1) if total else 0.0
            disks.append({
                "mount": mount, "fstype": fstype, "device": dev,
                "total_bytes": total, "used_bytes": used, "free_bytes": free,
                "percent": pct,
                "total_human": _human(total),
                "used_human":  _human(used),
                "free_human":  _human(free),
            })
        except ValueError:
            continue
    return disks


def _parse_net(lines):
    bytes_sent = bytes_recv = 0
    for ln in lines:
        if ":" not in ln:
            continue
        iface, stats = ln.split(":", 1)
        iface = iface.strip()
        if iface in ("lo",):
            continue
        cols = stats.split()
        if len(cols) < 16:
            continue
        try:
            bytes_recv += int(cols[0])
            bytes_sent += int(cols[8])
        except ValueError:
            continue
    return {
        "bytes_sent": bytes_sent, "bytes_recv": bytes_recv,
        "sent_human": _human(bytes_sent), "recv_human": _human(bytes_recv),
    }


def _parse_procs(lines, hostname=None):
    rows = []
    for ln in lines:
        parts = ln.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            pid = int(parts[0])
            user = parts[1][:24]
            cpu = float(parts[2])
            rss_kb = int(parts[3])
            etime = parts[4]
            name = parts[5][:40]
        except ValueError:
            continue
        rows.append({
            "pid": pid, "name": name, "user": user,
            "cpu_pct": cpu, "mem_bytes": rss_kb * 1024,
            "mem_mb": round(rss_kb / 1024, 1),
            "started_at": etime,
            "is_self": False,
        })
    return rows


def remote_snapshot(server) -> dict:
    """Run the one-shot probe script on `server` and return a dict shaped like
    server_monitor._snapshot() for the same client-side render."""
    import ssh as ssh_helper
    client = ssh_helper.get_client(server)
    stdin, stdout, stderr = client.exec_command(_REMOTE_SCRIPT, timeout=15)
    blob = stdout.read().decode("utf-8", errors="replace")
    sec = _split_sections(blob)

    hostname = (sec.get("HOSTNAME", [""]) or [""])[0].strip() or server.host

    uptime_sec = 0
    try:
        uptime_sec = int(float(sec.get("UPTIME", ["0"])[0].split()[0]))
    except Exception:
        pass

    load = (sec.get("LOAD", [""]) or [""])[0].split()
    load_1m  = float(load[0]) if len(load) >= 1 else 0.0
    load_5m  = float(load[1]) if len(load) >= 2 else 0.0
    load_15m = float(load[2]) if len(load) >= 3 else 0.0

    cpu_b = (sec.get("CPU_BEFORE", [""]) or [""])[0]
    cpu_a = (sec.get("CPU_AFTER",  [""]) or [""])[0]
    cpu_pct = _cpu_pct(cpu_b, cpu_a)

    # Per-core
    pc_b = sec.get("CPU_BEFORE_PERCORE", [])
    pc_a = sec.get("CPU_AFTER_PERCORE",  [])
    per_core = []
    for b, a in zip(pc_b, pc_a):
        per_core.append(_cpu_pct(b, a))

    try:
        cores_logical = int((sec.get("NPROC", ["1"]) or ["1"])[0])
    except ValueError:
        cores_logical = max(1, len(per_core))

    mi = _parse_meminfo(sec.get("MEMINFO", []))
    mem_total = mi.get("MemTotal", 0)
    mem_avail = mi.get("MemAvailable", mi.get("MemFree", 0))
    mem_used  = max(0, mem_total - mem_avail)
    mem_pct   = round(100 * mem_used / mem_total, 1) if mem_total else 0.0
    swap_total = mi.get("SwapTotal", 0)
    swap_free  = mi.get("SwapFree", 0)
    swap_used  = max(0, swap_total - swap_free)
    swap_pct   = round(100 * swap_used / swap_total, 1) if swap_total else 0.0

    disks = _parse_df(sec.get("DF", []))
    net   = _parse_net(sec.get("NET", []))
    procs = _parse_procs(sec.get("PROCS", []), hostname=hostname)

    def _format_uptime(s):
        d, r = divmod(s, 86400); h, r = divmod(r, 3600); m, _ = divmod(r, 60)
        if d: return f"{d}d {h}h {m}m"
        if h: return f"{h}h {m}m"
        return f"{m}m"

    return {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname,
        "remote": True,
        "remote_label": f"{server.username}@{server.host}:{server.port}",
        "cpu": {
            "percent": cpu_pct,
            "cores_physical": cores_logical,   # remote /proc doesn't give us physical easily
            "cores_logical":  cores_logical,
            "per_core": [round(c, 1) for c in per_core],
            "freq_mhz": None,
            "load_1m":  load_1m, "load_5m":  load_5m, "load_15m": load_15m,
        },
        "memory": {
            "total_bytes": mem_total, "used_bytes": mem_used, "available_bytes": mem_avail,
            "percent": mem_pct,
            "total_human": _human(mem_total), "used_human": _human(mem_used),
            "available_human": _human(mem_avail),
            "swap_total_human": _human(swap_total), "swap_used_human": _human(swap_used),
            "swap_percent": swap_pct,
        },
        "disks": disks,
        "network": net,
        "uptime": {
            "seconds": uptime_sec, "human": _format_uptime(uptime_sec),
            "boot_at": (datetime.fromtimestamp(time.time() - uptime_sec).strftime("%Y-%m-%d %H:%M")
                        if uptime_sec else "—"),
        },
        "processes": procs,
    }
