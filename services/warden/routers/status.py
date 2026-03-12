"""Consolidated metrics endpoint for connected mode.

Exposes a single GET /metrics endpoint that returns all system metrics,
disk usage, processes, network stats, container statuses, and health
checks — queried by the CP via mTLS.
"""

import os
import shutil
import socket

import docker
import psutil
from constants import (
    COREDNS_CONTAINER_NAME,
    ENVOY_CONTAINER_NAME,
    MANAGED_CONTAINERS,
    MITM_PROXY_CONTAINER_NAME,
    docker_client,
)
from fastapi import APIRouter

router = APIRouter()


def _collect_system_metrics():
    """Collect CPU, memory, disk, and load metrics."""
    mem = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    cpu_freq = psutil.cpu_freq()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "cpu_freq_mhz": round(cpu_freq.current) if cpu_freq else None,
        "memory_mb": round(mem.used / 1024 / 1024),
        "memory_limit_mb": round(mem.total / 1024 / 1024),
        "memory_percent": mem.percent,
        "disk_used_bytes": disk.used,
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
        "load_average": list(os.getloadavg()),
        "uptime_seconds": int(psutil.boot_time()),
    }


def _collect_disks():
    """Collect disk usage per mount point."""
    result = []
    for p in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(p.mountpoint)
            result.append(
                {
                    "path": p.mountpoint,
                    "device": p.device,
                    "fstype": p.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                }
            )
        except (PermissionError, OSError):
            continue
    return result


def _collect_processes():
    """Collect top 20 processes by CPU usage."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
        try:
            info = p.info
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info["cpu_percent"] or 0,
                    "memory_mb": round((info["memory_info"].rss if info["memory_info"] else 0) / 1024 / 1024, 1),
                    "status": info["status"],
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return procs[:20]


def _collect_network():
    """Collect network interface statistics."""
    counters = psutil.net_io_counters(pernic=True)
    result = []
    for name, stats in counters.items():
        if name == "lo":
            continue
        result.append(
            {
                "interface": name,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
            }
        )
    return result


def _collect_containers():
    """Collect Docker container statuses."""
    result = []
    for name in MANAGED_CONTAINERS:
        try:
            container = docker_client.containers.get(name)
            state = container.attrs.get("State", {})
            result.append(
                {
                    "name": name,
                    "status": container.status,
                    "image": container.image.tags[0] if container.image.tags else str(container.image.id)[:12],
                    "started_at": state.get("StartedAt"),
                    "health": state.get("Health", {}).get("Status"),
                }
            )
        except docker.errors.NotFound:
            result.append({"name": name, "status": "not_found", "image": None, "started_at": None, "health": None})
        except Exception as e:
            result.append({"name": name, "status": "error", "error": str(e)})
    return result


def _collect_health_checks():
    """Run deep health checks: containers, DNS, Envoy, MITM proxy, OpenObserve."""
    checks = {}

    # Check each container
    for name in MANAGED_CONTAINERS:
        try:
            container = docker_client.containers.get(name)
            checks[name] = {
                "status": "healthy" if container.status == "running" else "unhealthy",
                "container_status": container.status,
                "uptime": container.attrs["State"].get("StartedAt") if container.status == "running" else None,
            }
        except docker.errors.NotFound:
            checks[name] = {"status": "missing", "container_status": "not_found"}
        except Exception as e:
            checks[name] = {"status": "error", "error": str(e)}

    # Test DNS resolution via CoreDNS (10.200.2.5 on infra-net)
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        if container.status == "running":
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(3)
            query = b"\x12\x34"  # transaction ID
            query += b"\x01\x00"  # flags: standard query, recursion desired
            query += b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
            query += b"\x06google\x03com\x00"  # google.com
            query += b"\x00\x01\x00\x01"  # type A, class IN
            resolver.sendto(query, ("10.200.2.5", 53))
            data, _ = resolver.recvfrom(512)
            resolver.close()
            checks["dns_resolution"] = {
                "status": "healthy",
                "test": "google.com",
            }
        else:
            checks["dns_resolution"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["dns_resolution"] = {"status": "error", "error": str(e)}

    # Test Envoy readiness via admin port
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        if container.status == "running":
            result = container.exec_run(
                ["bash", "-c", "echo > /dev/tcp/localhost/9901"],
            )
            checks["envoy_ready"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
            }
        else:
            checks["envoy_ready"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["envoy_ready"] = {"status": "error", "error": str(e)}

    # Test MITM proxy readiness
    try:
        container = docker_client.containers.get(MITM_PROXY_CONTAINER_NAME)
        if container.status == "running":
            result = container.exec_run(
                ["python3", "-c", "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1',8080)); s.close()"],
            )
            checks["mitm_proxy_ready"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
            }
        else:
            checks["mitm_proxy_ready"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["mitm_proxy_ready"] = {"status": "error", "error": str(e)}

    # Check local OpenObserve
    try:
        from openobserve_client import is_openobserve_healthy

        checks["openobserve"] = {
            "status": "healthy" if is_openobserve_healthy() else "unhealthy",
        }
    except ImportError:
        checks["openobserve"] = {"status": "not_configured"}
    except Exception as e:
        checks["openobserve"] = {"status": "error", "error": str(e)}

    all_healthy = all(c.get("status") == "healthy" for c in checks.values())
    return {
        "status": "healthy" if all_healthy else "degraded",
        "checks": checks,
    }


@router.get("/metrics")
def get_metrics():
    """Consolidated system metrics, container statuses, and health checks."""
    return {
        "system": _collect_system_metrics(),
        "disks": _collect_disks(),
        "processes": _collect_processes(),
        "network": _collect_network(),
        "containers": _collect_containers(),
        "health": _collect_health_checks(),
    }
