import ipaddress
from ipaddress import IPv4Network

import ifaddr
import structlog

logger = structlog.get_logger()


def get_local_networks() -> list[IPv4Network]:
    """Return IPv4 subnets for all local interfaces (excluding link-local 169.254.x.x)."""
    networks: list[IPv4Network] = []
    link_local = IPv4Network("169.254.0.0/16")
    for adapter in ifaddr.get_adapters():
        for ip_info in adapter.ips:
            if not isinstance(ip_info.ip, str):
                continue  # skip IPv6 tuples
            try:
                iface = ipaddress.ip_interface(f"{ip_info.ip}/{ip_info.network_prefix}")
                net = iface.network
                if net.subnet_of(link_local):
                    continue
                if net == IPv4Network("127.0.0.0/8"):
                    continue
                networks.append(net)
            except (ValueError, TypeError):
                continue
    return networks


def validate_target_routable(target: str) -> tuple[bool, str]:
    """Check whether a scan target overlaps with any locally-routed network.

    Returns (True, "ok") if reachable, or (False, error_message) if not.
    """
    local_nets = get_local_networks()
    if not local_nets:
        return True, "ok"  # can't determine — allow scan

    try:
        target_net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            target_ip = ipaddress.ip_address(target)
            target_net = ipaddress.ip_network(f"{target_ip}/32")
        except ValueError:
            return True, "ok"  # hostname — skip check

    for local_net in local_nets:
        if target_net.overlaps(local_net):
            return True, "ok"

    local_str = ", ".join(str(n) for n in local_nets)
    return (
        False,
        f"Target {target} is not reachable from this machine — "
        f"local networks: {local_str}",
    )
