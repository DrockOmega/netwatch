"""A beacon sample can land before a flow's TLS hello: it carries the name learned earlier."""

from tests.test_ja3 import build_client_hello
from tools.bench_core_shard import GOOGLE6, GW_MAC, HOST6, HOST_MAC, _eth, _event, _ip6, _tcp, run_shard


def _beacon_flows(value):
    if isinstance(value, dict):
        if "first_local_egress" in value and "source_mac" in value:
            yield value
        for v in value.values():
            yield from _beacon_flows(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _beacon_flows(v)


def test_new_flow_carries_the_server_name_seen_on_an_earlier_flow(tmp_path):
    def packet(port, flags, payload, stamp):
        return _event(_eth(_ip6(_tcp(port, 443, flags, payload), 6, HOST6, GOOGLE6), HOST_MAC, GW_MAC, 0x86DD), stamp)

    t0 = 1_800_000_000.0
    events = [packet(50001, 0x02, b"", t0),
              packet(50001, 0x18, build_client_hello(sni="privacy.xboxlive.com"), t0 + 0.01),
              packet(50002, 0x18, b"data", t0 + 120)]  # the next poll: payload, but no hello
    outputs, _, _ = run_shard(events, tmp_path)
    flows = [f for m in outputs["merge"] for f in _beacon_flows(m["data"])]
    assert [f["source_port"] for f in flows] == [50001, 50002]
    assert flows[0]["domain"] == "privacy.xboxlive.com"
    assert flows[1]["domain"] == "privacy.xboxlive.com"


def test_a_restart_keeps_the_learned_name(tmp_path):
    # the console host's CI runners: the name was learned before the restart and is never resent after it.
    def packet(port, flags, payload, stamp):
        return _event(_eth(_ip6(_tcp(port, 443, flags, payload), 6, HOST6, GOOGLE6), HOST_MAC, GW_MAC, 0x86DD), stamp)

    t0 = 1_800_000_000.0
    run_shard([packet(50001, 0x02, b"", t0),
               packet(50001, 0x18, build_client_hello(sni="broker.actions.githubusercontent.com"), t0 + 0.01)], tmp_path)
    outputs, _, _ = run_shard([packet(50002, 0x18, b"data", t0 + 120)], tmp_path)
    flows = [f for m in outputs["merge"] for f in _beacon_flows(m["data"])]
    assert [f["domain"] for f in flows] == ["broker.actions.githubusercontent.com"]


def test_new_flow_carries_the_name_from_a_dns_answer(tmp_path):
    import ipaddress
    import struct

    from tools.bench_core_shard import _udp

    resolver = "2001:558:feed::1"
    question = b"".join(bytes([len(p)]) + p.encode() for p in "sis.jpush.io".split(".")) + b"\x00" + struct.pack("!HH", 28, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 28, 1, 60, 16) + ipaddress.ip_address(GOOGLE6).packed
    reply = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + answer
    t0 = 1_800_000_000.0
    events = [_event(_eth(_ip6(_udp(53, 40000, reply), 17, resolver, HOST6), GW_MAC, HOST_MAC, 0x86DD), t0),
              _event(_eth(_ip6(_tcp(50003, 7001, 0x18, b"data"), 6, HOST6, GOOGLE6), HOST_MAC, GW_MAC, 0x86DD), t0 + 1)]
    assert events[0]["dns_answers"] == (ipaddress.ip_address(GOOGLE6).packed,)
    outputs, _, _ = run_shard(events, tmp_path)
    flows = [f for m in outputs["merge"] for f in _beacon_flows(m["data"])]
    assert [f["domain"] for f in flows] == ["sis.jpush.io"]  # no TLS hello ever names this connection
