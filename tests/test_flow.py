import ipaddress

from netwatch_flow import BeaconDetector, FlowTracker, HumanWebClassifier


def event(timestamp, *, src="10.0.0.2", dst="8.8.8.8", sport=50000, dport=443,
          protocol="TCP", size=100, flags="S", mac="00:11:22:33:44:55"):
    return {
        "timestamp": timestamp,
        "src_ip": ipaddress.ip_address(src).packed,
        "dst_ip": ipaddress.ip_address(dst).packed,
        "source_port": sport,
        "port": dport,
        "protocol": protocol,
        "size_bytes": size,
        "tcp_flags": flags,
        "mac_src": mac,
        "sni_domain": "example.com",
    }


def test_bidirectional_packets_share_one_flow_and_counters():
    tracker = FlowTracker()
    outbound, created = tracker.observe(event(1), src_local=True, dst_local=False)
    inbound, reverse_created = tracker.observe(
        event(2, src="8.8.8.8", dst="10.0.0.2", sport=443, dport=50000, size=250, flags="A"),
        src_local=False,
        dst_local=True,
    )
    assert created is True and reverse_created is False
    assert outbound["flow_id"] == inbound["flow_id"]
    assert inbound["bytes_up"] == 100
    assert inbound["bytes_down"] == 250
    assert inbound["tcp_state"] == "established"


def test_flow_expiry_and_capacity_are_bounded():
    tracker = FlowTracker(max_flows=2, udp_idle_sec=5)
    for index in range(3):
        tracker.observe(event(index, dst=f"8.8.8.{index + 1}", protocol="UDP"), src_local=True)
    assert len(tracker.flows) == 2
    assert len(tracker.drain_evicted()) == 1
    assert len(tracker.expire(10)) == 2


def test_reused_five_tuple_gets_a_new_session_id():
    tracker = FlowTracker(udp_idle_sec=1)
    first, _ = tracker.observe(event(1, protocol="UDP"), src_local=True)
    tracker.expire(3)
    second, _ = tracker.observe(event(4, protocol="UDP"), src_local=True)
    assert first["flow_id"] != second["flow_id"]


def test_beacon_detector_requires_repeated_low_jitter_egress():
    tracker = FlowTracker(udp_idle_sec=1)
    detector = BeaconDetector(min_samples=4, max_cv=0.05, min_period_sec=5, cooldown_sec=60)
    finding = None
    for timestamp in (0, 10, 20, 30):
        flow, _ = tracker.observe(event(timestamp, protocol="UDP"), src_local=True, dst_local=False)
        finding = detector.observe(flow, timestamp)
    assert finding["kind"] == "BEACONING"
    assert finding["period_sec"] == 10


def test_beacon_detector_ignores_configured_periodic_service_ports():
    tracker = FlowTracker(udp_idle_sec=1)
    detector = BeaconDetector(
        min_samples=4,
        max_cv=0.05,
        min_period_sec=5,
        cooldown_sec=60,
        ignored_udp_ports=(123, 3478, 5349),
    )
    for timestamp in (0, 10, 20, 30):
        flow, _ = tracker.observe(
            event(timestamp, protocol="UDP", dport=3478),
            src_local=True,
            dst_local=False,
        )
        assert detector.observe(flow, timestamp) is None

    assert detector.timestamps == {}


def test_beacon_service_suppression_does_not_hide_tcp_on_same_port():
    tracker = FlowTracker(tcp_idle_sec=1)
    detector = BeaconDetector(
        min_samples=4,
        max_cv=0.05,
        min_period_sec=5,
        cooldown_sec=60,
        ignored_udp_ports=(3478,),
    )
    finding = None
    for timestamp in (0, 10, 20, 30):
        flow, _ = tracker.observe(
            event(timestamp, protocol="TCP", dport=3478),
            src_local=True,
            dst_local=False,
        )
        finding = detector.observe(flow, timestamp)

    assert finding["kind"] == "BEACONING"


def test_beacon_detector_ignores_configured_destination_identity():
    flow = {
        "src_local": True,
        "dst_local": False,
        "src_ip": bytes([10, 0, 0, 15]),
        "dst_ip": bytes([160, 79, 104, 10]),
        "destination_port": 443,
        "protocol": "TCP",
        "source_mac": "cc:96:e5:00:00:02",
        "first_seen": 0,
        "domain": "api.anthropic.com",
        "flow_id": "known-service",
    }
    by_domain = BeaconDetector(min_samples=3, ignored_domains=("anthropic.com",))
    by_ip = BeaconDetector(min_samples=3, ignored_destinations=("160.79.104.10",))
    for timestamp in (0, 10, 20, 30):
        flow["first_seen"] = timestamp
        flow["domain"] = "api.anthropic.com"
        assert by_domain.observe(flow, timestamp) is None
        flow["domain"] = ""
        assert by_ip.observe(flow, timestamp) is None


def test_beacon_detector_skips_invalid_ignored_destination():
    detector = BeaconDetector(ignored_destinations=("not-an-ip", "160.79.104.10"))

    assert detector.ignored_destinations == frozenset({bytes([160, 79, 104, 10])})


def test_beacon_device_endpoint_ignore_is_scoped_to_mac_network_and_port():
    ring = {"mac": "18:7F:88:00:00:05", "networks": ["44.224.0.0/11"], "ports": [8557]}
    detector = BeaconDetector(min_samples=3, ignored_device_endpoints=(
        ring, {"mac": "aa:bb:cc:dd:ee:ff", "networks": ["0.0.0.0/0"]}, {"networks": ["10.0.0.0/8"]}))
    assert list(detector.ignored_device_endpoints) == ["18:7f:88:00:00:05"]  # /0 and mac-less refused

    def fires(mac, dst, port):
        det = BeaconDetector(min_samples=3, ignored_device_endpoints=(ring,))
        flow = {"src_local": True, "dst_local": False, "src_ip": bytes([10, 0, 0, 62]), "dst_ip": bytes(dst),
                "destination_port": port, "protocol": "TCP", "source_mac": mac, "domain": "", "flow_id": "k"}
        return any(det.observe(dict(flow, first_seen=t), t) for t in (0, 6, 12, 18, 24))

    assert not fires("18:7f:88:00:00:05", [44, 229, 18, 208], 8557)
    assert fires("18:7f:88:00:00:05", [44, 229, 18, 208], 443)  # other port still scored
    assert fires("18:7f:88:00:00:05", [8, 8, 8, 8], 8557)  # outside the vendor range
    assert fires("1c:53:f9:00:00:07", [44, 229, 18, 208], 8557)  # other device


def test_late_domain_replaces_placeholder_and_increments_identity():
    tracker = FlowTracker()
    first = event(1)
    first["sni_domain"] = "encrypted-payload"
    initial, _ = tracker.observe(first, src_local=True, dst_local=False)
    later = event(2, flags="A")
    later["sni_domain"] = "evil.example"
    updated, created = tracker.observe(later, src_local=True, dst_local=False)
    assert initial["domain"] == ""
    assert created is False
    assert updated["domain"] == "evil.example"
    assert updated["identity_revision"] == 1
    assert updated["identity_changed"] is True


def test_reverse_preseed_marks_first_local_egress_transition():
    tracker = FlowTracker()
    inbound = event(1, src="8.8.8.8", dst="10.0.0.2", sport=53, dport=53000, protocol="UDP")
    tracker.observe(inbound, src_local=False, dst_local=True)
    outbound = event(2, sport=53000, dport=53, protocol="UDP")
    flow, created = tracker.observe(outbound, src_local=True, dst_local=False)
    assert created is False
    assert flow["observation_direction"] == "egress"
    assert flow["first_local_egress"] is True


def test_human_web_classifier_emits_one_explainable_session_observation():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    dns_packet = event(1, dst="1.1.1.1", dport=53, protocol="UDP")
    dns_packet["dns_qr"] = 0
    dns_packet["dns_qname"] = "chatgpt.com"
    dns_flow, _ = tracker.observe(dns_packet, src_local=True, dst_local=False)
    assert classifier.observe(dns_packet, dns_flow, src_local=True, dst_local=False) is None

    web = event(2, dst="104.18.32.47")
    web["sni_domain"] = "chatgpt.com"
    flow, _ = tracker.observe(web, src_local=True, dst_local=False)
    observation = classifier.observe(web, flow, src_local=True, dst_local=False)

    assert observation["label"] == "HUMAN LIKELY"
    assert observation["score"] >= 5
    assert "named host" in observation["reason"]
    assert classifier.observe(web, flow, src_local=True, dst_local=False) is None


def test_human_web_classifier_marks_background_hostname_as_noise():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    packet = event(10, dst="20.42.65.90")
    packet["sni_domain"] = "watson.events.data.microsoft.com"
    flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
    observation = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert observation["label"] == "WEB NOISE"
    assert "background-service hostname" in observation["reason"]


def test_human_web_classifier_does_not_treat_bare_http_syn_as_web_activity():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    packet = event(10, dport=80)
    packet["sni_domain"] = "encrypted-payload"
    flow, _ = tracker.observe(packet, src_local=True, dst_local=False)

    assert classifier.observe(packet, flow, src_local=True, dst_local=False) is None


def test_human_web_classifier_requires_a_response_for_unnamed_tcp():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    flow = None
    packet = None
    for timestamp in (1, 2, 3):
        packet = event(timestamp, dport=80, flags="PA")
        packet["sni_domain"] = "encrypted-payload"
        flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
        assert classifier.observe(packet, flow, src_local=True, dst_local=False) is None

    response = event(4, src="8.8.8.8", dst="10.0.0.2", sport=80, dport=50_000, flags="A")
    response["sni_domain"] = "encrypted-payload"
    tracker.observe(response, src_local=False, dst_local=True)
    packet = event(5, dport=80, flags="PA")
    packet["sni_domain"] = "encrypted-payload"
    flow, _ = tracker.observe(packet, src_local=True, dst_local=False)

    assert classifier.observe(packet, flow, src_local=True, dst_local=False)["label"] == "HUMAN POSSIBLE"


def test_human_web_background_suffix_requires_a_label_boundary():
    classifier = HumanWebClassifier()

    assert classifier._background_domain("telemetry.data.nvidia.com") is True
    assert classifier._background_domain("nottelemetry.data.nvidia.com") is False
    assert classifier._background_domain("fw.prod.gws.ring.amazon.dev") is True
    assert classifier._background_domain("notring.amazon.dev.example") is False
    assert classifier._background_domain("uk-script.dotmetrics.net") is True


def test_human_web_background_evidence_cannot_be_overpowered_by_a_burst():
    classifier = HumanWebClassifier()
    result = None
    for index, domain in enumerate((
            "first.example", "second.example", "fw-eventstream.prod.gws.ring.amazon.dev")):
        tracker = FlowTracker()
        packet = event(index + 1, sport=50_000 + index, dst=f"8.8.8.{index + 1}")
        packet["sni_domain"] = domain
        flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
        result = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert result["label"] == "WEB NOISE"
    assert result["score"] <= 2
    assert "background-service hostname" in result["reason"]


def test_human_web_recent_dns_must_match_the_observed_hostname():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    dns_packet = event(1, dst="1.1.1.1", dport=53, protocol="UDP")
    dns_packet["dns_qr"] = 0
    dns_packet["dns_qname"] = "unrelated.example"
    dns_flow, _ = tracker.observe(dns_packet, src_local=True, dst_local=False)
    assert classifier.observe(dns_packet, dns_flow, src_local=True, dst_local=False) is None

    web = event(2, dst="8.8.8.8")
    web["sni_domain"] = "target.example"
    flow, _ = tracker.observe(web, src_local=True, dst_local=False)
    observation = classifier.observe(web, flow, src_local=True, dst_local=False)

    assert "recent DNS" not in observation["reason"]


def test_human_web_known_automated_source_is_always_noise():
    tracker = FlowTracker()
    classifier = HumanWebClassifier(
        automation_sources=("90-48-6C-17-4C-E6",),
    )
    packet = event(10, mac="90:48:6c:17:4c:e6")
    packet["sni_domain"] = "otherwise-human.example"
    flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
    observation = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert observation["label"] == "WEB NOISE"
    assert observation["score"] <= 2
    assert "known automated source" in observation["reason"]


def test_human_web_automation_configuration_is_safe_and_canonical():
    classifier = HumanWebClassifier(
        background_domains=None,
        automation_sources=("2601:0281:da82:ba80:0000:0000:0000:0001",),
    )
    packet = event(
        10, src="2601:281:da82:ba80::1", dst="2606:4700:4700::1111",
        mac="",
    )
    flow, _ = FlowTracker().observe(packet, src_local=True, dst_local=False)
    observation = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert observation["label"] == "WEB NOISE"
    assert "known automated source" in observation["reason"]


def test_human_web_unnamed_burst_cannot_be_labeled_likely():
    classifier = HumanWebClassifier()
    result = None
    for index in range(3):
        tracker = FlowTracker()
        packet = event(index + 1, sport=50_000 + index, dst=f"8.8.8.{index + 1}")
        packet["sni_domain"] = "encrypted-payload"
        flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
        flow["packets_down"] = 1
        result = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert result["label"] == "HUMAN POSSIBLE"
    assert result["score"] == 4
    assert "no hostname attribution" in result["reason"]


def test_human_web_classifier_demotes_regular_cadence():
    classifier = HumanWebClassifier(periodic_min_samples=4, periodic_max_cv=0.05)
    result = None
    for index, timestamp in enumerate((0, 60, 120, 180)):
        tracker = FlowTracker()
        packet = event(timestamp, sport=50_000 + index, dst="20.42.65.91")
        packet["sni_domain"] = "service.example.com"
        flow, _ = tracker.observe(packet, src_local=True, dst_local=False)
        result = classifier.observe(packet, flow, src_local=True, dst_local=False)

    assert result["label"] == "WEB NOISE"
    assert "regular 60s cadence" in result["reason"]


def test_human_web_classifier_ignores_inbound_and_non_web_flows():
    tracker = FlowTracker()
    classifier = HumanWebClassifier()
    inbound = event(1, src="8.8.8.8", dst="10.0.0.2", sport=443, dport=50_000)
    inbound_flow, _ = tracker.observe(inbound, src_local=False, dst_local=True)
    assert classifier.observe(inbound, inbound_flow, src_local=False, dst_local=True) is None

    non_web = event(2, dport=22)
    non_web_flow, _ = tracker.observe(non_web, src_local=True, dst_local=False)
    assert classifier.observe(non_web, non_web_flow, src_local=True, dst_local=False) is None


def test_evicted_backlog_bounded():
    tracker = FlowTracker(max_flows=10)
    for index in range(1000):
        tracker.observe(event(index, dst=str(ipaddress.ip_address("8.8.0.0") + index)), src_local=True)
    assert len(tracker.evicted) <= 10 and tracker.evicted_dropped == 980
    assert len(tracker.drain_evicted()) == 10


def test_accepted_egress_rules_need_a_mac_a_scope_and_a_date():
    from netwatch_flow import accepted_egress_match, accepted_egress_rules

    mac = "1a:3c:96:68:4d:cc"
    good = {"macs": [mac], "domains": ["umeng.com"], "cidrs": ["8.8.8.0/24"], "note": "n", "review_by": "2027-01-13"}
    assert len(accepted_egress_rules([good])) == 1
    for bad in ({**good, "macs": []}, {**good, "domains": [], "cidrs": []}, {**good, "cidrs": ["0.0.0.0/0"]},
                {**good, "review_by": "soon"}, {**good, "macs": ["short"]}):
        assert accepted_egress_rules([bad]) == []
    [rule] = accepted_egress_rules([good])
    dst = ipaddress.ip_address("1.2.3.4").packed
    assert accepted_egress_match(rule, mac.upper(), "a.UMENG.com", dst)
    assert accepted_egress_match(rule, mac, "", ipaddress.ip_address("8.8.8.8").packed)
    assert not accepted_egress_match(rule, mac, "notumeng.com", dst)
    assert not accepted_egress_match(rule, "aa:bb:cc:dd:ee:ff", "umeng.com", dst)


def test_ignored_udp_port_matches_the_local_source_port():
    tracker = FlowTracker(tcp_idle_sec=1)
    detector = BeaconDetector(min_samples=4, max_cv=0.05, min_period_sec=5, cooldown_sec=60, ignored_udp_ports=(41641,))
    for timestamp in (0, 10, 20, 30):
        flow, _ = tracker.observe(event(timestamp, protocol="UDP", dport=46713, sport=41641), src_local=True, dst_local=False)
        assert detector.observe(flow, timestamp) is None
