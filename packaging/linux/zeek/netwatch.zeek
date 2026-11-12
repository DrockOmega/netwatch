# Zeek site policy for the NetWatch sensor: /etc/netwatch/zeek/netwatch.zeek, run by netwatch-zeek.service.
# JSON logs in /var/lib/zeek/logs, rotated hourly to <log>.<timestamp>.log; NetWatch tails the ones in
# ZEEK_LOG_PATHS, netwatch-zeek-cleanup deletes files untouched for 3 days.
@load base/frameworks/notice
@load policy/tuning/json-logs
@load policy/protocols/conn/community-id-logging   # joins Zeek rows to Suricata and NetWatch flows (/v1/flows)
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/conn/mac-logging
@load policy/protocols/dhcp/software
@load policy/protocols/http/software
@load policy/protocols/ssh/software
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/dns/detect-external-names
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/misc/detect-traceroute
@load policy/misc/capture-loss
@load policy/misc/stats

redef Site::local_nets += { 10.0.0.0/24, [2001:db8:0:1::]/64 };   # your LAN /24 and IPv6 /64s
redef ignore_checksums = T;             # mirror/offload: checksums are often not final on the wire
redef Pcap::snaplen = 65535;            # GRO-coalesced frames exceed 9216
redef Log::default_rotation_interval = 1 hr;
redef Known::use_host_store = F;        # standalone: no broker data store
redef Known::use_service_store = F;
# the console host runs every agent's git over SSH to GitHub with ControlMaster off (~1400 sessions a day); Zeek's auth
# heuristic reads ~2% of them as failures, which raised Password_Guessing. Only the console host to GitHub's git /20 is exempt.
redef SSH::ignore_guessers += { [10.0.0.15/32] = 140.82.112.0/20 };

# Windows telemetry/update, Netflix and Samsung push endpoints chain to the vendors' own roots, which Zeek's Mozilla
# store lacks: every Windows PC and TV would raise Invalid_Server_Cert. Only "unable to get local issuer" on a
# microsoft.com/netflix.com CN with that O= is dropped; expired, self-signed or lookalike-name certs still alert.
hook Notice::notice(n: Notice::Info) &priority=10
	{
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=([^,]*\.)?(microsoft\.com|netflix\.com),.*O=(Microsoft|Netflix)/ in n$sub )
		break;
	# A LAN phone's network-quality probes read as ICMP traceroute (a family iPhone, three cases by 10-30). Only an
	# outside host tracerouting stays a notice.
	if ( n$note == Traceroute::Detected && n?$src && Site::is_local_addr(n$src) )
		break;
	# OwnerIQ's ad pixel has served an expired cert since at least 10-28; apps on family phones keep trying it
	# (case 163395, 82 hits). Exact CN only; any other expired cert still alerts.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub && /certificate has expired/ in n$msg &&
	     n$sub == "CN=px.owneriq.net" )
		break;
	# Samsung TV/phone push (*.push.samsungosp.com) chains to Samsung's private root (also "self-signed in chain").
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /(unable to get local issuer certificate|self-signed certificate in certificate chain)/ in n$msg &&
	     /CN=\*\.push\.samsungosp\.com,O=SAMSUNG ELECTRONICS/ in n$sub )
		break;
	# Samsung SmartThings devices to *.samsungiotcloud.com: same private root, "self-signed in chain".
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /self-signed certificate in certificate chain/ in n$msg &&
	     /^CN=\*\.samsungiotcloud\.com,OU=uuid:[0-9a-f-]+,O=Samsung Electronics,C=KR$/ in n$sub )
		break;
	# Chamberlain MyQ garage/lock devices: MQTT 8883 to *.cloud.mydevice.com under Chamberlain's private root.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /self-signed certificate in certificate chain/ in n$msg &&
	     /^CN=\*\.cloud\.mydevice\.com,OU=MyQ,O=Chamberlain Group,/ in n$sub )
		break;
	# A household CommonSpirit Health (Centura) work laptop: the employer's VPN and its McAfee/Trellix ePO agent
	# broker (MQTT 8883, CN=localhost) chain to CommonSpirit's private root. The broker is only exempt inside
	# CommonSpirit's own 162.135.0.0/16 (Dignity Health, ARIN).
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=([^,]*\.)?centura\.org,.*O=Commonspirit Health,/ in n$sub )
		break;
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub && n?$id && n$id$resp_h in 162.135.0.0/16 &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=(localhost,OU=Broker - \{[0-9a-f-]+\}|[A-Z0-9_]+,OU=ePO),O=McAfee/ in n$sub )
		break;
	# Samsung TV/phone cloud services (*.samsungcloudsolution.com/.net) under Samsung's private root.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=\*\.samsungcloudsolution\.(com|net),O=Samsung Electronics,/ in n$sub )
		break;
	# AWS IoT Core legacy endpoints (MQTT 8883) chain to the VeriSign/Symantec root Mozilla dropped; the iRobot Roomba
	# hits them (cases d0b1dd, b8ce53, 11-01). Only "unable to get local issuer" on that exact CN shape and O= is dropped.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=\*\.iot\.[a-z0-9-]+\.amazonaws\.com,O=Amazon\.com\\?, Inc\.,/ in n$sub )
		break;
	# The Archer AX11000 access point's TP-Link cloud (*.tplinkcloud.com) under TP-Link's private root.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /self-signed certificate in certificate chain/ in n$msg &&
	     /^CN=\*\.tplinkcloud\.com,O=TP-LINK CORPORATION LIMITED,/ in n$sub )
		break;
	# ecobee thermostat device management (idt.ecobee.com:8190) under ecobee's private root.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=idt\.ecobee\.com,OU=Device Management Services,O=ecobee Technologies ULC,/ in n$sub )
		break;
	# WebRTC media (DTLS-SRTP) always uses a throwaway self-signed cert (CN=WebRTC in browsers, CN=mediasoupNNN on
	# mediasoup SFUs such as Daily.co, case 2e3a6f); the peer checks its fingerprint from the signalling channel, so
	# Zeek's chain check is meaningless there. UDP only.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub && n?$id &&
	     get_port_transport_proto(n$id$resp_p) == udp && /self signed certificate/ in n$msg &&
	     ( n$sub == "CN=WebRTC" || /^CN=mediasoup[0-9]+,O=mediasoup[0-9]+$/ in n$sub ) )
		break;
	# The household V-Link smart lock: its vendor's MQTT cloud on 8883.
	if ( n$note == SSL::Invalid_Server_Cert && n?$sub && n?$id && n$id$resp_p == 8883/tcp &&
	     /unable to get local issuer certificate/ in n$msg &&
	     /^CN=mqtt\.idlespacetech\.com,O=idlespacetech,/ in n$sub )
		break;
	}

# NetWatch takes bulk TCP/QUIC volume from Zeek (BULK_SHED_BYTES), but conn.log is written only when a connection
# ends. conn_interim.log carries a connection's cumulative counters every 10 s once either side has sent 1 MB,
# until it ends, so an upload reaches the volume detectors while it runs (ZEEK_LOG_PATHS conn*.log matches it).
module NetWatch;

export {
	redef enum Log::ID += { INTERIM_LOG };

	type Interim: record {
		ts: time &log;
		uid: string &log;
		id: conn_id &log;
		proto: transport_proto &log;
		duration: interval &log;
		orig_pkts: count &log &optional;
		orig_ip_bytes: count &log &optional;
		orig_bytes: count &log &optional;
		resp_pkts: count &log &optional;
		resp_ip_bytes: count &log &optional;
		resp_bytes: count &log &optional;
		orig_l2_addr: string &log &optional;
		resp_l2_addr: string &log &optional;
	};
}

const interim_interval = 10 sec;
const interim_after = 1000000;

event zeek_init()
	{
	Log::create_stream(INTERIM_LOG, [$columns=Interim, $path="conn_interim"]);
	}

function interim(c: connection, cnt: count): interval
	{
	local r = Interim($ts=network_time(), $uid=c$uid, $id=c$id, $proto=get_port_transport_proto(c$id$resp_p),
	                  $duration=c$duration);
	if ( c$orig?$num_pkts ) r$orig_pkts = c$orig$num_pkts;
	if ( c$orig?$num_bytes_ip ) r$orig_ip_bytes = c$orig$num_bytes_ip;
	if ( c$resp?$num_pkts ) r$resp_pkts = c$resp$num_pkts;
	if ( c$resp?$num_bytes_ip ) r$resp_ip_bytes = c$resp$num_bytes_ip;
	r$orig_bytes = c$orig$size;  # payload: the exfil detector counts this, not the ACK stream (b463)
	r$resp_bytes = c$resp$size;
	if ( c$orig?$l2_addr ) r$orig_l2_addr = c$orig$l2_addr;
	if ( c$resp?$l2_addr ) r$resp_l2_addr = c$resp$l2_addr;
	Log::write(INTERIM_LOG, r);
	return interim_interval;
	}

event new_connection(c: connection)
	{
	ConnThreshold::set_bytes_threshold(c, interim_after, T);
	ConnThreshold::set_bytes_threshold(c, interim_after, F);
	}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
	{
	if ( threshold != interim_after )
		return;
	ConnThreshold::delete_bytes_threshold(c, interim_after, ! is_orig);  # one poller per connection
	ConnPolling::watch(c, interim, 0, interim_interval);
	}
