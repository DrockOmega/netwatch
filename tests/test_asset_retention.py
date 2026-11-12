import time

from netwatch_assets import DurableAssetAnalyzer, list_assets, prune_assets
from netwatch_security_store import DurableIncidentStore

DAY = 86400
NOW = 1_000 * DAY
CONFIG = {"LOCAL_PREFIXES": ["10.0.0.0/8"]}


def count(store, table):
    return store._read(f"SELECT count(*) FROM {table}")[0][0]


def test_idle_assets_are_pruned_in_batches_and_pinned_ones_kept(tmp_path):
    store = DurableIncidentStore(tmp_path / "security.db", sensor_id="sensor-a")
    try:
        analyzer = DurableAssetAnalyzer(store, CONFIG)
        old = NOW - 100 * DAY
        with store._transaction():
            idle = [analyzer.observe(old, "TEST", None, mac=f"00:00:00:00:01:{i:02x}", ip=f"10.0.1.{i}")
                    for i in range(1, 6)]
            analyzer._service("10.0.1.1", old, "TEST", "r1", "tcp", 23)
            analyzer._software("10.0.1.1", old, "TEST", "r1", "TLS", "1.0")
            linked = analyzer.observe(old, "TEST", None, mac="00:00:00:00:02:01")
            targeted = analyzer.observe(old, "TEST", None, mac="00:00:00:00:02:02")
            exposed = analyzer.observe(old, "TEST", None, mac="00:00:00:00:02:03", ip="10.0.2.3")
            analyzer._service("10.0.2.3", NOW - DAY, "TEST", "r2", "tcp", 23)
            store.conn.execute("UPDATE security_assets SET last_seen=? WHERE asset_id=?", (old, exposed))
            recent = analyzer.observe(NOW - DAY, "TEST", None, mac="00:00:00:00:03:01")
        with store._transaction():
            store.conn.execute("INSERT INTO security_incidents VALUES ('case-1','k','TEST','x','LOW','Open',?,'{}')",
                               (old,))
            store.conn.execute("INSERT INTO security_case_links VALUES ('case-1','asset',?)", (linked,))
            store.conn.execute("""INSERT INTO security_response_actions (action_id, kind, target, scope,
                requested_by, reason, state, requested_at, expires_at, readback, body)
                VALUES ('act-1','quarantine_mac','00:00:00:00:02:02','','t','r','requested',?,?,
                'unverified','{}')""", (old, NOW + DAY))
        assert prune_assets(store, retention_days=90, batch=3, now=NOW) == (3, True)
        assert prune_assets(store, retention_days=90, batch=3, now=NOW) == (2, False)
        left = {asset["asset_id"] for asset in list_assets(store)}
        assert left == {linked, targeted, exposed, recent} and not left & set(idle)
        # Only the pinned asset's service and finding survive; the idle asset's software went with it.
        assert [count(store, t) for t in ("security_asset_services", "security_exposure_findings",
                                          "security_asset_software")] == [1, 1, 0]
        assert store._read("SELECT count(*) FROM security_asset_identities WHERE asset_id IN (?,?,?,?,?)",
                           idle)[0][0] == 0
        assert prune_assets(store, retention_days=0, now=time.time()) == (0, False)
    finally:
        store.close()
