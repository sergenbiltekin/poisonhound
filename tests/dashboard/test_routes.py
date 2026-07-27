from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from poisonhound.core.alert import Alert
from poisonhound.core.config import PoisonHoundConfig
from poisonhound.dashboard.app import create_app
from poisonhound.dashboard.store import AlertStore

USERNAME = "admin"
PASSWORD = "test-pass"


def _make_client(
    config_factory: Callable[..., PoisonHoundConfig],
    tmp_path: Path,
    store: AlertStore | None = None,
) -> TestClient:
    config = config_factory(dashboard={"password": PASSWORD, "username": USERNAME})
    store = store or AlertStore(":memory:")
    config_path = tmp_path / "config.yaml"
    config_path.write_text("interface: eth0\n", encoding="utf-8")
    app = create_app(store, lambda: config, config_path)
    return TestClient(app)


def _login(
    client: TestClient, username: str = USERNAME, password: str = PASSWORD
) -> None:
    resp = client.post(
        "/login",
        data={"username": username, "password": password, "next": "/"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_health_does_not_require_auth(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)

    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_alerts_list_redirects_to_login_when_unauthenticated(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)

    resp = client.get("/", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login")


def test_login_with_wrong_password_redirects_back_with_error(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)

    resp = client.post(
        "/login",
        data={"username": USERNAME, "password": "wrong-password", "next": "/"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?error=1")
    # still not authenticated
    assert client.get("/", follow_redirects=False).status_code == 303


def test_login_then_alerts_list_with_no_alerts(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)
    _login(client)

    resp = client.get("/")

    assert resp.status_code == 200
    assert "No alerts recorded yet" in resp.text


def test_logout_revokes_the_session(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)
    _login(client)
    assert client.get("/").status_code == 200

    client.get("/logout", follow_redirects=False)

    assert client.get("/", follow_redirects=False).status_code == 303


def test_alerts_list_shows_recorded_alert(
    config_factory: Callable[..., PoisonHoundConfig],
    tmp_path: Path,
    alert_factory: Callable[..., Alert],
) -> None:
    store = AlertStore(":memory:")
    store.insert_or_update(alert_factory(title="Test spoof alert"))
    client = _make_client(config_factory, tmp_path, store=store)
    _login(client)

    resp = client.get("/")

    assert resp.status_code == 200
    assert "Test spoof alert" in resp.text


def test_alert_detail_returns_404_for_unknown_id(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)
    _login(client)

    resp = client.get("/alerts/999")

    assert resp.status_code == 404


def test_alert_detail_shows_remediation_and_evidence(
    config_factory: Callable[..., PoisonHoundConfig],
    tmp_path: Path,
    alert_factory: Callable[..., Alert],
) -> None:
    store = AlertStore(":memory:")
    store.insert_or_update(
        alert_factory(remediation=["Do the thing"], evidence={"packet_summary": "ARP who-has"})
    )
    client = _make_client(config_factory, tmp_path, store=store)
    _login(client)
    alert_id = store.list_alerts()[0]["id"]

    resp = client.get(f"/alerts/{alert_id}")

    assert resp.status_code == 200
    assert "Do the thing" in resp.text
    assert "ARP who-has" in resp.text


def test_settings_form_prefills_current_config(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    client = _make_client(config_factory, tmp_path)
    _login(client)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "smtp.example.com" in resp.text


def test_settings_post_writes_config_and_triggers_reload(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    real_config_path = tmp_path / "config.yaml"
    real_config_path.write_text(
        """
interface: eth0
detectors:
  arp_spoof:
    gateway_ip: 192.168.1.1
  rogue_dhcp: {}
  ipv6_rogue_ra: {}
  name_resolution_canary: {}
smtp:
  host: smtp.example.com
  from_addr: alerts@example.com
  to_addrs: ["you@example.com"]
""",
        encoding="utf-8",
    )
    config = config_factory(dashboard={"password": PASSWORD, "username": USERNAME})
    store = AlertStore(":memory:")
    reload_calls: list[int] = []
    app = create_app(
        store, lambda: config, real_config_path, reload_config=lambda: reload_calls.append(1)
    )
    client = TestClient(app)
    _login(client)

    resp = client.post(
        "/settings",
        data={
            "smtp_host": "smtp.new-host.example.com",
            "smtp_port": "587",
            "smtp_from_addr": "alerts@example.com",
            "smtp_to_addrs": "you@example.com, other@example.com",
            "smtp_min_severity": "high",
            "arp_spoof_gateway_ip": "192.168.1.254",
            "rogue_dhcp_authorized_servers": "192.168.1.1",
            "ipv6_authorized_routers": "",
            "ipv6_authorized_dhcpv6_servers": "",
        },
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert reload_calls == [1]

    saved = yaml.safe_load(real_config_path.read_text(encoding="utf-8"))
    assert saved["smtp"]["host"] == "smtp.new-host.example.com"
    assert saved["smtp"]["to_addrs"] == ["you@example.com", "other@example.com"]
    assert saved["smtp"]["min_severity"] == "high"
    assert saved["detectors"]["arp_spoof"]["gateway_ip"] == "192.168.1.254"
    assert saved["detectors"]["rogue_dhcp"]["authorized_servers"] == ["192.168.1.1"]


def test_settings_post_leaves_password_unchanged_when_blank(
    config_factory: Callable[..., PoisonHoundConfig], tmp_path: Path
) -> None:
    real_config_path = tmp_path / "config.yaml"
    real_config_path.write_text(
        """
interface: eth0
detectors:
  arp_spoof:
    gateway_ip: 192.168.1.1
  rogue_dhcp: {}
  ipv6_rogue_ra: {}
  name_resolution_canary: {}
smtp:
  host: smtp.example.com
  password: existing-secret
  from_addr: alerts@example.com
  to_addrs: ["you@example.com"]
""",
        encoding="utf-8",
    )
    config = config_factory(dashboard={"password": PASSWORD, "username": USERNAME})
    store = AlertStore(":memory:")
    app = create_app(store, lambda: config, real_config_path)
    client = TestClient(app)
    _login(client)

    client.post(
        "/settings",
        data={
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_from_addr": "alerts@example.com",
            "smtp_to_addrs": "you@example.com",
            "smtp_min_severity": "medium",
            "arp_spoof_gateway_ip": "192.168.1.1",
        },
        follow_redirects=False,
    )

    saved = yaml.safe_load(real_config_path.read_text(encoding="utf-8"))
    assert saved["smtp"]["password"] == "existing-secret"
