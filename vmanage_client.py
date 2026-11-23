"""
vManage REST API Client (Single-Device, On-Demand)
- Supports vManage 19.2+ / 20.x (JSESSIONID + X-XSRF-TOKEN)
- Auto-prompts on self-signed SSL certificates
- Time-chunks 7-day queries so large fabrics never silently truncate
- Always logs out cleanly when finished
"""

from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple
import requests
import urllib3


class VManageClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: int = 30,
        ssl_prompt_cb: Optional[Callable[[str], bool]] = None,
    ):
        host = host.strip().rstrip("/")
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"https://{host}"
        self.base_url = host
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = True
        self.ssl_prompt_cb = ssl_prompt_cb
        self.session = requests.Session()
        self._authenticated = False

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs["verify"] = self.verify_ssl
        try:
            resp = self.session.request(method, url, **kwargs)
            return resp
        except requests.exceptions.SSLError as exc:
            if self.verify_ssl and self.ssl_prompt_cb is not None:
                allow_insecure = self.ssl_prompt_cb(str(exc))
                if allow_insecure:
                    self.verify_ssl = False
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    kwargs["verify"] = False
                    return self.session.request(method, url, **kwargs)
            raise

    def login(self) -> None:
        login_url = f"{self.base_url}/j_security_check"
        payload = {"j_username": self.username, "j_password": self.password}
        resp = self._request("POST", login_url, data=payload)
        if resp.status_code != 200 or b"<html>" in resp.content[:200].lower():
            raise RuntimeError(
                f"vManage login failed (HTTP {resp.status_code}). Check credentials and vManage IP."
            )

        # Fetch XSRF token (required on vManage 19.2+ / 20.x)
        token_url = f"{self.base_url}/dataservice/client/token"
        tok_resp = self._request("GET", token_url)
        if tok_resp.status_code == 200 and tok_resp.text.strip():
            self.session.headers["X-XSRF-TOKEN"] = tok_resp.text.strip()

        self.session.headers["Content-Type"] = "application/json"
        self._authenticated = True

    def logout(self) -> None:
        if not self._authenticated:
            return
        try:
            self._request("GET", f"{self.base_url}/logout")
        except Exception:
            pass
        finally:
            self._authenticated = False
            self.session.close()

    def get(self, endpoint: str) -> dict:
        url = f"{self.base_url}/dataservice{endpoint}"
        resp = self._request("GET", url)
        resp.raise_for_status()
        return resp.json()

    def post(self, endpoint: str, payload: dict) -> dict:
        url = f"{self.base_url}/dataservice{endpoint}"
        resp = self._request("POST", url, json=payload)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Single-Device Queries (NEVER pulls fabric-wide 2000+ branch data)
    # ------------------------------------------------------------------
    def get_device_info(self, system_ip: str) -> dict:
        data = self.get(f"/device?deviceId={system_ip}").get("data", [])
        if not data:
            raise ValueError(f"Device with System IP '{system_ip}' was not found in vManage.")
        return data[0]

    def get_sla_classes(self, system_ip: str) -> List[dict]:
        try:
            return self.get(f"/device/app-route/sla-class?deviceId={system_ip}").get("data", [])
        except Exception:
            return []

    def get_site_tunnels(self, site_id: str) -> List[dict]:
        try:
            res = self.get(f"/statistics/tunnelhealth/history?site={site_id}")
            return res if isinstance(res, list) else res.get("data", [])
        except Exception:
            return []

    def get_policy_from_vsmart(self, system_ip: str) -> List[dict]:
        try:
            return self.get(f"/device/policy/fromvsmart?deviceId={system_ip}").get("data", [])
        except Exception:
            return []

    def get_app_lists(self) -> Dict[str, Tuple[str, List[str]]]:
        """Fetch vManage app-list definitions (id and name -> (list_name, [application_names]))."""
        mapping: Dict[str, Tuple[str, List[str]]] = {}
        try:
            items = self.get("/template/policy/list/app").get("data", [])
            for item in items:
                list_id = item.get("listId")
                name = item.get("name", "App-List")
                entries = item.get("entries", [])
                apps = []
                for entry in entries:
                    val = entry.get("app") or entry.get("appFamily")
                    if val:
                        apps.append(val)
                if apps:
                    if name:
                        mapping[name] = (name, apps)
                    if list_id:
                        mapping[list_id] = (name, apps)
        except Exception:
            pass
        return mapping

    def get_data_prefix_lists(self) -> Dict[str, Tuple[str, List[str]]]:
        """Fetch vManage data-prefix-list definitions (id/name -> (list_name, [ip_prefixes]))."""
        mapping: Dict[str, Tuple[str, List[str]]] = {}
        try:
            items = self.get("/template/policy/list/dataprefix").get("data", [])
            for item in items:
                list_id = item.get("listId")
                name = item.get("name", "Prefix-List")
                prefixes = [
                    e.get("ipPrefix") for e in item.get("entries", []) if e.get("ipPrefix")
                ]
                if prefixes:
                    mapping[name] = (name, prefixes)
                    if list_id:
                        mapping[list_id] = (name, prefixes)
        except Exception:
            pass
        return mapping

    def get_sla_class_lists(self) -> Dict[str, str]:
        """Map vManage SLA class listId -> SLA class name (e.g., Queue0, Queue1)."""
        mapping: Dict[str, str] = {}
        try:
            items = self.get("/template/policy/list/sla").get("data", [])
            for item in items:
                list_id = item.get("listId")
                name = item.get("name")
                if list_id and name:
                    mapping[list_id] = name
        except Exception:
            pass
        return mapping

    def get_aar_policy_definitions(self) -> List[dict]:
        """Fetch detailed JSON definitions of active App-Aware Routing policies from vManage."""
        detailed: List[dict] = []
        try:
            # Prefer definitions referenced by the currently active centralized vSmart policy
            active_def_ids = set()
            vsmart_policies = self.get("/template/policy/vsmart").get("data", [])
            for pol in vsmart_policies:
                if pol.get("isPolicyActivated"):
                    p_def = pol.get("policyDefinition", {})
                    if isinstance(p_def, str):
                        import json
                        try:
                            p_def = json.loads(p_def)
                        except Exception:
                            p_def = {}
                    for asm in p_def.get("assembly", []):
                        if asm.get("type") == "appRoute" and asm.get("definitionId"):
                            active_def_ids.add(asm["definitionId"])

            all_aar = self.get("/template/policy/definition/approute").get("data", [])
            target_ids = [
                d.get("definitionId")
                for d in all_aar
                if d.get("definitionId") and (not active_def_ids or d.get("definitionId") in active_def_ids)
            ]
            for def_id in target_ids:
                try:
                    detail = self.get(f"/template/policy/definition/approute/{def_id}")
                    if detail:
                        detailed.append(detail)
                except Exception:
                    continue
        except Exception:
            pass
        return detailed

    @staticmethod
    def _chunk_time_windows(
        start_utc: datetime, end_utc: datetime, chunk_hours: int = 24
    ) -> List[Tuple[datetime, datetime]]:
        windows = []
        cursor = start_utc
        while cursor < end_utc:
            nxt = min(cursor + timedelta(hours=chunk_hours), end_utc)
            windows.append((cursor, nxt))
            cursor = nxt
        return windows

    @staticmethod
    def _fmt_vmanage_utc(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    def get_sla_and_bfd_events(
        self, system_ip: str, start_utc: datetime, end_utc: datetime
    ) -> List[dict]:
        """Fetch sla-change and bfd-state-change events strictly for system_ip, chunked by 24h."""
        all_events: List[dict] = []
        for win_start, win_end in self._chunk_time_windows(start_utc, end_utc, chunk_hours=24):
            payload = {
                "query": {
                    "condition": "AND",
                    "rules": [
                        {
                            "field": "entry_time",
                            "operator": "between",
                            "type": "date",
                            "value": [self._fmt_vmanage_utc(win_start), self._fmt_vmanage_utc(win_end)],
                        },
                        {
                            "field": "system_ip",
                            "operator": "in",
                            "type": "string",
                            "value": [system_ip],
                        },
                        {
                            "field": "eventname",
                            "operator": "in",
                            "type": "string",
                            "value": ["sla-change", "bfd-state-change"],
                        },
                    ],
                },
                "size": 10000,
            }
            resp = self.post("/event", payload)
            all_events.extend(resp.get("data", []))
        return all_events

    def get_approute_stats(
        self, system_ip: str, start_utc: datetime, end_utc: datetime
    ) -> List[dict]:
        """Fetch approute statistics (loss, latency, jitter) strictly for system_ip, chunked by 24h."""
        all_stats: List[dict] = []
        for win_start, win_end in self._chunk_time_windows(start_utc, end_utc, chunk_hours=24):
            payload = {
                "query": {
                    "condition": "AND",
                    "rules": [
                        {
                            "field": "entry_time",
                            "operator": "between",
                            "type": "date",
                            "value": [self._fmt_vmanage_utc(win_start), self._fmt_vmanage_utc(win_end)],
                        },
                        {
                            "field": "local_system_ip",
                            "operator": "in",
                            "type": "string",
                            "value": [system_ip],
                        },
                    ],
                },
                "size": 10000,
            }
            try:
                resp = self.post("/statistics/approute", payload)
                all_stats.extend(resp.get("data", []))
            except Exception:
                # Fallback field name 'vdevice_name' on older vManage versions
                payload["query"]["rules"][1]["field"] = "vdevice_name"
                try:
                    resp = self.post("/statistics/approute", payload)
                    all_stats.extend(resp.get("data", []))
                except Exception:
                    pass
        return all_stats

    def get_dpi_app_stats(
        self, system_ip: str, start_utc: datetime, end_utc: datetime, hostname: str = ""
    ) -> List[dict]:
        """
        Read-only fetch of vManage SAIE / DPI observed application flows strictly for system_ip.
        Tries historical /statistics/dpi (with multiple vManage 20.x field names),
        then /statistics/dpi/applications/summary, then real-time /device/dpi/applications & /device/dpi/flows.
        """
        # 1. Try historical /statistics/dpi across vManage field-name variants
        field_candidates = [("vdevice_name", system_ip), ("device_ip", system_ip), ("system_ip", system_ip)]
        if hostname:
            field_candidates.append(("host_name", hostname))

        for field_name, field_val in field_candidates:
            all_dpi: List[dict] = []
            for win_start, win_end in self._chunk_time_windows(start_utc, end_utc, chunk_hours=24):
                payload = {
                    "query": {
                        "condition": "AND",
                        "rules": [
                            {
                                "field": "entry_time",
                                "operator": "between",
                                "type": "date",
                                "value": [self._fmt_vmanage_utc(win_start), self._fmt_vmanage_utc(win_end)],
                            },
                            {
                                "field": field_name,
                                "operator": "in",
                                "type": "string",
                                "value": [field_val],
                            },
                        ],
                    },
                    "size": 10000,
                }
                try:
                    resp = self.post("/statistics/dpi", payload)
                    all_dpi.extend(resp.get("data", []))
                except Exception:
                    break
            if all_dpi:
                return all_dpi

        # 2. Try vManage SAIE / DPI summary & real-time device endpoints (100% read-only GET)
        get_endpoints = [
            f"/statistics/dpi/applications/summary?deviceId={system_ip}",
            f"/device/dpi/applications?deviceId={system_ip}",
            f"/device/dpi/flows?deviceId={system_ip}",
        ]
        for ep in get_endpoints:
            try:
                resp = self.get(ep)
                rows = resp if isinstance(resp, list) else resp.get("data", [])
                if rows:
                    return rows
            except Exception:
                continue

        return []

    def get_wan_interfaces(self, system_ip: str) -> List[dict]:
        """Read-only fetch of VPN 0 (transport/WAN) interfaces & speeds for target system_ip."""
        try:
            rows = self.get(f"/device/interface?deviceId={system_ip}").get("data", [])
            wan_rows = [
                r for r in rows
                if str(r.get("vpn-id", "")).strip() == "0"
                and not str(r.get("ifname", "")).lower().startswith(("loopback", "system", "tunnel"))
            ]
            return wan_rows if wan_rows else rows
        except Exception:
            return []

    def get_interface_stats(
        self, system_ip: str, start_utc: datetime, end_utc: datetime
    ) -> List[dict]:
        """
        Read-only fetch of 15-min WAN interface utilization (tx_kbps/rx_kbps) and
        errors/drops (rx_errors/tx_errors/rx_drops/tx_drops) strictly for system_ip.
        """
        for field_name in ("vdevice_name", "device_ip", "system_ip"):
            all_if_stats: List[dict] = []
            for win_start, win_end in self._chunk_time_windows(start_utc, end_utc, chunk_hours=24):
                payload = {
                    "query": {
                        "condition": "AND",
                        "rules": [
                            {
                                "field": "entry_time",
                                "operator": "between",
                                "type": "date",
                                "value": [self._fmt_vmanage_utc(win_start), self._fmt_vmanage_utc(win_end)],
                            },
                            {
                                "field": field_name,
                                "operator": "in",
                                "type": "string",
                                "value": [system_ip],
                            },
                        ],
                    },
                    "size": 10000,
                }
                try:
                    resp = self.post("/statistics/interface", payload)
                    all_if_stats.extend(resp.get("data", []))
                except Exception:
                    break
            if all_if_stats:
                return all_if_stats
        return []
