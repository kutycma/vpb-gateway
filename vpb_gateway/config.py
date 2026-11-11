import os
import tomllib
from pathlib import Path

DEFAULTS = {
    'server': {'host': '127.0.0.1', 'port': 8080},
    'storage': {'db_path': '/var/lib/vpb-gateway/gateway.db', 'state_path': '/var/lib/vpb-gateway/state.json'},
    'vpbank': {'base_url': 'https://neo.vpbank.com.vn', 'account_number': 'all'},
    'fetch': {'safety_poll_seconds': 900, 'poll_when_fcm_down_seconds': 60, 'followup_delays': [3, 8], 'min_fetch_interval_seconds': 2, 'bootstrap': 'ignore'},
    'routing': {'route_outgoing': False, 'forward_unmatched_to': ''}, 'auth': {}, 'telegram': {},
    'alerts': {'fcm_down_alert_minutes': 10, 'alert_on_unmatched': True, 'alert_after_failures': 3, 'notify_transactions': True},
}

def load(path=None):
    import copy
    result = copy.deepcopy(DEFAULTS)
    path = Path(path or os.environ.get('VPG_CONFIG', '/etc/vpb-gateway/config.toml'))
    with path.open('rb') as f:
        for section, values in tomllib.load(f).items():
            result.setdefault(section, {}).update(values)
    if result['fetch']['bootstrap'] not in ('ignore', 'process'):
        raise ValueError('Invalid bootstrap mode')
    return result
