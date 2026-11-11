import re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta

@dataclass
class Txn:
    bank_time: str
    account: str
    amount: int
    currency: str
    extra: str
    content: str
    raw: str
    direction: str

def parse_line(raw, account_key):
    date, account, amount, extra, content = raw.split('|', 4)
    timestamp = datetime.strptime(date, 'VPB:%d/%m/%Y %H:%M').replace(tzinfo=timezone(timedelta(hours=7)))
    m = re.fullmatch(r'([+-]?[0-9][0-9,. ]*)([A-Za-z]{3})', amount)
    if not m:
        raise ValueError('Invalid amount')
    value = int(re.sub(r'[, .]', '', m[1]))
    return Txn(timestamp.isoformat(), account or account_key, value, m[2].upper(), extra, content, raw, 'out' if m[1].startswith('-') else 'in')
