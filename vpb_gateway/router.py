import re
import secrets
import hashlib

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()

def patterns(route):
    import json
    if 'patterns' in route:
        if not isinstance(route['patterns'], list) or not route['patterns']: raise ValueError('Patterns required')
        return route['patterns']
    return (json.loads(route['patterns_json']) if route.get('patterns_json') else [{'prefix': route['prefix'], 'id_pattern': route.get('id_pattern') or '[0-9]{1,20}'}])


def validate_route(route, existing):
    import json
    normalized = []
    for item in patterns(route):
        if not isinstance(item, dict) or not isinstance(item.get('prefix'), str): raise ValueError('Invalid pattern')
        prefix = item['prefix'].upper()
        pattern = item.get('id_pattern', '[0-9]{1,20}')
        if not re.fullmatch('[A-Z][A-Z0-9]{0,9}', prefix):
            raise ValueError('Invalid prefix')
        from .security import safe_pattern
        safe_pattern(pattern)
        for old in existing:
            if old['name'] != route['name']:
                for other in patterns(old):
                    if prefix.startswith(other['prefix']) or other['prefix'].startswith(prefix):
                        raise ValueError('Prefix conflict')
        if any(prefix.startswith(p['prefix']) or p['prefix'].startswith(prefix) for p in normalized):
            raise ValueError('Prefix conflict')
        normalized.append(dict(prefix=prefix, id_pattern=pattern))
    if not normalized: raise ValueError('Patterns required')
    route.update(prefix=normalized[0]['prefix'], id_pattern=normalized[0]['id_pattern'], patterns_json=json.dumps(normalized))
    return route

def match(content, routes):
    variants = [content.upper(), re.sub(r'[\s_.-]', '', content.upper())]
    matches = {}
    for original in routes:
      for item in patterns(original):
        r = dict(original, **item)
        if not r['enabled']:
            continue
        pattern = re.compile(r'(?<![A-Z0-9])' + r['prefix'] + '(' + r['id_pattern'] + ')' + (r'(?![0-9])' if r['id_pattern'] == '[0-9]{1,20}' else ''))
        for variant in variants:
            found = list(pattern.finditer(variant))
            if found:
                codes = [r['prefix'] + m[1] for m in found]
                if r['name'] in matches:
                    previous = matches[r['name']]
                    matches[r['name']] = (previous[0], previous[1], list(dict.fromkeys(previous[2] + codes)))
                else:
                    matches[r['name']] = (r, found[0][1], codes)
                break
    if len(matches) != 1:
        return {'status': 'unmatched', 'reason': 'ambiguous' if matches else 'no_match'}
    r, order, codes = next(iter(matches.values()))
    return dict(status='matched', route=r['name'], order_id=order, code=codes[0], codes=codes)
