"""Verify evidence bytes and tamper-evident custody event chains."""
import json

import hashlib
def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
def chain(events):
    previous, result = '0'*64, []
    for event in events:
        payload = {'event':event,'previous':previous}
        previous = digest(json.dumps(payload,sort_keys=True,separators=(',',':')))
        result.append({**payload,'hash':previous})
    return result
def analyze(data):
    actual = {path:digest(text) for path,text in sorted(data.get('artifacts',{}).items())}
    expected = data.get('manifest',actual)
    changed = sorted(path for path in expected.keys() & actual.keys() if expected[path] != actual[path])
    supplied = data.get('custody_chain')
    generated = chain(data.get('events',[]))
    valid = True
    if supplied is not None:
        valid = supplied == chain([record['event'] for record in supplied])
    return {'manifest':actual,'changed':changed,'missing':sorted(expected.keys()-actual.keys()),
            'unexpected':sorted(actual.keys()-expected.keys()),'chain_valid':valid,'custody_chain':generated}

if __name__ == '__main__':
    import argparse, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Path to a JSON scenario')
    args = parser.parse_args()
    try:
        with open(args.input, encoding='utf-8') as source:
            data = json.load(source)
        if not isinstance(data, dict):
            raise ValueError('Input must be a JSON object')
        print(json.dumps(analyze(data), indent=2, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError) as error:
        print('Input error: '+str(error), file=sys.stderr)
        sys.exit(2)
