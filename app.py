import argparse
import collections
import json
import re
from common import serve

FAILED = re.compile(r'(?i)(failed password|authentication failure|invalid user|login failed|status=401)')
IP = re.compile(r'(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])')
USER = re.compile(r'(?i)(?:for (?:invalid user )?|user[=: ]+)([A-Za-z0-9_.-]{1,64})')

def analyze(values):
    text = values.get('log', '')
    if not text: return {'error': 'Paste local log text to analyze.'}
    ip_counts = collections.Counter(); user_counts = collections.Counter(); failed_lines = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if FAILED.search(line):
            failed_lines.append(line_no)
            ip_counts.update(IP.findall(line))
            match = USER.search(line)
            if match: user_counts[match.group(1)] += 1
    return {'total_lines': len(text.splitlines()), 'failed_authentication_events': len(failed_lines), 'top_source_ips': ip_counts.most_common(10), 'top_usernames': user_counts.most_common(10), 'flagged_line_numbers': failed_lines[:100], 'note': 'Counts are indicators for review. Correlate with time, identity, MFA, and known automation before acting.'}

def main():
    parser = argparse.ArgumentParser(description='Analyze a local authentication log without contacting any host.')
    parser.add_argument('path', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8088)
    args = parser.parse_args()
    if args.web: serve('Authentication Log Analyzer', [('log','Log text','textarea','Paste a small local auth.log or application-auth excerpt')], analyze, args.port)
    elif args.path:
        with open(args.path, encoding='utf-8', errors='replace') as handle: print(json.dumps(analyze({'log':handle.read()}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()
