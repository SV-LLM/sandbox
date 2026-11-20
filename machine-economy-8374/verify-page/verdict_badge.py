"""Q59: bounded cache of checker observations, never a verification authority."""
import collections
import datetime
import html
import threading
import time

CACHE_SECONDS = 300
MAX_ENTRIES = 256


def label(result):
    if not isinstance(result, dict) or result.get('failure_code'):
        return 'not checked'
    p = result.get('proof')
    if not isinstance(p, dict): return 'not checked'
    state = p.get('record_state')
    replay = p.get('replay')
    if state == 'verified' and isinstance(replay, dict) and replay.get('verdict') == 'MATCH':
        return 'Replay-Verified'
    if state in ('asserted', 'discovered', 'validation_failed'):
        return 'record present'
    if (state == 'none' and p.get('publishes_replayable_record') is False
            and p.get('negative_result') == 'NOT_FOUND_IN_CHECKED_LOCATIONS'
            and isinstance(p.get('checked'), list) and p['checked']):
        return 'no replayable record'
    return 'not checked'


class BadgeCache:
    def __init__(self, clock=time.monotonic, wall=time.time):
        self.clock, self.wall = clock, wall
        self.entries = collections.OrderedDict()
        self.lock = threading.Lock()

    def record(self, resource, result):
        if not isinstance(resource, str) or not 1 <= len(resource) <= 8192:
            return
        with self.lock:
            self.entries.pop(resource, None)
            self.entries[resource] = (self.clock(), self.wall(), label(result))
            while len(self.entries) > MAX_ENTRIES:
                self.entries.popitem(last=False)

    def observation(self, resource):
        with self.lock:
            entry = self.entries.get(resource)
            if entry is None or self.clock() - entry[0] >= CACHE_SECONDS:
                return 'not checked', 'no fresh check'
            return entry[2], datetime.datetime.fromtimestamp(
                entry[1], datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    def svg(self, resource):
        verdict, checked_at = self.observation(resource)
        text = html.escape(verdict + ' | ' + checked_at, quote=True)
        # Only the fixed verdict and check date are rendered. No resource text.
        width = 440
        return ("<svg xmlns='http://www.w3.org/2000/svg' width='440' height='24' "
                "role='img' aria-label='" + text + "'><title>" + text
                + "</title><rect width='440' height='24' rx='3' fill='#334155'/>"
                "<text x='220' y='16' text-anchor='middle' fill='white' "
                "font-family='Verdana,sans-serif' font-size='11'>" + text + "</text></svg>").encode()
