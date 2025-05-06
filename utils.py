import sys, json, time, re, subprocess, functools
from functools import cached_property
from copy import deepcopy
from types import SimpleNamespace

def unix_minutes():
    return time.time_ns() // (60 * (10**9))

ip4_pattern = re.compile(r"^[1-9][0-9]{0,2}(?:\.(?:0|[1-9][0-9]{0,2})){3}(?:/[1-9][0-9]?)?$")
def is_ip4(s):
    if not bool(ip4_pattern.match(s)):
        return False
    [s,*suffix] = s.split('/')
    if suffix and int(suffix[0]) not in range(1,33):
        return False
    for x in s.split('.'):
        if int(x) not in range(256):
            return False
    return True

def cidr4_to_intrange(cidr):
    if not is_ip4(cidr) or '/' not in cidr:
        raise TypeError()
    addr,network = cidr.split('/')
    addr_int = functools.reduce((lambda r,n: (r<<8)+int(n)), addr.split('.'), 0)
    mask = ~(0xFFFFFFFF >> int(network)) & 0xFFFFFFFF
    size = 1 << (32 - int(network))
    return range(addr_int & mask, (addr_int & mask) + size)

def range_diff(a_grp, b):
    for a in a_grp:
        if b.stop <= a.start or a.stop <= b.start:
            yield a
        else:
            for art,op in [(a.start, b.start), (b.stop, a.stop)]:
                if art < op:
                    yield range(art,op)

def text_column_widths(rows):
    col_widths = []
    for row in rows:
        row_sz, sz = len(row), len(col_widths)
        if row_sz > sz:
            col_widths += [0] * (row_sz - sz)
        for i,(c,width) in enumerate(zip(row, col_widths)):
            col_widths[i] = max(width, len(c))
    return col_widths

@(lambda x: x())
class qubes:
    #
    @cached_property
    def admin(self):
        import qubesadmin
        return qubesadmin

    @cached_property
    def app(self):
        return self.admin.Qubes()

    def query(self, client_name, api_call):
        try:
            query_result = self.app.qubesd_call(client_name, api_call)
        except self.admin.exc.QubesDaemonAccessError:
            msg = f"Forbidden access querying {client_name}. You may have " \
                + "forgotten to add the relevant tag (using qvm-tags), or " \
                + f"maybe {client_name} doesn't exist."
            print(msg, file=sys.stderr)
            raise
        return query_result.decode()

    @staticmethod
    def dns_addrs():
        r = []
        for key in ("/qubes-primary-dns","/qubes-secondary-dns"):
            proc = subprocess.run(
                        ["/usr/bin/qubesdb-read",key],
                        text=True,
                        capture_output=True)
            addr = proc.stdout.strip()
            if is_ip4(addr):
                r.append(addr)
        if not r:
            raise Exception("Couldn't retreive any DNS addresses")
        return r
