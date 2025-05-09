#!/usr/bin/python3

# likeafox's dynamic firewall for QubesOS systems
# (c) 2025 Jason Forbes <contact@jasonforbes.ca>

# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

options_defaults = {
    "workdir_path": "work",
    "clients_path": "clients",
    "profiles_subset": None,
    "min_wait_sec": 15,
    "max_wait_sec": (60*60*24),
}

from utils import *
from sites import *

import os, os.path, subprocess, traceback, signal, asyncio
from jinja2 import Template
from qubesagent.firewall import NftablesWorker



def resolve_filepath(path):
    if os.path.isabs(path):
        return path
    else:
        if '__file__' in globals():
            base_dir = os.path.dirname(os.path.realpath(__file__))
        else:
            base_dir = os.getcwd()
        return os.path.join(base_dir, path)

def interpret_qubes_firewall_rule(rule):
    rule_dict = dict(elem.split('=') for elem in rule.split(' '))
    nft,dns = NftablesWorker().prepare_rules("ponies", [rule_dict], 4)
    nft = nft.splitlines()
    dns = list(dns.keys())

    assert nft[0].startswith("flush chain")
    assert nft[1].startswith("table")
    assert nft[2].strip() == "chain ponies {"
    assert [x.strip() for x in nft[-2:]] == ["}","}"]

    nft_rules = [x.strip() for x in nft[3:-2]]
    assert len(nft_rules) > 0

    if dns:
        nft_rules[0] = f"{nft_rules[0]} #{dns[0]}"

    return nft_rules

class Client:
    def __init__(self, **dict_):
        assert set(dict_) >= {'name','profiles'}
        self.__dict__.update(dict_)

    @property
    def is_connected(self):
        netvm = qubes.query_property(self.name, "netvm")
        return netvm == qubes.app.local_name

    @cached_property
    def addr(self):
        addr = qubes.query_property(self.name, "ip")
        if not is_ip4(addr):
            raise ValueError()
        return addr

    @property
    def nft_rules(self):
        r = []
        qubes_rules = qubes.query(self.name, "admin.vm.firewall.Get").splitlines()
        policy_pat = re.compile(r'action=\w+')

        for rule in qubes_rules:
            if policy_pat.fullmatch(rule):
                if rule == "action=accept":
                    break
                else:
                    return r
            r += interpret_qubes_firewall_rule(rule)

        return r or [
            "ip daddr @dns-addrs tcp dport 53 accept",
            "ip daddr @dns-addrs udp dport 53 accept",
            "ip protocol icmp accept"
        ]

def load_clients_config(filepath):
    conf = []
    with open(filepath) as f:
        for l in f:
            l = l.rstrip()
            if l == '' or l.startswith('#'):
                continue
            client_name, *selected_profs = l.split()
            if client_name in (c.name for c in conf):
                raise ValueError("Duplicate entry for "+client_name)
            try:
                profiles = [
                    site_profile_alias_map[p] for p in selected_profs
                ]
            except KeyError:
                msg = f"Invalid site profile name {profname}. Please refer to " \
                    + "site_profiles for valid names."
                raise ValueError(msg)

            cli = Client(name=client_name, profiles=profiles)
            if not cli.is_connected:
                print(f"Warning: {cli.name} is not connected", file=sys.stderr)
            conf.append(cli)
    return conf

class Database:
    def __init__(self, dbpath, clear=False):
        self.dbpath = dbpath

        if os.path.isfile(dbpath):
            with open(dbpath) as f:
                self.data_loaded = json.load(f)
        else:
            self.data_loaded = {}

        if clear:
            self.data = {}
        else:
            self.data = deepcopy(self.data_loaded)

    def update(self, force, subset=None):
        now = unix_minutes()
        for name,profile in site_profiles.items():
            obj = self.data.get(name,
                {'nextRefreshMins':0,'addresses':[],'lastRefreshSucceeded':True}
            )

            if (not force and now < obj['nextRefreshMins']) \
                or (subset is not None and name not in subset):
                continue

            obj['nextRefreshMins'] = now + profile['refreshIntervalMins']
            obj['lastRefreshSucceeded'] = True
            print(f"refreshing {name}: ", end='', file=sys.stderr, flush=True)
            try:
                result = profile['refresh'](obj['addresses'])
                if type(result) is list:
                    if set(result) != set(obj['addresses']):
                        obj['addresses'] = result
                    # (otherwise forgo the update, it's simply a reordering of the same addresses)
                elif result is False:
                    pass
                else:
                    raise TypeError()
            except Exception as e:
                obj['lastRefreshSucceeded'] = False
                print("FAILED\nerror during refresh:", str(e), file=sys.stderr)
            else:
                print("OK", file=sys.stderr)

            self.data[name] = obj

    def save(self, force=False):
        if force or self.data != self.data_loaded:
            with open(self.dbpath, 'w') as f:
                json.dump(self.data, f)
                f.write('\n')
            self.data_loaded = self.data

    def print_status(self, subset=None):
        now = unix_minutes()
        rows = [("PROFILE","STATUS","IPS-ALLOWED")]
        for name,obj in self.data.items():
            if subset is not None and name not in subset:
                continue

            if obj['lastRefreshSucceeded'] == False:
                status = "Refresh-Failed"
            elif now >= obj['nextRefreshMins']:
                status = "Outdated"
            else:
                status = "Good"

            addr_ranges = []
            for addr in obj['addresses']:
                range_ = cidr4_to_intrange(addr)
                range_diff(addr_ranges, range_)
                addr_ranges.append(range_)
            ip_count = sum(len(r) for r in addr_ranges)

            rows.append((name, status, str(ip_count)))

        col_widths = text_column_widths(rows)
        for row in rows:
            print(*(c.ljust(w) for c,w in zip(row, col_widths)))

NFT_TEMPLATE_RAW = '''#!/usr/sbin/nft -f

table ip custom-dynamic {
}

delete table ip custom-dynamic

table ip custom-dynamic {
    set dns-addrs {
        typeof ip daddr
        elements = {
            {%- for addr in dns_addrs %}
            {{ addr }},
            {%- endfor %}
        }
    }
    {% for prof_name,content in data.items() %}
    {%- if content["addresses"] %}
    set {{ prof_name }} {
        typeof ip daddr
        flags interval
        auto-merge
        elements = {
            {%- for addr in content['addresses'] %}
            {{ addr }},
            {%- endfor %}
        }
    }
    {% endif %}
    {%- endfor %}
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifgroup != 2 accept
        ct state established,related accept
        {%- for cli in clients %}
        ip saddr {{ cli.addr }} jump cli-{{ cli.addr.replace('.','-') }}
        {%- endfor %}
        reject with icmp admin-prohibited
    }
    {% for cli in clients %}
    chain cli-{{ cli.addr.replace('.','-') }} {
        #{{ cli.name }}
        {%- for rule in cli.nft_rules %}
        {{ rule }}
        {%- endfor %}
        {%- for prof_name in cli.profiles %}
        {%- if data[prof_name]["addresses"] %}
        ip daddr @{{ prof_name }} accept
        {%- endif %}
        {%- endfor %}
    }
    {% endfor %}
}
'''

NFT_FAILSAFE = '''#!/usr/sbin/nft -f

#                         ! ! ! WARNING ! ! !
#
# Render failed! This is a safe-default nft file that only exists for user
# scripts that ignore errors and naively accept any file given to them.
#
#
#

table ip custom-dynamic {
}

delete table ip custom-dynamic

table ip custom-dynamic {
    chain forward {
        type filter hook forward priority filter; policy drop;
        iifgroup != 2 accept
        ct state established,related accept
        reject with icmp admin-prohibited
    }
}
'''

NFT_IP4_ONLY = '''#!/usr/sbin/nft -f

table inet custom-ip4-only {
}

flush table inet custom-ip4-only

table inet custom-ip4-only {
    chain forward {
        type filter hook forward priority filter - 1; policy drop;
        meta nfproto ipv4 accept
    }
}

'''

def render_nft(clients, data):
    env = {
        'clients': clients,
        'data': data,
        'dns_addrs': qubes.dns_addrs,
    }
    return Template(NFT_TEMPLATE_RAW).render(env)



class App:
    USE_ARGV = object()
    def __init__(self, actions_to_invoke=USE_ARGV):
        self.options = options_defaults.copy()
        self.actions = self._make_actions()
        self.runmode = "OK"
        # validate actions_to_invoke
        ati = sys.argv[1:] if (actions_to_invoke is self.USE_ARGV) \
                        else actions_to_invoke
        if type(ati) is str or not hasattr(ati,"__getitem__"):
            raise TypeError("type(actions_to_invoke) is "+type(ati))
        if invalid_acts := [str(a) for a in ati if a not in self.actions]:
            raise ValueError("invalid action(s): " + ' '.join(invalid_acts))
        #
        self.actions_to_invoke = ati
        self.next_to_invoke = 0
        self.loop_start = 0

    # lazy-loading saved states

    @cached_property
    def db(self):
        path = os.path.join(resolve_filepath(self.options['workdir_path']), "db.json")
        return Database(path)

    @cached_property
    def clients(self):
        path = resolve_filepath(self.options['clients_path'])
        return load_clients_config(path)

    @property
    def active_subset(self):
        if (r := self.options['profiles_subset']) is not None:
            return r
        else:
            r = set()
            for cli in self.clients:
                r |= set(cli.profiles)
            return r

    # actions

    def _make_actions(self):
        actions_ = {}

        def _name_of(f):
            return f.__name__.rstrip('_').replace('_','-')

        def action(f):
            actions_[_name_of(f)] = f

        def xmode_action(*modes):
            def d(f):
                def wrap():
                    if self.runmode in modes:
                        f()
                actions_[_name_of(f)] = wrap
            return d

        # action definitions

        @action
        def read_env():
            for k,v in os.environ.items():
                match k:
                    case "FW_WORKDIR_PATH":
                        self.options['workdir_path'] = v
                    case "FW_CLIENTS_PATH":
                        self.options['clients_path'] = v
                    case "FW_SUBSET":
                        self.options['profiles_subset'] = set(v.split(','))
                    case "FW_MIN_WAIT":
                        self.options['min_wait_sec'] = int(v)
                    case "FW_MAX_WAIT":
                        self.options['max_wait_sec'] = int(v)

        @xmode_action('OK')
        def refresh():
            self.db.update(force=False, subset=self.active_subset)

        @xmode_action('OK')
        def force_refresh():
            self.db.update(force=True, subset=self.active_subset)

        @xmode_action('OK','EXITING')
        def save():
            self.db.save(force=False)

        @action
        def status():
            if self.runmode != 'FAILED':
                self.db.print_status(self.options['profiles_subset'])
            else:
                print("Can't print database state because previous errors were encountered")

        def _render():
            try:
                if self.runmode == 'FAILED':
                    raise Exception("Rendering in a failed state")
                render_out = render_nft(self.clients, self.db.data)
            except Exception as e:
                r = NFT_IP4_ONLY + NFT_FAILSAFE
                return (r, e)
            else:
                r = NFT_IP4_ONLY + render_out
                return (r, None)

        @action
        def render_print():
            render_out, e = _render()
            print(render_out)
            if e is not None:
                raise e

        @action
        def render_activate():
            render_out, e = _render()
            try:
                workdir_path = resolve_filepath(self.options['workdir_path'])
                render_path = os.path.join(workdir_path, "out.nft")
                with open(render_path, 'w') as f:
                    f.write(render_out)
                os.chmod(render_path, 0o744)
                subprocess.run(render_path, check=True)
                print("nft activated", file=sys.stderr)
            finally:
                if e is not None:
                    raise e

        @xmode_action('OK')
        def wait():
            try:
                asyncio.run(self.do_wait())
            finally:
                if 'clients' in self.__dict__:
                    del self.__dict__['clients']

        @xmode_action('OK')
        def s1():
            time.sleep(1)

        @xmode_action('OK')
        def loop():
            self.next_to_invoke = self.loop_start

        @xmode_action('OK')
        def do_():
            self.loop_start = self.next_to_invoke

        @action
        def hi():
            msg = ["hi","bye"][int(self.runmode == 'EXITING')]
            print(msg)
            time.sleep(0.05)

        return actions_

    async def do_wait(self):
        '''doing nothing is complicated'''
        start_time = time.time()
        loop = asyncio.get_running_loop()
        async def min_wait():
            elapsed = time.time() - start_time
            await asyncio.sleep(self.options['min_wait_sec'] - elapsed)

        # task 1/3
        @(lambda f: asyncio.create_task(f()))
        async def firewall_update_waiting():
            @(lambda f: asyncio.create_task(f()))
            async def forever_task():
                while True:
                    await asyncio.sleep(55555)
            assert "SelectorEventLoop" in asyncio.__dict__
            assert isinstance(loop, asyncio.SelectorEventLoop)
            qdb = qubesdb.QubesDB()
            qdb.watch("/qubes-firewall/")
            qdb_watch_fd = qdb.watch_fd()
            def cb():
                loop.remove_reader(qdb_watch_fd)
                forever_task.cancel()
            loop.add_reader(qdb_watch_fd, cb)
            await forever_task
            await asyncio.sleep(0.5)
        for _ in range(2):
            await asyncio.sleep(0) #let firewall watcher get a head-start

        # task 2/3
        @(lambda f: asyncio.create_task(f()))
        async def clients_file_waiting():
            path = resolve_filepath(self.options['clients_path'])
            #await min_wait()
            while True:
                info = os.stat(path)
                if info.st_mtime > start_time:
                    return
                await asyncio.sleep(25)

        # task 3/3
        def determinate_secs():
            min_ = self.options['max_wait_sec']
            for prof in self.active_subset:
                if prof in self.db.data:
                    cur = self.db.data[prof]['nextRefreshMins'] * 60 + 59 - start_time
                    min_ = min(min_, cur)
                else:
                    return 0
            return max(min_, 0)
        determinate_waiting = \
            asyncio.create_task(asyncio.sleep(determinate_secs()))

        # now we play the waiting game
        tasks = (firewall_update_waiting, clients_file_waiting, determinate_waiting)
        hehe = asyncio.create_task(min_wait())
        waiting = asyncio.gather(
            hehe,
            asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        )

        handled_signals = (signal.SIGINT, signal.SIGTERM)
        for sig in handled_signals:
            def get_interrupted(*_):
                print(f"signal {sig} received. exiting soon.", file=sys.stderr)
                if self.runmode == 'OK':
                    self.runmode = "EXITING"
                waiting.cancel()
                hehe.cancel()
            loop.add_signal_handler(sig, get_interrupted)

        try:
            _,(done,pending) = await waiting
            for t in pending:
                t.cancel()
            await asyncio.wait(pending)
        except asyncio.CancelledError:
            pass
        finally:
            for sig in handled_signals:
                loop.remove_signal_handler(sig)

    #

    def run(self):
        while True:
            try:
                act = self.actions[self.actions_to_invoke[self.next_to_invoke]]
            except IndexError:
                break
            self.next_to_invoke += 1

            try:
                act()
            except Exception as e:
                self.runmode = "FAILED"
                traceback.print_exception(e)

        exit(bool(self.runmode == 'FAILED'))

if __name__ == '__main__':
    App().run()
