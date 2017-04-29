"""
Apache Traffic Server Support

"""
import logging
import re

from requests import status_codes


from newrelic_plugin_agent.plugins import base

LOGGER = logging.getLogger(__name__)


class ATS(base.JSONStatsPlugin):

    DEFAULT_PATH = '_stats'
    GUID = 'com.meetme.newrelic_trafficserver_agent'

    HTTP_STATUS_CODES = {
        '1xx': 'Informational',
        '100': 'Continue',
        '101': 'Switching Protocols',
        '102': 'Processing',

        '2xx': 'Success',
        '200': 'OK',
        '201': 'Created',
        '202': 'Accepted',
        '203': 'Non-authoritative Information',
        '204': 'No Content',
        '205': 'Reset Content',
        '206': 'Partial Content',
        '207': 'Multi-Status',
        '208': 'Already Reported',
        '226': 'IM Used',

        '3xx': 'Redirection',
        '300': 'Multiple Choices',
        '301': 'Moved Permanently',
        '302': 'Found',
        '303': 'See Other',
        '304': 'Not Modified',
        '305': 'Use Proxy',
        '307': 'Temporary Redirect',
        '308': 'Permanent Redirect',

        '4xx': 'Client Error',
        '400': 'Bad Request',
        '401': 'Unauthorized',
        '402': 'Payment Required',
        '403': 'Forbidden',
        '404': 'Not Found',
        '405': 'Method Not Allowed',
        '406': 'Not Acceptable',
        '407': 'Proxy Authentication Required',
        '408': 'Request Timeout',
        '409': 'Conflict',
        '410': 'Gone',
        '411': 'Length Required',
        '412': 'Precondition Failed',
        '413': 'Payload Too Large',
        '414': 'Request-URI Too Long',
        '415': 'Unsupported Media Type',
        '416': 'Requested Range Not Satisfiable',
        '417': 'Expectation Failed',
        '418': 'I\'m a teapot',
        '421': 'Misdirected Request',
        '422': 'Unprocessable Entity',
        '423': 'Locked',
        '424': 'Failed Dependency',
        '426': 'Upgrade Required',
        '428': 'Precondition Required',
        '429': 'Too Many Requests',
        '431': 'Request Header Fields Too Large',
        '444': 'Connection Closed Without Response',
        '451': 'Unavailable For Legal Reasons',
        '499': 'Client Closed Request',

        '5xx': 'Server Error',
        '500': 'Internal Server Error',
        '501': 'Not Implemented',
        '502': 'Bad Gateway',
        '503': 'Service Unavailable',
        '504': 'Gateway Timeout',
        '505': 'HTTP Version Not Supported',
        '506': 'Variant Also Negotiates',
        '507': 'Insufficient Storage',
        '508': 'Loop Detected',
        '510': 'Not Extended',
        '511': 'Network Authentication Required',
        '599': 'Network Connect Timeout Error',
    }

    # Connections
    CONNECTIONS_TYPES = {
        'proxy.process.http.total_client_connections': 'HTTP/Client',
        'proxy.process.http.total_server_connections': 'HTTP/Server',
        'proxy.process.http.origin_connections_throttled_out': 'HTTP/Server/Throttled',
    }

    # Requests
    REQUESTS_PREFIX = 'proxy.process.http.'
    REQUESTS_TYPES = {
        'incoming_requests': 'Totals/Incoming',
        'outgoing_requests': 'Totals/Outgoing',

        'head_requests': 'Methods/HEAD',
        'get_requests': 'Methods/GET',
        'post_requests': 'Methods/POST',
        'put_requests': 'Methods/PUT',
        'options_requests': 'Methods/OPTIONS',
        'trace_requests': 'Methods/TRACE',
        'delete_requests': 'Methods/DELETE',
        'purge_requests': 'Methods/PURGE',
        'push_requests': 'Methods/PUSH',
    }

    # Transactions Count
    TRANSACTION_COUNT_PREFIX = 'proxy.process.http.transaction_counts.'
    TRANSACTION_TIME_PREFIX = 'proxy.process.http.transaction_totaltime.'
    TRANSACTION_TYPES = {
        'hit_fresh': 'Hits/Fresh',
        'hit_revalidated': 'Hits/Revalidated',
        'miss_cold': 'Misses/Cold',
        'miss_not_cacheable': 'Misses/Not Cacheable',
        'miss_changed': 'Misses/Changed',
        'miss_client_no_cache': 'Misses/No Cache',
        'errors.connect_failed': 'Errors/Connection Failed',
        'errors.aborts': 'Errors/Aborts',
        'errors.possible_aborts': 'Errors/Possible Aborts',
        'errors.pre_accept_hangups': 'Errors/Pre-Accept Hangups',
        'errors.early_hangups': 'Errors/Early Hangup',
        'errors.empty_hangups': 'Errors/Empty Hangup',
        'errors.other': 'Errors/Other',
        'other.unclassified': 'Unclassified',
    }

    def add_datapoints(self, stats):
        """Add all of the data points for a node

        :param str stats: The stub stats content
        """
        stats = stats and stats.get('global')
        if not stats:
            return

        self.add_hostdb_datapoints(stats)
        self.add_connection_datapoints(stats)
        self.add_requests_datapoints(stats)
        self.add_responses_datapoints(stats)
        self.add_transactions_datapoints(stats)
        self.add_cache_datapoints(stats)

    def add_connection_datapoints(self, stats):
        for conn_type, name in ATS.CONNECTIONS_TYPES.items():
            value = long(stats.get(conn_type) or 0)
            self.add_derive_value(
                'Connections/%s' % name,
                'connections',
                value
            )

        count_key = 'proxy.process.http.total_client_connections'
        previous_count = self.derive_last_interval.get(count_key)
        count = long(stats.get(count_key) or 0)
        if previous_count is not None:
            time = float(stats.get('proxy.process.http.total_transactions_time') or 0)
            self.add_derive_value(
                'Connections/HTTP/Client',
                'secs|connections',
                time,
                count - previous_count
            )

        self.derive_last_interval[count_key] = count

    def add_requests_datapoints(self, stats):
        for request_type, name in ATS.REQUESTS_TYPES.items():
            value = long(stats.get(ATS.REQUESTS_PREFIX + request_type) or 0)
            self.add_derive_value(
                'Requests/%s' % name,
                'requests',
                value
            )

        incoming = long(stats.get(ATS.REQUESTS_PREFIX + 'incoming_requests') or 0)
        outgoing = long(stats.get(ATS.REQUESTS_PREFIX + 'outgoing_requests') or 0)
        if outgoing > 0:
            requests_ratio = 100 * float(incoming) / outgoing
            self.add_gauge_value('Scoreboard/Requests/Saved', '%', dns_ratio)

    def add_responses_datapoints(self, stats):
        for code, text in ATS.HTTP_STATUS_CODES.items():
            value = stats.get('proxy.process.http.%s_responses' % code)
            if value is not None:
                if code[1] == 'x':
                    metric_name = 'Scoreboard/Responses/%s %s' % (code, text)
                else:
                    metric_name = 'Responses/%s %s' % (code, text)
                self.add_derive_value(metric_name, 'responses', long(value))

    def add_transactions_datapoints(self, stats):
        for transaction, text in ATS.TRANSACTION_TYPES.items():
            count_key = ATS.TRANSACTION_COUNT_PREFIX + transaction

            count = long(stats.get(count_key) or 0)
            previous_count = self.derive_last_interval.get(count_key)

            if previous_count is not None:
                time = float(stats.get(ATS.TRANSACTION_TIME_PREFIX + transaction) or 0)
                self.add_derive_value(
                    'Transactions/%s' % text,
                    'secs|transactions',
                    time,
                    count - previous_count
                )

            self.derive_last_interval[count_key] = count

    def add_hostdb_datapoints(self, stats):
        dns_hits = long(stats.get('proxy.process.hostdb.total_hits') or 0)
        dns_lookup = long(stats.get('proxy.process.hostdb.total_lookups') or 0)

        self.add_derive_value(
            'HostDB/Entries',
            'hostnames',
            long(stats.get('proxy.process.hostdb.total_entries') or 0)
        )
        self.add_derive_value('HostDB/Hits', 'hostnames', dns_hits)
        self.add_derive_value('HostDB/Lookups', 'hostnames', dns_lookup)
        if dns_lookup > 0:
            dns_ratio = 100 * float(dns_hits) / dns_lookup
            self.add_gauge_value('Scoreboard/HostDB/Hits', '%', dns_ratio)

    def add_cache_datapoints(self, stats):
        megas = 1000000
        hits = long(stats.get('proxy.node.cache_total_hits') or 0)
        hits_mem = long(stats.get('proxy.node.cache_total_hits_mem') or 0)
        misses = long(stats.get('proxy.node.cache_total_misses') or 0)
        self.add_derive_value('Cache/Performance/Hits/Storage', 'requests', hits - hits_mem)
        self.add_derive_value('Cache/Performance/Hits/Memory', 'requests', hits_mem)
        self.add_derive_value('Cache/Performance/Misses', 'requests', misses)

        total = hits + misses
        if total > 0:
            self.add_gauge_value('Scoreboard/Cache/Hits', '%', 100 * float(hits) / total)
            self.add_gauge_value('Scoreboard/Storage/Hits', '%', 100 * float(hits - hits_mem) / total)
            self.add_gauge_value('Scoreboard/Memory/Hits', '%', 100 * float(hits_mem) / total)

        bytes_total = float(stats.get('proxy.process.cache.bytes_total') or 0) / megas
        bytes_used = float(stats.get('proxy.process.cache.bytes_used') or 0) / megas
        self.add_derive_value('Cache/Storage/Size', 'megabytes', bytes_total)
        self.add_derive_value('Cache/Storage/Used', 'megabytes', bytes_used)
        if bytes_total > 0:
            self.add_gauge_value('Scoreboard/Storage/Used', '%', 100 * float(bytes_used) / bytes_total)

        mem_total = float(stats.get('proxy.process.cache.ram_cache.total_bytes') or 0) / megas
        mem_used = float(stats.get('proxy.process.cache.ram_cache.bytes_used') or 0) / megas
        self.add_derive_value('Cache/Memory/Size', 'megabytes', mem_total)
        self.add_derive_value('Cache/Memory/Used', 'megabytes', mem_used)
        if mem_total > 0:
            self.add_gauge_value('Scoreboard/Memory/Use', '%', 100 * float(mem_used) / mem_total)

        served_bytes = float(stats.get('proxy.node.user_agent_total_bytes') or 0) / 1000000
        origin_bytes = float(stats.get('proxy.node.origin_server_total_bytes') or 0) / 1000000
        self.add_derive_value('Cache/Bandwidth/Origin', 'megabytes', origin_bytes)
        self.add_derive_value('Cache/Bandwidth/Served', 'megabytes', served_bytes)
        if served_bytes > 0:
            bandwidth_gain = 100 * float(served_bytes - origin_bytes) / served_bytes
            self.add_gauge_value('Scoreboard/Bandwidth/Saved', '%', bandwidth_gain)
