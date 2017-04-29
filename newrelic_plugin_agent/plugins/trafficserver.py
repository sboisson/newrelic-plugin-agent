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
        'proxy.process.http.total_client_connections': 'Client',
        'proxy.process.http.total_server_connections': 'Server',
        'proxy.process.http.origin_connections_throttled_out': 'Throttled Out',
    }

    # Requests
    REQUESTS_PREFIX = 'proxy.process.http.'
    REQUESTS_TYPES = {
        'incoming_requests': 'Incoming',
        'outgoing_requests': 'Outgoing',

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
    TRANSACTION_COUNT_PREFIX = 'proxy.node.http.transaction_counts.'
    TRANSACTION_TIME_PREFIX = 'proxy.process.http.transaction_totaltime.'
    TRANSACTION_TYPES = {
        'hit_fresh': 'Hits Fresh',
        'hit_revalidated': 'Hits Revalidated',
        'miss_cold': 'Misses Cold',
        'miss_not_cacheable': 'Misses No Cacheable',
        'miss_changed': 'Misses Changed',
        'miss_client_no_cache': 'Misses No Cache',
        'errors.connect_failed': 'Errors/Connection Failed',
        'errors.aborts': 'Errors/Aborts',
        'errors.possible_aborts': 'Errors/Possible Aborts',
        'errors.pre_accept_hangups': 'Errors/Pre-Accept Hangups',
        'errors.early_hangups': 'Errors/Early Hangup',
        'errors.empty_hangups': 'Errors/Empty Hangup',
        'errors.other': 'Erros/Other',
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

    def add_requests_datapoints(self, stats):
        for request_type, name in ATS.REQUESTS_TYPES.items():
            value = long(stats.get(REQUESTS_PREFIX + request_type) or 0)
            self.add_derive_value(
                'Requests/%s' % name,
                'requests',
                value
            )

    def add_responses_datapoints(self, stats):
        for code, text in ATS.HTTP_STATUS_CODES.items():
            value = stats.get('proxy.process.http.%s_response' % code)
            if value is not None:
                self.add_derive_value(
                    'Responses/Status/%s %s' % (code, text),
                    'responses',
                    long(value)
                )

    def add_transactions_datapoints(self, stats):
        for transaction, text in ATS.TRANSACTION_TYPES.items():
            count = long(stats.get(TRANSACTION_COUNT_PREFIX + transaction) or 0)
            time = float(stats.get(TRANSACTION_TIME_PREFIX + transaction) or 0)
            self.add_derive_value(
                'Transactions/Counts/%s' % name,
                'transactions',
                count
            )
            self.add_derive_timing_value(
                'Transactions/Timing/%s' % name,
                'seconds',
                time,
                count
            )

    def add_hostdb_datapoints(self, stats):
        dns_hits = long(stats.get('proxy.node.hostdb.total_hits') or 0)
        dns_lookup = long(stats.get('proxy.node.hostdb.total_lookups') or 0)

        self.add_derive_value(
            'HostDB/Entries',
            'hostnames',
            long(stats.get('proxy.process.hostdb.total_entries') or 0)
        )
        self.add_derive_value('HostDB/Hits', 'hostnames', dns_hits)
        self.add_derive_value('HostDB/Lookups', 'hostnames', dns_lookup)
        if dns_lookup > 0:
            dns_ratio = 100 * float(dns_hits) / dns_lookup
            self.add_gauge_value('HostDB/Hit Ratio', 'ratio', dns_ratio)

    def add_cache_datapoints(self, stats):
        hits = long(stats.get('proxy.node.cache_total_hits') or 0)
        hits_mem = long(stats.get('proxy.node.cache_total_hits_mem') or 0)
        misses = long(stats.get('proxy.node.cache_total_misses') or 0)
        self.add_derive_value('Cache/Statistics/Hits', 'requests', hits)
        self.add_derive_value('Cache/Statistics/Memory Hits', 'requests', hits_mem)
        self.add_derive_value('Cache/Statistics/Misses', 'requests', misses)

        total = hits + misses
        if total > 0:
            self.add_gauge_value('Cache/Statistics/Hit Ratio', 'ratio', 100 * float(hits) / total)
            self.add_gauge_value('Cache/Statistics/Memory Hit Ratio', 'ratio', 100 * float(hits_mem) / total)

        bytes_total = long(stats.get('proxy.process.cache.bytes_total') or 0)
        bytes_used = long(stats.get('proxy.process.cache.bytes_used') or 0)
        self.add_derive_value('Cache/Storage/Size', 'bytes', bytes_total)
        self.add_derive_value('Cache/Storage/Used', 'bytes', bytes_used)
        if bytes_total > 0:
            self.add_gauge_value('Cache/Storage/Use', 'ratio', 100 * float(bytes_used) / bytes_total)

        mem_total = long(stats.get('proxy.process.cache.ram_cache.total_bytes') or 0)
        mem_used = long(stats.get('proxy.process.cache.ram_cache.bytes_used') or 0)
        self.add_derive_value('Cache/Memory/Size', 'bytes', mem_total)
        self.add_derive_value('Cache/Memory/Used', 'bytes', mem_used)
        if mem_total > 0:
            self.add_gauge_value('Cache/Memory/Use', 'ratio', 100 * float(mem_used) / mem_total)

        served_bytes = long(stats.get('proxy.node.user_agent_total_bytes') or 0)
        origin_bytes = long(stats.get('proxy.node.origin_server_total_bytes') or 0)
        self.add_derive_value('Cache/Bandwidth/Origin', 'bytes', origin_bytes)
        self.add_derive_value('Cache/Bandwidth/Served', 'bytes', served_bytes)
        if served_bytes > 0:
            bandwidth_gain = 100 * float(served_bytes - origin_bytes) / served_bytes
            self.add_gauge_value('Cache/Bandwidth/Gain', 'ratio', bandwidth_gain)
