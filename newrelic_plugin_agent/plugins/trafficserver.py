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

    RESPONSES_SIZE = {
        'proxy.process.http.response_document_size_100': '100 Bytes',
        'proxy.process.http.response_document_size_1K': '1 KB',
        'proxy.process.http.response_document_size_3K': '3 KB',
        'proxy.process.http.response_document_size_5K': '5 KB',
        'proxy.process.http.response_document_size_10K': '10 KB',
        'proxy.process.http.response_document_size_1M': '1 MB',
        'proxy.process.http.response_document_size_inf': '> 1 MB',
    }

    # Connections
    CONNECTIONS_TYPES = {
        'proxy.process.http.total_client_connections': 'HTTP/Client',
        'proxy.process.http.total_server_connections': 'HTTP/Server',
    }

    CONNECTIONS_GAUGES = {
        'proxy.process.http.current_client_connections': 'Scoreboard/Connections/HTTP/Client/Current',
        'proxy.process.http.current_active_client_connections': 'Scoreboard/Connections/HTTP/Client/Active',
        'proxy.process.http.current_server_connections': 'Scoreboard/Connections/HTTP/Server/Current',
    }

    # Requests
    REQUESTS_PREFIX = 'proxy.process.http.'
    REQUESTS_TYPES = {
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

    CACHE_OPERATIONS = {
        'proxy.process.cache.lookup': 'Cache/Operations/Lookup',
        'proxy.process.cache.write': 'Cache/Operations/Write',
        'proxy.process.cache.update': 'Cache/Operations/Update',
        'proxy.process.cache.read': 'Cache/Operations/Read',
        'proxy.process.cache.remove': 'Cache/Operations/Remove',
        'proxy.process.cache.evacuate': 'Cache/Operations/Evacuate',
        'proxy.process.cache.scan': 'Cache/Operations/Scan',
        'proxy.process.cache.read_busy': 'Cache/Operations/Read Busy',
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

    def add_document_size_datapoints(self, metric_prefix, requests, header_size, body_size):
        if requests > 0:
            self.add_derive_value(
                metric_prefix + '/Total',
                'bytes|requests',
                header_size + body_size,
                requests
            )
            self.add_derive_value(
                metric_prefix + '/Header',
                'bytes|requests',
                header_size,
                requests
            )
            self.add_derive_value(
                metric_prefix + '/Body',
                'bytes|requests',
                header_size,
                requests
            )

    def add_connection_datapoints(self, stats):
        client_connections = long(stats.get('proxy.process.http.total_client_connections') or 0)
        server_connections = long(stats.get('proxy.process.http.total_server_connections') or 0)
        broken_server_connections = long(stats.get('proxy.process.http.broken_server_connections') or 0)

        self.add_derive_value('Connections/HTTP/Server/Broken', 'connections', broken_server_connections)
        client_connections = self.add_derive_value('Connections/HTTP/Client', 'connections', client_connections)
        server_connections = self.add_derive_value('Connections/HTTP/Server', 'connections', server_connections)

        incoming_requests = self.add_derive_value(
            'Requests/Totals/Incoming',
            'requests|connections',
            long(stats.get(ATS.REQUESTS_PREFIX + 'incoming_requests') or 0),
            client_connections
        )

        self.add_document_size_datapoints(
            'Responses/Sizes/Client',
            incoming_requests,
            long(stats.get('proxy.process.http.user_agent_response_header_total_size') or 0),
            long(stats.get('proxy.process.http.user_agent_response_document_total_size') or 0)
        )

        outgoing_requests = self.add_derive_value(
            'Requests/Totals/Outgoing',
            'requests|connections',
            long(stats.get(ATS.REQUESTS_PREFIX + 'outgoing_requests') or 0),
            server_connections
        )

        self.add_document_size_datapoints(
            'Responses/Sizes/Client',
            incoming_requests,
            long(stats.get('proxy.process.http.origin_server_response_header_total_size') or 0),
            long(stats.get('proxy.process.http.origin_server_response_document_total_size') or 0)
        )

        if outgoing_requests > 0:
            requests_ratio = 100 * float(incoming_requests) / outgoing_requests
            self.add_gauge_value('Scoreboard/Requests/Saved', '%', requests_ratio)

        for key, label for ATS.CONNECTIONS_GAUGES.items():
            self.add_gauge_value(
                label,
                'connections',
                float(stats.get(key) or 0)
            )

        keepalive_timeout_key = 'proxy.process.net.dynamic_keep_alive_timeout_in_count'
        keepalive_timeouts = long(stats.get(keepalive_timeout_key) or 0)
        previous_keepalive_timeouts = self.derive_last_interval.get(keepalive_timeout_key)
        if previous_keepalive_timeouts is not None:
            self.add_derive_value(
                'Scoreboard/Keep Alive/Timeout',
                'seconds|connections',
                long(stats.get('proxy.process.net.dynamic_keep_alive_timeout_in_total') or 0),
                keepalive_timeouts - previous_keepalive_timeouts
            )
        self.derive_last_interval[keepalive_timeout_key] = keepalive_timeouts



# proxy.process.http.completed_requests
# proxy.process.http.connect_requests

# proxy.process.cache.gc_bytes_evacuated
# proxy.process.cache.evacuate.active
# proxy.process.cache.evacuate.failure
# proxy.process.cache.evacuate.success

# proxy.process.cache.read_busy.failure
# proxy.process.cache.read_busy.success
# proxy.process.cache.read.failure
# proxy.process.cache.read.success
# proxy.process.cache.remove.failure
# proxy.process.cache.remove.success
# proxy.process.cache.scan.failure
# proxy.process.cache.scan.success
# proxy.process.cache.update.failure
# proxy.process.cache.update.success
# proxy.process.cache.write.failure
# proxy.process.cache.write.success

# proxy.process.http.cache_read_error
# proxy.process.http.cache_read_errors
# proxy.process.http.cache_updates
# proxy.process.http.cache_write_errors
# proxy.process.http.cache_writes

# proxy.process.net.accepts_currently_open

# proxy.process.congestion.congested_on_conn_failures
# proxy.process.congestion.congested_on_max_connection

    def add_requests_datapoints(self, stats):
        for request_type, name in ATS.REQUESTS_TYPES.items():
            value = long(stats.get(ATS.REQUESTS_PREFIX + request_type) or 0)
            self.add_derive_value(
                'Requests/%s' % name,
                'requests',
                value,
                skip_if_zero=True
            )

    def add_responses_datapoints(self, stats):
        for code, text in ATS.HTTP_STATUS_CODES.items():
            value = stats.get('proxy.process.http.%s_responses' % code)
            if value is not None:
                if code[1] == 'x':
                    metric_name = 'Scoreboard/Responses/%s %s' % (code, text)
                else:
                    metric_name = 'Responses/%cxx/%s %s' % (code[0], code, text)
                self.add_derive_value(metric_name, 'responses', long(value), skip_if_zero=True)

        for key, text in ATS.RESPONSES_SIZE.items():
            self.add_derive_value(
                'Responses/Sizes/Distribution/%s' % text,
                'responses',
                long(stats.get(key) or 0)
            )

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
                    count - previous_count,
                    skip_if_zero=True
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
        dns_hits = self.add_derive_value('HostDB/Hits', 'hostnames', dns_hits)
        dns_lookup = self.add_derive_value('HostDB/Lookups', 'hostnames', dns_lookup)
        if dns_lookup > 0:
            dns_ratio = 100 * float(dns_hits) / dns_lookup
            self.add_gauge_value('Scoreboard/HostDB/Hits', '%', dns_ratio)

    def add_cache_datapoints(self, stats):
        hits = long(stats.get('proxy.node.cache_total_hits') or 0)
        hits_mem = long(stats.get('proxy.node.cache_total_hits_mem') or 0)
        misses = long(stats.get('proxy.node.cache_total_misses') or 0)

        storage_hits = self.add_derive_value('Cache/Performance/Hits/Storage', 'requests', hits - hits_mem)
        memory_hits = self.add_derive_value('Cache/Performance/Hits/Memory', 'requests', hits_mem)
        misses = self.add_derive_value('Cache/Performance/Misses', 'requests', misses)

        if storage_hits and memory_hits and misses:
            total = storage_hits + memory_hits + misses
            self.add_gauge_value('Scoreboard/Cache/Hits', '%', 100 * float(storage_hits + memory_hits) / total)
            self.add_gauge_value('Scoreboard/Disk/Hits', '%', 100 * float(storage_hits) / total)
            self.add_gauge_value('Scoreboard/Memory/Hits', '%', 100 * float(memory_hits) / total)

        for key, label in ATS.CACHE_OPERATIONS.items():
            self.add_derive_value(label + '/Success', None, long(stats.get(key + '.success') or 0), skip_if_zero=True)
            self.add_derive_value(label + '/Failure', None, long(stats.get(key + '.failure') or 0), skip_if_zero=True)

        # Bandwidth
        served_bytes = float(stats.get('proxy.node.user_agent_total_bytes') or 0)
        origin_bytes = float(stats.get('proxy.node.origin_server_total_bytes') or 0)
        origin_bytes = self.add_derive_value('Cache/Bandwidth/Origin', 'bytes', origin_bytes)
        served_bytes = self.add_derive_value('Cache/Bandwidth/Served', 'bytes', served_bytes)
        if served_bytes > 0:
            bandwidth_gain = 100 * float(served_bytes - origin_bytes) / served_bytes
            self.add_gauge_value('Scoreboard/Bandwidth/Saved', '%', bandwidth_gain)

        # Disk cache
        bytes_total = float(stats.get('proxy.process.cache.bytes_total') or 0)
        bytes_used = float(stats.get('proxy.process.cache.bytes_used') or 0)
        entries_used = long(stats.get('proxy.process.cache.direntries.used') or 0)
        self.add_derive_value('Cache/Disk/Size', 'bytes', bytes_total)
        self.add_derive_value('Cache/Disk/Used', 'bytes', bytes_used)
        self.add_derive_value('Cache/Disk/Entries', None, entries_used)
        if bytes_total > 0:
            self.add_gauge_value('Scoreboard/Disk/Used', '%', 100 * float(bytes_used) / bytes_total)
        if bytes_used > 0:
            self.add_gauge_value('Scoreboard/Disk/Entry Size', '%', bytes_used / entries_used)

        # Memory cache
        mem_total = float(stats.get('proxy.process.cache.ram_cache.total_bytes') or 0)
        mem_used = float(stats.get('proxy.process.cache.ram_cache.bytes_used') or 0)
        self.add_derive_value('Cache/Memory/Size', 'bytes', mem_total)
        self.add_derive_value('Cache/Memory/Used', 'bytes', mem_used)
        if mem_total > 0:
            self.add_gauge_value('Scoreboard/Memory/Use', '%', 100 * float(mem_used) / mem_total)
