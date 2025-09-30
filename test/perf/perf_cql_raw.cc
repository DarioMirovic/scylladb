/*
 * Copyright (C) 2025-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include <cstdlib>
#include <seastar/core/app-template.hh>
#include <seastar/core/future.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/semaphore.hh>
#include <seastar/core/when_all.hh>
#include <seastar/net/api.hh>
#include <seastar/net/socket_defs.hh>
#include <seastar/util/defer.hh>
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/lowres_clock.hh>
#include <seastar/core/abort_source.hh>
#include <fmt/format.h>
#include <signal.h>
#include <iomanip>
#include <limits>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include "db/config.hh"
#include "test/perf/perf.hh"
#include "test/lib/random_utils.hh"
#include "transport/server.hh"
#include "transport/response.hh"
#include <cstring>

namespace perf {
using namespace seastar;
namespace bpo = boost::program_options;
using namespace cql_transport;

// Small hand and AI crafted CQL client that  builds raw
// frames directly and sends over a tcp connection to exercise the full
// CQL binary protocol parsing path without any external driver layers.

struct raw_cql_test_config {
    std::string workload; // read | write
    unsigned partitions;  // number of partitions existing / to write
    unsigned duration_in_seconds;
    unsigned operations_per_shard;
    unsigned concurrency; // connections per shard
    bool continue_after_error;
    uint16_t port = 9042; // native transport port
    std::string username; // optional auth username
    std::string password; // optional auth password
    std::string remote_host = "127.0.0.1"; // target host for CQL + REST (empty => in-process server mode)
    bool connection_per_request = false; // create and tear down a connection for every request
    unsigned connection_rate = 0; // target number of extra AUTH (connect+startup) handshakes per second (total or per shard)
    bool connection_rate_per_shard = false; // interpret connection_rate as per shard if true
    bool connection_on_all_shards = false; // run connection driver on all shards instead of shard 0 only
};

std::ostream& operator<<(std::ostream& os, const raw_cql_test_config& c) {
    return os << "{workload=" << c.workload
              << ", partitions=" << c.partitions
              << ", concurrency=" << c.concurrency
              << ", duration=" << c.duration_in_seconds
              << ", ops_per_shard=" << c.operations_per_shard
              << (c.username.empty() ? "" : ", auth")
              << (c.connection_per_request ? ", connection_per_request" : "")
              << (c.connection_rate ? ", connection_rate=" + std::to_string(c.connection_rate) + (c.connection_rate_per_shard ? "/shard" : "(total)") : "")
              << (c.connection_on_all_shards && c.connection_rate ? ", conn_all_shards" : "")
              << "}";
}

// Basic frame building helpers (CQL v4)
// Binary protocol v4 header is 9 bytes:
//  0: version (request direction bit clear, thus 0x04)
//  1: flags
//  2: stream id (msb)
//  3: stream id (lsb)
//  4: opcode
//  5..8: body length (big endian)
struct frame_builder {
    int16_t stream_id;
    bytes_ostream body;
    // CQL protocol uses big-endian (network order) for all multi-byte numeric primitives.
    // The generic write<T>() helper used elsewhere in the codebase emits host-endian order
    // (little-endian on our platforms), so we serialize bytes manually here to avoid double
    // or incorrect swapping.
    void write_int(int32_t v) {
        auto p = body.write_place_holder(4);
        p[0] = (uint8_t)((uint32_t)v >> 24);
        p[1] = (uint8_t)((uint32_t)v >> 16);
        p[2] = (uint8_t)((uint32_t)v >> 8);
        p[3] = (uint8_t)((uint32_t)v);
    }
    void write_short(uint16_t v) {
        auto p = body.write_place_holder(2);
        p[0] = (uint8_t)(v >> 8);
        p[1] = (uint8_t)(v & 0xFF);
    }
    void write_byte(uint8_t v) { auto p = body.write_place_holder(1); write<uint8_t>(p, v); }
    void write_string(std::string_view s) { write_short(s.size()); body.write(s.data(), s.size()); }
    void write_long_string(std::string_view s) { write_int(s.size()); body.write(s.data(), s.size()); }
    temporary_buffer<char> finish(cql_binary_opcode op) {
        size_t len = body.size();
        static constexpr size_t header_size = 9;
        temporary_buffer<char> buf(len + header_size);
        auto* p = buf.get_write();
        p[0] = 0x04; // version 4 request
        p[1] = 0;    // flags
        p[2] = (stream_id >> 8) & 0xFF;
        p[3] = stream_id & 0xFF;
        p[4] = static_cast<uint8_t>(op);
        uint32_t be_len = htonl(len);
        std::memcpy(p + 5, &be_len, 4);
        // Copy accumulated body bytes into the outgoing buffer.
        // bytes_ostream doesn't provide a direct contiguous view unless linearized;
        // iterate fragments to avoid an extra allocation.
        size_t off = 0;
        for (auto frag : body.fragments()) {
            std::memcpy(p + header_size + off, frag.begin(), frag.size());
            off += frag.size();
        }
        SCYLLA_ASSERT(off == len);
        return buf;
    }
};

class raw_cql_connection {
    connected_socket _cs;
    input_stream<char> _in;
    output_stream<char> _out;
    // Ensure only one in-flight request per connection. Without this, two
    // workload fibers may interleave writes and especially reads on the same
    // input/output streams leading to undefined behavior and crashes
    // (double-setting futures inside seastar's pollable fd state).
    // Note: currently it should not be needed as we do only one
    // concurrent request per connection.
    semaphore _use_sem{1};
    sstring _username;
    sstring _password;
public:
    raw_cql_connection(connected_socket cs, sstring username = {}, sstring password = {})
        : _cs(std::move(cs)), _in(_cs.input()), _out(_cs.output()), _username(std::move(username)), _password(std::move(password)) {}

    int16_t allocate_stream() {
        // We send one request at a time per connection, so we can reuse stream id 0.
        return 0;
    }

    future<> send_frame(temporary_buffer<char> buf) {
        co_await _out.write(std::move(buf));
        co_await _out.flush();
    }

    future<cql_binary_opcode> read_one_frame(bytes& payload) {
        static constexpr size_t header_size = 9;
        auto hdr_buf = co_await _in.read_exactly(header_size);
        if (hdr_buf.empty()) {
            throw std::runtime_error("connection closed");
        }
        if (hdr_buf.size() != header_size) {
            throw std::runtime_error("short frame header");
        }
        const unsigned char* h = reinterpret_cast<const unsigned char*>(hdr_buf.get());
        uint8_t version = h[0];
        (void)version; // unused currently
        uint8_t flags = h[1]; (void)flags;
        uint16_t stream = (h[2] << 8) | h[3]; (void)stream;
        auto opcode = static_cast<cql_binary_opcode>(h[4]);
        uint32_t len; std::memcpy(&len, h + 5, 4); len = ntohl(len);
        // Basic protocol sanity checks to catch framing issues early.
        if ((version & 0x7F) != 0x04) {
            throw std::runtime_error(fmt::format("unexpected protocol version byte 0x{:02x} (expected 0x84/0x04)", version));
        }
        if (len > (32u << 20)) { // 32MB arbitrary safety limit
            throw std::runtime_error(fmt::format("suspiciously large frame body length {} > 32MB (malformed?)", len));
        }
        auto body = co_await _in.read_exactly(len);
        if (body.size() != len) {
            throw std::runtime_error("short frame body");
        }
        payload = bytes(bytes::initialized_later(), len);
        std::memcpy(payload.begin(), body.get(), len);
        co_return opcode;
    }

    future<> startup() {
        auto startup_stream = allocate_stream();
        frame_builder fb{startup_stream};
        // STARTUP frame body (v4): <map<string,string>> of options
        // map encodes with a <short n> for number of entries, then n*(<string><string>)
        fb.write_short(1); // one entry
        fb.write_string("CQL_VERSION");
        fb.write_string("3.0.0");
        co_await send_frame(fb.finish(cql_binary_opcode::STARTUP));
        bytes payload; auto op = co_await read_one_frame(payload);
        // If user supplied credentials we require the server to challenge with AUTHENTICATE.
        if (!_username.empty() && op != cql_binary_opcode::AUTHENTICATE) {
            throw std::runtime_error("--username specified but server did not request authentication (expected AUTHENTICATE frame)");
        }
        if (op == cql_binary_opcode::AUTHENTICATE) {
            // Assume PasswordAuthenticator; send SASL PLAIN (no need to inspect class name).
            frame_builder auth_fb{startup_stream}; // reuse same stream id per protocol spec
            if (_username.empty()) {
                // Send empty bytes (legacy AllowAll / will trigger error if auth required but no creds supplied)
                auth_fb.write_int(0);
            } else {
                // SASL PLAIN: 0x00 username 0x00 password
                std::string plain;
                plain.reserve(2 + _username.size() + _password.size());
                plain.push_back('\0');
                plain.append(_username.c_str(), _username.size());
                plain.push_back('\0');
                plain.append(_password.c_str(), _password.size());
                auth_fb.write_int(plain.size());
                auth_fb.body.write(plain.data(), plain.size());
            }
            co_await send_frame(auth_fb.finish(cql_binary_opcode::AUTH_RESPONSE));
            payload = bytes();
            op = co_await read_one_frame(payload);
        }
        if (op != cql_binary_opcode::READY && op != cql_binary_opcode::AUTH_SUCCESS) {
            // Try to decode ERROR for better diagnostics
            if (op == cql_binary_opcode::ERROR && payload.size() >= 4) {
                int32_t code = ntohl(*reinterpret_cast<const int32_t*>(payload.begin()));
                // message string follows: <string>
                if (payload.size() >= 6) {
                    auto p = payload.begin() + 4;
                    uint16_t slen = ntohs(*reinterpret_cast<const uint16_t*>(p));
                    p += 2;
                    sstring msg;
                    if (payload.size() >= 6 + slen) {
                        msg = sstring(reinterpret_cast<const char*>(p), slen);
                    }
                    throw std::runtime_error(fmt::format("expected READY/AUTH_SUCCESS, got ERROR code={} msg='{}'", code, msg));
                }
            }
            throw std::runtime_error(fmt::format("expected READY/AUTH_SUCCESS, got opcode {}", (int)op));
        }
        if (!_username.empty()) {
            // With credentials expect AUTH_SUCCESS explicitly.
            if (op != cql_binary_opcode::AUTH_SUCCESS) {
                throw std::runtime_error("authentication expected AUTH_SUCCESS but got different opcode");
            }
        }
    }

    future<> query_simple(std::string_view q) {
        // Serialize use of the underlying socket to avoid concurrent reads
        // on the same input stream which are not supported.
        co_await _use_sem.wait();
        auto releaser = seastar::defer([this] { _use_sem.signal(); });
        auto stream = allocate_stream();
        frame_builder fb{stream};
        // QUERY frame (v4): <long string><short consistency><byte flags>
        fb.write_long_string(q);
        fb.write_short(0x0001); // ONE
        fb.write_byte(0); // flags
        co_await send_frame(fb.finish(cql_binary_opcode::QUERY));
        bytes payload; auto op = co_await read_one_frame(payload);
        if (op == cql_binary_opcode::ERROR) {
            throw std::runtime_error("server returned ERROR to QUERY");
        }
    }
};

static future<> ensure_schema(raw_cql_connection& conn) {
    co_await conn.query_simple("CREATE KEYSPACE IF NOT EXISTS ks WITH replication={'class': 'NetworkTopologyStrategy'}");
    co_await conn.query_simple("CREATE TABLE IF NOT EXISTS ks.cf (pk blob primary key, c0 blob, c1 blob, c2 blob, c3 blob, c4 blob)");
}

static bytes make_key(uint64_t seq) {
    bytes b(bytes::initialized_later(), sizeof(seq));
    auto i = b.begin();
    write<uint64_t>(i, seq);
    return b;
}

static sstring to_hex(bytes_view b) {
    static const char* digits = "0123456789abcdef";
    sstring r;
    r.resize(b.size() * 2);
    for (size_t i = 0; i < b.size(); ++i) {
        r[2 * i] = digits[(b[i] >> 4) & 0xF];
        r[2 * i + 1] = digits[b[i] & 0xF];
    }
    return r;
}

static future<> write_one(raw_cql_connection& c, uint64_t seq) {
    auto key = to_hex(make_key(seq));
    co_await c.query_simple(fmt::format("INSERT INTO ks.cf(pk,c0,c1,c2,c3,c4) VALUES (0x{},0x01,0x02,0x03,0x04,0x05)", key));
}
static future<> read_one(raw_cql_connection& c, uint64_t seq) {
    auto key = to_hex(make_key(seq));
    co_await c.query_simple(fmt::format("SELECT * FROM ks.cf WHERE pk=0x{}", key));
}

// Perform one logical operation (write or read) using an existing connection.
static future<> do_request(raw_cql_connection& c, const raw_cql_test_config& cfg) {
    auto seq = tests::random::get_int<uint64_t>(cfg.partitions - 1);
    if (cfg.workload == "write") {
        co_await write_one(c, seq);
    } else {
        co_await read_one(c, seq);
    }
}

// Create a fresh connection, run a single operation, then let it go out of scope.
static future<> run_one_with_new_connection(const raw_cql_test_config& cfg) {
    connected_socket cs;
    try {
        cs = co_await connect(socket_address{net::inet_address{cfg.remote_host}, cfg.port});
    } catch (...) {
        cs = connected_socket();
    }
    if (!cs) {
        throw std::runtime_error("Failed to connect (per-request mode, single attempt)");
    }
    raw_cql_connection c(std::move(cs), sstring(cfg.username), sstring(cfg.password));
    co_await c.startup();
    co_await do_request(c, cfg);
}

// Poll the REST API /compaction_manager/compactions until it returns an empty JSON array
// indicating there are no ongoing compactions. Throws on timeout.
static void wait_for_compactions(const raw_cql_test_config& cfg) {
    using namespace std::chrono_literals;
    const unsigned max_attempts = 600; // ~60s
    bool announced = false;
    for (unsigned attempt = 0; attempt < max_attempts; ++attempt) {
        try {
            connected_socket http_cs = connect(socket_address{
                    net::inet_address{cfg.remote_host}, (uint16_t)10000}).get();
            input_stream<char> in = http_cs.input();
            output_stream<char> out = http_cs.output();
            sstring req = seastar::format("GET /compaction_manager/compactions HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", cfg.remote_host);
            out.write(req).get();
            out.flush().get();
            sstring resp;
            while (true) {
                auto buf = in.read().get();
                if (!buf) {
                    break;
                }
                resp.append(buf.get(), buf.size());
            }
            auto pos = resp.find("\r\n\r\n");
            if (pos != sstring::npos) {
                auto body = resp.substr(pos + 4);
                boost::algorithm::trim(body);
                if (body == "[]") {
                    if (attempt) {
                        std::cout << "Compactions drained after " << attempt << " polls" << std::endl;
                    }
                    return;
                } else if (!announced) {
                    std::cout << "Waiting for compactions to end..." << std::endl;
                    announced = true;
                }
            }
        } catch (...) {
            // Ignore and retry
        }
        sleep(100ms).get();
    }
    throw std::runtime_error("Timed out waiting for compactions to drain (endpoint did not return empty JSON array)");
}

// Thread-local connection pool state extracted so that initialization can be performed
// outside of the timed body passed to time_parallel (avoids depressing the first TPS sample).
static thread_local std::vector<std::unique_ptr<raw_cql_connection>> tl_conns;
static thread_local bool tl_initialized = false;
static thread_local semaphore tl_init_sem(1);

// Connection driver per-shard stats (for supplemental AUTH/connect workload)
struct shard_conn_stats {
    uint64_t attempts = 0;
    uint64_t successes = 0;
    uint64_t failures = 0;
    uint64_t total_latency_ns = 0; // sum of startup() latency
    uint64_t min_latency_ns = std::numeric_limits<uint64_t>::max();
    uint64_t max_latency_ns = 0;
    utils::estimated_histogram auth_hist{160}; // store latency samples (microseconds) for percentile estimation
};
static thread_local shard_conn_stats tl_conn_stats; // only updated on shards running the driver

// Aggregate (cross-shard) connection stats including derived metrics
struct aggregated_conn_stats {
    uint64_t attempts = 0;
    uint64_t successes = 0;
    uint64_t failures = 0;
    double throughput = 0.0; // successes per second
    double avg_startup_latency_us = 0.0; // average startup() latency in microseconds
    double median_startup_latency_us = 0.0; // median
    double p99_startup_latency_us = 0.0;
    double min_startup_latency_us = std::numeric_limits<double>::max();
    double max_startup_latency_us = 0.0;
    utils::estimated_histogram auth_hist{160};
};

static std::ostream& operator<<(std::ostream& os, const aggregated_conn_stats& s) {
    // Follow formatting style used in perf_result (multi-line, aligned) for readability.
    os << "auth_startup_latency:\n";
    if (s.successes) {
        os << "        mean="   << std::setw(10) << std::fixed << std::setprecision(3) << s.avg_startup_latency_us << "\n";
        os << "        median=" << std::setw(10) << std::fixed << std::setprecision(3) << s.median_startup_latency_us << "\n";
        os << "        p99="    << std::setw(10) << std::fixed << std::setprecision(3) << s.p99_startup_latency_us << "\n";
        os << "        min="    << std::setw(10) << std::fixed << std::setprecision(3) << (s.min_startup_latency_us == std::numeric_limits<double>::max() ? 0.0 : s.min_startup_latency_us) << "\n";
        os << "        max="    << std::setw(10) << std::fixed << std::setprecision(3) << s.max_startup_latency_us << "\n";
    } else {
        os << "        (no successful AUTH samples)\n";
    }
    os << "auth_connections:\n";
    os << "        throughput=" << std::fixed << std::setprecision(2) << s.throughput << " conn/s";
    return os;
}

// Start background connection/auth drivers based on config. Populates 'futs' with the running tasks.
static void start_connection_drivers(const raw_cql_test_config& cfg, seastar::abort_source& abort, std::vector<future<>>& futs) {
    if (!cfg.connection_rate) {
        return; // disabled
    }
    unsigned shards_participating = cfg.connection_on_all_shards ? smp::count : 1u;
    double per_shard_rate;
    if (cfg.connection_rate_per_shard) {
        per_shard_rate = cfg.connection_rate; // each shard does full rate
    } else {
        per_shard_rate = cfg.connection_on_all_shards ? (double(cfg.connection_rate) / double(shards_participating)) : double(cfg.connection_rate);
    }
    if (per_shard_rate <= 0.0) {
        std::cout << "Computed per-shard connection rate <= 0, connection driver disabled" << std::endl;
        return;
    }
    auto deadline = lowres_clock::now() + std::chrono::seconds(cfg.duration_in_seconds);
    for (unsigned s = 0; s < shards_participating; ++s) {
        futs.push_back(smp::submit_to(s, [cfg, &abort, per_shard_rate, deadline] () -> future<> {
            using namespace std::chrono;
            auto period = duration_cast<lowres_clock::duration>(duration<double>(1.0 / per_shard_rate));
            if (period <= period.zero()) {
                co_return;
            }
            auto next_due = lowres_clock::now();
            while (!abort.abort_requested() && lowres_clock::now() < deadline) {
                ++tl_conn_stats.attempts;
                try {
                    auto cs = co_await connect(socket_address{net::inet_address{cfg.remote_host}, cfg.port});
                    raw_cql_connection c(std::move(cs), sstring(cfg.username), sstring(cfg.password));
                    auto auth_start = lowres_clock::now();
                    co_await c.startup();
                    auto auth_end = lowres_clock::now();
                    ++tl_conn_stats.successes;
                    auto dur_ns = (auth_end - auth_start).count();
                    tl_conn_stats.total_latency_ns += dur_ns;
                    tl_conn_stats.min_latency_ns = std::min(tl_conn_stats.min_latency_ns, (uint64_t)dur_ns);
                    tl_conn_stats.max_latency_ns = std::max(tl_conn_stats.max_latency_ns, (uint64_t)dur_ns);
                    // Record microseconds in histogram for better bucket coverage
                    auto dur_us = std::chrono::duration_cast<std::chrono::microseconds>(auth_end - auth_start).count();
                    if (dur_us <= 0) { dur_us = 1; }
                    tl_conn_stats.auth_hist.add(dur_us);
                } catch (...) {
                    ++tl_conn_stats.failures;
                    if (!cfg.continue_after_error) {
                        static thread_local unsigned err_printed = 0;
                        if (err_printed < 5) {
                            ++err_printed;
                            std::cerr << "Connection driver error: " << std::current_exception() << std::endl;
                        }
                    }
                }
                next_due += period;
                auto now = lowres_clock::now();
                if (next_due > now) {
                    co_await sleep(next_due - now);
                } else {
                    next_due = now;
                }
            }
        }));
    }
    std::cout << "Started connection driver: total_rate=" << cfg.connection_rate
              << (cfg.connection_rate_per_shard ? " (per-shard)" : " (total)")
              << ", per_shard_rate=" << per_shard_rate
              << ", shards=" << shards_participating << std::endl;
}

static void stop_connection_drivers(seastar::abort_source& abort, std::vector<future<>>& futs) {
    abort.request_abort();
    if (futs.empty()) {
        return;
    }
    try {
        when_all(futs.begin(), futs.end()).get();
    } catch (...) {}
}

static aggregated_conn_stats aggregate_connection_stats(const raw_cql_test_config& cfg) {
    aggregated_conn_stats agg;
    for (unsigned s = 0; s < smp::count; ++s) {
        auto shard_stats = smp::submit_to(s, [] {
            return make_ready_future<shard_conn_stats>(tl_conn_stats);
        }).get();
        agg.attempts += shard_stats.attempts;
        agg.successes += shard_stats.successes;
        agg.failures += shard_stats.failures;
        agg.avg_startup_latency_us += shard_stats.total_latency_ns; // accumulate raw ns temporarily (will convert)
        if (shard_stats.min_latency_ns != std::numeric_limits<uint64_t>::max()) {
            agg.min_startup_latency_us = std::min(agg.min_startup_latency_us, double(shard_stats.min_latency_ns) / 1000.0);
        }
        agg.max_startup_latency_us = std::max(agg.max_startup_latency_us, double(shard_stats.max_latency_ns) / 1000.0);
        agg.auth_hist.merge(shard_stats.auth_hist);
    }
    double duration = cfg.duration_in_seconds ? cfg.duration_in_seconds : 1.0;
    // avg_startup_latency_ms currently holds total latency in ns; convert
    uint64_t total_latency_ns = static_cast<uint64_t>(agg.avg_startup_latency_us);
    agg.throughput = duration ? double(agg.successes) / duration : 0.0;
    agg.avg_startup_latency_us = agg.successes ? (double(total_latency_ns) / 1000.0 / agg.successes) : 0.0; // ns -> us
    if (agg.min_startup_latency_us == std::numeric_limits<double>::max()) {
        agg.min_startup_latency_us = 0.0; // no samples
    }
    if (agg.auth_hist.count()) {
        auto p99_us = agg.auth_hist.percentile(0.99);
        agg.p99_startup_latency_us = double(p99_us);
        auto p50_us = agg.auth_hist.percentile(0.50);
        agg.median_startup_latency_us = double(p50_us);
    }
    return agg;
}

static future<> prepare_thread_connections(const raw_cql_test_config cfg) {
    if (tl_initialized) {
        co_return;
    }
    co_await tl_init_sem.wait();
    if (!tl_initialized) {
        try {
            tl_conns.reserve(cfg.concurrency);
            for (unsigned i = 0; i < cfg.concurrency; ++i) {
                connected_socket cs;
                for (int attempt = 0; attempt < 200; ++attempt) {
                    try {
                        cs = co_await connect(socket_address{net::inet_address{cfg.remote_host}, cfg.port});
                    } catch (...) {
                        cs = connected_socket();
                    }
                    if (cs) {
                        break;
                    }
                    co_await sleep(std::chrono::milliseconds(25));
                }
                if (!cs) {
                    throw std::runtime_error("Failed to connect to native transport port");
                }
                auto c = std::make_unique<raw_cql_connection>(std::move(cs), sstring(cfg.username), sstring(cfg.password));
                co_await c->startup();
                tl_conns.push_back(std::move(c));
            }
            tl_initialized = true;
        } catch (...) {
            tl_init_sem.signal();
            throw;
        }
    }
    tl_init_sem.signal();
}

// If workload is 'read', populate the requested number of partitions once (on shard 0)
// so the measured phase performs only SELECT operations.
static void prepopulate_if_needed(const raw_cql_test_config& cfg) {
    if (cfg.workload != "read") {
        return;
    }
    try {
        connected_socket cs;
        for (int attempt = 0; attempt < 200; ++attempt) {
            try {
                cs = connect(socket_address{net::inet_address{cfg.remote_host}, cfg.port}).get();
            } catch (...) {
                cs = connected_socket();
            }
            if (cs) {
                break;
            }
            sleep(std::chrono::milliseconds(25)).get();
        }
        if (!cs) {
            throw std::runtime_error("populate phase: failed to connect");
        }
        raw_cql_connection conn(std::move(cs),
                sstring(cfg.username), sstring(cfg.password));
        conn.startup().get();
        ensure_schema(conn).get();
        for (uint64_t seq = 0; seq < cfg.partitions; ++seq) {
            write_one(conn, seq).get();
        }
        std::cout << "Pre-populated " << cfg.partitions << " partitions" << std::endl;
    } catch (...) {
        std::cerr << "Population failed: " << std::current_exception() << std::endl;
        throw;
    }
}

static void workload_main(raw_cql_test_config cfg) {
    std::cout << "Running test with config: " << cfg << std::endl;
    prepopulate_if_needed(cfg);
    try {
        wait_for_compactions(cfg);
    } catch (...) {
        std::cerr << "Compaction wait failed: " << std::current_exception() << std::endl;
        throw;
    }
    if (cfg.connection_rate && cfg.connection_per_request) {
        throw std::runtime_error("--connection-rate is not compatible with --connection-per-request (every request already connects)");
    }
    if (!cfg.connection_per_request) {
        // Warm up: establish all per-thread connections before measurement.
        try {
            smp::invoke_on_all([cfg] {
                return prepare_thread_connections(cfg);
            }).get();
        } catch (...) {
            std::cerr << "Connection preparation failed: " << std::current_exception() << std::endl;
            throw;
        }
    }
    if (cfg.workload == "write") {
        ensure_schema(*tl_conns[0]).get();
    }

    seastar::abort_source conn_abort;
    std::vector<future<>> conn_driver_futs;
    if (cfg.connection_rate) {
        start_connection_drivers(cfg, conn_abort, conn_driver_futs);
    }

    auto results = time_parallel([cfg] () -> future<> {
        if (cfg.connection_per_request) {
            co_await run_one_with_new_connection(cfg);
        } else {
            static thread_local size_t idx = 0;
            auto& c = *tl_conns[idx++ % tl_conns.size()];
            co_await do_request(c, cfg);
        }
    }, cfg.concurrency, cfg.duration_in_seconds, cfg.operations_per_shard, !cfg.continue_after_error);
    std::cout << aggregated_perf_results(results) << std::endl;

    if (cfg.connection_rate) {
        stop_connection_drivers(conn_abort, conn_driver_futs);
        auto stats = aggregate_connection_stats(cfg);
        std::cout << stats << std::endl;
    }
}

std::function<int(int, char**)> cql_raw(std::function<int(int, char**)> scylla_main, std::function<void(lw_shared_ptr<db::config>)>* after_init_func) {
    return [=](int ac, char** av) -> int {
        raw_cql_test_config c;
        bpo::options_description opts_desc;
        opts_desc.add_options()
            ("workload", bpo::value<std::string>()->default_value("read"), "workload type: read|write")
            ("partitions", bpo::value<unsigned>()->default_value(10000), "number of partitions")
            ("duration", bpo::value<unsigned>()->default_value(5), "test duration seconds")
            ("operations-per-shard", bpo::value<unsigned>()->default_value(0), "fixed op count per shard")
            ("concurrency", bpo::value<unsigned>()->default_value(100), "connections per shard")
            ("continue-after-error", bpo::value<bool>()->default_value(false), "continue after error")
            ("username", bpo::value<std::string>()->default_value(""), "authentication username")
            ("password", bpo::value<std::string>()->default_value(""), "authentication password")
            ("remote-host", bpo::value<std::string>()->default_value(""), "remote host to connect to, leave empty to run in-process server")
            ("connection-per-request", bpo::value<bool>()->default_value(false), "create a fresh connection for every request")
            ("connection-rate", bpo::value<unsigned>()->default_value(0), "additional AUTH (connect+startup) handshakes per second (total unless --connection-rate-per-shard)")
            ("connection-rate-per-shard", bpo::value<bool>()->default_value(false), "interpret --connection-rate as per shard instead of total")
            ("connection-on-all-shards", bpo::value<bool>()->default_value(false), "run background connection driver on all shards (default: shard 0 only)");
        bpo::variables_map vm;
        bpo::store(bpo::command_line_parser(ac,av).options(opts_desc).allow_unregistered().run(), vm);

        c.workload = vm["workload"].as<std::string>();
        c.partitions = vm["partitions"].as<unsigned>();
        c.duration_in_seconds = vm["duration"].as<unsigned>();
        c.operations_per_shard = vm["operations-per-shard"].as<unsigned>();
        c.concurrency = vm["concurrency"].as<unsigned>();
        c.continue_after_error = vm["continue-after-error"].as<bool>();
        c.username = vm["username"].as<std::string>();
        c.password = vm["password"].as<std::string>();
        c.remote_host = vm["remote-host"].as<std::string>();
        c.connection_per_request = vm["connection-per-request"].as<bool>();
        c.connection_rate = vm["connection-rate"].as<unsigned>();
        c.connection_rate_per_shard = vm["connection-rate-per-shard"].as<bool>();
        c.connection_on_all_shards = vm["connection-on-all-shards"].as<bool>();

        if (!c.username.empty() && c.password.empty()) {
            std::cerr << "--username specified without --password" << std::endl;
            return 1;
        }
        if (c.workload != "read" && c.workload != "write") {
            std::cerr << "Unknown workload: " << c.workload << "\n"; return 1;
        }

        // Remove test options to not disturb scylla main app
        for (auto& opt : opts_desc.options()) {
            auto name = opt->canonical_display_name(bpo::command_line_style::allow_long);
            std::tie(ac, av) = cut_arg(ac, av, name);
        }

        if (!c.remote_host.empty()) {
            // if remote-host provided (non-empty) we run standalone
            c.port = 9042; // TODO: make configurable
            app_template app;
            return app.run(ac, av, [c = std::move(c)] () -> future<> {
                return seastar::async([c = std::move(c)] () {
                    workload_main(c);
                    exit(0);
                });
            });
        } else {
            // in-process mode
            c.remote_host = "127.0.0.1";
        }

        // Unconditionally append --api-address=127.0.0.1 so the main server binds API locally.
        static std::string api_arg = "--api-address=127.0.0.1";
        {
            // Build a new argv with the extra argument (simple leak acceptable for process lifetime)
            char** new_av = new char*[ac + 2];
            for (int i = 0; i < ac; ++i) { new_av[i] = av[i]; }
            new_av[ac] = const_cast<char*>(api_arg.c_str());
            new_av[ac + 1] = nullptr;
            av = new_av;
            ++ac;
        }

        *after_init_func = [c](lw_shared_ptr<db::config> cfg) mutable {
            c.port = cfg->native_transport_port();
            (void)seastar::async([c]() {
                try {
                    workload_main(c);
                } catch (...) {
                    std::cerr << "Perf test failed: " << std::current_exception() << std::endl;
                    raise(SIGKILL); // abnormal shutdown to signal test failure
                }
                raise(SIGINT); // normal shutdown request after test completion
            });
        };
        return scylla_main(ac,av);
    };
}

} // namespace perf
