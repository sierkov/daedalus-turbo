/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <functional>
#include <memory>
#include <optional>
#include <string>
#ifdef __clang__
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#ifdef _MSC_VER
#   include <SDKDDKVer.h>
#endif
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#ifndef BOOST_ALLOW_DEPRECATED_HEADERS
#   define BOOST_ALLOW_DEPRECATED_HEADERS
#   define DT_CLEAR_BOOST_DEPRECATED_HEADERS
#endif
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#ifdef DT_CLEAR_BOOST_DEPRECATED_HEADERS
#   undef BOOST_ALLOW_DEPRECATED_HEADERS
#undef DT_CLEAR_BOOST_DEPRECATED_HEADERS
#endif
#ifdef __clang__
#   pragma GCC diagnostic pop
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/url.hpp>
#include <dt/asio.hpp>
#include <dt/blake2b.hpp>
#include <dt/file.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::http {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct download_queue_async::impl {
        static constexpr size_t max_connections = 8;

        impl(asio::worker &asio_worker=asio::worker::get())
            : _asio_worker { asio_worker }, _asio_name { fmt::format("download-queue-{:p}", static_cast<void*>(this)) }
        {
            _asio_worker.add_before_action(_asio_name, [this] { _asio_before_run(); });
            _asio_worker.add_after_action(_asio_name, [this] { _asio_after_run(); });
        }

        ~impl()
        {
            while (_queue_size.load() > 0 || _active_conns.load() > 0) {
                logger::warn("destroying download_queue with active_tasks: waiting for them to finish");
                std::this_thread::sleep_for(std::chrono::seconds { 1 });
            }
            _asio_worker.del_before_action(_asio_name);
            _asio_worker.del_after_action(_asio_name);
        }

        void download(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
        {
            _add_request(request { url, save_path, priority, handler });
        }

        bool process_ok(bool report_progress, scheduler *sched)
        {
            _report = report_progress;
            static constexpr std::chrono::milliseconds report_interval { 5000 };
            auto next_report = std::chrono::system_clock::now() + report_interval;
            for (;;) {
                auto queue_sz = _queue_size.load();
                auto n_conns = _active_conns.load();
                auto now = std::chrono::system_clock::now();
                if (now >= next_report) {
                    logger::debug("download_queue::process_ok queue_size: {} active_conns: {}", queue_sz, n_conns);
                    next_report = now + report_interval;
                }
                if (queue_sz == 0 && n_conns == 0)
                    break;
                if (sched != nullptr)
                    sched->process_once();
                else
                    std::this_thread::sleep_for(scheduler::default_wait_interval);
            }
            auto res = _success.load();
            _success = true;
            return res;
        }

        speed_mbps internet_speed()
        {
            return speed_mbps { _speed_current.load(), _speed_max.load() };
        }
    private:
        struct request {
            std::string url {};
            std::string save_path {};
            uint64_t priority = 0;
            std::function<void(result &&)> handler {};
            std::vector<std::string> errors {};

            bool operator<(const request &b) const
            {
                return priority > b.priority;
            }
        };

        struct connection: std::enable_shared_from_this<connection> {
            connection(impl &dlq, net::io_context& ioc, tcp::resolver &resolver)
                : _dlq { dlq }, _ioc { ioc }, _resolver { resolver }
            {
            }

            void run()
            {
                _take_request();
            }
        private:
            impl &_dlq;
            net::io_context &_ioc;
            tcp::resolver &_resolver;
            std::optional<std::string> _host {};
            std::optional<std::string> _port {};
            std::optional<tcp::resolver::results_type> _connect_endpoint {};
            std::optional<beast::tcp_stream> _stream {};
            beast::flat_buffer _buffer {};
            std::optional<http::request<http::empty_body>> _http_req {};
            std::optional<http::response_parser<http::dynamic_body>> _http_parser {};
            request _req {};

            void _take_request()
            {
                auto req = _dlq._take_request();
                if (!req)
                    return;
                _req = std::move(*req);
                boost::url_view uri { _req.url };
                if (uri.scheme() != "http")
                    throw error("only http urls are supported but got {}", _req.url);
                if (uri.path().empty())
                    throw error("path component of the downloaded URI cannot be empty but got {}", _req.url);
                _http_req.emplace();
                _http_req->version(11);
                _http_req->keep_alive(true);
                _http_req->method(http::verb::get);
                _http_req->target(uri.path());
                _http_req->set(http::field::host, uri.host());
                _http_req->set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
                _http_req->prepare_payload();
                _resolve(uri.host(), uri.port());
            }

            void _handle_error(const std::string &error, bool recoverable=true)
            {
                _dlq._report_result(std::move(_req), result { .url=_req.url, .error=error }, recoverable);
                if (_stream) {
                    logger::debug("{}: closing the connection after an error", _req.url);
                    _stream->close();
                    _stream.reset();
                }
                _take_request();
            }

            void _resolve(const std::string_view &host, const std::string_view &port)
            {
                if (_host == host && _port == port && _connect_endpoint) {
                    logger::trace("{}: skipping resolving {}:{} - cached", _req.url, host, port);
                    _connect();
                } else {
                    logger::trace("{}: resolving {}:{}", _req.url, host, port);
                    _host = host;
                    _port = port;
                    if (_stream) {
                        logger::debug("{}: closing the connection because the target endpoint has changed", _req.url);
                        _stream->close();
                        _stream.reset();
                    }
                    _resolver.async_resolve(host, port.empty() ? "80" : port, beast::bind_front_handler(&connection::_on_resolve, shared_from_this()));
                }
            }

            void _on_resolve(beast::error_code ec, tcp::resolver::results_type results)
            {
                if (ec) {
                    _handle_error(fmt::format("async_resolve failed: {}", ec.message()));
                    return;
                }
                _connect_endpoint.emplace(results);
                _connect();
            }

            void _connect()
            {
                if (_host && _port && _stream) {
                    logger::trace("{}: skipping reconnecting to {}:{} - connection already available", _req.url, *_host, *_port);
                    _write();
                } else {
                    logger::trace("{}: connecting to {}:{}", _req.url, *_host, *_port);
                    _stream.emplace(_ioc);
                    _stream->expires_after(std::chrono::seconds(10));
                    _stream->async_connect(*_connect_endpoint, beast::bind_front_handler(&connection::_on_connect, shared_from_this()));
                }
            }

            void _on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
            {
                if (ec) {
                    _handle_error(fmt::format("async_connect failed: {}", ec.message()));
                    return;
                }
                _write();
            }

            void _write()
            {
                logger::trace("{}: sending HTTP request", _req.url);
                _stream->expires_after(std::chrono::seconds(10));
                http::async_write(*_stream, *_http_req, beast::bind_front_handler(&connection::_on_write, shared_from_this()));
            }

            void _on_write(beast::error_code ec, std::size_t /*bytes_transferred*/)
            {
                if (ec) {
                    _handle_error(fmt::format("async_write failed: {}", ec.message()));
                    return;
                }
                _http_parser.emplace();
                _http_parser->body_limit(1 << 26);
                logger::trace("{}: waiting for HTTP response", _req.url);
                _buffer.clear();
                _stream->expires_after(std::chrono::seconds(30));
                http::async_read(*_stream, _buffer, *_http_parser, beast::bind_front_handler(&connection::_on_read, shared_from_this()));
            }

            void _on_read(beast::error_code ec, std::size_t /*bytes_transferred*/)
            {
                if (ec) {
                    _handle_error(fmt::format("aync_read failed: {}", ec.message()));
                    return;
                }
                auto &res = _http_parser->get();
                auto http_status = res.result_int();
                if (!_http_parser->keep_alive()) {
                    logger::debug("{}: remote turns down keep-alive, closing the connection", _req.url);
                    _stream->close();
                    _stream.reset();
                }
                if (http_status == 200) {
                    std::string body = boost::beast::buffers_to_string(res.body().data());
                    file::write(_req.save_path, body);
                    size_t body_size = 0;
                    if (_http_parser->content_length())
                        body_size = *_http_parser->content_length();
                    else
                        body_size = std::filesystem::file_size(_req.save_path);
                    _dlq._report_result(std::move(_req), result { std::move(_req.url), std::move(_req.save_path), {}, body_size });
                } else {
                    _dlq._report_result(std::move(_req), result { std::move(_req.url), std::move(_req.save_path), fmt::format("bad http status: {}", http_status) });
                }
                _take_request();
            }
        };

        struct perf_stats {
            std::atomic_size_t oks = 0;
            std::atomic_size_t errors = 0;
            std::atomic_size_t bytes = 0;

            double report(double duration_secs, size_t queue_size, size_t active_conns)
            {
                auto num_requests = oks + errors;
                double error_rate = num_requests > 0 ? static_cast<double>(errors) * 100 / num_requests : 0.0;
                logger::trace("download-queue size: {} active connections: {}", queue_size, active_conns);
                double speed_mb_sec = static_cast<double>(bytes) / 1'000'000 / duration_secs;
                auto speed_mbps = speed_mb_sec * 8;
                logger::debug("download-queue performance over the last reporting period: download speed: {:0.1f} MB/sec, requests: {}, error rate: {:0.2f}%",
                    speed_mb_sec, num_requests, error_rate);
                oks = 0;
                errors = 0;
                bytes = 0;
                return speed_mbps;
            }
        };

        static constexpr size_t stats_report_span_secs = 5;
        static constexpr std::chrono::seconds stats_report_span { stats_report_span_secs };

        asio::worker &_asio_worker;
        std::string _asio_name;
        tcp::resolver _resolver { _asio_worker.io_context() };
        std::atomic_bool _success { true };
        alignas(mutex::padding) std::mutex _queue_mutex {};
        std::priority_queue<request> _queue {};
        std::atomic_size_t _active_conns { 0 };
        std::atomic_size_t _queue_size { 0 };
        perf_stats _stats {};
        std::atomic_bool _report { false };
        std::atomic<double> _speed_max { 0.0 };
        std::atomic<double> _speed_current { 0.0 };
        std::chrono::time_point<std::chrono::system_clock> _stats_next_report { std::chrono::system_clock::now() + stats_report_span };

        void _asio_before_run()
        {
            if (_queue_size > 0 && _active_conns < max_connections) {
                auto conn = std::make_shared<connection>(*this, _asio_worker.io_context(), _resolver);
                // if successful a copy of the shared_ptr will be kept in the I/O context
                conn->run();
                logger::trace("created new connection instance use_count: {}", conn.use_count());
            }
        }

        void _asio_after_run()
        {
            const auto now = std::chrono::system_clock::now();
            if (now >= _stats_next_report) {
                auto current_speed = _stats.report(stats_report_span_secs, _queue_size, _active_conns);
                if (current_speed > 0) {
                    for (;;) {
                        double max_copy = _speed_max.load();
                        if (current_speed <= max_copy || _speed_max.compare_exchange_strong(max_copy, current_speed))
                            break;
                    }
                    _speed_current = current_speed;
                }
                _stats_next_report = now + stats_report_span;
                if (_report)
                    progress::get().inform();
            }
        }

        void _add_request(request &&req, bool update_priority=false)
        {
            std::scoped_lock lk { _queue_mutex };
            if (update_priority && !_queue.empty())
                req.priority = _queue.top().priority + 1;
            _queue.emplace(std::move(req));
            _queue_size = _queue.size();
        }

        std::optional<request> _take_request()
        {
            std::optional<request> res {};
            {
                std::scoped_lock lock { _queue_mutex };
                if (!_queue.empty()) {
                    auto req = _queue.top();
                    _queue.pop();
                    _queue_size = _queue.size();
                    ++_active_conns;
                    res.emplace(std::move(req));
                }
            }
            return res;
        }

        void _report_result(request &&req, result &&res, bool recoverable=false)
        {
            --_active_conns;
            if (res.error) {
                ++_stats.errors;
                if (recoverable) {
                    req.errors.emplace_back(*res.error);
                    if (req.errors.size() < 10) {
                        logger::debug("retrying after a recoverable download issue with {}: {} num_errors: {}", req.url, *res.error, req.errors.size());
                        _add_request(std::move(req), true);
                        return;
                    }
                }
                logger::error("download of {} failed: {}", res.url, *res.error);
                _success = false;
            } else {
                logger::trace("downloaded {}", res.url);
                ++_stats.oks;
                _stats.bytes += res.size;
            }
            req.handler(std::move(res));
        }
    };

    download_queue_async::download_queue_async(): _impl { std::make_unique<download_queue_async::impl>() }
    {
    }

    download_queue_async::~download_queue_async() =default;

    void download_queue_async::_download_impl(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
    {
        _impl->download(url, save_path, priority, handler);
    }

    bool download_queue_async::_process_ok_impl(bool report_progress, scheduler *sched)
    {
        return _impl->process_ok(report_progress, sched);
    }

    download_queue::speed_mbps download_queue_async::_internet_speed_impl()
    {
        return _impl->internet_speed();
    }

}