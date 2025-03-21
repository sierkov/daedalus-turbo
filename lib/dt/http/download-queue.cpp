/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <functional>
#include <memory>
#include <optional>
#include <queue>
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
        static constexpr size_t max_connections = 6;

        impl(asio::worker &asio_worker=asio::worker::get())
            : _asio_worker { asio_worker }, _asio_name { fmt::format("download-queue-{:p}", static_cast<void*>(this)) }
        {
            _asio_worker.add_before_action(_asio_name, [this] { _asio_before_run(); });
            _asio_worker.add_after_action(_asio_name, [this] { _asio_after_run(); });
        }

        ~impl()
        {
            _destroy = true;
            const auto num_reqs = cancel([](const auto &) { return true; });
            if (num_reqs > 0)
                logger::warn("download_queue destroyed before completion: cancelled {} requests", num_reqs);
            while (_queue_size.load() > 0 || _active_conns.load() > 0) {
                logger::warn("destroying download_queue with active_tasks: waiting for them to finish");
                std::this_thread::sleep_for(std::chrono::seconds { 1 });
            }
            _asio_worker.del_before_action(_asio_name);
            _asio_worker.del_after_action(_asio_name);
        }

        size_t cancel(const cancel_predicate &pred)
        {
            size_t num_cancelled = 0;
            request_queue new_queue {};
            mutex::scoped_lock lk { _queue_mutex };
            while (!_queue.empty()) {
                auto req = _queue.top();
                _queue.pop();
                if (pred(req)) {
                    ++num_cancelled;
                } else {
                    new_queue.emplace(std::move(req));
                }
            }
            _queue = std::move(new_queue);
            _queue_size = _queue.size();
            return num_cancelled;
        }

        void download(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
        {
            _add_request(request { url, save_path, priority, handler });
        }

        bool process_ok(const bool report_progress, scheduler *sched)
        {
            static constexpr std::chrono::milliseconds report_interval { 5000 };
            auto next_report = std::chrono::system_clock::now() + report_interval;
            for (;;) {
                const auto queue_sz = _queue_size.load();
                const auto n_conns = _active_conns.load();
                const auto now = std::chrono::system_clock::now();
                if (now >= next_report) {
                    logger::debug("download_queue::process_ok scheduler: {} queue_size: {} active_conns: {}",
                        sched != nullptr, queue_sz, n_conns);
                    next_report = now + report_interval;
                    if (report_progress)
                        progress::get().inform();
                }
                if (queue_sz == 0 && n_conns == 0)
                    break;
                if (sched != nullptr) {
                    sched->process_once();
                } else {
                    mutex::unique_lock lk { _work_mutex };
                    _work_cv.wait_for(lk, scheduler::default_wait_interval);
                }
            }
            const auto res = _success.load();
            _success = true;
            return res;
        }
    private:
        struct connection: std::enable_shared_from_this<connection> {
            connection(impl &dlq, net::io_context& ioc, tcp::resolver &resolver)
                : _dlq { dlq }, _ioc { ioc }, _resolver { resolver }
            {
                _dlq._connection_create();
            }

            ~connection()
            {
                _dlq._connection_close();
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
                    throw error(fmt::format("only http urls are supported but got {}", _req.url));
                if (uri.path().empty())
                    throw error(fmt::format("path component of the downloaded URI cannot be empty but got {}", _req.url));
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
                    _connect();
                } else {
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
                    _write();
                } else {
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
                const auto num_requests = oks + errors;
                const double error_rate = num_requests > 0 ? static_cast<double>(errors) * 100 / num_requests : 0.0;
                const double speed_mb_sec = static_cast<double>(bytes) / 1'000'000 / duration_secs;
                const auto speed_mbps = speed_mb_sec * 8;
                logger::debug("download-queue size: {} connections: {} download speed: {:0.1f} MB/sec, requests: {}, fail rate: {:0.2f}%",
                    queue_size, active_conns, speed_mb_sec, num_requests, error_rate);
                oks = 0;
                errors = 0;
                bytes = 0;
                return speed_mbps;
            }
        };

        using request_queue = std::priority_queue<request>;

        static constexpr size_t stats_report_span_secs = 5;
        static constexpr std::chrono::seconds stats_report_span { stats_report_span_secs };

        asio::worker &_asio_worker;
        std::string _asio_name;
        tcp::resolver _resolver { _asio_worker.io_context() };
        std::atomic_bool _success { true };
        mutex::unique_lock::mutex_type _queue_mutex alignas(mutex::alignment) {};
        request_queue _queue {};
        mutable mutex::unique_lock::mutex_type _work_mutex alignas(mutex::alignment) {};
        std::condition_variable_any _work_cv alignas(mutex::alignment) {};
        std::atomic_size_t _active_conns { 0 };
        std::atomic_size_t _queue_size { 0 };
        perf_stats _stats {};
        std::chrono::time_point<std::chrono::system_clock> _stats_next_report { std::chrono::system_clock::now() + stats_report_span };
        bool _destroy = false;

        void _asio_before_run()
        {
            if (_queue_size > 0 && _active_conns < max_connections) {
                const auto conn = std::make_shared<connection>(*this, _asio_worker.io_context(), _resolver);
                // if successful a copy of the shared_ptr will be kept in the I/O context
                conn->run();
                logger::debug("created new connection instance use_count: {}", conn.use_count());
            }
        }

        void _asio_after_run()
        {
            const auto now = std::chrono::system_clock::now();
            if (now >= _stats_next_report) {
                const auto current_speed = _stats.report(stats_report_span_secs, _queue_size, _active_conns);
                _asio_worker.internet_speed_report(current_speed);
                _stats_next_report = now + stats_report_span;
            }
        }

        void _connection_create()
        {
            auto num_active = ++_active_conns;
            logger::debug("connection_create: active_conns: {}", num_active);
        }

        void _connection_close()
        {
            auto num_active = --_active_conns;
            logger::debug("connection_close: active_conns: {}", num_active);
            if (num_active == 0 && !_destroy)
                _work_cv.notify_one();
        }

        void _add_request(request &&req, const bool update_priority=false)
        {
            mutex::scoped_lock lk { _queue_mutex };
            if (update_priority && !_queue.empty())
                req.priority = _queue.top().priority + 1;
            _queue.emplace(std::move(req));
            _queue_size = _queue.size();
        }

        std::optional<request> _take_request()
        {
            std::optional<request> res {};
            {
                mutex::scoped_lock lock { _queue_mutex };
                if (!_queue.empty()) {
                    auto req = _queue.top();
                    _queue.pop();
                    _queue_size = _queue.size();
                    res.emplace(std::move(req));
                }
            }
            return res;
        }

        void _report_result(request &&req, result &&res, bool recoverable=false)
        {
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
                logger::debug("downloaded {}", res.url);
                ++_stats.oks;
                _stats.bytes += res.size;
            }
            try {
                req.handler(std::move(res));
            } catch (const std::exception &ex) {
                _success = false;
                logger::error("request handler for url {} failed: std::exception: {}", req.url, ex.what());
            } catch (...) {
                _success = false;
                logger::error("request handler for url {} failed: unknown exception", req.url);
            }
        }
    };

    download_queue_async::download_queue_async(): _impl { std::make_unique<download_queue_async::impl>() }
    {
    }

    download_queue_async::~download_queue_async() =default;

    size_t download_queue_async::_cancel_impl(const cancel_predicate &pred)
    {
        return _impl->cancel(pred);
    }

    void download_queue_async::_download_impl(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
    {
        _impl->download(url, save_path, priority, handler);
    }

    bool download_queue_async::_process_ok_impl(bool report_progress, scheduler *sched)
    {
        return _impl->process_ok(report_progress, sched);
    }
}