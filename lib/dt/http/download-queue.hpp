/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_NG_HPP
#define DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_NG_HPP

#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#ifdef __clang__
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wdeprecated-declarations"
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
#   undef DT_CLEAR_BOOST_DEPRECATED_HEADERS
#endif
#ifdef __clang__
#   pragma GCC diagnostic pop
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/url.hpp>
#include <dt/logger.hpp>
#include <dt/memory.hpp>
#include <dt/mutex.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::http {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct download_queue {
        static constexpr size_t max_connections = 8;

        struct result {
            std::string url {};
            std::string save_path {};
            std::optional<std::string> error {};
            size_t size = 0;

            operator bool() const
            {
                return !static_cast<bool>(error);
            }
        };

        download_queue()
        {
        }

        ~download_queue()
        {
            _shutdown = true;
            _ioc.stop();
            _worker.join();
        }

        void download(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
        {
            std::scoped_lock lk { _queue_mutex };
            _queue.emplace(url, save_path, priority, handler);
        }

        bool process_ok(bool report_progress=false, scheduler *sched = nullptr)
        {
            _report = report_progress;
            for (;;) {
                {
                    std::scoped_lock lk { _queue_mutex, _conns_mutex };
                    if (_queue.empty() && _conns.size() == max_connections)
                        break;
                }
                bool did_work = false;
                if (sched != nullptr)
                    did_work = sched->process_once();
                if (!did_work)
                    std::this_thread::sleep_for(std::chrono::milliseconds { 100 });
            }
            return _success;
        }

        void process(bool report_progress=false, scheduler *sched = nullptr)
        {
            if (!process_ok(report_progress, sched))
                throw error("some download requests have failed, please check the logs");
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
            connection(download_queue &dlq, net::io_context& ioc, tcp::resolver &resolver)
                : _dlq { dlq }, _ioc { ioc }, _resolver { resolver }
            {
            }

            void download(request &&req)
            {
                boost::url_view uri { req.url };
                if (uri.scheme() != "http")
                    throw error("only http urls are supported but got {}", req.url);
                if (uri.path().empty())
                    throw error("path component of the downloaded URI cannot be empty but got {}", req.url);
                _req = std::move(req);
                _http_req.emplace();
                _http_req->version(11);
                _http_req->keep_alive(true);
                _http_req->method(http::verb::get);
                _http_req->target(uri.path());
                _http_req->set(http::field::host, uri.host());
                _http_req->set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
                _resolve(uri.host(), uri.port());
            }
        private:
            download_queue &_dlq;
            net::io_context &_ioc;
            tcp::resolver &_resolver;
            std::optional<std::string> _host {};
            std::optional<std::string> _port {};
            std::optional<tcp::resolver::results_type> _connect_endpoint {};
            std::optional<beast::tcp_stream> _stream {};
            beast::flat_buffer _buffer {};
            std::optional<http::request<http::empty_body>> _http_req {};
            std::optional<http::response_parser<http::file_body>> _http_parser {};
            request _req {};

            void _handle_error(const std::string &error, bool recoverable=true)
            {
                _req.errors.emplace_back(error);
                if (_req.errors.size() < 10 && recoverable) {
                    logger::debug("retrying after a recoverable download issue with {}: {} num_errors: {}", _req.url, error, _req.errors.size());
                    _dlq._retry_request(shared_from_this(), std::move(_req));
                } else {
                    logger::warn("download error {} priority {}: {}", _req.url, _req.priority, error);
                    _dlq._report_result(shared_from_this(), _req, result { .url=_req.url, .error=error });
                }
            }

            void _resolve(const std::string_view &host, const std::string_view &port)
            {
                if (_host == host && _port == port && _connect_endpoint) {
                    _connect();
                } else {
                    _host = host;
                    _port = port;
                    _resolver.async_resolve(host, port.empty() ? "80" : port, beast::bind_front_handler(&connection::_on_resolve, shared_from_this()));
                }
            }

            void _on_resolve(beast::error_code ec, tcp::resolver::results_type results)
            {
                if (ec) {
                    _handle_error(ec.message());
                    return;
                }
                _connect_endpoint.emplace(results);
                _connect();
                
            }

            void _connect()
            {
                _stream.emplace(_ioc);
                _stream->expires_after(std::chrono::seconds(5));
                _stream->async_connect(*_connect_endpoint, beast::bind_front_handler(&connection::_on_connect, shared_from_this()));
            }

            void _on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
            {
                if (ec) {
                    _handle_error(ec.message());
                    return;
                }
                _stream->expires_after(std::chrono::seconds(5));
                http::async_write(*_stream, *_http_req, beast::bind_front_handler(&connection::_on_write, shared_from_this()));
            }

            void _on_write(beast::error_code ec, std::size_t /*bytes_transferred*/)
            {
                if (ec) {
                    _handle_error(ec.message());
                    return;
                }
                {
                    beast::error_code open_ec {};
                    _http_parser.emplace();
                    _http_parser->body_limit(1 << 26);
                    _http_parser->get().body().open(_req.save_path.c_str(), beast::file_mode::write, open_ec);
                    if (open_ec) {
                        _handle_error(open_ec.message());
                        return;
                    }
                }
                _buffer.clear();
                _stream->expires_after(std::chrono::seconds(30));
                http::async_read(*_stream, _buffer, *_http_parser, beast::bind_front_handler(&connection::_on_read, shared_from_this()));
            }

            void _on_read(beast::error_code ec, std::size_t /*bytes_transferred*/)
            {
                if (ec) {
                    _handle_error(ec.message());
                    return;
                }
                auto &res = _http_parser->get();
                res.body().close();
                size_t body_size = 0;
                if (_http_parser->content_length())
                    body_size = *_http_parser->content_length();
                else 
                    body_size = std::filesystem::file_size(_req.save_path);
                auto http_status = _http_parser->get().result_int();
                if (http_status == 200) {
                    _dlq._report_result(shared_from_this(), _req, result { std::move(_req.url), std::move(_req.save_path), {}, body_size });
                } else {
                    _dlq._report_result(shared_from_this(), _req, result { std::move(_req.url), std::move(_req.save_path), fmt::format("bad http status: {}", http_status) });
                }                
            }
        };

        struct perf_stats {
            std::atomic_size_t oks = 0;
            std::atomic_size_t errors = 0;
            std::atomic_size_t bytes = 0;

            void report(double duration_secs)
            {
                auto num_requests = oks + errors;
                double error_rate = num_requests > 0 ? static_cast<double>(errors) * 100 / num_requests : 0.0;
                logger::debug("download-queue performance over the last reporting period: download speed: {:0.1f} MB/sec, requests: {}, error rate: {:0.2f}%",
                    static_cast<double>(bytes) / 1'000'000 / duration_secs, num_requests, error_rate);
                oks = 0;
                errors = 0;
                bytes = 0;
            }
        };

        net::io_context _ioc {};
        tcp::resolver _resolver { _ioc };
        std::atomic_bool _shutdown { false };
        std::atomic_bool _success { true };
        alignas(mutex::padding) std::mutex _queue_mutex {};
        std::priority_queue<request> _queue {};
        alignas(mutex::padding) std::mutex _conns_mutex {};
        std::vector<std::shared_ptr<connection>> _conns {}; // connections available for work
        std::thread _worker { [&] { _io_thread(); } };
        perf_stats _stats {};
        std::atomic_bool _report { false };

        void _io_thread()
        {
            {
                std::scoped_lock lk { _conns_mutex };
                while (_conns.size() < max_connections)
                    _conns.emplace_back(std::make_shared<connection>(*this, _ioc, _resolver));
            }
            auto report_span = std::chrono::seconds { 5 };
            auto report_span_secs = std::chrono::duration<double>(report_span).count();
            auto next_report = std::chrono::system_clock::now() + report_span;
            for (;;) {
                try {
                    {
                        std::scoped_lock lk { _queue_mutex, _conns_mutex };
                        while (!_queue.empty() && !_conns.empty()) {
                            auto req = _queue.top();
                            auto conn = _conns.back();
                            conn->download(std::move(req));
                            _queue.pop();
                            _conns.pop_back();
                        }
                    }
                    _ioc.run_for(std::chrono::milliseconds { 100 });
                    auto now = std::chrono::system_clock::now();
                    if (now >= next_report) {
                        _stats.report(report_span_secs);
                        next_report = now + report_span;
                        if (_report)
                            progress::get().inform();
                    }
                } catch (std::exception &ex) {
                    logger::warn("async I/O error: {}", ex.what());
                }
                if (_shutdown) {
                    _stats.report(report_span_secs);
                    break;
                }
                _ioc.restart();
            }
        }

        void _report_result(const std::shared_ptr<connection> &conn, const request &req, result &&res)
        {
            if (res.error) {
                logger::error("download of {} failed: {}", res.url, *res.error);
                _success = false;
                _stats.errors++;
            } else {
                logger::trace("downloaded {}", res.url);
                _stats.oks++;
                _stats.bytes += res.size;
            }
            {
                std::scoped_lock lk { _conns_mutex };
                _conns.push_back(conn);
            }
            req.handler(std::move(res));
        }

        void _retry_request(const std::shared_ptr<connection> &conn, request &&req)
        {
            {
                std::scoped_lock lk { _conns_mutex };
                _conns.push_back(conn);
            }
            _stats.errors++;
            std::scoped_lock lk { _queue_mutex };
            if (!_queue.empty())
                req.priority = _queue.top().priority * 2;
            _queue.emplace(std::move(req));
        }
    };
}

#endif // !DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_NG_HPP