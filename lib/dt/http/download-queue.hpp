/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP
#define DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP

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
#include <dt/scheduler.hpp>

namespace daedalus_turbo::http {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct download_queue {
        static constexpr size_t max_io_threads = 1;

        struct network_error: error {
            using error::error;
        };

        struct result {
            std::string url {};
            std::string body {};
            std::string error {};

            operator bool() const
            {
                return error.empty();
            }
        };

        struct request {
            std::string url {};
            uint64_t priority = 0;
            std::function<void(result &&)> handler {};
            std::vector<std::string> errors {};

            bool operator<(const request &b) const
            {
                return priority > b.priority;
            }
        };

        download_queue(scheduler &sched, size_t max_requests=0, size_t task_prio=1000, const std::string &task_name="download")
            : _sched { sched }, _task_name { task_name }, _task_prio { task_prio }, _resolver { _ioc },
                _requests_max { _max_allowed_requests(max_requests) },
                _max_io_threads { max_io_threads }, _shutdown { std::make_shared<std::atomic_bool>(false) }
        {
            if (_max_io_threads == 0)
                throw error("max_io_threads cannot be zero!");
            logger::debug("created download queue with {} max active requests", _requests_max);
            auto shutdown_copy = _shutdown;
            _ioc_process = [&, shutdown_copy] {
                size_t num_done = 0;
                try {
                    {
                        std::scoped_lock lk { _queue_mutex };
                        while (_requests_active < _requests_max && !_queue.empty()) {
                            auto req = _queue.top();
                            _download(std::move(req));
                            _queue.pop();
                            --_queue_size;
                        }
                    }
                    num_done = _ioc.run_for(std::chrono::milliseconds { 1000 });
                    if (num_done == 0 && !*shutdown_copy) {
                        _ioc.restart();
                    }
                } catch (std::exception &ex) {
                    logger::warn("async I/O error: {}", ex.what());
                }
                return num_done;
            };
        }

        ~download_queue()
        {
            logger::debug("download queue shutdown initiated: tasks: {} active I/O threads: {}", size(), _sched.task_count(_task_name));
            *_shutdown = true;
            _ioc.stop();
        }

        void start()
        {
            if (_queue_size != 0 || _requests_active != 0)
                throw error("cannot start an active download queue must finish first");
            _ioc.restart();
            _complete = false;
            *_shutdown = false;
            _success = true;
            auto shutdown_copy = _shutdown;
            _sched.on_result(_task_name, [this, shutdown_copy](const auto &) {
                if (!*shutdown_copy) {
                    _sched.submit(_task_name, _task_prio, _ioc_process);
                }
            });
            for (size_t ti = 0; ti < _max_io_threads; ti++)
                _sched.submit(_task_name, _task_prio, _ioc_process);
        }

        void download(const std::string &url, uint64_t priority, const std::function<void(result &&)> &handler)
        {
            _add_request(url, priority, handler);
        }

        std::string download_sync(const std::string &url)
        {
            boost::url_view uri { url };
            beast::tcp_stream stream { _ioc };
            stream.connect(_resolver.resolve(uri.host(), uri.port().empty() ? "80" : uri.port()));
            http::request<http::string_body> req { http::verb::get, uri.path(), 11 };
            req.set(http::field::host, uri.host());
            req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
            http::write(stream, req);
            beast::flat_buffer buffer {};
            http::response_parser<http::dynamic_body> parser {};
            parser.body_limit(1 << 26);
            http::read(stream, buffer, parser);
            const auto &res = parser.get();
            std::string body = boost::beast::buffers_to_string(res.body().data());
            if (res.result() != http::status::ok)
                throw error("HTTP request to {} failed with code {} and data:\n{}\n", url, res.result_int(), body);
            beast::error_code ec {};
            stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            if(ec && ec != beast::errc::not_connected)
                throw beast::system_error{ec};
            return body;
        }

        size_t size() const
        {
            return _requests_active + _queue_size;
        }

        bool empty() const
        {
            return size() == 0;
        }

        void complete()
        {
            if (!_complete) {
                _complete = true;
                if (empty())
                    *_shutdown = true;
                logger::debug("download queue filled: requests: {}, I/O threads scheduled/active: {}/{} shutdown: {}",
                    size(), _max_io_threads, _sched.task_count(_task_name), static_cast<bool>(*_shutdown));
            }
        }

        bool success() const
        {
            return _success;
        }
    private:
        scheduler &_sched;
        std::string _task_name;
        size_t _task_prio;
        net::io_context _ioc {};
        tcp::resolver _resolver;
        const size_t _requests_max = 0;
        const size_t _max_io_threads;
        std::atomic_size_t _requests_active = 0;
        std::shared_ptr<std::atomic_bool> _shutdown;
        std::atomic_bool _complete = false;
        std::atomic_bool _success = true;
        std::function<std::any()> _ioc_process {};
        alignas(mutex::padding) std::mutex _queue_mutex {};
        std::priority_queue<request> _queue {};
        // keep the size separately in an atomic var to not acquire mutex for read access to the size
        std::atomic_size_t _queue_size = 0;

        struct session: std::enable_shared_from_this<session>
        {
            session(download_queue &dlq, net::io_context& ioc, tcp::resolver &resolver)
                : _dlq { dlq }, _resolver { resolver }, _stream { ioc }
            {
                _http_parser.body_limit(1 << 26);
            }

            void download(request &&req)
            {
                boost::url_view uri { req.url };
                if (uri.scheme() != "http")
                    throw error("only http urls are supported but got {}", req.url);
                if (uri.path().empty())
                    throw error("path component of the downloaded URI cannot be empty but got {}", req.url);
                _req = std::move(req);
                _http_req.version(11);
                _http_req.method(http::verb::get);
                _http_req.target(uri.path());
                _http_req.set(http::field::host, uri.host());
                _http_req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
                _resolver.async_resolve(uri.host(), uri.port().empty() ? "80" : uri.port(), beast::bind_front_handler(&session::_on_resolve, shared_from_this()));
            }
        private:
            download_queue &_dlq;
            tcp::resolver &_resolver;
            beast::tcp_stream _stream;
            beast::flat_buffer _buffer {};
            http::request<http::empty_body> _http_req {};
            http::response_parser<http::dynamic_body> _http_parser {};
            request _req {};

            void _handle_error(const std::string &error, bool recoverable=true)
            {
                _req.errors.emplace_back(error);
                if (_req.errors.size() < 10 && recoverable) {
                    logger::debug("retrying after a recoverable download issue with {}: {} num_errors: {}", _req.url, error, _req.errors.size());
                    _dlq._reinsert_request(std::move(_req));
                } else {
                    logger::warn("download error {} priority {}: {}", _req.url, _req.priority, error);
                    _dlq._report_failure(_req, result { .url=_req.url, .error=error });
                }
            }

            void _on_resolve(beast::error_code ec, tcp::resolver::results_type results)
            {
                if(ec) {
                    _handle_error(ec.message());
                    return;
                }
                _stream.expires_after(std::chrono::seconds(30));
                _stream.async_connect(results, beast::bind_front_handler(&session::_on_connect, shared_from_this()));
            }

            void _on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
            {
                if(ec) {
                    _handle_error(ec.message());
                    return;
                }
                _stream.expires_after(std::chrono::seconds(120));
                http::async_write(_stream, _http_req, beast::bind_front_handler(&session::_on_write, shared_from_this()));
            }

            void _on_write(beast::error_code ec, std::size_t bytes_transferred)
            {
                boost::ignore_unused(bytes_transferred);
                if(ec) {
                    _handle_error(ec.message());
                    return;
                }
                http::async_read(_stream, _buffer, _http_parser, beast::bind_front_handler(&session::_on_read, shared_from_this()));
            }

            void _on_read(beast::error_code ec, std::size_t bytes_transferred)
            {
                boost::ignore_unused(bytes_transferred);
                if(ec) {
                    _handle_error(ec.message());
                    return;
                }
                const auto &res = _http_parser.get();
                auto http_status = res.result_int();
                if (http_status != 200) {
                    _handle_error(fmt::format("bad http status: {}", http_status), false);
                    return;
                }
                std::string body = boost::beast::buffers_to_string(res.body().data());
                _dlq._report_success(_req, result { std::move(_req.url), std::move(body) });
                _stream.socket().shutdown(tcp::socket::shutdown_both, ec);
                if(ec && ec != beast::errc::not_connected)
                    logger::warn("socket shutdown failure: {}", ec.message());
            }
        };

        static size_t _sys_max_requests()
        {
            // One cardano chunk can take 30-40 MB compressed.
            // Thus, 100 in-memory buffers can tak 3-4 GB of RAM and requires to chose the parameter carefully
            auto avail_ram = memory::physical_mb();
            if (avail_ram <= 4096)
                return 8;
            if (avail_ram <= 8192)
                return 24;
            if (avail_ram <= 16384)
                return 48;
            return 96;
        }

        static size_t _max_allowed_requests(size_t user_max_requests)
        {
            auto sys_max_requests = _sys_max_requests();
            if (user_max_requests == 0 || user_max_requests > sys_max_requests)
                return sys_max_requests;
            return user_max_requests;
        }

        void _add_request(const std::string &url, uint64_t priority, const std::function<void(result &&)> &orig_handler)
        {
            if (_complete)
                throw error("the queue is complete, can't add new tasks!");
            std::scoped_lock lk { _queue_mutex };
            _queue.emplace(url, priority, orig_handler);
            _queue_size++;
        }

        void _report_success(const request &req, result &&res)
        {
            --_requests_active;
            logger::trace("downloaded {}: {} bytes, remaining requests: {}", res.url, res.body.size(), size());
            req.handler(std::move(res));
            if (_complete && _requests_active == 0 && _queue_size == 0)
                *_shutdown = true;
        }

        void _report_failure(const request &req, result &&res)
        {
            --_requests_active;
            _success = false;
            logger::trace("download of {} failed: {}, remaining requests: {}", res.url, res.error, size());
            req.handler(std::move(res));
            if (_complete && _requests_active == 0 && _queue_size == 0)
                *_shutdown = true;
        }

        void _reinsert_request(request &&req)
        {
            std::scoped_lock lk { _queue_mutex };
            --_requests_active;
            // ensure that failing request won't be retried immediately
            if (!_queue.empty())
                req.priority = _queue.top().priority * 2;
            _queue.emplace(std::move(req));
            _queue_size++;
        }

        void _download(request &&req)
        {
            // expects that _queue_mutex is acquired and held by its caller
            ++_requests_active;
            std::make_shared<session>(*this, _ioc, _resolver)->download(std::move(req));
        }
    };
}

#endif // !DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP