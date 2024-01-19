/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_API_HPP
#define DAEDALUS_TURBO_HTTP_API_HPP

#include <future>
#ifdef __clang__
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
#define BOOST_ASIO_HAS_STD_INVOKE_RESULT 1
#ifndef BOOST_ALLOW_DEPRECATED_HEADERS
#   define BOOST_ALLOW_DEPRECATED_HEADERS
#   define DT_CLEAR_BOOST_DEPRECATED_HEADERS
#endif
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/spawn.hpp>
#ifdef DT_CLEAR_BOOST_DEPRECATED_HEADERS
#   undef BOOST_ALLOW_DEPRECATED_HEADERS
#   undef DT_CLEAR_BOOST_DEPRECATED_HEADERS
#endif
#ifdef __clang__
#   pragma GCC diagnostic pop
#endif
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>

#include <dt/chunk-registry.hpp>
#include <dt/format.hpp>
#include <dt/json.hpp>
#include <dt/history.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>
#include <dt/progress.hpp>
#include <dt/requirements.hpp>
#include <dt/sync/http.hpp>
#include <dt/util.hpp>

namespace fmt {
    template<>
    struct formatter<boost::string_view>: public formatter<std::string_view> {
        template<typename FormatContext>
        auto format(const boost::string_view &sv, FormatContext &ctx) const -> decltype(ctx.out()) {
            return formatter<std::string_view>::format(std::string_view { sv.data(), sv.size() }, ctx);
        }
    };
}

namespace daedalus_turbo::http_api {
    namespace beast = boost::beast;
    namespace http = beast::http;
    namespace net = boost::asio;
    namespace dt = daedalus_turbo;
    namespace json = boost::json;
    using tcp = boost::asio::ip::tcp;

    struct server {
        server(const std::string &db_dir, const std::string &idx_dir, const std::string &host)
            : _db_dir { db_dir }, _idx_dir { idx_dir }, _host { host }, _indexers { indexer::default_list(_sched, _idx_dir) }
                , _requirements_status { requirements::check(_db_dir) }
        {
        }

        void serve(const net::ip::address &ip, uint16_t port)
        {
            std::thread worker { [&] { _worker_thread(); } };
            {
                std::scoped_lock results_lk { _results_mutex };
                _results.emplace("/sync/", std::optional<json::value> {});
            }
            {
                std::unique_lock queue_lk { _queue_mutex };
                _queue.emplace_back("/sync/");
                queue_lk.unlock();
                _queue_cv.notify_one();
            }
            net::io_context ioc { 1 };
            net::spawn(ioc, std::bind(&server::_do_listen, std::ref(*this), std::ref(ioc), tcp::endpoint { ip, port }, std::placeholders::_1));
            ioc.run();
        }

    private:
        enum class sync_status { syncing, ready, failed };

        struct send_lambda {
            beast::tcp_stream& stream_;
            bool& close_;
            beast::error_code& ec_;
            net::yield_context yield_;

            send_lambda(beast::tcp_stream& stream, bool& close, beast::error_code& ec, net::yield_context yield)
                : stream_(stream), close_(close), ec_(ec), yield_(yield)
            {
            }

            template<bool isRequest, class Body, class Fields>
            void operator()(http::message<isRequest, Body, Fields>&& msg) const
            {
                close_ = msg.need_eof();
                http::serializer<isRequest, Body, Fields> sr{msg};
                http::async_write(stream_, sr, yield_[ec_]);
            }
        };

        const std::string _db_dir, _idx_dir, _host;
        scheduler sched { std::max(scheduler::default_worker_count() - 1, static_cast<size_t>(1)) };
        indexer::indexer_map _indexers {};
        std::unique_ptr<indexer::incremental> _cr {};
        std::unique_ptr<reconstructor> _reconst {};
        std::optional<std::string> _sync_error {};
        std::optional<chunk_registry::chunk_info> _sync_last_chunk {};
        std::atomic<sync_status> _sync_status { sync_status::syncing };
        requirements::check_status _requirements_status {};

        // request queue
        alignas(mutex::padding) std::mutex _queue_mutex {};
        alignas(mutex::padding) std::condition_variable _queue_cv;
        std::deque<std::string> _queue {};
        alignas(mutex::padding) std::mutex _results_mutex {};
        std::map<std::string, std::optional<json::value>> _results {};

        std::pair<std::string_view, std::vector<std::string_view>> _parse_target(const std::string_view &target)
        {
            std::optional<std::string_view> req_id {};
            std::vector<std::string_view> params {};
            if (target.at(0) != '/')
                throw error("target must begin with / but got: '{}'", target);
            size_t start = 1;
            while (start < target.size()) {
                size_t end = target.find('/', start);
                if (end == target.npos)
                    end = target.size();
                std::string_view part = target.substr(start, end - start);
                if (!part.empty()) {
                    if (!req_id)
                        req_id.emplace(part);
                    else
                        params.emplace_back(part);
                }
                start = end + 1;
            }
            if (!req_id)
                throw error("target must have request id: '{}'", target);
            return std::make_pair(std::move(*req_id), std::move(params));
        }

        json::value _error_response(const std::string &msg)
        {
            logger::error(msg);
            return json::value {
                { "error", msg }
            };
        }

        void _process_request(const std::string &target)
        {
            json::value resp {};
            try {
                timer t { fmt::format("handling request {}", target) };
                const auto [req_id, params] = _parse_target(target);
                logger::info("begin processing request {} with params {}", req_id, params);
                if (req_id == "tx" && params.size() == 1 && params[0].size() == 2 * 32) {
                    resp = _api_tx_info(uint8_vector::from_hex(params[0]));
                } else if (req_id == "stake" && params.size() == 1) {
                    auto bytes = uint8_vector::from_hex(params[0]);
                    cardano::address addr { bytes };
                    if (!addr.has_stake_id())
                        throw error("provided address does not have a stake-key component: {}", bytes);
                    resp = _api_stake_id_info(addr.stake_id());
                } else if (req_id == "stake-assets" && params.size() == 3) {
                    auto bytes = uint8_vector::from_hex(params.at(0));
                    cardano::address addr { bytes };
                    if (!addr.has_stake_id())
                        throw error("provided address does not have a stake-key component: {}", bytes);
                    auto offset = std::stoull(static_cast<std::string>(params.at(1)));
                    auto count = std::stoull(static_cast<std::string>(params.at(2)));
                    resp = _api_stake_assets(addr.stake_id(), offset, count);
                } else if (req_id == "stake-txs" && params.size() == 3) {
                    auto bytes = uint8_vector::from_hex(params.at(0));
                    cardano::address addr { bytes };
                    if (!addr.has_stake_id())
                        throw error("provided address does not have a stake-key component: {}", bytes);
                    auto offset = std::stoull(static_cast<std::string>(params.at(1)));
                    auto count = std::stoull(static_cast<std::string>(params.at(2)));
                    resp = _api_stake_txs(addr.stake_id(), offset, count);
                } else if (req_id == "pay" && params.size() == 1) {
                    auto bytes = uint8_vector::from_hex(params[0]);
                    cardano::address addr { bytes };
                    if (!addr.has_pay_id())
                        throw error("provided address does not have a payment-key component: {}", bytes);
                    resp = _api_pay_id_info(addr.pay_id());
                } else if (req_id == "pay-assets" && params.size() == 3) {
                    auto bytes = uint8_vector::from_hex(params.at(0));
                    cardano::address addr { bytes };
                    if (!addr.has_pay_id())
                        throw error("provided address does not have a payment-key component: {}", bytes);
                    auto offset = std::stoull(static_cast<std::string>(params.at(1)));
                    auto count = std::stoull(static_cast<std::string>(params.at(2)));
                    resp = _api_pay_assets(addr.pay_id(), offset, count);
                } else if (req_id == "pay-txs" && params.size() == 3) {
                    auto bytes = uint8_vector::from_hex(params.at(0));
                    cardano::address addr { bytes };
                    if (!addr.has_pay_id())
                        throw error("provided address does not have a pay-key component: {}", bytes);
                    auto offset = std::stoull(static_cast<std::string>(params.at(1)));
                    auto count = std::stoull(static_cast<std::string>(params.at(2)));
                    resp = _api_pay_txs(addr.pay_id(), offset, count);
                } else if (req_id == "sync") {
                    resp = _api_sync();
                } else {
                    throw error("unsupported endpoint '{}'", req_id);
                }
                logger::info("request {} succeeded in {:0.3f} secs", target, t.stop());
            } catch (std::exception &ex) {
                resp = _error_response(fmt::format("request {} failed: {}", target, ex.what()));
            }
            {
                std::scoped_lock lk { _results_mutex };
                _results[target] = std::move(resp);
            }
        }
        
        void _worker_thread()
        {
            for (;;) {
                std::unique_lock lock { _queue_mutex };
                bool have_work = _queue_cv.wait_for(lock, std::chrono::seconds { 1 }, [&]{ return !_queue.empty(); });
                logger::debug("http-api worker thread waiting for tasks returned with {}", have_work);
                if (have_work) {
                    const auto target = _queue.front();
                    _queue.pop_front();
                    lock.unlock();
                    _process_request(target);
                }
            }
        }

        http::response<http::string_body> _send_json_response(const http::request<http::string_body>& req, const json::value &json_resp)
        {
            timer t { "http-api serialize json and send the response" };
            auto resp_str = json::serialize(json_resp);
            resp_str += '\n';
            const auto target = std::string_view { req.target().data(), req.target().size() };
            if (!target.starts_with("/status/"))
                logger::info("response to {} size: {}", target, resp_str.size());
            else
                logger::trace("response to {} size: {}", target, resp_str.size());
            http::string_body::value_type body { std::move(resp_str) };
            const std::string &mime_type = "application/json";
            auto const size = body.size();

            http::response<http::string_body> res { std::piecewise_construct, std::make_tuple(std::move(body)), std::make_tuple(http::status::ok, req.version()) };
            res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res.set(http::field::content_type, mime_type);
            res.content_length(size);
            res.keep_alive(req.keep_alive());
            return res;
        }

        http::response<http::string_body> _api_status(const http::request<http::string_body>& req)
        {
            json::object resp {};
            resp.emplace("ready", _sync_status == sync_status::ready);
            resp.emplace("requirements", _requirements_status.to_json());
            auto progress_copy = progress::get().copy();
            if (!progress_copy.empty()) {
                json::object task_progress {};
                for (const auto &[name, value]: progress_copy)
                    task_progress.emplace(name, value);
                resp.emplace("progress", std::move(task_progress));
            }
            {
                json::object requests {};
                std::scoped_lock lk { _results_mutex };
                for (const auto &[req_id, resp]: _results)
                    requests.emplace(req_id, static_cast<bool>(resp));
                resp.emplace("requests", std::move(requests));
            }
            switch (_sync_status) {
                case sync_status::ready:
                    if (_sync_last_chunk) {
                        resp.emplace("lastBlock", json::object {
                            { "hash", fmt::format("{}", _sync_last_chunk->last_block_hash) },
                            { "slot", static_cast<uint64_t>(_sync_last_chunk->last_slot) },
                            { "epoch", _sync_last_chunk->last_slot.epoch() },
                            { "epochSlot", _sync_last_chunk->last_slot.epoch_slot() },
                            { "timestamp", fmt::format("{} UTC", _sync_last_chunk->last_slot.timestamp()) }
                        });
                    }
                    break;
                case sync_status::syncing:
                    break;
                case sync_status::failed:
                    resp.emplace("error", *_sync_error);
                    break;
                default:
                    throw error("internal error: unsupported value of the internal status: {}", static_cast<int>(_sync_status.load()));
            }
            return _send_json_response(req, std::move(resp));
        }

        json::value _api_sync()
        {
            logger::info("sync start");
            _sync_status = sync_status::syncing;
            _sync_error.reset();
            _sync_last_chunk.reset();
            try {
                _cr = std::make_unique<indexer::incremental>(_sched, _db_dir, _indexers);
                {
                    sync::http::syncer syncr { _sched, *_cr, _host, false };
                    syncr.sync();
                }
                _reconst = std::make_unique<reconstructor>(_sched, *_cr, _idx_dir);
                _sync_last_chunk = _cr->last_chunk();
                _sync_status = sync_status::ready;
                logger::info("synchronization complete, all API endpoints are available now");
            } catch (std::exception &ex) {
                _sync_error.emplace(ex.what());
                logger::error("sync failed: {}", *_sync_error);
                _sync_status = sync_status::failed;
            }
            return json::value { "synchronization complete" };
        }

        json::value _api_tx_info(const buffer &tx_hash)
        {
            auto tx_info = _reconst->find_tx(tx_hash);
            if (!tx_info) {
                return json::object {
                    { "hash", fmt::format("{}", tx_hash) },
                    { "error", "transaction data have not been found!" }
                };
            }
            history_mock_block block { tx_info.block_info, tx_info.tx_raw, tx_info.offset };
            auto tx_ptr = cardano::make_tx(tx_info.tx_raw, block);
            auto &tx = *tx_ptr; // eliminate a clash with CLang's -Wpotentially-evaluated-expression
            logger::info("tx: {} type: {} slot: {}", tx.hash().span(), typeid(tx).name(), tx_info.block_info.slot);
            return tx.to_json();
        }

        json::value _api_stake_id_info(const stake_ident &id)
        {
            auto hist = _reconst->find_stake_history(id);
            if (hist.transactions.size() == 0) {
                return json::object {
                    { "id", hist.id.to_json() },
                    { "error", "could't find any transactions referencing this stake key!" }
                };
            }
            return hist.to_json();
        }

        json::value _api_stake_txs(const stake_ident &id, size_t offset, size_t max_items)
        {
            auto hist = _reconst->find_stake_history(id);
            return json::object {
                { "id", hist.id.to_json() },
                { "txCount", hist.transactions.size() },
                { "txOffset", offset },
                { "transactions", hist.transactions.to_json(offset, max_items) }
            };
        }

        json::object _api_stake_assets(const stake_ident &id, size_t offset, size_t max_items)
        {
            auto hist = _reconst->find_stake_history(id);
            return json::object {
                { "id", hist.id.to_json() },
                { "assetCount", hist.balance_assets.size() },
                { "assetOffset", offset },
                { "assets", hist.balance_assets.to_json(offset, max_items) }
            };
        }

        json::value _api_pay_id_info(const pay_ident &pay_id)
        {
            auto hist = _reconst->find_pay_history(pay_id);
            if (hist.transactions.size() == 0) {
                return json::object {
                    { "id", hist.id.to_json() },
                    { "error", "could't find any transactions referencing this payment key!" }
                };
            }
            return hist.to_json();
        }

        json::value _api_pay_txs(const pay_ident &id, size_t offset, size_t max_items)
        {
            auto hist = _reconst->find_pay_history(id);
            return json::object {
                { "id", hist.id.to_json() },
                { "txCount", hist.transactions.size() },
                { "txOffset", offset },
                { "transactions", hist.transactions.to_json(offset, max_items) }
            };
        }

        json::object _api_pay_assets(const pay_ident &id, size_t offset, size_t max_items)
        {
            auto hist = _reconst->find_pay_history(id);
            return json::object {
                { "id", hist.id.to_json() },
                { "assetCount", hist.balance_assets.size() },
                { "assetOffset", offset },
                { "assets", hist.balance_assets.to_json(offset, max_items) }
            };
        }

        void _handle_request(http::request<http::string_body> &&req, send_lambda &&send)
        {
            if(req.method() != http::verb::get)
                throw error("Unsupported HTTP method {}", static_cast<std::string_view>(req.method_string()));
            const auto target = static_cast<std::string>(req.target());
            try {
                timer t { target, logger::level::info };
                if (target.starts_with("/status/")) {
                    send(_api_status(req));
                } else if (_sync_status != sync_status::ready) {
                    json::value resp {};
                    if (_sync_status == sync_status::syncing)
                        resp = _error_response("Sync in progress, the API is not yet ready!");
                    else if (_sync_status == sync_status::failed)
                        resp = _error_response(*_sync_error);
                    else
                        resp = _error_response("The syncronization state is unknown");
                    send(_send_json_response(req, resp));
                } else {
                    std::optional<json::value> resp {};
                    {
                        std::scoped_lock results_lk { _results_mutex };
                        if (_results.contains(target)) {
                            auto &cached_res = _results.at(target);
                            if (cached_res) {
                                resp.emplace();
                                std::swap(*resp, *cached_res);
                                _results.erase(target);
                            } else {
                                resp.emplace(json::object { { "delayed", true } });
                            }
                        } else {
                            _results.emplace(target, std::optional<json::value> {});
                        }
                    }
                    if (!resp) {
                        std::unique_lock queue_lk { _queue_mutex };
                        _queue.emplace_back(target);
                        queue_lk.unlock();
                        _queue_cv.notify_one();
                        resp = json::object { { "delayed", true } };
                    }
                    send(_send_json_response(req, std::move(*resp)));
                }
            } catch (std::exception &ex) {
                logger::error("request {}: {}", target, ex.what());
                send(_send_json_response(req, _error_response("Illegal request")));
            }
        }

        void _fail(beast::error_code ec, char const* what)
        {
            logger::error("{}: {}", what, ec.message());
        }

        void _do_session(beast::tcp_stream& stream, net::yield_context yield)
        {
            bool close = false;
            beast::error_code ec;
            beast::flat_buffer buffer;
            send_lambda lambda { stream, close, ec, yield };

            for(;;) {
                stream.expires_after(std::chrono::seconds(30));
                http::request<http::string_body> req;
                http::async_read(stream, buffer, req, yield[ec]);
                if(ec == http::error::end_of_stream) break;
                if(ec) return _fail(ec, "read");
                _handle_request(std::move(req), std::move(lambda));
                if(ec) return _fail(ec, "write");
                if(close) break;
            }
            stream.socket().shutdown(tcp::socket::shutdown_send, ec);
        }

        void _do_listen(net::io_context& ioc, tcp::endpoint endpoint, net::yield_context yield)
        {
            beast::error_code ec;
            tcp::acceptor acceptor(ioc);
            acceptor.open(endpoint.protocol(), ec);
            if(ec) return _fail(ec, "open");
            acceptor.set_option(net::socket_base::reuse_address(true), ec);
            if(ec) return _fail(ec, "set_option");
            acceptor.bind(endpoint, ec);
            if(ec) return _fail(ec, "bind");
            acceptor.listen(net::socket_base::max_listen_connections, ec);
            if(ec) return _fail(ec, "listen");
            logger::info("http-api server is ready to serve requests");
            for(;;) {
                tcp::socket socket(ioc);
                acceptor.async_accept(socket, yield[ec]);
                if(ec) _fail(ec, "accept");
                else boost::asio::spawn(acceptor.get_executor(), std::bind(&server::_do_session, std::ref(*this), beast::tcp_stream(std::move(socket)), std::placeholders::_1));
            }
        }
    };
}

#endif // !DAEDALUS_TURBO_HTTP_API_HPP