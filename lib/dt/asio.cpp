/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <chrono>
#include <map>
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
#include <dt/asio.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::asio {
    namespace net = boost::asio;
    using tcp = boost::asio::ip::tcp;

    struct worker::impl {
        explicit impl() =default;

        ~impl()
        {
            _shutdown = true;
            _ioc.stop();
            _worker.join();
        }

        void add_before_action(const std::string &name, const action_type &act)
        {
            mutex::scoped_lock lk { _before_actions_mutex };
            auto [it, created] = _before_actions.try_emplace(name, act);
            if (!created)
                throw error("duplicate before action: {}", name);
        }

        void del_before_action(const std::string &name)
        {
            mutex::scoped_lock lk { _before_actions_mutex };
            if (_before_actions.erase(name) != 1)
                throw error("missing before action: {}", name);
        }

        void add_after_action(const std::string &name, const action_type &act)
        {
            mutex::scoped_lock lk { _after_actions_mutex };
            auto [it, created] = _after_actions.try_emplace(name, act);
            if (!created)
                throw error("duplicate after action: {}", name);
        }

        void del_after_action(const std::string &name)
        {
            mutex::scoped_lock lk { _after_actions_mutex };
            if (_after_actions.erase(name) != 1)
                throw error("missing after action: {}", name);
        }

        net::io_context &io_context()
        {
            return _ioc;
        }
    private:
        static void _run_isolated(const std::string_view &name, const action_type &act)
        {
            try {
                act();
            } catch (const error &ex) {
                logger::error("asio {} failed: {}", name, ex);
            } catch (const std::exception &ex) {
                logger::error("asio {} std::exception: {}", name, ex.what());
            } catch (...) {
                logger::error("asio {} failed: unknown exception", name);
            }
        }

        void _io_thread()
        {
            for (;;) {
                static std::string_view loop_name { "asio loop" };
                _run_isolated(loop_name, [&] {
                    {
                        mutex::scoped_lock lk { _before_actions_mutex };
                        for (const auto &[name, act]: _before_actions)
                            _run_isolated(name, act);
                    }
                    _ioc.run_for(std::chrono::milliseconds { 100 });
                    {
                        mutex::scoped_lock lk { _after_actions_mutex };
                        for (const auto &[name, act]: _after_actions)
                            _run_isolated(name, act);
                    }
                });
                if (_shutdown)
                    break;
                if (_ioc.stopped())
                    _ioc.restart();
            }
        }

        std::atomic_bool _shutdown { false };
        net::io_context _ioc {};
        alignas(mutex::padding) mutex::unique_lock::mutex_type _before_actions_mutex {};
        std::map<std::string, std::function<void()>> _before_actions {};
        alignas(mutex::padding) mutex::unique_lock::mutex_type _after_actions_mutex {};
        std::map<std::string, std::function<void()>> _after_actions {};
        std::thread _worker { [&] { _io_thread(); } };
    };

    worker &worker::get()
    {
        static worker w {};
        return w;
    }

    worker::worker(): _impl { std::make_unique<impl>() }
    {
    }

    worker::~worker() =default;

    void worker::add_before_action(const std::string &name, const action_type &act)
    {
        _impl->add_before_action(name, act);
    }

    void worker::del_before_action(const std::string &name)
    {
        _impl->del_before_action(name);
    }

    void worker::add_after_action(const std::string &name, const action_type &act)
    {
        _impl->add_after_action(name, act);
    }

    void worker::del_after_action(const std::string &name)
    {
        _impl->del_after_action(name);
    }

    net::io_context &worker::io_context()
    {
        return _impl->io_context();
    }
}
