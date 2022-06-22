#ifndef CLIENT_STATE_H
#define CLIENT_STATE_H

#include "MyClientEvents.hpp"
#include "MyClockTick.hpp"
#include "MyRemoveOverride.hpp"
#include "MySessionStats.hpp"
#include "MySocketProtect.hpp"
#include "MyReconnectNotify.hpp"
#include <openvpn/transport/client/httpcli.hpp>
#include <openvpn/common/options.hpp>
namespace libopenvpn
{
    using namespace openvpn;
    namespace Private
    {
        class ClientState
        {
        public:
            // state objects
            OptionList options;
            libopenvpn::EvalConfig eval;
            MySocketProtect socket_protect;
            libopenvpn::MyReconnectNotify reconnect_notify;
            libopenvpn::MyRemoteOverride remote_override;
            ClientCreds::Ptr creds;
            libopenvpn::MySessionStats::Ptr stats;
            libopenvpn::MyClientEvents::Ptr events;
            ClientConnect::Ptr session;
            std::unique_ptr<libopenvpn::MyClockTick> clock_tick;

            // extra settings submitted by API client
            std::string server_override;
            std::string port_override;
            Protocol proto_override;
            //IPv6Setting ipv6;
            int conn_timeout = 0;
            bool tun_persist = false;
            bool wintun = false;
            bool google_dns_fallback = false;
            bool synchronous_dns_lookup = false;
            bool autologin_sessions = false;
            bool retry_on_auth_failed = false;
            std::string private_key_password;
            std::string external_pki_alias;
            bool disable_client_cert = false;
            int ssl_debug_level = 0;
            int default_key_direction = -1;
            bool force_aes_cbc_ciphersuites = false;
            std::string tls_version_min_override;
            std::string tls_cert_profile_override;
            std::string gui_version;
            std::string sso_methods;
            bool allow_local_lan_access;
            std::string hw_addr_override;
            std::string platform_version;
            ProtoContextOptions::Ptr proto_context_options;
            PeerInfo::Set::Ptr extra_peer_info;
            HTTPProxyTransport::Options::Ptr http_proxy_options;
            unsigned int clock_tick_ms = 0;
#ifdef OPENVPN_GREMLIN
            Gremlin::Config::Ptr gremlin_config;
#endif
            bool alt_proxy = false;
            bool dco = false;
            bool echo = false;
            bool info = false;

            template <typename SESSION_STATS, typename CLIENT_EVENTS>
            void attach(OpenVPNClientBase *parent,
                        openvpn_io::io_context *io_context,
                        Stop *async_stop_global)
            {
                // only one attachment per instantiation allowed
                if (attach_called)
                    throw Exception("ClientState::attach() can only be called once per ClientState instantiation");
                attach_called = true;

                // async stop
                async_stop_global_ = async_stop_global;

                // io_context
                if (io_context)
                    io_context_ = io_context;
                else
                {
                    io_context_ = new openvpn_io::io_context(1); // concurrency hint=1
                    io_context_owned = true;
                }

                // client stats
                stats.reset(new SESSION_STATS(parent));

                // client events
                events.reset(new CLIENT_EVENTS(parent));

                // socket protect
                socket_protect.set_parent(parent);

                // reconnect notifications
                reconnect_notify.set_parent(parent);

                // remote override
                remote_override.set_parent(parent);
            }

            ClientState() {}

            ~ClientState()
            {
                stop_scope_local.reset();
                stop_scope_global.reset();
                socket_protect.detach_from_parent();
                reconnect_notify.detach_from_parent();
                remote_override.detach_from_parent();
                if (clock_tick)
                    clock_tick->detach_from_parent();
                if (stats)
                    stats->detach_from_parent();
                if (events)
                    events->detach_from_parent();
                session.reset();
                if (io_context_owned)
                    delete io_context_;
            }

            // foreign thread access

            void enable_foreign_thread_access()
            {
                foreign_thread_ready.store(true, std::memory_order_release);
            }

            bool is_foreign_thread_access()
            {
                return foreign_thread_ready.load(std::memory_order_acquire);
            }

            // io_context

            openvpn_io::io_context *io_context()
            {
                return io_context_;
            }

            // async stop

            Stop *async_stop_local()
            {
                return &async_stop_local_;
            }

            Stop *async_stop_global()
            {
                return async_stop_global_;
            }

            void trigger_async_stop_local()
            {
                async_stop_local_.stop();
            }

            // disconnect
            void on_disconnect()
            {
                if (clock_tick)
                    clock_tick->cancel();
            }

            void setup_async_stop_scopes()
            {
                stop_scope_local.reset(new AsioStopScope(*io_context(), async_stop_local(), [this]() {
                    OPENVPN_ASYNC_HANDLER;
                    session->graceful_stop();
                }));

                stop_scope_global.reset(new AsioStopScope(*io_context(), async_stop_global(), [this]() {
                    OPENVPN_ASYNC_HANDLER;
                    trigger_async_stop_local();
                }));
            }

        private:
            ClientState(const ClientState &) = delete;
            ClientState &operator=(const ClientState &) = delete;

            bool attach_called = false;

            Stop async_stop_local_;
            Stop *async_stop_global_ = nullptr;

            std::unique_ptr<AsioStopScope> stop_scope_local;
            std::unique_ptr<AsioStopScope> stop_scope_global;

            openvpn_io::io_context *io_context_ = nullptr;
            bool io_context_owned = false;

            std::atomic<bool> foreign_thread_ready{false};
        };
    }; // namespace Private
} // namespace libopenvpn

#endif