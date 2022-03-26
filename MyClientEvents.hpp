#ifndef MY_CLIENT_EVENTS_H
#define MY_CLIENT_EVENTS_H
#include "OpenVPNClientBase.hpp"
#include <openvpn/common/rc.hpp>
#include <openvpn/common/count.hpp>
#include <openvpn/client/clievent.hpp>
namespace libopenvpn
{
    using namespace openvpn;

    class MyClientEvents : public ClientEvent::Queue
    {
    public:
        typedef RCPtr<MyClientEvents> Ptr;

        MyClientEvents(OpenVPNClientBase *parent_arg) : parent(parent_arg) {}

        virtual void add_event(ClientEvent::Base::Ptr event) override
        {
            if (parent)
            {
                Event ev;
                ev.name = event->name();
                ev.info = event->render();
                ev.error = event->is_error();
                ev.fatal = event->is_fatal();

                // save connected event
                if (event->id() == ClientEvent::CONNECTED)
                    last_connected = std::move(event);
                else if (event->id() == ClientEvent::DISCONNECTED)
                    parent->on_disconnect();
                parent->event(ev);
            }
        }

        void get_connection_info(ConnectionInfo &ci)
        {
            ClientEvent::Base::Ptr connected = last_connected;
            if (connected)
            {
                const ClientEvent::Connected *c = connected->connected_cast();
                if (c)
                {
                    ci.user = c->user;
                    ci.serverHost = c->server_host;
                    ci.serverPort = c->server_port;
                    ci.serverProto = c->server_proto;
                    ci.serverIp = c->server_ip;
                    ci.vpnIp4 = c->vpn_ip4;
                    ci.vpnIp6 = c->vpn_ip6;
                    ci.gw4 = c->vpn_gw4;
                    ci.gw6 = c->vpn_gw6;
                    ci.clientIp = c->client_ip;
                    ci.tunName = c->tun_name;
                    ci.defined = true;
                    return;
                }
            }
            ci.defined = false;
        }

        void detach_from_parent()
        {
            parent = nullptr;
        }

    private:
        OpenVPNClientBase *parent;
        ClientEvent::Base::Ptr last_connected;
    };
} // namespace libopenvpn
#endif