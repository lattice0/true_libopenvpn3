#ifndef MY_REMOTE_OVERRIDE
#define MY_REMOTE_OVERRIDE
#include "OpenVPNClientBase.hpp"
#include <openvpn/client/remotelist.hpp>
#include <openvpn/common/hostport.hpp>

namespace libopenvpn
{
    using namespace openvpn;
    class MyRemoteOverride : public RemoteList::RemoteOverride
    {
    public:
        void set_parent(OpenVPNClientBase *parent_arg)
        {
            parent = parent_arg;
        }

        void detach_from_parent()
        {
            parent = nullptr;
        }

        virtual RemoteList::Item::Ptr get() override
        {
            if (parent)
            {
                const std::string title = "remote-override";
                libopenvpn::RemoteOverride ro;
                try
                {
                    parent->remote_override(ro);
                }
                catch (const std::exception &e)
                {
                    ro.error = e.what();
                }
                RemoteList::Item::Ptr ri(new RemoteList::Item);
                if (ro.error.empty())
                {
                    if (!ro.ip.empty())
                        ri->set_ip_addr(IP::Addr(ro.ip, title));
                    if (ro.host.empty())
                        ro.host = ro.ip;
                    HostPort::validate_host(ro.host, title);
                    HostPort::validate_port(ro.port, title);
                    ri->server_host = std::move(ro.host);
                    ri->server_port = std::move(ro.port);
                    ri->transport_protocol = Protocol::parse(ro.proto, Protocol::CLIENT_SUFFIX, title.c_str());
                }
                else
                    throw Exception("remote override exception: " + ro.error);
                return ri;
            }
            else
                return RemoteList::Item::Ptr();
        }

    private:
        OpenVPNClientBase *parent = nullptr;
    };
} // namespace openvpn
#endif