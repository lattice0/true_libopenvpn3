#ifndef MY_RECONNECT_NOTIFY
#define MY_RECONNECT_NOTIFY
#include "OpenVPNClientBase.hpp"
#include <openvpn/transport/reconnect_notify.hpp>
namespace libopenvpn
{
    using namespace openvpn;

    class MyReconnectNotify : public ReconnectNotify
    {
    public:
        MyReconnectNotify() : parent(nullptr) {}

        void set_parent(OpenVPNClientBase *parent_arg)
        {
            parent = parent_arg;
        }

        void detach_from_parent()
        {
            parent = nullptr;
        }

        virtual bool pause_on_connection_timeout()
        {
            if (parent)
                return parent->pause_on_connection_timeout();
            else
                return false;
        }

    private:
        OpenVPNClientBase *parent;
    };
} // namespace libopenvpn
#endif