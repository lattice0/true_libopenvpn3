#ifndef MY_CLOCK_TICK
#define MY_CLOCK_TICK
#include "OpenVPNClientBase.hpp"
#include <openvpn/client/clievent.hpp>
#include <openvpn/time/asiotimer.hpp>
namespace libopenvpn
{
    using namespace openvpn;

    class MyClockTick
    {
    public:
        MyClockTick(openvpn_io::io_context &io_context,
                    OpenVPNClientBase *parent_arg,
                    const unsigned int ms)
            : timer(io_context),
              parent(parent_arg),
              period(Time::Duration::milliseconds(ms))
        {
        }

        void cancel()
        {
            timer.cancel();
        }

        void detach_from_parent()
        {
            parent = nullptr;
        }

        void schedule()
        {
            timer.expires_after(period);
            timer.async_wait([this](const openvpn_io::error_code &error) {
                if (!parent || error)
                    return;
                try
                {
                    parent->clock_tick();
                }
                catch (...)
                {
                }
                schedule();
            });
        }

    private:
        AsioTimer timer;
        OpenVPNClientBase *parent;
        const Time::Duration period;
    };
} // namespace libopenvpn
#endif