#ifndef MY_SESSION_STATS_H
#define MY_SESSION_STATS_H
#include "OpenVPNClientBase.hpp"
#include <openvpn/log/sessionstats.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/count.hpp>
#include <openvpn/error/error.hpp>

namespace libopenvpn
{
    using namespace openvpn;
    class MySessionStats : public SessionStats
    {
    public:
        typedef RCPtr<MySessionStats> Ptr;

        MySessionStats(OpenVPNClientBase *parent_arg)
            : parent(parent_arg)
        {
            std::memset(errors, 0, sizeof(errors));
#ifdef OPENVPN_DEBUG_VERBOSE_ERRORS
            session_stats_set_verbose(true);
#endif
        }

        static size_t combined_n()
        {
            return N_STATS + Error::N_ERRORS;
        }

        static std::string combined_name(const size_t index)
        {
            if (index < N_STATS + Error::N_ERRORS)
            {
                if (index < N_STATS)
                    return stat_name(index);
                else
                    return Error::name(index - N_STATS);
            }
            else
                return "";
        }

        count_t combined_value(const size_t index) const
        {
            if (index < N_STATS + Error::N_ERRORS)
            {
                if (index < N_STATS)
                    return get_stat(index);
                else
                    return errors[index - N_STATS];
            }
            else
                return 0;
        }

        count_t stat_count(const size_t index) const
        {
            return get_stat_fast(index);
        }

        count_t error_count(const size_t index) const
        {
            return errors[index];
        }

        void detach_from_parent()
        {
            parent = nullptr;
        }

        virtual void error(const size_t err, const std::string *text = nullptr)
        {
            if (err < Error::N_ERRORS)
            {
#ifdef OPENVPN_DEBUG_VERBOSE_ERRORS
                if (text)
                    OPENVPN_LOG("ERROR: " << Error::name(err) << " : " << *text);
                else
                    OPENVPN_LOG("ERROR: " << Error::name(err));
#endif
                ++errors[err];
            }
        }

    private:
        OpenVPNClientBase *parent;
        count_t errors[Error::N_ERRORS];
    };
} // namespace openvpn
#endif //