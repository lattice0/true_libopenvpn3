#ifndef OPENVPN_CLIENT_H
#define OPENVPN_CLIENT_H
#define OPENVPN_EXTERNAL_TUN_FACTORY
#ifdef OPENVPN_REMOTE_OVERRIDE
#include <openvpn/common/process.hpp>
#endif
#include <openvpn/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_MAC
#include <CoreFoundation/CFBundle.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

// If enabled, don't direct ovpn3 core logging to
// OpenVPNClient::log() virtual method.
// Instead, logging will go to LogBaseSimple::log().
// In this case, make sure to define:
//   LogBaseSimple log;
// at the top of your main() function to receive
// log messages from all threads.
// Also, note that the OPENVPN_LOG_GLOBAL setting
// MUST be consistent across all compilation units.
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN
#if defined(USE_MBEDTLS)
#include <openvpn/mbedtls/util/pkcs1.hpp>
#endif

#if defined(OPENVPN_PLATFORM_WIN)
#include <openvpn/win/console.hpp>
#include <shellapi.h>
#endif

#ifdef USE_NETCFG
#include "client/core-client-netcfg.hpp"
#endif

// use SITNL by default
#ifndef OPENVPN_USE_IPROUTE2
#define OPENVPN_USE_SITNL
#endif
//TODO: ????
#include "OpenVPNClientBase.hpp"
#define OPENVPN_CLIENT_EXPORT
#ifndef OPENVPN_LOG
// log thread settings
#define OPENVPN_LOG_CLASS libopenvpn::LogReceiver
#define OPENVPN_LOG_INFO libopenvpn::LogInfo
//TODO: verify this log thing
#include "openvpn/log/logthread.hpp" // should be included early
#endif

// log SSL handshake messages
#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

// on Android and iOS, use TunBuilderBase abstraction
#include <openvpn/common/platform.hpp>
#if (defined(OPENVPN_PLATFORM_ANDROID) || defined(OPENVPN_PLATFORM_IPHONE)) && !defined(OPENVPN_FORCE_TUN_NULL) && !defined(OPENVPN_EXTERNAL_TUN_FACTORY)
//TODO: inspect this
#define USE_TUN_BUILDER
#endif

#include <openvpn/init/initprocess.hpp>
#include <openvpn/common/bigmutex.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/platform_string.hpp>
#include <openvpn/common/count.hpp>
#include <openvpn/asio/asiostop.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/time/timestr.hpp>
#include <openvpn/client/cliconnect.hpp>
#include <openvpn/client/cliopthelper.hpp>
#include <openvpn/options/merge.hpp>
#include <openvpn/error/excode.hpp>
#include <openvpn/crypto/selftest.hpp>
#include "MyClientEvents.hpp"
#include "MyClockTick.hpp"
#include "MyRemoveOverride.hpp"
#include "MySessionStats.hpp"
#include "MySocketProtect.hpp"
#include "MyReconnectNotify.hpp"
#include "ClientState.hpp"
#include "VirtualTun.h"
#include "VirtualVPNAsioStream.h"
// copyright
#include <openvpn/legal/copyright.hpp>
#include <openvpn/tun/builder/base.hpp>
#include <openvpn/options/merge.hpp>

namespace libopenvpn
{
	using namespace openvpn;
	class OpenVPNClient : public OpenVPNClientBase
	{
		protected:
		std::function<void(std::string)> log_f;
		std::function<void(const Event&)> event_f;

	public:
		OpenVPNClient(std::shared_ptr<VAsioStream> vAsioStream, std::string replacementIpv4, std::string replacementIpv6) : 
		vAsioStream(vAsioStream), 
		replacementIpv4(replacementIpv4), 
		replacementIpv6(replacementIpv6)
		{
			//tun = new VirtualTunSetup::Setup(socketPair);
			//= std::make_shared<VirtualTunSetup::Setup::Ptr>(socketPair);
#ifndef OPENVPN_NORESET_TIME
			// We keep track of time as binary milliseconds since a time base, and
			// this can wrap after ~48 days on 32 bit systems, so it's a good idea
			// to periodically reinitialize the base.
			Time::reset_base_conditional();
#endif

			state = new Private::ClientState();
			state->proto_context_options.reset(new ProtoContextOptions());
		}
		
		void setLogFunction(std::function<void(std::string)> log_) {
			this->log_f = log_;
		}
		void setOnEvent(std::function<void(const Event)> onEvent_) {
			this->event_f = onEvent_;
		}

		enum ClockTickAction
		{
			CT_UNDEF,
			CT_STOP,
			CT_RECONNECT,
			CT_PAUSE,
			CT_RESUME,
			CT_STATS,
		};

		TunClientFactory *new_tun_factory(const ExternalTun::Config &conf, const OptionList &opt) override
		{
			//std::cout << "new_tun_factory called" << std::endl;
			return new VirtualTun::ClientConfig(conf, opt, this->vAsioStream, this->replacementIpv4, this->replacementIpv6);
		}

		bool is_dynamic_challenge() const
		{
			return !dc_cookie.empty();
		}

		std::string dynamic_challenge_cookie()
		{
			return dc_cookie;
		}

		std::string epki_ca;
		std::string epki_cert;
#if defined(USE_MBEDTLS)
		MbedTLSPKI::PKContext epki_ctx; // external PKI context
#endif

		void set_clock_tick_action(const ClockTickAction action)
		{
			clock_tick_action = action;
		}

		void print_stats()
		{
			const int n = stats_n();
			std::vector<long long> stats = stats_bundle();
			std::stringstream s;
			s << "STATS:" << std::endl;
			for (int i = 0; i < n; ++i)
			{
				const long long value = stats[i];
				if (value)
					s << "  " << stats_name(i) << " : " << value;
			}
			log_f(s.str());
		}

#ifdef OPENVPN_REMOTE_OVERRIDE
		void set_remote_override_cmd(const std::string &cmd)
		{
			remote_override_cmd = cmd;
		}
#endif

	public:
		std::shared_ptr<libopenvpn::VAsioStream> vAsioStream;
		std::string replacementIpv4;
		std::string replacementIpv6;
		virtual void event(const Event &ev) override
		{
			if (this->event_f) {
				event_f(ev);
			}
			std::stringstream s;
			s << date_time() << " EVENT: " << ev.name;
			if (!ev.info.empty())
				s << ' ' << ev.info;
			if (ev.fatal)
				s << " [FATAL-ERR]";
			else if (ev.error)
				s << " [ERR]";
			//s << std::endl;
			if (ev.name == "DYNAMIC_CHALLENGE")
			{
				dc_cookie = ev.info;

				DynamicChallenge dc;
				if (parse_dynamic_challenge(ev.info, dc))
				{
					s << std::endl;
					s << "DYNAMIC CHALLENGE" << std::endl;
					s << "challenge: " << dc.challenge << std::endl;
					s << "echo: " << dc.echo << std::endl;
					s << "responseRequired: " << dc.responseRequired << std::endl;
					s << "stateID: " << dc.stateID;
				}
			}
			else if (ev.name == "INFO" && (string::starts_with(ev.info, "OPEN_URL:http://") || string::starts_with(ev.info, "OPEN_URL:https://")))
			{
				// launch URL
				const std::string url_str = ev.info.substr(9);
#ifdef OPENVPN_PLATFORM_MAC
				std::thread thr([url_str]() {
					CFURLRef url = CFURLCreateWithBytes(
						NULL,					  // allocator
						(UInt8 *)url_str.c_str(), // URLBytes
						url_str.length(),		  // length
						kCFStringEncodingUTF8,	  // encoding
						NULL					  // baseURL
					);
					LSOpenCFURLRef(url, 0);
					CFRelease(url);
				});
				thr.detach();
#else
				s << "No implementation to launch " << url_str;
#endif
			}
			log_f(s.str());
		}

		virtual void log(const LogInfo &log) override
		{
			std::lock_guard<std::mutex> lock(log_mutex);
			std::stringstream s;
			s << date_time() << ' ' << log.text << std::flush;
			log_f(s.str());
		}

		virtual void clock_tick() override
		{
			const ClockTickAction action = clock_tick_action;
			clock_tick_action = CT_UNDEF;
			std::stringstream s;
			switch (action)
			{
			case CT_STOP:
				s << "signal: CT_STOP";
				log_f(s.str());
				stop();
				break;
			case CT_RECONNECT:
				s << "signal: CT_RECONNECT";
				log_f(s.str());
				reconnect(0);
				break;
			case CT_PAUSE:
				s << "signal: CT_PAUSE";
				log_f(s.str());
				pause("clock-tick pause");
				break;
			case CT_RESUME:
				s << "signal: CT_RESUME";
				log_f(s.str());
				resume();
				break;
			case CT_STATS:
				s << "signal: CT_STATS";
				log_f(s.str());
				print_stats();
				break;
			default:
				break;
			}
		}

		virtual void external_pki_cert_request(ExternalPKICertRequest &certreq) override
		{
			if (!epki_cert.empty())
			{
				certreq.cert = epki_cert;
				certreq.supportingChain = epki_ca;
			}
			else
			{
				certreq.error = true;
				certreq.errorText = "external_pki_cert_request not implemented";
			}
		}

		virtual void external_pki_sign_request(ExternalPKISignRequest &signreq) override
		{
#if defined(USE_MBEDTLS)
			if (epki_ctx.defined())
			{
				try
				{
					// decode base64 sign request
					BufferAllocated signdata(256, BufferAllocated::GROW);
					base64->decode(signdata, signreq.data);

					// get MD alg
					const mbedtls_md_type_t md_alg = PKCS1::DigestPrefix::MbedTLSParse().alg_from_prefix(signdata);

					// log info
					OPENVPN_LOG("SIGN[" << PKCS1::DigestPrefix::MbedTLSParse::to_string(md_alg) << ',' << signdata.size() << "]: " << render_hex_generic(signdata));

					// allocate buffer for signature
					BufferAllocated sig(mbedtls_pk_get_len(epki_ctx.get()), BufferAllocated::ARRAY);

					// sign it
					size_t sig_size = 0;
					const int status = mbedtls_pk_sign(epki_ctx.get(),
													   md_alg,
													   signdata.c_data(),
													   signdata.size(),
													   sig.data(),
													   &sig_size,
													   rng_callback,
													   this);
					if (status != 0)
						throw Exception("mbedtls_pk_sign failed, err=" + openvpn::to_string(status));
					if (sig.size() != sig_size)
						throw Exception("unexpected signature size");

					// encode base64 signature
					signreq.sig = base64->encode(sig);
					OPENVPN_LOG("SIGNATURE[" << sig_size << "]: " << signreq.sig);
				}
				catch (const std::exception &e)
				{
					signreq.error = true;
					signreq.errorText = std::string("external_pki_sign_request: ") + e.what();
				}
			}
			else
#endif
			{
				signreq.error = true;
				signreq.errorText = "external_pki_sign_request not implemented";
			}
		}

		/*
	//DO NOT DELETE! Used by MBED_TLS
	//TODO: make orwellOpenVPNClient trapped in here as a closure
	// RNG callback
	static int rng_callback(void *arg, unsigned char *data, size_t len)
	{
		Client *self = (Client *)arg;
		if (!self->rng)
		{
			self->rng.reset(new SSLLib::RandomAPI(false));
			self->rng->assert_crypto();
		}
		return self->rng->rand_bytes_noexcept(data, len) ? 0 : -1; // using -1 as a general-purpose mbed TLS error code
	}
	*/

		virtual bool pause_on_connection_timeout() override
		{
			return false;
		}

#ifdef OPENVPN_REMOTE_OVERRIDE
		virtual bool remote_override_enabled() override
		{
			return !remote_override_cmd.empty();
		}

		virtual void remote_override(RemoteOverride &ro)
		{
			RedirectPipe::InOut pio;
			Argv argv;
			argv.emplace_back(remote_override_cmd);
			OPENVPN_LOG(argv.to_string());
			const int status = system_cmd(remote_override_cmd,
										  argv,
										  nullptr,
										  pio,
										  RedirectPipe::IGNORE_ERR);
			if (!status)
			{
				const std::string out = string::first_line(pio.out);
				OPENVPN_LOG("REMOTE OVERRIDE: " << out);
				auto svec = string::split(out, ',');
				if (svec.size() == 4)
				{
					ro.host = svec[0];
					ro.ip = svec[1];
					ro.port = svec[2];
					ro.proto = svec[3];
				}
				else
					ro.error = "cannot parse remote-override, expecting host,ip,port,proto (at least one or both of host and ip must be defined)";
			}
			else
				ro.error = "status=" + std::to_string(status);
		}
#endif

		std::mutex log_mutex;
		std::string dc_cookie;
		RandomAPI::Ptr rng; // random data source for epki
		volatile ClockTickAction clock_tick_action = CT_UNDEF;

#ifdef OPENVPN_REMOTE_OVERRIDE
		std::string remote_override_cmd;
#endif

		bool tun_builder_new() override
		{
			tbc.tun_builder_set_mtu(1500);
			return true;
		}

		int tun_builder_establish() override
		{
			std::stringstream s;
			s << "tun builder establish called";
			log_f(s.str());
			return 0;
			/*
		if (!tun)
		{
			tun.reset(new VirtualTunSetup::Setup());
		}

		VirtualTunSetup::Setup::Config config;
		config.layer = Layer(Layer::Type::OSI_LAYER_3);
		// no need to add bypass routes on establish since we do it on socket_protect
		config.add_bypass_routes_on_establish = false;
		return tun->establish(tbc, &config, nullptr, std::cout);
		*/
		}

		bool tun_builder_add_address(const std::string &address,
									 int prefix_length,
									 const std::string &gateway, // optional
									 bool ipv6,
									 bool net30) override
		{
			return tbc.tun_builder_add_address(address, prefix_length, gateway, ipv6, net30);
		}

		bool tun_builder_add_route(const std::string &address,
								   int prefix_length,
								   int metric,
								   bool ipv6) override
		{
			return tbc.tun_builder_add_route(address, prefix_length, metric, ipv6);
		}

		bool tun_builder_reroute_gw(bool ipv4,
									bool ipv6,
									unsigned int flags) override
		{
			return tbc.tun_builder_reroute_gw(ipv4, ipv6, flags);
		}

		bool tun_builder_set_remote_address(const std::string &address,
											bool ipv6) override
		{
			return tbc.tun_builder_set_remote_address(address, ipv6);
		}

		bool tun_builder_set_session_name(const std::string &name) override
		{
			return tbc.tun_builder_set_session_name(name);
		}

		bool tun_builder_add_dns_server(const std::string &address, bool ipv6) override
		{
			return tbc.tun_builder_add_dns_server(address, ipv6);
		}

		void tun_builder_teardown(bool disconnect) override
		{
			/*
		std::ostringstream os;
		auto os_print = Cleanup([&os]() { OPENVPN_LOG_STRING(os.str()); });
		tun->destroy(os);
		*/
		}

		/*
			Looks like this is just a way to init only one time
			these libraries:
			Time::reset_base();
			CompressContext::init_static();
			init_openssl("auto");
			base64_init_static();

			It only inits them one time
		*/
		static OPENVPN_CLIENT_EXPORT void init_process()
		{
			InitProcess::Init();
		}

		static OPENVPN_CLIENT_EXPORT void uninit_process()
		{
			//TODO: WHAT GOES HERE?
			//InitProcess::Uninit();
		}

		OPENVPN_CLIENT_EXPORT OpenVPNClient()
		{
			std::stringstream s;
			s << "OpenVPNClient constructor CALLED";
			log_f(s.str());
#ifndef OPENVPN_NORESET_TIME
			// We keep track of time as binary milliseconds since a time base, and
			// this can wrap after ~48 days on 32 bit systems, so it's a good idea
			// to periodically reinitialize the base.
			Time::reset_base_conditional();
#endif

			state = new Private::ClientState();
			state->proto_context_options.reset(new ProtoContextOptions());
		}

		static OPENVPN_CLIENT_EXPORT void parse_config(const Config &config, EvalConfig &eval, openvpn::OptionList &options)
		{
			try
			{
				// validate proto_override
				if (!config.protoOverride.empty())
					Protocol::parse(config.protoOverride, Protocol::NO_SUFFIX);

				// validate IPv6 setting
				//if (!config.ipv6.empty())
				//	IPv6Setting::parse(config.ipv6);

				// parse config
				OptionList::KeyValueList kvl;
				kvl.reserve(config.contentList.size());
				for (size_t i = 0; i < config.contentList.size(); ++i)
				{
					const KeyValue &kv = config.contentList[i];
					kvl.push_back(new OptionList::KeyValue(kv.key, kv.value));
				}
				const ParseClientConfig cc = ParseClientConfig::parse(config.content, &kvl, options);
#ifdef OPENVPN_DUMP_CONFIG
				std::stringstream s;
				s << "---------- ARGS ----------" << std::endl;
				s << options.render(Option::RENDER_PASS_FMT | Option::RENDER_NUMBER | Option::RENDER_BRACKET) << std::endl;
				s << "---------- MAP ----------" << std::endl;
				s << options.render_map();
				log_f(s.str());
#endif
				eval.error = cc.error();
				eval.message = cc.message();
				eval.userlockedUsername = cc.userlockedUsername();
				eval.profileName = cc.profileName();
				eval.friendlyName = cc.friendlyName();
				eval.autologin = cc.autologin();
				eval.externalPki = cc.externalPki();
				eval.staticChallenge = cc.staticChallenge();
				eval.staticChallengeEcho = cc.staticChallengeEcho();
				eval.privateKeyPasswordRequired = cc.privateKeyPasswordRequired();
				eval.allowPasswordSave = cc.allowPasswordSave();
				eval.remoteHost = config.serverOverride.empty() ? cc.firstRemoteListItem().host : config.serverOverride;
				eval.remotePort = cc.firstRemoteListItem().port;
				eval.remoteProto = cc.firstRemoteListItem().proto;
				for (ParseClientConfig::ServerList::const_iterator i = cc.serverList().begin(); i != cc.serverList().end(); ++i)
				{
					ServerEntry se;
					se.server = i->server;
					se.friendlyName = i->friendlyName;
					eval.serverList.push_back(se);
				}
			}
			catch (const std::exception &e)
			{
				eval.error = true;
				eval.message = Unicode::utf8_printable<std::string>(std::string("ERR_PROFILE_GENERIC: ") + e.what(), 256);
			}
		}

		OPENVPN_CLIENT_EXPORT void parse_extras(const Config &config, EvalConfig &eval)
		{
			try
			{
				state->server_override = config.serverOverride;
				state->port_override = config.portOverride;
				state->conn_timeout = config.connTimeout;
				state->tun_persist = config.tunPersist;
				state->wintun = config.wintun;
				state->google_dns_fallback = config.googleDnsFallback;
				state->synchronous_dns_lookup = config.synchronousDnsLookup;
				state->autologin_sessions = config.autologinSessions;
				state->retry_on_auth_failed = config.retryOnAuthFailed;
				state->private_key_password = config.privateKeyPassword;
				if (!config.protoOverride.empty())
					state->proto_override = Protocol::parse(config.protoOverride, Protocol::NO_SUFFIX);
				//if (!config.ipv6.empty())
				//	state->ipv6 = IPv6Setting::parse(config.ipv6);
				if (!config.compressionMode.empty())
					state->proto_context_options->parse_compression_mode(config.compressionMode);
				if (eval.externalPki)
					state->external_pki_alias = config.externalPkiAlias;
				state->disable_client_cert = config.disableClientCert;
				state->ssl_debug_level = config.sslDebugLevel;
				state->default_key_direction = config.defaultKeyDirection;
				state->force_aes_cbc_ciphersuites = config.forceAesCbcCiphersuites;
				state->tls_version_min_override = config.tlsVersionMinOverride;
				state->tls_cert_profile_override = config.tlsCertProfileOverride;
				state->allow_local_lan_access = config.allowLocalLanAccess;
				state->gui_version = config.guiVersion;
				state->sso_methods = config.ssoMethods;
				state->platform_version = config.platformVersion;
				state->hw_addr_override = config.hwAddrOverride;
				state->alt_proxy = config.altProxy;
				state->dco = config.dco;
				state->echo = config.echo;
				state->info = config.info;
				state->clock_tick_ms = config.clockTickMS;
				if (!config.gremlinConfig.empty())
				{
#ifdef OPENVPN_GREMLIN
					state->gremlin_config.reset(new Gremlin::Config(config.gremlinConfig));
#else
					log_f("client not built with OPENVPN_GREMLIN");
					throw Exception("client not built with OPENVPN_GREMLIN");
#endif
				}
				state->extra_peer_info = PeerInfo::Set::new_from_foreign_set(config.peerInfo);
				if (!config.proxyHost.empty())
				{
					HTTPProxyTransport::Options::Ptr ho(new HTTPProxyTransport::Options());
					ho->set_proxy_server(config.proxyHost, config.proxyPort);
					ho->username = config.proxyUsername;
					ho->password = config.proxyPassword;
					ho->allow_cleartext_auth = config.proxyAllowCleartextAuth;
					state->http_proxy_options = ho;
				}
			}
			catch (const std::exception &e)
			{
				eval.error = true;
				eval.message = Unicode::utf8_printable<std::string>(e.what(), 256);
			}
		}

		OPENVPN_CLIENT_EXPORT long max_profile_size()
		{
			return ProfileParseLimits::MAX_PROFILE_SIZE;
		}

		OPENVPN_CLIENT_EXPORT MergeConfig merge_config_static(const std::string &path,
															  bool follow_references)
		{
			ProfileMerge pm(path, "ovpn", "", follow_references ? ProfileMerge::FOLLOW_PARTIAL : ProfileMerge::FOLLOW_NONE,
							ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
			return build_merge_config(pm);
		}

		OPENVPN_CLIENT_EXPORT MergeConfig merge_config_string_static(const std::string &config_content)
		{
			ProfileMergeFromString pm(config_content, "", ProfileMerge::FOLLOW_NONE,
									  ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
			return build_merge_config(pm);
		}

		OPENVPN_CLIENT_EXPORT MergeConfig build_merge_config(const ProfileMerge &pm)
		{
			MergeConfig ret;
			ret.status = pm.status_string();
			ret.basename = pm.basename();
			if (pm.status() == ProfileMerge::MERGE_SUCCESS)
			{
				ret.refPathList = pm.ref_path_list();
				ret.profileContent = pm.profile_content();
			}
			else
			{
				ret.errorText = pm.error();
			}
			return ret;
		}

		static OPENVPN_CLIENT_EXPORT EvalConfig eval_config_static(const Config &config)
		{
			EvalConfig eval;
			OptionList options;
			parse_config(config, eval, options);
			return eval;
		}

		// API client submits the configuration here before calling connect()
		OPENVPN_CLIENT_EXPORT EvalConfig eval_config(const Config &config)
		{
			// parse and validate configuration file
			EvalConfig eval;
			parse_config(config, eval, state->options);
			if (eval.error)
				return eval;

			// handle extra settings in config
			parse_extras(config, eval);
			state->eval = eval;
			return eval;
		}

		OPENVPN_CLIENT_EXPORT Status provide_creds(const ProvideCreds &creds)
		{
			Status ret;
			try
			{
				ClientCreds::Ptr cc = new ClientCreds();
				cc->set_username(creds.username);
				cc->set_password(creds.password);
				cc->set_response(creds.response);
				cc->set_dynamic_challenge_cookie(creds.dynamicChallengeCookie, creds.username);
				cc->set_replace_password_with_session_id(creds.replacePasswordWithSessionID);
				cc->enable_password_cache(creds.cachePassword);
				state->creds = cc;
			}
			catch (const std::exception &e)
			{
				ret.error = true;
				ret.message = Unicode::utf8_printable<std::string>(e.what(), 256);
			}
			return ret;
		}

		OPENVPN_CLIENT_EXPORT bool socket_protect(int socket, std::string remote, bool ipv6) override
		{
			return true;
		}

		OPENVPN_CLIENT_EXPORT bool parse_dynamic_challenge(const std::string &cookie, DynamicChallenge &dc)
		{
			try
			{
				ChallengeResponse cr(cookie);
				dc.challenge = cr.get_challenge_text();
				dc.echo = cr.get_echo();
				dc.responseRequired = cr.get_response_required();
				dc.stateID = cr.get_state_id();
				return true;
			}
			catch (const std::exception &)
			{
				return false;
			}
		}

		OPENVPN_CLIENT_EXPORT void process_epki_cert_chain(const ExternalPKICertRequest &req)
		{
			// Get cert and add to options list
			if (!req.cert.empty())
			{
				Option o;
				o.push_back("cert");
				o.push_back(req.cert);
				state->options.add_item(o);
			}

			// Get the supporting chain, if it exists, and use
			// it for ca (if ca isn't defined), or otherwise use
			// it for extra-certs (if ca is defined but extra-certs
			// is not).
			if (!req.supportingChain.empty())
			{
				if (!state->options.exists("ca"))
				{
					Option o;
					o.push_back("ca");
					o.push_back(req.supportingChain);
					state->options.add_item(o);
				}
				else if (!state->options.exists("extra-certs"))
				{
					Option o;
					o.push_back("extra-certs");
					o.push_back(req.supportingChain);
					state->options.add_item(o);
				}
			}
		}

		OPENVPN_CLIENT_EXPORT Status connect()
		{
#if !defined(OPENVPN_OVPNCLI_SINGLE_THREAD)
			openvpn_io::detail::signal_blocker signal_blocker; // signals should be handled by parent thread
#endif
#if defined(OPENVPN_LOG_LOGTHREAD_H) && !defined(OPENVPN_LOG_LOGBASE_H)
#ifdef OPENVPN_LOG_GLOBAL
#error ovpn3 core logging object only supports thread-local scope
#endif
			Log::Context log_context(this);
#endif

			OPENVPN_LOG(platform());

			return do_connect();
		}

		OPENVPN_CLIENT_EXPORT Status do_connect()
		{
			Status status;
			bool session_started = false;
			try
			{
				connect_attach();
#if defined(OPENVPN_OVPNCLI_ASYNC_SETUP)
				openvpn_io::post(*state->io_context(), [this]() {
					do_connect_async();
				});
#else
				connect_setup(status, session_started);
#endif
				connect_run();
				std::stringstream s;
				s << "OpenVPN connection probably ENDED safely";
				log_f(s.str());
				return status;
			}
			catch (const std::exception &e)
			{
				if (session_started)
					connect_session_stop();
				return status_from_exception(e);
			}
		}

		OPENVPN_CLIENT_EXPORT void do_connect_async()
		{
			enum StopType
			{
				NONE,
				SESSION,
				EXPLICIT,
			};
			StopType stop_type = NONE;
			Status status;
			bool session_started = false;
			try
			{
				connect_setup(status, session_started);
			}
			catch (const std::exception &e)
			{
				stop_type = session_started ? SESSION : EXPLICIT;
				status = status_from_exception(e);
			}
			if (status.error)
			{
				ClientEvent::Base::Ptr ev = new ClientEvent::ClientSetup(status.status, status.message);
				state->events->add_event(std::move(ev));
			}
			if (stop_type == SESSION)
				connect_session_stop();
#ifdef OPENVPN_IO_REQUIRES_STOP
			if (stop_type == EXPLICIT)
				state->io_context()->stop();
#endif
		}

		OPENVPN_CLIENT_EXPORT void connect_setup(Status &status, bool &session_started)
		{
			//std::cout << "connect_setup!" << std::endl;
			// set global MbedTLS debug level
#if defined(USE_MBEDTLS) || defined(USE_MBEDTLS_APPLE_HYBRID)
			mbedtls_debug_set_threshold(state->ssl_debug_level); // fixme -- using a global method for this seems wrong
#endif

			// load options
			ClientOptions::Config cc;
			cc.cli_stats = state->stats;
			cc.cli_events = state->events;
			cc.server_override = state->server_override;
			cc.port_override = state->port_override;
			cc.proto_override = state->proto_override;
			//cc.ipv6 = state->ipv6;
			cc.conn_timeout = state->conn_timeout;
			cc.tun_persist = state->tun_persist;
			//cc.wintun = state->wintun;
			cc.google_dns_fallback = state->google_dns_fallback;
			cc.synchronous_dns_lookup = state->synchronous_dns_lookup;
			cc.autologin_sessions = state->autologin_sessions;
			cc.retry_on_auth_failed = state->retry_on_auth_failed;
			cc.proto_context_options = state->proto_context_options;
			cc.http_proxy_options = state->http_proxy_options;
			cc.alt_proxy = state->alt_proxy;
			cc.dco = state->dco;
			cc.echo = state->echo;
			cc.info = state->info;
			cc.reconnect_notify = &state->reconnect_notify;
			if (remote_override_enabled())
				cc.remote_override = &state->remote_override;
			cc.private_key_password = state->private_key_password;
			cc.disable_client_cert = state->disable_client_cert;
			cc.ssl_debug_level = state->ssl_debug_level;
			cc.default_key_direction = state->default_key_direction;
			//TODO:???
			//cc.force_aes_cbc_ciphersuites = state->force_aes_cbc_ciphersuites;
			cc.tls_version_min_override = state->tls_version_min_override;
			cc.tls_cert_profile_override = state->tls_cert_profile_override;
			cc.gui_version = state->gui_version;
			//cc.sso_methods = state->sso_methods;
			//cc.hw_addr_override = state->hw_addr_override;
			//cc.platform_version = state->platform_version;
			cc.extra_peer_info = state->extra_peer_info;
			cc.stop = state->async_stop_local();
			cc.allow_local_lan_access = state->allow_local_lan_access;
#ifdef OPENVPN_GREMLIN
			cc.gremlin_config = state->gremlin_config;
#endif
			cc.socket_protect = &state->socket_protect;
#if defined(USE_TUN_BUILDER)
			cc.builder = this;
#endif
#if defined(OPENVPN_EXTERNAL_TUN_FACTORY)
			cc.extern_tun_factory = this;
#endif
#if defined(OPENVPN_EXTERNAL_TRANSPORT_FACTORY)
			cc.extern_transport_factory = this;
#endif
			// force Session ID use and disable password cache if static challenge is enabled
			if (state->creds && !state->creds->get_replace_password_with_session_id() && !state->eval.autologin && !state->eval.staticChallenge.empty())
			{
				state->creds->set_replace_password_with_session_id(true);
				state->creds->enable_password_cache(false);
			}
			//std::cout << "gonna check state->eval.externalPki" << std::endl;
			//std::cout << "state->eval.externalPki: " << state->eval.externalPki << std::endl;
			//std::cout << "!state->disable_client_cert" << !state->disable_client_cert << std::endl;
			// external PKI
#if !defined(USE_APPLE_SSL)
			if (state->eval.externalPki && !state->disable_client_cert)
			{
				std::stringstream s;
				s << "external_pki_alias?" << std::endl;

				if (!state->external_pki_alias.empty())
				{
					s << "external_pki_alias NOT empty";
					ExternalPKICertRequest req;
					req.alias = state->external_pki_alias;
					external_pki_cert_request(req);
					if (!req.error)
					{
						cc.external_pki = this;
						s<< std::endl;
						s << "gonna process_epki_cert_chain";
						process_epki_cert_chain(req);
					}
					else
					{
						s<< std::endl;
						s << "external_pki_error";
						external_pki_error(req, Error::EPKI_CERT_ERROR);
						log_f(s.str());
						return;
					}
					log_f(s.str());
				}
				else
				{
					status.error = true;
					status.message = "Missing External PKI alias";
					log_f(s.str());
					return;
				}
			}
#endif

#ifdef USE_OPENSSL
			if (state->options.exists("allow-name-constraints"))
			{
				ClientEvent::Base::Ptr ev = new ClientEvent::UnsupportedFeature("allow-name-constraints",
																				"Always verified correctly with OpenSSL", false);
				state->events->add_event(std::move(ev));
			}
#endif

			for (std::vector<Option>::iterator it = state->options.begin(); it != state->options.end(); ++it)
			{
				//std::cout << "option" << std::endl;
				//it->doSomething();
			}
			//std::cout << state->options << std::endl;
			// build client options object
			ClientOptions::Ptr client_options = new ClientOptions(state->options, cc);
			// configure creds in options
			client_options->submit_creds(state->creds);
			// instantiate top-level client session
			state->session.reset(new ClientConnect(*state->io_context(), client_options));
			// convenience clock tick
			if (state->clock_tick_ms)
			{
				state->clock_tick.reset(new MyClockTick(*state->io_context(), this, state->clock_tick_ms));
				state->clock_tick->schedule();
			}
			// raise an exception if app has expired
			check_app_expired();
			// start VPN
			state->session->start(); // queue reads on socket/tun
			session_started = true;

			// wire up async stop
			state->setup_async_stop_scopes();

			// prepare to start reactor
			connect_pre_run();
			state->enable_foreign_thread_access();
		}

		OPENVPN_CLIENT_EXPORT Status status_from_exception(const std::exception &e)
		{
			Status ret;
			ret.error = true;
			ret.message = Unicode::utf8_printable<std::string>(e.what(), 256);

			// if exception is an ExceptionCode, translate the code
			// to return status string
			{
				const ExceptionCode *ec = dynamic_cast<const ExceptionCode *>(&e);
				if (ec && ec->code_defined())
					ret.status = Error::name(ec->code());
			}
			return ret;
		}

		OPENVPN_CLIENT_EXPORT void connect_attach() override
		{
			state->attach<MySessionStats, MyClientEvents>(this,
														  nullptr,
														  get_async_stop());
		}

		OPENVPN_CLIENT_EXPORT void connect_pre_run() override
		{
		}

		OPENVPN_CLIENT_EXPORT void connect_run() override
		{
			state->io_context()->run();
		}

		OPENVPN_CLIENT_EXPORT void connect_session_stop() override
		{
			state->session->stop();		 // On exception, stop client...
			state->io_context()->poll(); //   and execute completion handlers.
		}

		OPENVPN_CLIENT_EXPORT ConnectionInfo connection_info()
		{
			ConnectionInfo ci;
			if (state->is_foreign_thread_access())
			{
				MyClientEvents *events = state->events.get();
				if (events)
					events->get_connection_info(ci);
			}
			return ci;
		}

		OPENVPN_CLIENT_EXPORT bool session_token(SessionToken &tok)
		{
			if (state->is_foreign_thread_access())
			{
				ClientCreds *cc = state->creds.get();
				if (cc && cc->session_id_defined())
				{
					tok.username = cc->get_username();
					tok.session_id = cc->get_password();
					return true;
				}
			}
			return false;
		}

		OPENVPN_CLIENT_EXPORT Stop *get_async_stop() override
		{
			return nullptr;
		}

		OPENVPN_CLIENT_EXPORT void external_pki_error(const ExternalPKIRequestBase &req, const size_t err_type)
		{
			if (req.error)
			{
				if (req.invalidAlias)
				{
					ClientEvent::Base::Ptr ev = new ClientEvent::EpkiInvalidAlias(req.alias);
					state->events->add_event(std::move(ev));
				}

				ClientEvent::Base::Ptr ev = new ClientEvent::EpkiError(req.errorText);
				state->events->add_event(std::move(ev));

				state->stats->error(err_type);
				if (state->session)
					state->session->dont_restart();
			}
		}

		OPENVPN_CLIENT_EXPORT bool sign(const std::string &data, std::string &sig, const std::string &algorithm) override
		{
			ExternalPKISignRequest req;
			req.data = data;
			req.alias = state->external_pki_alias;
			req.algorithm = algorithm;
			external_pki_sign_request(req); // call out to derived class for RSA signature
			if (!req.error)
			{
				sig = req.sig;
				return true;
			}
			else
			{
				external_pki_error(req, Error::EPKI_SIGN_ERROR);
				return false;
			}
		}

		OPENVPN_CLIENT_EXPORT bool remote_override_enabled() override
		{
			return false;
		}

		OPENVPN_CLIENT_EXPORT void remote_override(RemoteOverride &) override
		{
		}

		OPENVPN_CLIENT_EXPORT int stats_n()
		{
			return (int)MySessionStats::combined_n();
		}

		OPENVPN_CLIENT_EXPORT std::string stats_name(int index)
		{
			return MySessionStats::combined_name(index);
		}

		OPENVPN_CLIENT_EXPORT long long stats_value(int index) const
		{
			if (state->is_foreign_thread_access())
			{
				MySessionStats *stats = state->stats.get();
				if (stats)
				{
					if (index == SessionStats::BYTES_IN || index == SessionStats::BYTES_OUT)
						stats->dco_update();
					return stats->combined_value(index);
				}
			}
			return 0;
		}

		OPENVPN_CLIENT_EXPORT std::vector<long long> stats_bundle() const
		{
			std::vector<long long> sv;
			const size_t n = MySessionStats::combined_n();
			sv.reserve(n);
			if (state->is_foreign_thread_access())
			{
				MySessionStats *stats = state->stats.get();
				if (stats)
					stats->dco_update();
				for (size_t i = 0; i < n; ++i)
					sv.push_back(stats ? stats->combined_value(i) : 0);
			}
			else
			{
				for (size_t i = 0; i < n; ++i)
					sv.push_back(0);
			}
			return sv;
		}

		OPENVPN_CLIENT_EXPORT InterfaceStats tun_stats() const
		{
			InterfaceStats ret;
			if (state->is_foreign_thread_access())
			{
				MySessionStats *stats = state->stats.get();

				// The reason for the apparent inversion between in/out below is
				// that TUN_*_OUT stats refer to data written to tun device,
				// but from the perspective of tun interface, this is incoming
				// data.  Vice versa for TUN_*_IN.
				if (stats)
				{
					ret.bytesOut = stats->stat_count(SessionStats::TUN_BYTES_IN);
					ret.bytesIn = stats->stat_count(SessionStats::TUN_BYTES_OUT);
					ret.packetsOut = stats->stat_count(SessionStats::TUN_PACKETS_IN);
					ret.packetsIn = stats->stat_count(SessionStats::TUN_PACKETS_OUT);
					ret.errorsOut = stats->error_count(Error::TUN_READ_ERROR);
					ret.errorsIn = stats->error_count(Error::TUN_WRITE_ERROR);
					return ret;
				}
			}

			ret.bytesOut = 0;
			ret.bytesIn = 0;
			ret.packetsOut = 0;
			ret.packetsIn = 0;
			ret.errorsOut = 0;
			ret.errorsIn = 0;
			return ret;
		}

		OPENVPN_CLIENT_EXPORT TransportStats transport_stats() const
		{
			TransportStats ret;
			ret.lastPacketReceived = -1; // undefined

			if (state->is_foreign_thread_access())
			{
				MySessionStats *stats = state->stats.get();
				if (stats)
				{
					stats->dco_update();
					ret.bytesOut = stats->stat_count(SessionStats::BYTES_OUT);
					ret.bytesIn = stats->stat_count(SessionStats::BYTES_IN);
					ret.packetsOut = stats->stat_count(SessionStats::PACKETS_OUT);
					ret.packetsIn = stats->stat_count(SessionStats::PACKETS_IN);

					// calculate time since last packet received
					{
						const Time &lpr = stats->last_packet_received();
						if (lpr.defined())
						{
							const Time::Duration dur = Time::now() - lpr;
							const unsigned int delta = (unsigned int)dur.to_binary_ms();
							if (delta <= 60 * 60 * 24 * 1024) // only define for time periods <= 1 day
								ret.lastPacketReceived = delta;
						}
					}
					return ret;
				}
			}

			ret.bytesOut = 0;
			ret.bytesIn = 0;
			ret.packetsOut = 0;
			ret.packetsIn = 0;
			return ret;
		}

		OPENVPN_CLIENT_EXPORT void stop()
		{
			if (state->is_foreign_thread_access())
				state->trigger_async_stop_local();
		}

		OPENVPN_CLIENT_EXPORT void pause(const std::string &reason)
		{
			if (state->is_foreign_thread_access())
			{
				ClientConnect *session = state->session.get();
				if (session)
					session->thread_safe_pause(reason);
			}
		}

		OPENVPN_CLIENT_EXPORT void resume()
		{
			if (state->is_foreign_thread_access())
			{
				ClientConnect *session = state->session.get();
				if (session)
					session->thread_safe_resume();
			}
		}

		OPENVPN_CLIENT_EXPORT void reconnect(int seconds)
		{
			if (state->is_foreign_thread_access())
			{
				ClientConnect *session = state->session.get();
				if (session)
					session->thread_safe_reconnect(seconds);
			}
		}

		OPENVPN_CLIENT_EXPORT void post_cc_msg(const std::string &msg)
		{
			if (state->is_foreign_thread_access())
			{
				ClientConnect *session = state->session.get();
				if (session)
					session->thread_safe_post_cc_msg(msg);
			}
		}

		OPENVPN_CLIENT_EXPORT void on_disconnect() override
		{
			state->on_disconnect();
		}

		OPENVPN_CLIENT_EXPORT std::string crypto_self_test()
		{
			return SelfTest::crypto_self_test();
		}

		OPENVPN_CLIENT_EXPORT int app_expire()
		{
#ifdef APP_EXPIRE_TIME
			return APP_EXPIRE_TIME;
#else
			return 0;
#endif
		}

		OPENVPN_CLIENT_EXPORT void check_app_expired()
		{
#ifdef APP_EXPIRE_TIME
			if (Time::now().seconds_since_epoch() >= APP_EXPIRE_TIME)
				throw app_expired();
#endif
		}

		OPENVPN_CLIENT_EXPORT std::string copyright()
		{
			return openvpn_copyright;
		}

		OPENVPN_CLIENT_EXPORT std::string platform()
		{
			std::string ret = platform_string();
#ifdef PRIVATE_TUNNEL_PROXY
			ret += " PT_PROXY";
#endif
#ifdef ENABLE_DCO
			ret += " DCO";
#endif
#ifdef OPENVPN_GREMLIN
			ret += " GREMLIN";
#endif
#ifdef OPENVPN_DEBUG
			ret += " built on " __DATE__ " " __TIME__;
#endif
			return ret;
		}

		OPENVPN_CLIENT_EXPORT ~OpenVPNClient()
		{
			delete state;
		}

	protected:
		//VirtualTunSetup::Setup::Ptr tun; // = new VirtualTunSetup::Setup();
		TunBuilderCapture tbc;
	};
} // namespace libopenvpn
#endif