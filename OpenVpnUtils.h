#ifndef OPENVPN_UTILS_H
#define OPENVPN_UTILS_H
//#include "OpenVPNClient.hpp"
#ifdef OPENVPN_USE_LOG_BASE_SIMPLE
#define OPENVPN_LOG_GLOBAL // use global rather than thread-local log object pointer
#include <openvpn/log/logbasesimple.hpp>
#endif
//#include <openvpn/common/getpw.hpp>

//#include <openvpn/common/getpw.hpp>
//#include <string>
//#include "VirtualVPNAsioStream.h"
//#include <memory>
using namespace openvpn;
using namespace libopenvpn;

std::string read_profile(std::string fn)
{

	ProfileMerge pm(fn.c_str(), "ovpn", "", ProfileMerge::FOLLOW_FULL,
					ProfileParseLimits::MAX_LINE_SIZE, ProfileParseLimits::MAX_PROFILE_SIZE);
	if (pm.status() != ProfileMerge::MERGE_SUCCESS)
		OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());
	return pm.profile_content();
}

std::unique_ptr<OpenVPNClient> build_openvpn_client_from_profile_string(std::string profile,
																		std::string username_,
																		std::string password_,
																		std::shared_ptr<libopenvpn::VAsioStream> vAsioStream,
																		std::string replacementIpv4,
																		std::string replacementIpv6)
{
	std::string username = username_;
	std::string password = password_;
	std::string response;
	std::string dynamicChallengeCookie;
	std::string proto;
	std::string ipv6;
	std::string server;
	std::string port;
	int timeout = 0;
	std::string compress;
	std::string privateKeyPassword;
	std::string tlsVersionMinOverride;
	std::string tlsCertProfileOverride;
	std::string proxyHost;
	std::string proxyPort;
	std::string proxyUsername;
	std::string proxyPassword;
	std::string peer_info;
	std::string gremlin;
	bool eval = false;
	bool self_test = false;
	bool cachePassword = false;
	bool disableClientCert = false;
	bool proxyAllowCleartextAuth = false;
	int defaultKeyDirection = -1;
	bool forceAesCbcCiphersuites = false;
	int sslDebugLevel = 0;
	bool googleDnsFallback = false;
	bool autologinSessions = false;
	bool retryOnAuthFailed = false;
	bool tunPersist = false;
	bool wintun = false;
	bool merge = false;
	bool version = false;
	bool altProxy = false;
	bool dco = false;
	std::string epki_cert_fn;
	std::string epki_ca_fn;
	std::string epki_key_fn;
#ifdef OPENVPN_REMOTE_OVERRIDE
	std::string remote_override_cmd;
#endif

	int ch;	

	Config config;
	config.guiVersion = "cli 1.0";
#if defined(OPENVPN_PLATFORM_WIN)
	int nargs = 0;
	auto argvw = CommandLineToArgvW(GetCommandLineW(), &nargs);
	UTF8 utf8(Win::utf8(argvw[nargs - 1]));
	//config.content = read_profile(ovpnPath);
	config.content = profile;
#else
	//config.content = read_profile(ovpnPath);
	config.content = profile;
	//std::cout << "profile: " << config.content <<std::endl;
#endif
	/*
	for (int i = 1; i < 2; ++i)
    {
      config.content += "ORWELL_ZAINCO.ovpn";
      config.content += '\n';
    }
	*/
	config.serverOverride = server;
	config.portOverride = port;
	config.protoOverride = proto;
	config.connTimeout = timeout;
	config.compressionMode = compress;
	config.ipv6 = ipv6;
	config.privateKeyPassword = privateKeyPassword;
	config.tlsVersionMinOverride = tlsVersionMinOverride;
	config.tlsCertProfileOverride = tlsCertProfileOverride;
	config.disableClientCert = disableClientCert;
	config.proxyHost = proxyHost;
	config.proxyPort = proxyPort;
	config.proxyUsername = proxyUsername;
	config.proxyPassword = proxyPassword;
	config.proxyAllowCleartextAuth = proxyAllowCleartextAuth;
	config.altProxy = altProxy;
	config.dco = dco;
	config.defaultKeyDirection = defaultKeyDirection;
	config.forceAesCbcCiphersuites = forceAesCbcCiphersuites;
	config.sslDebugLevel = sslDebugLevel;
	config.googleDnsFallback = googleDnsFallback;
	config.autologinSessions = autologinSessions;
	config.retryOnAuthFailed = retryOnAuthFailed;
	config.tunPersist = tunPersist;
	config.gremlinConfig = gremlin;
	config.info = true;
	config.wintun = wintun;
	config.ssoMethods = "openurl";
#if defined(OPENVPN_OVPNCLI_SINGLE_THREAD)
	config.clockTickMS = 250;
#endif

	if (!epki_cert_fn.empty())
		config.externalPkiAlias = "epki"; // dummy string

	PeerInfo::Set::parse_csv(peer_info, config.peerInfo);

	// allow -s server override to reference a friendly name
	// in the config.
	//   setenv SERVER <HOST>/<FRIENDLY_NAME>
	if (!config.serverOverride.empty())
	{
		const EvalConfig eval = OpenVPNClient::eval_config_static(config);
		for (auto &se : eval.serverList)
		{
			if (config.serverOverride == se.friendlyName)
			{
				config.serverOverride = se.server;
				break;
			}
		}
	}
	/*
	if (eval)
	{
		const EvalConfig eval = OpenVPNClient::eval_config_static(config);
		std::cout << "EVAL PROFILE" << std::endl;
		std::cout << "error=" << eval.error << std::endl;
		std::cout << "message=" << eval.message << std::endl;
		std::cout << "userlockedUsername=" << eval.userlockedUsername << std::endl;
		std::cout << "profileName=" << eval.profileName << std::endl;
		std::cout << "friendlyName=" << eval.friendlyName << std::endl;
		std::cout << "autologin=" << eval.autologin << std::endl;
		std::cout << "externalPki=" << eval.externalPki << std::endl;
		std::cout << "staticChallenge=" << eval.staticChallenge << std::endl;
		std::cout << "staticChallengeEcho=" << eval.staticChallengeEcho << std::endl;
		std::cout << "privateKeyPasswordRequired=" << eval.privateKeyPasswordRequired << std::endl;
		std::cout << "allowPasswordSave=" << eval.allowPasswordSave << std::endl;

		if (!config.serverOverride.empty())
			std::cout << "server=" << config.serverOverride << std::endl;

		for (size_t i = 0; i < eval.serverList.size(); ++i)
		{
			const ServerEntry &se = eval.serverList[i];
			std::cout << '[' << i << "] " << se.server << '/' << se.friendlyName << std::endl;
		}

		//TODO: return something here
	}
	*/
	//else
	{
#if defined(USE_NETCFG)
		DBus conn(G_BUS_TYPE_SYSTEM);
		conn.Connect();
		NetCfgTunBuilder<Client> orwellOpenVPNClient(conn.GetConnection());
#else
		auto orwellOpenVPNClient = std::make_unique<OpenVPNClient>(vAsioStream, replacementIpv4, replacementIpv6);
#endif
		const EvalConfig eval = orwellOpenVPNClient->eval_config(config);
		if (eval.error)
			OPENVPN_THROW_EXCEPTION("eval config error: " << eval.message);
		if (eval.autologin)
		{
			if (!username.empty() || !password.empty())
				std::cout << "NOTE: creds were not needed" << std::endl;
		}
		else
		{
			if (username.empty())
				OPENVPN_THROW_EXCEPTION("need creds");
			ProvideCreds creds;
			if (password.empty() && dynamicChallengeCookie.empty())
			{
				std::cout << "needs to fill password!!!" << std::endl;
				std::exit(1);
			}
				//password = get_password("Password:");
			creds.username = username;
			creds.password = password;
			creds.response = response;
			creds.dynamicChallengeCookie = dynamicChallengeCookie;
			creds.replacePasswordWithSessionID = true;
			creds.cachePassword = cachePassword;
			Status creds_status = orwellOpenVPNClient->provide_creds(creds);
			if (creds_status.error)
				OPENVPN_THROW_EXCEPTION("creds error: " << creds_status.message);
		}

		// external PKI
		if (!epki_cert_fn.empty())
		{
			orwellOpenVPNClient->epki_cert = read_text_utf8(epki_cert_fn);
			if (!epki_ca_fn.empty())
				orwellOpenVPNClient->epki_ca = read_text_utf8(epki_ca_fn);
#if defined(USE_MBEDTLS)
			if (!epki_key_fn.empty())
			{
				const std::string epki_key_txt = read_text_utf8(epki_key_fn);
				orwellOpenVPNClient->epki_ctx.parse(epki_key_txt, "EPKI", privateKeyPassword);
			}
			else
				OPENVPN_THROW_EXCEPTION("--epki-key must be specified");
#endif
		}

#ifdef OPENVPN_REMOTE_OVERRIDE
		orwellOpenVPNClient->set_remote_override_cmd(remote_override_cmd);
#endif
		return orwellOpenVPNClient;
	}
}
std::unique_ptr<OpenVPNClient> build_openvpn_client_from_profile_path(std::string path,
																	  std::shared_ptr<libopenvpn::VAsioStream> vAsioStream,
																	  std::string replacementIpv4,
																	  std::string replacementIpv6)
{
	return build_openvpn_client_from_profile_string(read_profile(path), "", "", vAsioStream, replacementIpv4, replacementIpv6);
}
#endif //OPENVPN_UTILS_H