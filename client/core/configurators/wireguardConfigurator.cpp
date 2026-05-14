#include "wireguardConfigurator.h"

#include <QDebug>
#include <QJsonDocument>
#include <QProcess>
#include <QRegularExpression>
#include <QString>
#include <QTemporaryDir>
#include <QTemporaryFile>

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/utilities.h"
#include "core/models/containerConfig.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include <QJsonArray>

using namespace amnezia;

namespace
{
QString nativeContainerDir(DockerContainer container)
{
    return QStringLiteral("/opt/amnezia/%1").arg(ContainerUtils::containerToString(container));
}

QString nativeInterfaceName(DockerContainer container)
{
    return container == DockerContainer::Udp2RawAwg ? QStringLiteral("amnawg0") : QStringLiteral("amnwg0");
}

QString nativeConfigPath(DockerContainer container)
{
    return nativeContainerDir(container) +
           (container == DockerContainer::Udp2RawAwg ? QStringLiteral("/awg/amnawg0.conf")
                                                     : QStringLiteral("/wireguard/amnwg0.conf"));
}

QString nativePublicKeyPath(DockerContainer container)
{
    return nativeContainerDir(container) +
           (container == DockerContainer::Udp2RawAwg ? QStringLiteral("/awg/wireguard_server_public_key.key")
                                                     : QStringLiteral("/wireguard/wireguard_server_public_key.key"));
}

QString nativePskPath(DockerContainer container)
{
    return nativeContainerDir(container) +
           (container == DockerContainer::Udp2RawAwg ? QStringLiteral("/awg/wireguard_psk.key")
                                                     : QStringLiteral("/wireguard/wireguard_psk.key"));
}

QHostAddress nextClientAddress(const QList<QHostAddress> &usedIps, const QString &subnetAddress)
{
    quint32 candidate = QHostAddress(subnetAddress.section('/', 0, 0)).toIPv4Address() + 2;
    if (!usedIps.isEmpty()) {
        candidate = usedIps.last().toIPv4Address() + 1;
    }

    for (int guard = 0; guard < 1024; ++guard) {
        const quint8 lastOctet = static_cast<quint8>(candidate & 0xff);
        if (lastOctet != 0 && lastOctet != 1 && lastOctet != 255) {
            return QHostAddress(candidate);
        }
        ++candidate;
    }

    return QHostAddress();
}
}

WireguardConfigurator::WireguardConfigurator(SshSession* sshSession, bool isAwg,
                                             QObject *parent)
    : ConfiguratorBase(sshSession, parent), m_isAwg(isAwg)
{
    m_serverConfigPath =
            m_isAwg ? amnezia::protocols::awg::serverConfigPath : amnezia::protocols::wireguard::serverConfigPath;
    m_serverPublicKeyPath =
            m_isAwg ? amnezia::protocols::awg::serverPublicKeyPath : amnezia::protocols::wireguard::serverPublicKeyPath;
    m_serverPskKeyPath =
            m_isAwg ? amnezia::protocols::awg::serverPskKeyPath : amnezia::protocols::wireguard::serverPskKeyPath;
    m_configTemplate = m_isAwg ? ProtocolScriptType::awg_template : ProtocolScriptType::wireguard_template;

    m_protocolName = m_isAwg ? configKey::awg : configKey::wireguard;
    m_defaultPort = m_isAwg ? protocols::awg::defaultPort : protocols::wireguard::defaultPort;
}

WireguardConfigurator::ConnectionData WireguardConfigurator::genClientKeys()
{
    // TODO review
    constexpr size_t EDDSA_KEY_LENGTH = 32;

    ConnectionData connData;

    unsigned char buff[EDDSA_KEY_LENGTH];
    int ret = RAND_priv_bytes(buff, EDDSA_KEY_LENGTH);
    if (ret <= 0)
        return connData;

    EVP_PKEY *pKey = EVP_PKEY_new();
    q_check_ptr(pKey);
    pKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, &buff[0], EDDSA_KEY_LENGTH);

    size_t keySize = EDDSA_KEY_LENGTH;

    // save private key
    unsigned char priv[EDDSA_KEY_LENGTH];
    EVP_PKEY_get_raw_private_key(pKey, priv, &keySize);
    connData.clientPrivKey = QByteArray::fromRawData((char *)priv, keySize).toBase64();

    // save public key
    unsigned char pub[EDDSA_KEY_LENGTH];
    EVP_PKEY_get_raw_public_key(pKey, pub, &keySize);
    connData.clientPubKey = QByteArray::fromRawData((char *)pub, keySize).toBase64();

    return connData;
}

QList<QHostAddress> WireguardConfigurator::getIpsFromConf(const QString &input)
{
    QRegularExpression regex("AllowedIPs = (\\d+\\.\\d+\\.\\d+\\.\\d+)");
    QRegularExpressionMatchIterator matchIterator = regex.globalMatch(input);

    QList<QHostAddress> ips;

    while (matchIterator.hasNext()) {
        QRegularExpressionMatch match = matchIterator.next();
        const QString address_string { match.captured(1) };
        const QHostAddress address { address_string };
        if (address.isNull()) {
            qWarning() << "Couldn't recognize the ip address: " << address_string;
        } else {
            ips << address;
        }
    }

    return ips;
}

WireguardConfigurator::ConnectionData WireguardConfigurator::prepareWireguardConfig(const ServerCredentials &credentials,
                                                                                    DockerContainer container,
                                                                                    const WireGuardServerConfig* serverConfig,
                                                                                    const AwgServerConfig* awgServerConfig,
                                                                                    const DnsSettings &dnsSettings,
                                                                                    ErrorCode &errorCode)
{
    WireguardConfigurator::ConnectionData connData = WireguardConfigurator::genClientKeys();
    connData.host = credentials.hostName;
    
    QString portStr = m_defaultPort;
    if (serverConfig && !serverConfig->port.isEmpty()) {
        portStr = serverConfig->port;
    } else if (awgServerConfig && !awgServerConfig->port.isEmpty()) {
        portStr = awgServerConfig->port;
    }
    if (serverConfig && !serverConfig->udp2rawPublicPort.isEmpty()) {
        portStr = serverConfig->udp2rawPublicPort;
    } else if (awgServerConfig && !awgServerConfig->udp2rawPublicPort.isEmpty()) {
        portStr = awgServerConfig->udp2rawPublicPort;
    }
    connData.port = portStr;

    if (connData.clientPrivKey.isEmpty() || connData.clientPubKey.isEmpty()) {
        errorCode = ErrorCode::InternalError;
        return connData;
    }

    QString configPath = m_serverConfigPath;
    const bool isNativeUdp2Raw = ContainerUtils::isNativeHostContainer(container);
    if (isNativeUdp2Raw) {
        configPath = nativeConfigPath(container);
    } else if (container == DockerContainer::Awg) {
        configPath = amnezia::protocols::awg::serverLegacyConfigPath;
    }
    QString getIpsScript = QString("cat %1 | grep AllowedIPs").arg(configPath);
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    if (isNativeUdp2Raw) {
        errorCode = m_sshSession->runScript(credentials, QStringLiteral("sudo %1").arg(getIpsScript), cbReadStdOut);
    } else {
        errorCode = m_sshSession->runContainerScript(credentials, container, getIpsScript, cbReadStdOut);
    }
    if (errorCode != ErrorCode::NoError) {
        return connData;
    }
    auto ips = getIpsFromConf(stdOut);

    QString subnetAddress = container == DockerContainer::Udp2RawAwg
            ? QString::fromLatin1(protocols::udp2raw::defaultAwgSubnetAddress)
            : QString::fromLatin1(protocols::wireguard::defaultSubnetAddress);
    if (serverConfig && !serverConfig->subnetAddress.isEmpty()) {
        subnetAddress = serverConfig->subnetAddress;
    } else if (awgServerConfig && !awgServerConfig->subnetAddress.isEmpty()) {
        subnetAddress = awgServerConfig->subnetAddress;
    }
    QHostAddress nextIp = nextClientAddress(ips, subnetAddress);

    connData.clientIP = nextIp.toString();

    // Get keys
    connData.serverPubKey = isNativeUdp2Raw
            ? m_sshSession->getTextFileFromHost(credentials, nativePublicKeyPath(container), errorCode)
            : m_sshSession->getTextFileFromContainer(container, credentials, m_serverPublicKeyPath, errorCode);
    connData.serverPubKey.replace("\n", "");
    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    connData.pskKey = isNativeUdp2Raw
            ? m_sshSession->getTextFileFromHost(credentials, nativePskPath(container), errorCode)
            : m_sshSession->getTextFileFromContainer(container, credentials, m_serverPskKeyPath, errorCode);
    connData.pskKey.replace("\n", "");

    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    // Add client to config
    QString configPart = QString("[Peer]\n"
                                 "PublicKey = %1\n"
                                 "PresharedKey = %2\n"
                                 "AllowedIPs = %3/32\n\n")
                                 .arg(connData.clientPubKey, connData.pskKey, connData.clientIP);

    if (isNativeUdp2Raw) {
        const QString appendScript = QStringLiteral("cat <<'EOF' | sudo tee -a %1 >/dev/null\n%2EOF\n")
                                             .arg(configPath, configPart);
        errorCode = m_sshSession->runHostScript(credentials, appendScript);
    } else {
        errorCode = m_sshSession->uploadTextFileToContainer(container, credentials, configPart, configPath,
                                                                  libssh::ScpOverwriteMode::ScpAppendToExisting);
    }

    if (errorCode != ErrorCode::NoError) {
        return connData;
    }

    bool isAwg = (container == DockerContainer::Awg2 || container == DockerContainer::Udp2RawAwg);
    QString bin = isAwg ? QStringLiteral("awg") : QStringLiteral("wg");
    QString iface = isNativeUdp2Raw ? nativeInterfaceName(container) : (isAwg ? QStringLiteral("awg0") : QStringLiteral("wg0"));
    QString script = isNativeUdp2Raw
            ? QString("sudo bash -c '%1 syncconf %2 <(%1-quick strip %3)'").arg(bin, iface, configPath)
            : QString("sudo docker exec -i $CONTAINER_NAME bash -c '%1 syncconf %2 <(%1-quick strip %3)'").arg(bin, iface, configPath);

    errorCode = m_sshSession->runScript(
            credentials,
            m_sshSession->replaceVars(script, amnezia::genBaseVars(credentials, container, dnsSettings.primaryDns, dnsSettings.secondaryDns)));

    return connData;
}

ProtocolConfig WireguardConfigurator::createConfig(const ServerCredentials &credentials, DockerContainer container,
                                                    const ContainerConfig &containerConfig,
                                                    const DnsSettings &dnsSettings,
                                                    ErrorCode &errorCode)
{
    const WireGuardServerConfig* wireguardServerConfig = nullptr;
    const WireGuardClientConfig* wireguardClientConfig = nullptr;
    const AwgServerConfig* awgServerConfig = nullptr;
    const AwgClientConfig* awgClientConfig = nullptr;
    
    if (auto* wireGuardProtocolConfig = containerConfig.getWireGuardProtocolConfig()) {
        wireguardServerConfig = &wireGuardProtocolConfig->serverConfig;
        if (wireGuardProtocolConfig->clientConfig.has_value()) {
            wireguardClientConfig = &wireGuardProtocolConfig->clientConfig.value();
        }
    } else if (auto* awgProtocolConfig = containerConfig.getAwgProtocolConfig()) {
        awgServerConfig = &awgProtocolConfig->serverConfig;
        if (awgProtocolConfig->clientConfig.has_value()) {
            awgClientConfig = &awgProtocolConfig->clientConfig.value();
        }
    }
    
    amnezia::ScriptVars vars = amnezia::genBaseVars(credentials, container, dnsSettings.primaryDns, dnsSettings.secondaryDns);
    vars.append(amnezia::genProtocolVarsForContainer(container, containerConfig));
    QString scriptData = amnezia::scriptData(m_configTemplate, container);
    QString config = m_sshSession->replaceVars(scriptData, vars);

    ConnectionData connData = prepareWireguardConfig(credentials, container, wireguardServerConfig, awgServerConfig, dnsSettings, errorCode);
    if (errorCode != ErrorCode::NoError) {
        return WireGuardProtocolConfig{};
    }

    config.replace("$WIREGUARD_CLIENT_PRIVATE_KEY", connData.clientPrivKey);
    config.replace("$WIREGUARD_CLIENT_IP", connData.clientIP);
    config.replace("$WIREGUARD_SERVER_PUBLIC_KEY", connData.serverPubKey);
    config.replace("$WIREGUARD_PSK", connData.pskKey);

    QString mtu = protocols::wireguard::defaultMtu;
    if (wireguardClientConfig && !wireguardClientConfig->mtu.isEmpty()) {
        mtu = wireguardClientConfig->mtu;
    } else if (awgClientConfig && !awgClientConfig->mtu.isEmpty()) {
        mtu = awgClientConfig->mtu;
    }
    if (ContainerUtils::isUdp2RawContainer(container)) {
        mtu = protocols::udp2raw::defaultMtu;
    }
    
    WireGuardProtocolConfig protocolConfig;
    if (wireguardServerConfig) {
        protocolConfig.serverConfig = *wireguardServerConfig;
    }
    
    WireGuardClientConfig clientConfig;
    clientConfig.nativeConfig = config;
    clientConfig.hostName = connData.host;
    clientConfig.port = connData.port.toInt();
    clientConfig.clientIp = connData.clientIP;
    clientConfig.clientPrivateKey = connData.clientPrivKey;
    clientConfig.clientPublicKey = connData.clientPubKey;
    clientConfig.serverPublicKey = connData.serverPubKey;
    clientConfig.presharedKey = connData.pskKey;
    clientConfig.clientId = connData.clientPubKey;
    clientConfig.allowedIps = ContainerUtils::isUdp2RawContainer(container)
        ? QStringList { "0.0.0.0/0" }
        : QStringList { "0.0.0.0/0", "::/0" };
    clientConfig.persistentKeepAlive = "25";
    clientConfig.mtu = mtu;
    clientConfig.isObfuscationEnabled = false;
    if (wireguardServerConfig && !wireguardServerConfig->udp2rawPublicPort.isEmpty()) {
        clientConfig.udp2rawPublicPort = wireguardServerConfig->udp2rawPublicPort;
        clientConfig.udp2rawInternalPort = wireguardServerConfig->udp2rawInternalPort;
        clientConfig.udp2rawPassword = wireguardServerConfig->udp2rawPassword;
        clientConfig.udp2rawRawMode = wireguardServerConfig->udp2rawRawMode;
        clientConfig.udp2rawRemoteHost = connData.host;
        clientConfig.udp2rawRemotePort = wireguardServerConfig->udp2rawPublicPort;
    }
    
    protocolConfig.setClientConfig(clientConfig);
    
    return protocolConfig;
}

ProtocolConfig WireguardConfigurator::processConfigWithLocalSettings(const ConnectionSettings &settings,
                                                                     ProtocolConfig protocolConfig)
{
    return ConfiguratorBase::processConfigWithLocalSettings(settings, protocolConfig);
}

ProtocolConfig WireguardConfigurator::processConfigWithExportSettings(const ExportSettings &settings,
                                                                      ProtocolConfig protocolConfig)
{
    return ConfiguratorBase::processConfigWithExportSettings(settings, protocolConfig);
}
