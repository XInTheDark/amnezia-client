#include "wireguardInstaller.h"

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhosted/sshSession.h"

using namespace amnezia;
using namespace ProtocolUtils;

namespace
{
QString nativeContainerDir(DockerContainer container)
{
    return QStringLiteral("/opt/amnezia/%1").arg(ContainerUtils::containerToString(container));
}

QString nativeWireGuardConfigPath(DockerContainer container)
{
    return nativeContainerDir(container) + QStringLiteral("/wireguard/amnwg0.conf");
}

QMap<QString, QString> parseEnvFile(const QString &env)
{
    QMap<QString, QString> values;
    const QStringList lines = env.split('\n');
    for (const QString &line : lines) {
        const int pos = line.indexOf('=');
        if (pos <= 0) {
            continue;
        }
        values.insert(line.left(pos).trimmed(), line.mid(pos + 1).trimmed());
    }
    return values;
}
}

WireguardInstaller::WireguardInstaller(QObject *parent)
    : InstallerBase(parent)
{
}

ErrorCode WireguardInstaller::extractConfigFromContainer(DockerContainer container, const ServerCredentials &credentials,
                                                         SshSession* sshSession, ContainerConfig &config)
{
    ErrorCode errorCode = ErrorCode::NoError;
    
    const bool isNativeUdp2Raw = container == DockerContainer::Udp2RawWireGuard;
    const QString configPath = isNativeUdp2Raw ? nativeWireGuardConfigPath(container)
                                               : QString::fromLatin1(protocols::wireguard::serverConfigPath);
    QString serverConfig = isNativeUdp2Raw
            ? sshSession->getTextFileFromHost(credentials, configPath, errorCode)
            : sshSession->getTextFileFromContainer(container, credentials, configPath, errorCode);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    QMap<QString, QString> serverConfigMap;
    auto serverConfigLines = serverConfig.split("\n");
    for (auto &line : serverConfigLines) {
        auto trimmedLine = line.trimmed();
        if (trimmedLine.startsWith("[") && trimmedLine.endsWith("]")) {
            continue;
        } else {
            QStringList parts = trimmedLine.split(" = ");
            if (parts.count() == 2) {
                serverConfigMap.insert(parts[0].trimmed(), parts[1].trimmed());
            }
        }
    }

    if (auto* wgConfig = config.getWireGuardProtocolConfig()) {
        wgConfig->serverConfig.subnetAddress = serverConfigMap.value("Address").remove("/24");
        if (container == DockerContainer::Udp2RawWireGuard) {
            ErrorCode envError = ErrorCode::NoError;
            QString udp2rawEnv = sshSession->getTextFileFromHost(credentials, nativeContainerDir(container) + QStringLiteral("/udp2raw.env"), envError);
            if (envError == ErrorCode::NoError) {
                const QMap<QString, QString> env = parseEnvFile(udp2rawEnv);
                if (env.value(QStringLiteral("UDP2RAW_IMPL_VERSION")).toInt() != protocols::udp2raw::nativeHostImplementationVersion) {
                    return ErrorCode::ServerContainerMissingError;
                }
                wgConfig->serverConfig.udp2rawPublicPort = env.value(QStringLiteral("UDP2RAW_PUBLIC_PORT"));
                wgConfig->serverConfig.udp2rawInternalPort = env.value(QStringLiteral("UDP2RAW_INTERNAL_PORT"));
                wgConfig->serverConfig.port = wgConfig->serverConfig.udp2rawInternalPort;
                wgConfig->serverConfig.udp2rawPassword = env.value(QStringLiteral("UDP2RAW_PASSWORD"));
                wgConfig->serverConfig.udp2rawRawMode = env.value(QStringLiteral("UDP2RAW_RAW_MODE"));
                wgConfig->serverConfig.udp2rawImplementationVersion = protocols::udp2raw::nativeHostImplementationVersion;
                wgConfig->serverConfig.subnetAddress = env.value(QStringLiteral("WIREGUARD_SUBNET_IP"), wgConfig->serverConfig.subnetAddress);
                wgConfig->serverConfig.subnetCidr = env.value(QStringLiteral("WIREGUARD_SUBNET_CIDR"), wgConfig->serverConfig.subnetCidr);
            } else {
                return ErrorCode::ServerContainerMissingError;
            }
        }
    }
    
    return ErrorCode::NoError;
}
