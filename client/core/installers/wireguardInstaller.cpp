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

WireguardInstaller::WireguardInstaller(QObject *parent)
    : InstallerBase(parent)
{
}

ErrorCode WireguardInstaller::extractConfigFromContainer(DockerContainer container, const ServerCredentials &credentials,
                                                         SshSession* sshSession, ContainerConfig &config)
{
    ErrorCode errorCode = ErrorCode::NoError;
    
    QString serverConfig = sshSession->getTextFileFromContainer(container, credentials,
                                                                      protocols::wireguard::serverConfigPath, errorCode);
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
            QString udp2rawEnv = sshSession->getTextFileFromContainer(container, credentials, "/opt/amnezia/udp2raw.env", envError);
            if (envError == ErrorCode::NoError) {
                const auto envLines = udp2rawEnv.split("\n");
                for (const QString &line : envLines) {
                    const QStringList parts = line.split("=");
                    if (parts.size() != 2) {
                        continue;
                    }
                    if (parts[0] == "UDP2RAW_PUBLIC_PORT") {
                        wgConfig->serverConfig.udp2rawPublicPort = parts[1].trimmed();
                    } else if (parts[0] == "UDP2RAW_INTERNAL_PORT") {
                        wgConfig->serverConfig.udp2rawInternalPort = parts[1].trimmed();
                        wgConfig->serverConfig.port = parts[1].trimmed();
                    } else if (parts[0] == "UDP2RAW_PASSWORD") {
                        wgConfig->serverConfig.udp2rawPassword = parts[1].trimmed();
                    } else if (parts[0] == "UDP2RAW_RAW_MODE") {
                        wgConfig->serverConfig.udp2rawRawMode = parts[1].trimmed();
                    }
                }
            }
        }
    }
    
    return ErrorCode::NoError;
}
