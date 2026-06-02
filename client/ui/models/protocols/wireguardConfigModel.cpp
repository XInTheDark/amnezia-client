#include "wireguardConfigModel.h"

#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"

using namespace amnezia;
using namespace ProtocolUtils;

WireGuardConfigModel::WireGuardConfigModel(QObject *parent) : QAbstractListModel(parent)
{
}

int WireGuardConfigModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 1;
}

bool WireGuardConfigModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid() || index.row() < 0 || index.row() >= ContainerUtils::allContainers().size()) {
        return false;
    }

    QString strValue = value.toString();

    switch (role) {
    case Roles::SubnetAddressRole: m_protocolConfig.serverConfig.subnetAddress = strValue; break;
    case Roles::PortRole:
        if (ContainerUtils::isUdp2RawContainer(m_container)) {
            m_protocolConfig.serverConfig.udp2rawPublicPort = strValue;
        } else {
            m_protocolConfig.serverConfig.port = strValue;
        }
        break;
    case Roles::ClientMtuRole: {
        if (!m_protocolConfig.clientConfig.has_value()) {
            m_protocolConfig.clientConfig = amnezia::WireGuardClientConfig{};
        }
        m_protocolConfig.clientConfig->mtu = strValue;
        break;
    }
    default:
        return false;
    }

    emit dataChanged(index, index, QList { role });
    return true;
}

QVariant WireGuardConfigModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) {
        return QVariant();
    }

    switch (role) {
    case Roles::SubnetAddressRole: return m_protocolConfig.serverConfig.subnetAddress;
    case Roles::PortRole:
        return ContainerUtils::isUdp2RawContainer(m_container)
            ? m_protocolConfig.serverConfig.udp2rawPublicPort
            : m_protocolConfig.serverConfig.port;
    case Roles::ClientMtuRole: {
        if (m_protocolConfig.clientConfig.has_value()) {
            return m_protocolConfig.clientConfig->mtu;
        }
        return ContainerUtils::isUdp2RawContainer(m_container)
            ? QString::fromLatin1(protocols::udp2raw::defaultMtu)
            : QString::fromLatin1(protocols::wireguard::defaultMtu);
    }
    case Roles::Udp2RawPasswordRole: return m_protocolConfig.serverConfig.udp2rawPassword;
    case Roles::Udp2RawRawModeRole: return m_protocolConfig.serverConfig.udp2rawRawMode;
    case Roles::IsUdp2RawRole: return ContainerUtils::isUdp2RawContainer(m_container);
    }

    return QVariant();
}

void WireGuardConfigModel::updateModel(amnezia::DockerContainer container, const amnezia::WireGuardProtocolConfig &protocolConfig)
{
    beginResetModel();
    m_container = container;
    
    m_protocolConfig = protocolConfig;
    
    applyDefaultsToServerConfig(m_protocolConfig.serverConfig);
    
    if (!m_protocolConfig.clientConfig.has_value()) {
        m_protocolConfig.clientConfig = amnezia::WireGuardClientConfig{};
    }
    applyDefaultsToClientConfig(m_protocolConfig.clientConfig.value());
    
    m_originalProtocolConfig = m_protocolConfig;
    
    endResetModel();
}

void WireGuardConfigModel::applyDefaultsToServerConfig(amnezia::WireGuardServerConfig& config)
{
    if (config.subnetAddress.isEmpty()) {
        config.subnetAddress = protocols::wireguard::defaultSubnetAddress;
    }
    if (ContainerUtils::isUdp2RawContainer(m_container)) {
        if (config.udp2rawPublicPort.isEmpty()) {
            config.udp2rawPublicPort = protocols::udp2raw::defaultPublicPort;
        }
        if (config.udp2rawInternalPort.isEmpty()) {
            config.udp2rawInternalPort = protocols::wireguard::defaultPort;
        }
        if (config.port.isEmpty()) {
            config.port = config.udp2rawInternalPort;
        }
        if (config.udp2rawRawMode.isEmpty()) {
            config.udp2rawRawMode = protocols::udp2raw::defaultRawMode;
        }
    } else if (config.port.isEmpty()) {
        config.port = protocols::wireguard::defaultPort;
    }
    if (ContainerUtils::isUdp2RawContainer(m_container)) {
        config.transportProto = "tcp";
    } else if (config.transportProto.isEmpty()) {
        config.transportProto = ProtocolUtils::transportProtoToString(
            ProtocolUtils::defaultTransportProto(amnezia::Proto::WireGuard), amnezia::Proto::WireGuard);
    }
}

void WireGuardConfigModel::applyDefaultsToClientConfig(amnezia::WireGuardClientConfig& config)
{
    if (config.mtu.isEmpty()) {
        config.mtu = ContainerUtils::isUdp2RawContainer(m_container)
            ? QString::fromLatin1(protocols::udp2raw::defaultMtu)
            : QString::fromLatin1(protocols::wireguard::defaultMtu);
    }
}

amnezia::WireGuardProtocolConfig WireGuardConfigModel::getProtocolConfig()
{
    bool serverSettingsChanged = !m_protocolConfig.serverConfig.hasEqualServerSettings(m_originalProtocolConfig.serverConfig);
    
    if (serverSettingsChanged) {
        m_protocolConfig.clearClientConfig();
    }
    
    return m_protocolConfig;
}

bool WireGuardConfigModel::isServerSettingsEqual()
{
    return m_protocolConfig.serverConfig.hasEqualServerSettings(m_originalProtocolConfig.serverConfig);
}

QHash<int, QByteArray> WireGuardConfigModel::roleNames() const
{
    QHash<int, QByteArray> roles;

    roles[SubnetAddressRole] = "subnetAddress";
    roles[PortRole] = "port";
    roles[ClientMtuRole] = "clientMtu";
    roles[Udp2RawPasswordRole] = "udp2rawPassword";
    roles[Udp2RawRawModeRole] = "udp2rawRawMode";
    roles[IsUdp2RawRole] = "isUdp2Raw";

    return roles;
}
