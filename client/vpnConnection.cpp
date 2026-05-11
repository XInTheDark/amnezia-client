#include "vpnConnection.h"

#include <QDebug>
#include <QEventLoop>
#include <QFile>
#include <QHostInfo>
#include <QJsonObject>
#include <QObject>
#include <QRemoteObjectPendingCall>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <core/configurators/openVpnConfigurator.h>
#include <core/configurators/wireguardConfigurator.h>

#ifdef AMNEZIA_DESKTOP
    #include "core/utils/ipcClient.h"
    #include "mozilla/pinghelper.h"
    #include <core/protocols/wireGuardProtocol.h>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QThread>

#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include "platforms/ios/ios_controller.h"
#endif

#include "core/utils/networkUtilities.h"
#include "vpnConnection.h"

using namespace ProtocolUtils;

namespace
{
    constexpr int kReconnectTimeoutMs = 45000;
    constexpr int kServiceReplyTimeoutMs = 5000;
}

VpnConnection::VpnConnection(SecureServersRepository *serversRepository,
                             SecureAppSettingsRepository *appSettingsRepository, QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_checkTimer(this)
{
    m_reconnectTimeoutTimer.setSingleShot(true);
    m_reconnectTimeoutTimer.setInterval(kReconnectTimeoutMs);
    connect(&m_reconnectTimeoutTimer, &QTimer::timeout, this, [this]() {
        if (!m_reconnectInProgress) {
            return;
        }

        qWarning() << "VPN reconnect timed out";
        m_reconnectInProgress = false;
        m_reconnectRestarting = false;
        m_reconnectPending = false;
        if (m_vpnProtocol) {
            m_vpnProtocol->disconnect(this);
            m_vpnProtocol->stop();
            m_vpnProtocol.reset();
        }
#ifdef AMNEZIA_DESKTOP
        stopPingStats();
#endif
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(ErrorCode::InternalError);
    });

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    m_checkTimer.setInterval(1000);
    connect(IosController::Instance(), &IosController::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(IosController::Instance(), &IosController::bytesChanged, this, &VpnConnection::onBytesChanged);
#endif
}

VpnConnection::~VpnConnection()
{
#ifdef AMNEZIA_DESKTOP
    stopPingStats();
#endif
}

void VpnConnection::onBytesChanged(quint64 receivedBytes, quint64 sentBytes)
{
    emit bytesChanged(receivedBytes, sentBytes);
}

void VpnConnection::onKillSwitchModeChanged(bool enabled)
{
#ifdef AMNEZIA_DESKTOP
    IpcClient::withInterface([enabled](QSharedPointer<IpcInterfaceReplica> iface) {
        auto reply = iface->refreshKillSwitch(enabled);
        auto *watcher = new QRemoteObjectPendingCallWatcher(reply);
        QObject::connect(watcher, &QRemoteObjectPendingCallWatcher::finished, [watcher]() {
            if (watcher->returnValue().toBool())
                qDebug() << "VpnConnection::onKillSwitchModeChanged: Killswitch refreshed";
            else
                qWarning() << "VpnConnection::onKillSwitchModeChanged: Failed to execute remote refreshKillSwitch call";
            watcher->deleteLater();
        });
    });
#endif
}

void VpnConnection::onConnectionStateChanged(Vpn::ConnectionState state)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_serversRepository || !m_appSettingsRepository) {
        qCritical() << "VpnConnection::onConnectionStateChanged: repositories not initialized";
        return;
    }

    ServerConfig defaultServer = m_serversRepository->server(m_serversRepository->defaultServerIndex());
    DockerContainer container = defaultServer.defaultContainer();

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        switch (state) {
        case Vpn::ConnectionState::Connected: {
            iface->resetIpStack();

            auto flushDns = iface->flushDns();
            auto *flushDnsWatcher = new QRemoteObjectPendingCallWatcher(flushDns);
            QObject::connect(flushDnsWatcher, &QRemoteObjectPendingCallWatcher::finished, [flushDnsWatcher]() {
                if (flushDnsWatcher->returnValue().toBool())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";
                flushDnsWatcher->deleteLater();
            });

            if (!ContainerUtils::isAwgContainer(container) && container != DockerContainer::WireGuard) {
                QString dns1 = m_vpnConfiguration.value(configKey::dns1).toString();
                QString dns2 = m_vpnConfiguration.value(configKey::dns2).toString();

    #ifdef Q_OS_MACOS
                if (!m_appSettingsRepository->isSitesSplitTunnelingEnabled()
                    || m_appSettingsRepository->routeMode() != amnezia::RouteMode::VpnAllExceptSites) {
                    iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
                }
    #else
                iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << dns1 << dns2);
    #endif

                if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
                    iface->routeDeleteList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0");
                    RouteMode routeMode = m_appSettingsRepository->routeMode();
                    if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                        QTimer::singleShot(1000, m_vpnProtocol.data(), [this, routeMode]() {
                            addSitesRoutes(m_vpnProtocol->vpnGateway(), routeMode);
                        });
                    } else if (routeMode == amnezia::RouteMode::VpnAllExceptSites) {
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "0.0.0.0/1");
                        iface->routeAddList(m_vpnProtocol->vpnGateway(), QStringList() << "128.0.0.0/1");

                        iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << remoteAddress());
    #ifdef Q_OS_MACOS
                        iface->routeAddList(m_vpnProtocol->routeGateway(), QStringList() << dns1 << dns2);
    #endif
                        addSitesRoutes(m_vpnProtocol->routeGateway(), routeMode);
                    }
                }
            }
        } break;
        case Vpn::ConnectionState::Disconnected:
        case Vpn::ConnectionState::Error: {
            auto flushDns = iface->flushDns();
            auto *flushDnsWatcher = new QRemoteObjectPendingCallWatcher(flushDns);
            QObject::connect(flushDnsWatcher, &QRemoteObjectPendingCallWatcher::finished, [flushDnsWatcher]() {
                if (flushDnsWatcher->returnValue().toBool())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully flushed DNS";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to flush DNS";
                flushDnsWatcher->deleteLater();
            });

            auto clearSavedRoutes = iface->clearSavedRoutes();
            auto *clearSavedRoutesWatcher = new QRemoteObjectPendingCallWatcher(clearSavedRoutes);
            QObject::connect(clearSavedRoutesWatcher, &QRemoteObjectPendingCallWatcher::finished, [clearSavedRoutesWatcher]() {
                if (clearSavedRoutesWatcher->returnValue().toBool())
                    qDebug() << "VpnConnection::onConnectionStateChanged: Successfully cleared saved routes";
                else
                    qWarning() << "VpnConnection::onConnectionStateChanged: Failed to clear saved routes";
                clearSavedRoutesWatcher->deleteLater();
            });
        } break;
        default: break;
        }
    });
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    if (state == Vpn::ConnectionState::Connected || state == Vpn::ConnectionState::Connecting
        || state == Vpn::ConnectionState::Reconnecting) {
        m_checkTimer.start();
    } else {
        m_checkTimer.stop();
    }
#endif
}

const QString &VpnConnection::remoteAddress() const
{
    return m_remoteAddress;
}

void VpnConnection::setRepositories(SecureServersRepository *serversRepository,
                                    SecureAppSettingsRepository *appSettingsRepository)
{
    m_serversRepository = serversRepository;
    m_appSettingsRepository = appSettingsRepository;
}

void VpnConnection::addSitesRoutes(const QString &gw, amnezia::RouteMode mode)
{
#ifdef AMNEZIA_DESKTOP
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::addSitesRoutes: repositories not initialized";
        return;
    }

    QStringList ips;
    QStringList sites;
    const QVariantMap &m = m_appSettingsRepository->vpnSites(mode);
    for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
        if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
            ips.append(i.key());
        } else {
            if (NetworkUtilities::checkIpSubnetFormat(i.value().toString())) {
                ips.append(i.value().toString());
            }
            sites.append(i.key());
        }
    }
    ips.removeDuplicates();

    IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) { iface->routeAddList(gw, ips); });

    // re-resolve domains
    for (const QString &site : sites) {
        const auto &cbResolv = [this, site, gw, mode, ips](const QHostInfo &hostInfo) {
            const QList<QHostAddress> &addresses = hostInfo.addresses();
            QString ipv4Addr;
            for (const QHostAddress &addr : hostInfo.addresses()) {
                if (addr.protocol() == QAbstractSocket::NetworkLayerProtocol::IPv4Protocol) {
                    const QString &ip = addr.toString();
                    // qDebug() << "VpnConnection::addSitesRoutes updating site" << site << ip;
                    if (!ips.contains(ip)) {
                        IpcClient::withInterface([&gw, &ip](QSharedPointer<IpcInterfaceReplica> iface) {
                            iface->routeAddList(gw, QStringList() << ip);
                        });
                        m_appSettingsRepository->addVpnSite(mode, site, ip);
                    }
                    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
                        auto reply = iface->flushDns();
                        if (!reply.waitForFinished(kServiceReplyTimeoutMs) || !reply.returnValue())
                            qWarning() << "VpnConnection::addSitesRoutes: Failed to flush DNS";
                    });
                    break;
                }
            }
        };
        QHostInfo::lookupHost(site, this, cbResolv);
    }
#endif
}

QSharedPointer<VpnProtocol> VpnConnection::vpnProtocol() const
{
    return m_vpnProtocol;
}

void VpnConnection::disconnectSlots()
{
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect();
    }
}

ErrorCode VpnConnection::lastError() const
{
#ifdef Q_OS_ANDROID
    return ErrorCode::AndroidError;
#endif

    if (m_vpnProtocol.isNull()) {
        return ErrorCode::InternalError;
    }

    return m_vpnProtocol.data()->lastError();
}

Vpn::ConnectionState VpnConnection::connectionState() const
{
    return m_connectionState;
}

void VpnConnection::connectToVpn(int serverIndex, DockerContainer container, const QJsonObject &vpnConfiguration)
{
    if (!m_appSettingsRepository || !m_serversRepository) {
        qCritical() << "VpnConnection::connectToVpn: repositories not initialized";
        setConnectionState(Vpn::ConnectionState::Error);
        return;
    }

    qDebug() << QString("Trying to connect to VPN, server index is %1, container is %2, route mode is")
                        .arg(serverIndex)
                        .arg(ContainerUtils::containerToString(container))
             << m_appSettingsRepository->routeMode();

    m_remoteAddress = NetworkUtilities::getIPAddress(vpnConfiguration.value(configKey::hostName).toString());
    m_currentContainer = container;
    setConnectionState(Vpn::ConnectionState::Connecting);

    m_vpnConfiguration = vpnConfiguration;

#ifdef AMNEZIA_DESKTOP
    if (m_vpnProtocol) {
        m_vpnProtocol->disconnect(this);
        if (m_reconnectInProgress) {
            m_reconnectInProgress = false;
            m_reconnectRestarting = false;
            m_reconnectPending = false;
            m_reconnectTimeoutTimer.stop();
        }
        stopPingStats();
        m_vpnProtocol->stop();
        m_vpnProtocol.reset();
    }
    m_tunnelGateway.clear();
    m_tunnelLocalAddress.clear();
    appendKillSwitchConfig();
#endif

    appendSplitTunnelingConfig();

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    ErrorCode err = createAndStartProtocol(container);
    if (err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
    return;
#elif defined Q_OS_ANDROID
    androidVpnProtocol = createDefaultAndroidVpnProtocol();
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);
#elif defined Q_OS_IOS || defined(MACOS_NE)
    Proto proto = ContainerUtils::defaultProtocol(container);
    IosController::Instance()->connectVpn(proto, m_vpnConfiguration);
    connect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
    return;
#endif

    createProtocolConnections();

    if (ErrorCode err = m_vpnProtocol->start(); err != ErrorCode::NoError) {
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
}

ErrorCode VpnConnection::createAndStartProtocol(DockerContainer container)
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    m_vpnProtocol.reset(VpnProtocol::factory(container, m_vpnConfiguration));
    if (!m_vpnProtocol) {
        return ErrorCode::InternalError;
    }

    ErrorCode err = m_vpnProtocol->prepare();
    if (err != ErrorCode::NoError) {
        m_vpnProtocol.reset();
        return err;
    }

    createProtocolConnections();
    err = m_vpnProtocol->start();
    if (err != ErrorCode::NoError) {
        m_vpnProtocol->disconnect(this);
        m_vpnProtocol.reset();
    }
    return err;
#else
    Q_UNUSED(container)
    return ErrorCode::InternalError;
#endif
}

void VpnConnection::createProtocolConnections()
{
    connect(m_vpnProtocol.data(), &VpnProtocol::protocolError, this, &VpnConnection::vpnProtocolError);
    connect(m_vpnProtocol.data(), &VpnProtocol::connectionStateChanged, this, &VpnConnection::setConnectionState);
    connect(m_vpnProtocol.data(), SIGNAL(bytesChanged(quint64, quint64)), this, SLOT(onBytesChanged(quint64, quint64)));
    m_vpnProtocol->setStatsUpdatesEnabled(m_statsUpdatesEnabled);

#ifdef AMNEZIA_DESKTOP
    connect(m_vpnProtocol.data(), &VpnProtocol::tunnelAddressesUpdated, this, &VpnConnection::onTunnelAddressesUpdated);

    IpcClient::withInterface([this](QSharedPointer<IpcInterfaceReplica> rep) {
        connect(rep.data(), &IpcInterfaceReplica::networkChanged, this, &VpnConnection::reconnectToVpn,
                static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));
        connect(rep.data(), &IpcInterfaceReplica::wakeup, this, &VpnConnection::reconnectToVpn,
                static_cast<Qt::ConnectionType>(Qt::QueuedConnection | Qt::UniqueConnection));
    });
#endif
}

#ifdef AMNEZIA_DESKTOP
void VpnConnection::onTunnelAddressesUpdated(const QString &gateway, const QString &localAddress)
{
    if (!gateway.isEmpty()) {
        m_tunnelGateway = gateway;
    }
    if (!localAddress.isEmpty()) {
        m_tunnelLocalAddress = localAddress;
    }

    startPingStatsIfReady();
}

void VpnConnection::startPingStatsIfReady()
{
    if (!m_statsUpdatesEnabled || m_connectionState != Vpn::ConnectionState::Connected || m_vpnProtocol.isNull()) {
        return;
    }

    const QString gateway = !m_tunnelGateway.isEmpty() ? m_tunnelGateway : m_vpnProtocol->vpnGateway();
    const QString localAddress = !m_tunnelLocalAddress.isEmpty() ? m_tunnelLocalAddress : m_vpnProtocol->vpnLocalAddress();

    if (gateway.isEmpty() || localAddress.isEmpty()) {
        return;
    }

    if (m_pingHelper && m_pingGateway == gateway && m_pingLocalAddress == localAddress) {
        return;
    }

    stopPingStats();

    m_pingGateway = gateway;
    m_pingLocalAddress = localAddress;
    m_pingHelper = new PingHelper();
    m_pingHelper->setParent(this);
    connect(m_pingHelper, &PingHelper::pingSentAndReceived, this, &VpnConnection::pingChanged);
    connect(m_pingHelper, &PingHelper::connectionLose, this, [this]() { emit pingChanged(-1); });
    m_pingHelper->start(m_pingGateway, m_pingLocalAddress);
}

void VpnConnection::stopPingStats()
{
    if (!m_pingHelper) {
        return;
    }

    m_pingHelper->stop();
    m_pingHelper->deleteLater();
    m_pingHelper = nullptr;
    m_pingGateway.clear();
    m_pingLocalAddress.clear();
    emit pingChanged(-1);
}
#endif

void VpnConnection::appendKillSwitchConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendKillSwitchConfig: repositories not initialized";
        return;
    }

    m_vpnConfiguration.insert(configKey::killSwitchOption,
                              QVariant(m_appSettingsRepository->isKillSwitchEnabled()).toString());
    m_vpnConfiguration.insert(configKey::allowedDnsServers,
                              QVariant(m_appSettingsRepository->getAllowedDnsServers()).toJsonValue());
}

void VpnConnection::appendSplitTunnelingConfig()
{
    if (!m_appSettingsRepository) {
        qCritical() << "VpnConnection::appendSplitTunnelingConfig: repositories not initialized";
        return;
    }

    bool allowSiteBasedSplitTunneling = true;

    // this block is for old native configs and for old self-hosted configs
    auto protocolName = m_vpnConfiguration.value(configKey::vpnProto).toString();
    if (protocolName == ProtocolUtils::protoToString(Proto::Awg)
        || protocolName == ProtocolUtils::protoToString(Proto::WireGuard)) {
        allowSiteBasedSplitTunneling = false;
        auto configData = m_vpnConfiguration.value(protocolName + "_config_data").toObject();
        if (configData.value(configKey::allowedIps).isString()) {
            QJsonArray allowedIpsJsonArray =
                    QJsonArray::fromStringList(configData.value(configKey::allowedIps).toString().split(", "));
            configData.insert(configKey::allowedIps, allowedIpsJsonArray);
            m_vpnConfiguration.insert(protocolName + "_config_data", configData);
        } else if (configData.value(configKey::allowedIps).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("AllowedIPs")) {
                    auto allowedIpsString = line.split(" = ");
                    if (allowedIpsString.size() < 1) {
                        break;
                    }
                    QJsonArray allowedIpsJsonArray = QJsonArray::fromStringList(allowedIpsString.at(1).split(", "));
                    configData.insert(configKey::allowedIps, allowedIpsJsonArray);
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        if (configData.value(configKey::persistentKeepAlive).isUndefined()) {
            auto nativeConfig = configData.value(configKey::config).toString();
            auto nativeConfigLines = nativeConfig.split("\n");
            for (auto &line : nativeConfigLines) {
                if (line.contains("PersistentKeepalive")) {
                    auto persistentKeepaliveString = line.split(" = ");
                    if (persistentKeepaliveString.size() < 1) {
                        break;
                    }
                    configData.insert(configKey::persistentKeepAlive, persistentKeepaliveString.at(1));
                    m_vpnConfiguration.insert(protocolName + "_config_data", configData);
                    break;
                }
            }
        }

        QJsonArray allowedIpsJsonArray = configData.value(configKey::allowedIps).toArray();
        if (allowedIpsJsonArray.contains("0.0.0.0/0") && allowedIpsJsonArray.contains("::/0")) {
            allowSiteBasedSplitTunneling = true;
        }
    }

    amnezia::RouteMode routeMode = amnezia::RouteMode::VpnAllSites;
    QJsonArray sitesJsonArray;
    if (m_appSettingsRepository->isSitesSplitTunnelingEnabled()) {
        routeMode = m_appSettingsRepository->routeMode();

        if (allowSiteBasedSplitTunneling) {
            QStringList sites;
            const QVariantMap &m = m_appSettingsRepository->vpnSites(routeMode);
            for (auto i = m.constBegin(); i != m.constEnd(); ++i) {
                if (NetworkUtilities::checkIpSubnetFormat(i.key())) {
                    sites.append(i.key());
                } else if (NetworkUtilities::checkIpSubnetFormat(i.value().toString())) {
                    sites.append(i.value().toString());
                }
            }
            sites.removeDuplicates();
            for (const auto &site : sites) {
                sitesJsonArray.append(site);
            }

            if (sitesJsonArray.isEmpty()) {
                routeMode = amnezia::RouteMode::VpnAllSites;
            } else if (routeMode == amnezia::RouteMode::VpnOnlyForwardSites) {
                // Allow traffic to Amnezia DNS
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns1).toString());
                sitesJsonArray.append(m_vpnConfiguration.value(configKey::dns2).toString());
            }
        }
    }

    m_vpnConfiguration.insert(configKey::splitTunnelType, routeMode);
    m_vpnConfiguration.insert(configKey::splitTunnelSites, sitesJsonArray);

    amnezia::AppsRouteMode appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
    QJsonArray appsJsonArray;
    if (m_appSettingsRepository->isAppsSplitTunnelingEnabled()) {
        appsRouteMode = m_appSettingsRepository->appsRouteMode();

        auto apps = m_appSettingsRepository->vpnApps(appsRouteMode);
        for (const auto &app : apps) {
            appsJsonArray.append(app.appPath.isEmpty() ? app.packageName : app.appPath);
        }

        if (appsJsonArray.isEmpty()) {
            appsRouteMode = amnezia::AppsRouteMode::VpnAllApps;
        }
    }

    m_vpnConfiguration.insert(configKey::appSplitTunnelType, appsRouteMode);
    m_vpnConfiguration.insert(configKey::splitTunnelApps, appsJsonArray);

    qDebug() << QString("Site split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isSitesSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(routeMode);
    qDebug() << QString("App split tunneling is %1, route mode is %2")
                        .arg(m_appSettingsRepository->isAppsSplitTunnelingEnabled() ? "enabled" : "disabled")
                        .arg(appsRouteMode);
}

#ifdef Q_OS_ANDROID
void VpnConnection::restoreConnection()
{
    createAndroidConnections();

    m_vpnProtocol.reset(androidVpnProtocol);

    createProtocolConnections();
}

void VpnConnection::createAndroidConnections()
{
    androidVpnProtocol = createDefaultAndroidVpnProtocol();

    connect(AndroidController::instance(), &AndroidController::connectionStateChanged, androidVpnProtocol,
            &AndroidVpnProtocol::setConnectionState);
    connect(AndroidController::instance(), &AndroidController::statisticsUpdated, androidVpnProtocol,
            &AndroidVpnProtocol::setBytesChanged);
}

AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()
{
    return new AndroidVpnProtocol(m_vpnConfiguration);
}
#endif

QString VpnConnection::bytesPerSecToText(quint64 bytes)
{
    double mbps = bytes * 8 / 1e6;
    return QString("%1 %2").arg(QString::number(mbps, 'f', 2)).arg(tr("Mbps")); // Mbit/s
}

void VpnConnection::reconnectToVpn()
{
    if (m_vpnProtocol.isNull())
        return;

    if (m_reconnectInProgress) {
        qDebug() << "Reconnect already in progress; scheduling another restart";
        m_reconnectPending = true;
        m_reconnectTimeoutTimer.start();
        return;
    }

    if (m_connectionState != Vpn::ConnectionState::Connected) {
        qWarning() << QString("Reconnect triggered during inappropriate state: %1; ignoring slot")
                              .arg(QMetaEnum::fromType<Vpn::ConnectionState>().valueToKey(m_connectionState));
        return;
    }

    qDebug() << "Reconnect triggered. Reconnecting to the server";

    m_reconnectInProgress = true;
    m_reconnectRestarting = true;
    m_reconnectPending = false;
    m_reconnectTimeoutTimer.start();
    setConnectionState(Vpn::ConnectionState::Reconnecting);

    restartProtocolForReconnect();
}

void VpnConnection::restartProtocolForReconnect()
{
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
    if (m_currentContainer == DockerContainer::None) {
        qWarning() << "Reconnect requested without a saved container";
        m_reconnectInProgress = false;
        m_reconnectRestarting = false;
        m_reconnectPending = false;
        m_reconnectTimeoutTimer.stop();
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(ErrorCode::InternalError);
        return;
    }

    if (m_vpnProtocol) {
        m_vpnProtocol->stop();
        m_vpnProtocol->disconnect(this);
        m_vpnProtocol.reset();
    }

#ifdef AMNEZIA_DESKTOP
    stopPingStats();
    m_tunnelGateway.clear();
    m_tunnelLocalAddress.clear();
#endif

    m_reconnectRestarting = false;
    ErrorCode err = createAndStartProtocol(m_currentContainer);
    if (err != ErrorCode::NoError) {
        m_reconnectInProgress = false;
        m_reconnectPending = false;
        m_reconnectTimeoutTimer.stop();
        setConnectionState(Vpn::ConnectionState::Error);
        emit vpnProtocolError(err);
    }
#endif
}

void VpnConnection::schedulePendingReconnectIfNeeded(Vpn::ConnectionState state)
{
    if (!m_reconnectPending) {
        return;
    }

    if (state == Vpn::ConnectionState::Connected) {
        qDebug() << "Running pending reconnect restart after duplicate trigger";
        m_reconnectPending = false;
        QTimer::singleShot(0, this, [this]() {
            if (m_connectionState == Vpn::ConnectionState::Connected) {
                reconnectToVpn();
            }
        });
        return;
    }

    if (state == Vpn::ConnectionState::Disconnected || state == Vpn::ConnectionState::Error) {
        m_reconnectPending = false;
    }
}

void VpnConnection::disconnectFromVpn()
{
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    // iOS/macOS NE use IosController directly; m_vpnProtocol is not set there.
    IosController::Instance()->disconnectVpn();
    disconnect(&m_checkTimer, &QTimer::timeout, IosController::Instance(), &IosController::checkStatus);
#endif

    if (m_vpnProtocol.isNull()) {
        setConnectionState(Vpn::ConnectionState::Disconnected);
        return;
    }

    if (m_reconnectInProgress) {
        m_reconnectInProgress = false;
        m_reconnectRestarting = false;
        m_reconnectPending = false;
        m_reconnectTimeoutTimer.stop();
    }

    setConnectionState(Vpn::ConnectionState::Disconnecting);

#ifdef Q_OS_ANDROID
    auto *const connection = new QMetaObject::Connection;
    *connection = connect(AndroidController::instance(), &AndroidController::vpnStateChanged, this,
                          [this, connection](AndroidController::ConnectionState state) {
                              if (state == AndroidController::ConnectionState::DISCONNECTED) {
                                  setConnectionState(Vpn::ConnectionState::Disconnected);
                                  disconnect(*connection);
                                  delete connection;
                              }
                          });
#endif

    m_vpnProtocol->stop();

#if !defined(Q_OS_ANDROID) && !defined(AMNEZIA_DESKTOP)
    m_vpnProtocol->deleteLater();
#endif

    m_vpnProtocol = nullptr;
}

void VpnConnection::setStatsUpdatesEnabled(bool enabled)
{
    if (m_statsUpdatesEnabled == enabled) {
        return;
    }

    m_statsUpdatesEnabled = enabled;

    if (m_vpnProtocol) {
        m_vpnProtocol->setStatsUpdatesEnabled(enabled);
    }

#ifdef AMNEZIA_DESKTOP
    if (enabled) {
        startPingStatsIfReady();
    } else {
        stopPingStats();
    }
#endif
}

void VpnConnection::setConnectionState(Vpn::ConnectionState state)
{
    if (state == Vpn::Disconnected && m_reconnectRestarting) {
        qDebug() << "Ignoring transient disconnect during reconnect restart";
        return;
    }

    onConnectionStateChanged(state);

    if (state == Vpn::Connected || state == Vpn::Disconnected || state == Vpn::Error) {
        const bool reconnectWasInProgress = m_reconnectInProgress;
        m_reconnectInProgress = false;
        m_reconnectRestarting = false;
        m_reconnectTimeoutTimer.stop();
        if (reconnectWasInProgress) {
            schedulePendingReconnectIfNeeded(state);
        }
    }

    if (m_connectionState == state) {
        return;
    }

    m_connectionState = state;
    emit connectionStateChanged(state);

#ifdef AMNEZIA_DESKTOP
    if (state == Vpn::Connected && m_statsUpdatesEnabled) {
        startPingStatsIfReady();
    } else if (state == Vpn::Disconnected || state == Vpn::Disconnecting || state == Vpn::Error || state == Vpn::Unknown) {
        stopPingStats();
    }
#endif
}
