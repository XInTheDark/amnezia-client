#include "udp2RawProtocol.h"

#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/utilities.h"
#include "ipc.h"

#include <QFileInfo>
#include <QHostInfo>
#include <QJsonObject>
#include <QProcess>
#include <QThread>
#include <QUdpSocket>

using namespace amnezia;

namespace
{
constexpr int kServiceReplyTimeoutMs = 5000;
constexpr int kProcessReplicaTimeoutMs = 5000;
constexpr int kUdp2RawStartupDelayMs = 250;
constexpr int kUdp2RawProbeTimeoutMs = 5000;

QString configValue(const QJsonObject &config, const QLatin1String &key, const QString &fallback = {})
{
    const QString value = config.value(key).toString();
    return value.isEmpty() ? fallback : value;
}
}

Udp2RawProtocol::Udp2RawProtocol(const QJsonObject &configuration, QObject *parent)
    : WireguardProtocol(configuration, parent)
{
    m_probeTimeoutTimer.setSingleShot(true);
    m_trafficProbeTimer.setSingleShot(true);
    connect(&m_probeTimeoutTimer, &QTimer::timeout, this, [this]() {
        if (!m_dnsProbeFinished) {
            failPostHandshakeProbe(QStringLiteral("DNS probe timed out"));
        }
    });
    connect(this, &VpnProtocol::connectionStateChanged, this, [this](Vpn::ConnectionState state) {
        if (state == Vpn::ConnectionState::Connected && !m_probeStarted) {
            qInfo() << "UDP2Raw stage: WG/AWG handshake complete";
            startPostHandshakeProbes();
        }
        if ((state == Vpn::ConnectionState::Disconnected || state == Vpn::ConnectionState::Error) && m_udp2rawProcess && !m_stoppingUdp2raw) {
            stopUdp2Raw();
        }
    });
    connect(this, &VpnProtocol::bytesChanged, this, [this](quint64 receivedBytes, quint64 sentBytes) {
        if (!m_probeStarted || connectionState() != Vpn::ConnectionState::Connected) {
            return;
        }
        if (sentBytes > 0) {
            m_probeTxObserved = true;
        }
        if (receivedBytes > 0) {
            m_probeRxObserved = true;
        }
        if (m_probeTxObserved && m_probeRxObserved && !m_probeGrowthLogged) {
            m_probeGrowthLogged = true;
            qInfo() << "UDP2Raw stage: rx/tx growth observed";
        }
    });
    connect(&m_trafficProbeTimer, &QTimer::timeout, this, &Udp2RawProtocol::finishTrafficProbe);
}

Udp2RawProtocol::~Udp2RawProtocol()
{
    Udp2RawProtocol::stop();
}

ErrorCode Udp2RawProtocol::start()
{
    m_probeStarted = false;
    m_dnsProbeFinished = false;
    m_probeTxObserved = false;
    m_probeRxObserved = false;
    m_probeGrowthLogged = false;
    m_probeTimeoutTimer.stop();
    m_trafficProbeTimer.stop();
    const ErrorCode udp2rawError = startUdp2Raw();
    if (udp2rawError != ErrorCode::NoError) {
        return udp2rawError;
    }

    qInfo() << "UDP2Raw stage: starting WG/AWG backend";
    const ErrorCode wireguardError = WireguardProtocol::start();
    if (wireguardError != ErrorCode::NoError) {
        stopUdp2Raw();
    } else {
        qInfo() << "UDP2Raw stage: WG/AWG backend start requested";
    }
    return wireguardError;
}

void Udp2RawProtocol::stop()
{
    m_probeTimeoutTimer.stop();
    m_trafficProbeTimer.stop();
    WireguardProtocol::stop();
    stopUdp2Raw();
}

int Udp2RawProtocol::allocateLocalPort() const
{
    QUdpSocket socket;
    if (!socket.bind(QHostAddress::LocalHost, 0)) {
        return 0;
    }
    return socket.localPort();
}

ErrorCode Udp2RawProtocol::startUdp2Raw()
{
    const QString executablePath = Utils::udp2rawExecPath();
    if (executablePath.isEmpty() || !QFileInfo::exists(executablePath)) {
        return ErrorCode::Udp2RawExecutableMissing;
    }

    const QString protocolName = m_rawConfig.value(configKey::protocol).toString();
    QJsonObject vpnConfigData = m_rawConfig.value(protocolName + "_config_data").toObject();
    if (vpnConfigData.isEmpty()) {
        return ErrorCode::InternalError;
    }

    const QString remoteHost = configValue(vpnConfigData, configKey::udp2rawRemoteHost,
                                           vpnConfigData.value(configKey::hostName).toString());
    const QString remoteIp = NetworkUtilities::getIPAddress(remoteHost);
    if (remoteIp.isEmpty()) {
        return ErrorCode::InternalError;
    }

    const QString remotePort = configValue(vpnConfigData, configKey::udp2rawRemotePort,
                                           configValue(vpnConfigData, configKey::udp2rawPublicPort));
    const QString password = vpnConfigData.value(configKey::udp2rawPassword).toString();
    const QString rawMode = configValue(vpnConfigData, configKey::udp2rawRawMode, protocols::udp2raw::defaultRawMode);
    if (remotePort.toInt() <= 0 || password.isEmpty() || rawMode != protocols::udp2raw::defaultRawMode) {
        return ErrorCode::InternalError;
    }

    const int localPort = allocateLocalPort();
    if (localPort <= 0) {
        return ErrorCode::InternalError;
    }

    m_udp2rawProcess = IpcClient::CreatePrivilegedProcess();
    if (!m_udp2rawProcess || !m_udp2rawProcess->waitForSource(kProcessReplicaTimeoutMs)) {
        m_udp2rawProcess.reset();
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

    connect(m_udp2rawProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardOutput, this, [this]() {
        auto reply = m_udp2rawProcess->readAllStandardOutput();
        if (reply.waitForFinished(kServiceReplyTimeoutMs)) {
            qDebug().noquote() << "[udp2raw]:" << QString::fromUtf8(reply.returnValue()).trimmed();
        }
    });
    connect(m_udp2rawProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardError, this, [this]() {
        auto reply = m_udp2rawProcess->readAllStandardError();
        if (reply.waitForFinished(kServiceReplyTimeoutMs)) {
            qDebug().noquote() << "[udp2raw]:" << QString::fromUtf8(reply.returnValue()).trimmed();
        }
    });
    connect(m_udp2rawProcess.data(), &IpcProcessInterfaceReplica::finished, this,
            [this](int exitCode, QProcess::ExitStatus exitStatus) {
                if (m_stoppingUdp2raw) {
                    return;
                }

                qCritical() << "udp2raw process stopped" << exitCode << exitStatus;
                WireguardProtocol::stop();
                setLastError(ErrorCode::Udp2RawExecutableCrashed);
            },
            Qt::QueuedConnection);

    m_udp2rawProcess->setProcessChannelMode(QProcess::MergedChannels);
    m_udp2rawProcess->setProgram(PermittedProcess::Udp2Raw);
    m_udp2rawProcess->setArguments({ "-c",
                                     "-l", QString("127.0.0.1:%1").arg(localPort),
                                     "-r", QString("%1:%2").arg(remoteIp, remotePort),
                                     "-k", password,
                                     "--raw-mode", rawMode });
    qInfo().noquote() << QString("UDP2Raw stage: starting local udp2raw_mp 127.0.0.1:%1 -> %2:%3")
                             .arg(localPort)
                             .arg(remoteIp, remotePort);
    m_udp2rawProcess->start();

    auto waitForStarted = m_udp2rawProcess->waitForStarted(kServiceReplyTimeoutMs);
    if (!waitForStarted.waitForFinished(kServiceReplyTimeoutMs) || !waitForStarted.returnValue()) {
        m_udp2rawProcess->close();
        m_udp2rawProcess.reset();
        return ErrorCode::Udp2RawExecutableCrashed;
    }

    QThread::msleep(kUdp2RawStartupDelayMs);
    qInfo() << "UDP2Raw stage: local UDP2Raw started";

    vpnConfigData[configKey::udp2rawRemoteHost] = remoteIp;
    vpnConfigData[configKey::udp2rawRemotePort] = remotePort;
    vpnConfigData[configKey::hostName] = "127.0.0.1";
    vpnConfigData[configKey::port] = localPort;
    m_rawConfig.insert(protocolName + "_config_data", vpnConfigData);
    m_rawConfig[configKey::hostName] = remoteIp;

    return ErrorCode::NoError;
}

void Udp2RawProtocol::startPostHandshakeProbes()
{
    m_probeStarted = true;
    m_probeTxObserved = false;
    m_probeRxObserved = false;
    m_probeGrowthLogged = false;
    m_trafficProbeTimer.start(kUdp2RawProbeTimeoutMs);
    qInfo() << "UDP2Raw stage: post-handshake probes started";

#ifdef Q_OS_MAC
    auto *ipProbe = new QProcess(this);
    ipProbe->setProgram(QStringLiteral("/sbin/ping"));
    ipProbe->setArguments({ QStringLiteral("-c"), QStringLiteral("1"), QStringLiteral("-W"), QStringLiteral("3000"),
                            QStringLiteral("1.1.1.1") });
    connect(ipProbe, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this, ipProbe](int exitCode, QProcess::ExitStatus exitStatus) {
                ipProbe->deleteLater();
                if (exitStatus != QProcess::NormalExit || exitCode != 0) {
                    failPostHandshakeProbe(QStringLiteral("IP probe failed"));
                    return;
                }

                qInfo() << "UDP2Raw stage: internet probe passed";
                m_dnsProbeFinished = false;
                m_probeTimeoutTimer.start(kUdp2RawProbeTimeoutMs);
                QHostInfo::lookupHost(QStringLiteral("google.com"), this, [this](const QHostInfo &hostInfo) {
                    m_dnsProbeFinished = true;
                    m_probeTimeoutTimer.stop();
                    if (hostInfo.error() != QHostInfo::NoError || hostInfo.addresses().isEmpty()) {
                        failPostHandshakeProbe(QStringLiteral("DNS probe failed"));
                        return;
                    }
                    qInfo() << "UDP2Raw stage: DNS probe passed";
                });
            });
    ipProbe->start();
#else
    qDebug() << "UDP2Raw post-handshake probes are only enabled on macOS";
#endif
}

void Udp2RawProtocol::failPostHandshakeProbe(const QString &reason)
{
    qCritical().noquote() << "UDP2Raw post-handshake probe failed:" << reason;
    m_probeTimeoutTimer.stop();
    m_trafficProbeTimer.stop();
    WireguardProtocol::stop();
    setLastError(ErrorCode::InternalError);
}

void Udp2RawProtocol::finishTrafficProbe()
{
    if (!m_probeStarted || connectionState() != Vpn::ConnectionState::Connected) {
        return;
    }

    qInfo() << "UDP2Raw stage: traffic probe result"
            << "txObserved=" << m_probeTxObserved
            << "rxObserved=" << m_probeRxObserved;

    if (m_probeTxObserved && !m_probeRxObserved) {
        failPostHandshakeProbe(QStringLiteral("traffic probe saw tx growth but no rx growth"));
    }
}

void Udp2RawProtocol::stopUdp2Raw()
{
    if (!m_udp2rawProcess) {
        return;
    }

    m_stoppingUdp2raw = true;
    m_udp2rawProcess->blockSignals(true);
    if (!m_udp2rawProcess->isReplicaValid()) {
        m_udp2rawProcess.reset();
        m_stoppingUdp2raw = false;
        return;
    }
#ifndef Q_OS_WIN
    m_udp2rawProcess->terminate();
    auto waitForFinished = m_udp2rawProcess->waitForFinished(1000);
    if (!waitForFinished.waitForFinished(kServiceReplyTimeoutMs) || !waitForFinished.returnValue()) {
        m_udp2rawProcess->kill();
        m_udp2rawProcess->waitForFinished(1000);
    }
#else
    m_udp2rawProcess->kill();
#endif
    m_udp2rawProcess->close();
    m_udp2rawProcess.reset();
    m_stoppingUdp2raw = false;
}
