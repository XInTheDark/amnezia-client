#ifndef UDP2RAWPROTOCOL_H
#define UDP2RAWPROTOCOL_H

#include <QSharedPointer>
#include <QTimer>

#include "core/utils/ipcClient.h"
#include "wireGuardProtocol.h"

class Udp2RawProtocol : public WireguardProtocol
{
    Q_OBJECT

public:
    explicit Udp2RawProtocol(const QJsonObject &configuration, QObject *parent = nullptr);
    ~Udp2RawProtocol() override;

    ErrorCode start() override;
    void stop() override;

private:
    ErrorCode startUdp2Raw();
    void stopUdp2Raw();
    int allocateLocalPort() const;
    void startPostHandshakeProbes();
    void failPostHandshakeProbe(const QString &reason);
    void finishTrafficProbe();

    QSharedPointer<IpcProcessInterfaceReplica> m_udp2rawProcess;
    QTimer m_probeTimeoutTimer;
    QTimer m_trafficProbeTimer;
    bool m_stoppingUdp2raw = false;
    bool m_probeStarted = false;
    bool m_dnsProbeFinished = false;
    bool m_probeTxObserved = false;
    bool m_probeRxObserved = false;
    bool m_probeGrowthLogged = false;
};

#endif // UDP2RAWPROTOCOL_H
