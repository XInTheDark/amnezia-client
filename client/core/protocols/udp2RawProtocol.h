#ifndef UDP2RAWPROTOCOL_H
#define UDP2RAWPROTOCOL_H

#include <QSharedPointer>

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

    QSharedPointer<IpcProcessInterfaceReplica> m_udp2rawProcess;
    bool m_stoppingUdp2raw = false;
};

#endif // UDP2RAWPROTOCOL_H
