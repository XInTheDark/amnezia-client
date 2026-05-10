#ifndef CONNECTIONUICONTROLLER_H
#define CONNECTIONUICONTROLLER_H

#include <QElapsedTimer>
#include <QObject>

#include "core/controllers/connectionController.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/protocols/vpnProtocol.h"
#include "core/controllers/serversController.h"

class ConnectionUiController : public QObject
{
    Q_OBJECT

public:
    Q_PROPERTY(bool isConnected READ isConnected NOTIFY connectionStateChanged)
    Q_PROPERTY(bool isConnectionInProgress READ isConnectionInProgress NOTIFY connectionStateChanged)
    Q_PROPERTY(QString connectionStateText READ connectionStateText NOTIFY connectionStateChanged)
    Q_PROPERTY(QString downloadSpeed READ downloadSpeed NOTIFY statsChanged)
    Q_PROPERTY(QString uploadSpeed READ uploadSpeed NOTIFY statsChanged)
    Q_PROPERTY(QString pingText READ pingText NOTIFY statsChanged)

    explicit ConnectionUiController(ConnectionController* connectionController,
                                    ServersController* serversController,
                                    QObject *parent = nullptr);

    ~ConnectionUiController() = default;

    bool isConnected() const;
    bool isConnectionInProgress() const;
    QString connectionStateText() const;
    QString downloadSpeed() const;
    QString uploadSpeed() const;
    QString pingText() const;

public slots:
    void toggleConnection();

    void openConnection();
    void closeConnection();

    ErrorCode getLastConnectionError();
    void onConnectionStateChanged(Vpn::ConnectionState state);

    void onCurrentContainerUpdated();

    void onTranslationsUpdated();
    void onBytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void onPingChanged(qint64 msec);

signals:
    void connectionStateChanged();
    void statsChanged();

    void connectionErrorOccurred(ErrorCode errorCode);
    void reconnectWithUpdatedContainer(const QString &message);

    void connectButtonClicked();
    void preparingConfig();
    void prepareConfig();

private:
    Vpn::ConnectionState getCurrentConnectionState();
    void clearStats();

    ConnectionController* m_connectionController;
    ServersController* m_serversController;

    bool m_isConnected = false;
    bool m_isConnectionInProgress = false;
    QString m_connectionStateText = tr("Connect");
    QString m_downloadSpeed;
    QString m_uploadSpeed;
    QString m_pingText;
    QElapsedTimer m_speedTimer;

    Vpn::ConnectionState m_state;
};

#endif
