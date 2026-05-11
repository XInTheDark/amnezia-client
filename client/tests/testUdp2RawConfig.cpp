#include <QJsonObject>
#include <QTest>

#include "core/models/containerConfig.h"
#include "core/models/protocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"

using namespace amnezia;

class TestUdp2RawConfig : public QObject
{
    Q_OBJECT

private slots:
    void testContainerStringParsing()
    {
        QCOMPARE(ContainerUtils::containerToString(DockerContainer::Udp2RawWireGuard),
                 QStringLiteral("amnezia-udp2raw-wireguard"));
        QCOMPARE(ContainerUtils::containerToString(DockerContainer::Udp2RawAwg),
                 QStringLiteral("amnezia-udp2raw-awg"));
        QCOMPARE(ContainerUtils::containerFromString(QStringLiteral("amnezia-udp2raw-wireguard")),
                 DockerContainer::Udp2RawWireGuard);
        QCOMPARE(ContainerUtils::containerFromString(QStringLiteral("amnezia-udp2raw-awg")),
                 DockerContainer::Udp2RawAwg);
        QCOMPARE(ContainerUtils::defaultProtocol(DockerContainer::Udp2RawWireGuard), Proto::WireGuard);
        QCOMPARE(ContainerUtils::defaultProtocol(DockerContainer::Udp2RawAwg), Proto::Awg);
        QVERIFY(ContainerUtils::isUdp2RawContainer(DockerContainer::Udp2RawWireGuard));
        QVERIFY(ContainerUtils::isUdp2RawContainer(DockerContainer::Udp2RawAwg));
        QVERIFY(ContainerUtils::isWireGuardLikeContainer(DockerContainer::Udp2RawWireGuard));
        QVERIFY(ContainerUtils::isAwgContainer(DockerContainer::Udp2RawAwg));
    }

    void testWireGuardUdp2RawJsonRoundTrip()
    {
        WireGuardProtocolConfig protocolConfig;
        protocolConfig.serverConfig.port = QStringLiteral("60850");
        protocolConfig.serverConfig.udp2rawPublicPort = QStringLiteral("8443");
        protocolConfig.serverConfig.udp2rawInternalPort = QStringLiteral("60850");
        protocolConfig.serverConfig.udp2rawPassword = QStringLiteral("secret");
        protocolConfig.serverConfig.udp2rawRawMode = QString::fromLatin1(protocols::udp2raw::defaultRawMode);

        WireGuardClientConfig clientConfig;
        clientConfig.hostName = QStringLiteral("127.0.0.1");
        clientConfig.port = 3333;
        clientConfig.udp2rawPublicPort = protocolConfig.serverConfig.udp2rawPublicPort;
        clientConfig.udp2rawInternalPort = protocolConfig.serverConfig.udp2rawInternalPort;
        clientConfig.udp2rawPassword = protocolConfig.serverConfig.udp2rawPassword;
        clientConfig.udp2rawRawMode = protocolConfig.serverConfig.udp2rawRawMode;
        clientConfig.udp2rawRemoteHost = QStringLiteral("64.235.43.101");
        clientConfig.udp2rawRemotePort = QStringLiteral("8443");
        protocolConfig.setClientConfig(clientConfig);

        ContainerConfig containerConfig;
        containerConfig.container = DockerContainer::Udp2RawWireGuard;
        containerConfig.protocolConfig = protocolConfig;

        const ContainerConfig restored = ContainerConfig::fromJson(containerConfig.toJson());
        QCOMPARE(restored.container, DockerContainer::Udp2RawWireGuard);
        QCOMPARE(restored.getProtocolType(), Proto::WireGuard);
        QCOMPARE(restored.protocolConfig.port(), QStringLiteral("8443"));

        const auto *restoredProtocol = restored.getWireGuardProtocolConfig();
        QVERIFY(restoredProtocol);
        QCOMPARE(restoredProtocol->serverConfig.port, QStringLiteral("60850"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawPublicPort, QStringLiteral("8443"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawInternalPort, QStringLiteral("60850"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawPassword, QStringLiteral("secret"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawRawMode, QStringLiteral("faketcp"));
        QVERIFY(restoredProtocol->clientConfig.has_value());
        QCOMPARE(restoredProtocol->clientConfig->hostName, QStringLiteral("127.0.0.1"));
        QCOMPARE(restoredProtocol->clientConfig->port, 3333);
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemoteHost, QStringLiteral("64.235.43.101"));
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemotePort, QStringLiteral("8443"));
    }

    void testAwgUdp2RawJsonRoundTrip()
    {
        AwgProtocolConfig protocolConfig;
        protocolConfig.serverConfig.port = QStringLiteral("51820");
        protocolConfig.serverConfig.protocolVersion = protocols::awg::awgV2;
        protocolConfig.serverConfig.udp2rawPublicPort = QStringLiteral("8443");
        protocolConfig.serverConfig.udp2rawInternalPort = QStringLiteral("51820");
        protocolConfig.serverConfig.udp2rawPassword = QStringLiteral("secret");
        protocolConfig.serverConfig.udp2rawRawMode = QString::fromLatin1(protocols::udp2raw::defaultRawMode);

        AwgClientConfig clientConfig;
        clientConfig.hostName = QStringLiteral("127.0.0.1");
        clientConfig.port = 3333;
        clientConfig.udp2rawPublicPort = protocolConfig.serverConfig.udp2rawPublicPort;
        clientConfig.udp2rawInternalPort = protocolConfig.serverConfig.udp2rawInternalPort;
        clientConfig.udp2rawPassword = protocolConfig.serverConfig.udp2rawPassword;
        clientConfig.udp2rawRawMode = protocolConfig.serverConfig.udp2rawRawMode;
        clientConfig.udp2rawRemoteHost = QStringLiteral("64.235.43.101");
        clientConfig.udp2rawRemotePort = QStringLiteral("8443");
        protocolConfig.setClientConfig(clientConfig);

        ContainerConfig containerConfig;
        containerConfig.container = DockerContainer::Udp2RawAwg;
        containerConfig.protocolConfig = protocolConfig;

        const ContainerConfig restored = ContainerConfig::fromJson(containerConfig.toJson());
        QCOMPARE(restored.container, DockerContainer::Udp2RawAwg);
        QCOMPARE(restored.getProtocolType(), Proto::Awg);
        QCOMPARE(restored.protocolConfig.port(), QStringLiteral("8443"));

        const auto *restoredProtocol = restored.getAwgProtocolConfig();
        QVERIFY(restoredProtocol);
        QCOMPARE(restoredProtocol->serverConfig.port, QStringLiteral("51820"));
        QCOMPARE(restoredProtocol->serverConfig.protocolVersion, protocols::awg::awgV2);
        QCOMPARE(restoredProtocol->serverConfig.udp2rawPublicPort, QStringLiteral("8443"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawInternalPort, QStringLiteral("51820"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawPassword, QStringLiteral("secret"));
        QCOMPARE(restoredProtocol->serverConfig.udp2rawRawMode, QStringLiteral("faketcp"));
        QVERIFY(restoredProtocol->clientConfig.has_value());
        QCOMPARE(restoredProtocol->clientConfig->hostName, QStringLiteral("127.0.0.1"));
        QCOMPARE(restoredProtocol->clientConfig->port, 3333);
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemoteHost, QStringLiteral("64.235.43.101"));
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemotePort, QStringLiteral("8443"));
    }
};

QTEST_MAIN(TestUdp2RawConfig)
#include "testUdp2RawConfig.moc"
