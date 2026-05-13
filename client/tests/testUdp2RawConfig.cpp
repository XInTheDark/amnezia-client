#include <QJsonObject>
#include <QFile>
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

private:
    QString readScript(const QString &path)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) {
            QTest::qFail(qPrintable(QStringLiteral("Unable to open %1").arg(path)), __FILE__, __LINE__);
            return {};
        }
        return QString::fromUtf8(file.readAll());
    }

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
        protocolConfig.serverConfig.udp2rawImplementationVersion = protocols::udp2raw::nativeHostImplementationVersion;

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
        QCOMPARE(restoredProtocol->serverConfig.udp2rawImplementationVersion, protocols::udp2raw::nativeHostImplementationVersion);
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
        protocolConfig.serverConfig.udp2rawImplementationVersion = protocols::udp2raw::nativeHostImplementationVersion;

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
        QCOMPARE(restoredProtocol->serverConfig.udp2rawImplementationVersion, protocols::udp2raw::nativeHostImplementationVersion);
        QVERIFY(restoredProtocol->clientConfig.has_value());
        QCOMPARE(restoredProtocol->clientConfig->hostName, QStringLiteral("127.0.0.1"));
        QCOMPARE(restoredProtocol->clientConfig->port, 3333);
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemoteHost, QStringLiteral("64.235.43.101"));
        QCOMPARE(restoredProtocol->clientConfig->udp2rawRemotePort, QStringLiteral("8443"));
    }

    void testNativeHostServerScriptInvariants()
    {
        const QString wgConfigure = readScript(QStringLiteral(":/server_scripts/udp2raw_wireguard/configure_container.sh"));
        const QString awgConfigure = readScript(QStringLiteral(":/server_scripts/udp2raw_awg/configure_container.sh"));
        const QString removeScript = readScript(QStringLiteral(":/server_scripts/remove_container.sh"));

        for (const QString &script : { wgConfigure, awgConfigure }) {
            QVERIFY(script.contains(QStringLiteral("UDP2RAW_IMPL_VERSION=$IMPL_VERSION")));
            QVERIFY(script.contains(QStringLiteral("systemctl enable --now")));
            QVERIFY(script.contains(QStringLiteral("server_diagnostics.sh")));
            QVERIFY(script.contains(QStringLiteral("chown -R root:root \"$BASE_DIR\"")));
            QVERIFY(script.contains(QStringLiteral("-l \"0.0.0.0:$UDP2RAW_PUBLIC_PORT\"")));
            QVERIFY(script.contains(QStringLiteral("-r \"127.0.0.1:$UDP2RAW_INTERNAL_PORT\"")));
            QVERIFY(script.contains(QStringLiteral("-p tcp --dport \"$UDP2RAW_PUBLIC_PORT\" -j ACCEPT")));
            QVERIFY(script.contains(QStringLiteral("-p udp --dport \"$UDP2RAW_INTERNAL_PORT\" -j DROP")));
            QVERIFY(script.contains(QStringLiteral("net.ipv4.ip_forward=1")));
            QVERIFY(script.contains(QStringLiteral("MASQUERADE")));
            QVERIFY(!script.contains(QStringLiteral("docker run")));
            QVERIFY(!script.contains(QStringLiteral("docker exec")));
            QVERIFY(!script.contains(QStringLiteral("--cipher-mode none")));
            QVERIFY(!script.contains(QStringLiteral("--auth-mode none")));
            QVERIFY(!script.contains(QStringLiteral("--sock-buf")));
        }

        QVERIFY(wgConfigure.contains(QStringLiteral("IFACE=\"amnwg0\"")));
        QVERIFY(wgConfigure.contains(QStringLiteral("Address = $SERVER_INTERFACE_IP/$SUBNET_CIDR")));
        QVERIFY(awgConfigure.contains(QStringLiteral("IFACE=\"amnawg0\"")));
        QVERIFY(awgConfigure.contains(QStringLiteral("Address = $SERVER_INTERFACE_IP/$SUBNET_CIDR")));
        QVERIFY(removeScript.contains(QStringLiteral("sudo test -x /opt/amnezia/$CONTAINER_NAME/remove.sh")));
    }
};

QTEST_MAIN(TestUdp2RawConfig)
#include "testUdp2RawConfig.moc"
