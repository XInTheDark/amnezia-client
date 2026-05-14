#include <QJsonObject>
#include <QFile>
#include <QTest>

#include "core/models/containerConfig.h"
#include "core/models/serverConfig.h"
#include "core/models/protocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include "core/models/protocols/wireGuardProtocolConfig.h"
#include "core/controllers/connectionController.h"
#include "core/installers/awgInstaller.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "secureQSettings.h"

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
        protocolConfig.serverConfig.subnetAddress = QString::fromLatin1(protocols::udp2raw::defaultAwgSubnetAddress);
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
        QCOMPARE(restoredProtocol->serverConfig.subnetAddress, QStringLiteral("10.8.2.0"));
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

    void testAwgUdp2RawUsesSeparateDefaultSubnet()
    {
        AwgInstaller installer;
        const ContainerConfig containerConfig = installer.generateConfig(DockerContainer::Udp2RawAwg, 8445, TransportProto::Tcp);

        const auto *protocolConfig = containerConfig.getAwgProtocolConfig();
        QVERIFY(protocolConfig);
        QCOMPARE(protocolConfig->serverConfig.subnetAddress, QString::fromLatin1(protocols::udp2raw::defaultAwgSubnetAddress));
        QVERIFY(protocolConfig->serverConfig.subnetAddress != QString::fromLatin1(protocols::wireguard::defaultSubnetAddress));
    }

    void testUdp2RawConnectionDoesNotUseAmneziaDns()
    {
        SecureQSettings settings(QStringLiteral("AmneziaVPNTests"),
                                 QStringLiteral("Udp2RawConnectionDoesNotUseAmneziaDns"),
                                 this,
                                 false);
        settings.clearSettings();
        SecureServersRepository serversRepository(&settings);
        SecureAppSettingsRepository appSettingsRepository(&settings);
        appSettingsRepository.setPrimaryDns(QStringLiteral("9.9.9.9"));
        appSettingsRepository.setSecondaryDns(QStringLiteral("149.112.112.112"));

        VpnConnection vpnConnection(&serversRepository, &appSettingsRepository);
        ConnectionController controller(&serversRepository, &appSettingsRepository, &vpnConnection);

        WireGuardProtocolConfig protocolConfig;
        protocolConfig.serverConfig.udp2rawPublicPort = QStringLiteral("8443");
        protocolConfig.serverConfig.udp2rawInternalPort = QStringLiteral("51820");
        protocolConfig.serverConfig.udp2rawPassword = QStringLiteral("secret");
        protocolConfig.serverConfig.udp2rawRawMode = QString::fromLatin1(protocols::udp2raw::defaultRawMode);
        protocolConfig.serverConfig.udp2rawImplementationVersion = protocols::udp2raw::nativeHostImplementationVersion;

        WireGuardClientConfig clientConfig;
        clientConfig.nativeConfig = QStringLiteral("DNS = $PRIMARY_DNS, $SECONDARY_DNS");
        clientConfig.hostName = QStringLiteral("142.91.102.48");
        clientConfig.port = 8443;
        clientConfig.clientIp = QStringLiteral("10.8.1.2");
        clientConfig.clientPrivateKey = QStringLiteral("client-private");
        clientConfig.clientPublicKey = QStringLiteral("client-public");
        clientConfig.serverPublicKey = QStringLiteral("server-public");
        clientConfig.presharedKey = QStringLiteral("psk");
        clientConfig.clientId = QStringLiteral("client-public");
        clientConfig.allowedIps = QStringList { QStringLiteral("0.0.0.0/0"), QStringLiteral("::/0") };
        clientConfig.udp2rawPublicPort = protocolConfig.serverConfig.udp2rawPublicPort;
        clientConfig.udp2rawInternalPort = protocolConfig.serverConfig.udp2rawInternalPort;
        clientConfig.udp2rawPassword = protocolConfig.serverConfig.udp2rawPassword;
        clientConfig.udp2rawRawMode = protocolConfig.serverConfig.udp2rawRawMode;
        clientConfig.udp2rawRemoteHost = QStringLiteral("142.91.102.48");
        clientConfig.udp2rawRemotePort = protocolConfig.serverConfig.udp2rawPublicPort;
        protocolConfig.setClientConfig(clientConfig);

        ContainerConfig containerConfig;
        containerConfig.container = DockerContainer::Udp2RawWireGuard;
        containerConfig.protocolConfig = protocolConfig;

        SelfHostedServerConfig selfHostedServer;
        selfHostedServer.hostName = QStringLiteral("142.91.102.48");
        selfHostedServer.description = QStringLiteral("UDP2Raw test");
        selfHostedServer.defaultContainer = DockerContainer::Udp2RawWireGuard;
        selfHostedServer.containers.insert(DockerContainer::Udp2RawWireGuard, containerConfig);

        const QJsonObject vpnConfig = controller.createConnectionConfiguration(
            { QString::fromLatin1(protocols::dns::amneziaDnsIp), QStringLiteral("1.0.0.1") },
            ServerConfig { selfHostedServer },
            containerConfig,
            DockerContainer::Udp2RawWireGuard);

        QCOMPARE(vpnConfig.value(configKey::dns1).toString(), QStringLiteral("9.9.9.9"));
        QCOMPARE(vpnConfig.value(configKey::dns2).toString(), QStringLiteral("149.112.112.112"));

        const QJsonObject wgConfig = vpnConfig.value(ProtocolUtils::key_proto_config_data(Proto::WireGuard)).toObject();
        const QString nativeConfig = wgConfig.value(configKey::config).toString();
        QVERIFY(nativeConfig.contains(QStringLiteral("DNS = 9.9.9.9, 149.112.112.112")));
        QVERIFY(!nativeConfig.contains(QString::fromLatin1(protocols::dns::amneziaDnsIp)));

        settings.clearSettings();
    }

    void testUdp2RawConnectionClampsMtu()
    {
        SecureQSettings settings(QStringLiteral("AmneziaVPNTests"),
                                 QStringLiteral("Udp2RawConnectionClampsMtu"),
                                 this,
                                 false);
        settings.clearSettings();
        SecureServersRepository serversRepository(&settings);
        SecureAppSettingsRepository appSettingsRepository(&settings);

        VpnConnection vpnConnection(&serversRepository, &appSettingsRepository);
        ConnectionController controller(&serversRepository, &appSettingsRepository, &vpnConnection);

        WireGuardProtocolConfig protocolConfig;
        protocolConfig.serverConfig.udp2rawPublicPort = QStringLiteral("8443");
        protocolConfig.serverConfig.udp2rawInternalPort = QStringLiteral("51820");
        protocolConfig.serverConfig.udp2rawPassword = QStringLiteral("secret");
        protocolConfig.serverConfig.udp2rawRawMode = QString::fromLatin1(protocols::udp2raw::defaultRawMode);
        protocolConfig.serverConfig.udp2rawImplementationVersion = protocols::udp2raw::nativeHostImplementationVersion;

        WireGuardClientConfig clientConfig;
        clientConfig.hostName = QStringLiteral("142.91.102.48");
        clientConfig.port = 8443;
        clientConfig.clientIp = QStringLiteral("10.8.1.2");
        clientConfig.clientPrivateKey = QStringLiteral("client-private");
        clientConfig.clientPublicKey = QStringLiteral("client-public");
        clientConfig.serverPublicKey = QStringLiteral("server-public");
        clientConfig.presharedKey = QStringLiteral("psk");
        clientConfig.clientId = QStringLiteral("client-public");
        clientConfig.allowedIps = QStringList { QStringLiteral("0.0.0.0/0") };
        clientConfig.mtu = QStringLiteral("1376");
        clientConfig.udp2rawPublicPort = protocolConfig.serverConfig.udp2rawPublicPort;
        clientConfig.udp2rawInternalPort = protocolConfig.serverConfig.udp2rawInternalPort;
        clientConfig.udp2rawPassword = protocolConfig.serverConfig.udp2rawPassword;
        clientConfig.udp2rawRawMode = protocolConfig.serverConfig.udp2rawRawMode;
        clientConfig.udp2rawRemoteHost = QStringLiteral("142.91.102.48");
        clientConfig.udp2rawRemotePort = protocolConfig.serverConfig.udp2rawPublicPort;
        protocolConfig.setClientConfig(clientConfig);

        ContainerConfig containerConfig;
        containerConfig.container = DockerContainer::Udp2RawWireGuard;
        containerConfig.protocolConfig = protocolConfig;

        SelfHostedServerConfig selfHostedServer;
        selfHostedServer.hostName = QStringLiteral("142.91.102.48");
        selfHostedServer.description = QStringLiteral("UDP2Raw MTU test");
        selfHostedServer.defaultContainer = DockerContainer::Udp2RawWireGuard;
        selfHostedServer.containers.insert(DockerContainer::Udp2RawWireGuard, containerConfig);

        const QJsonObject vpnConfig = controller.createConnectionConfiguration(
            { QStringLiteral("1.1.1.1"), QStringLiteral("1.0.0.1") },
            ServerConfig { selfHostedServer },
            containerConfig,
            DockerContainer::Udp2RawWireGuard);

        const QJsonObject wgConfig = vpnConfig.value(ProtocolUtils::key_proto_config_data(Proto::WireGuard)).toObject();
        QCOMPARE(wgConfig.value(configKey::mtu).toString(), QString::fromLatin1(protocols::udp2raw::defaultMtu));

        settings.clearSettings();
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
            QVERIFY(script.contains(QStringLiteral("net.ipv4.conf.all.rp_filter=0")));
            QVERIFY(script.contains(QStringLiteral("net.ipv4.conf.default.rp_filter=0")));
            QVERIFY(script.contains(QStringLiteral("net.ipv4.conf.$UDP2RAW_INTERFACE.rp_filter=0")));
            QVERIFY(script.contains(QStringLiteral("MASQUERADE")));
            QVERIFY(!script.contains(QStringLiteral("! -o \"$UDP2RAW_INTERFACE\" -j MASQUERADE")));
            QVERIFY(!script.contains(QStringLiteral("AMN_U2R_")));
            QVERIFY(!script.contains(QStringLiteral("iptables -N")));
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
        QVERIFY(removeScript.contains(QStringLiteral("exit 0")));
    }
};

QTEST_MAIN(TestUdp2RawConfig)
#include "testUdp2RawConfig.moc"
