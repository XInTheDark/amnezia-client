#ifndef WIREGUARDPROTOCOLCONFIG_H
#define WIREGUARDPROTOCOLCONFIG_H

#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <optional>

namespace amnezia
{

struct WireGuardServerConfig {
    QString port;
    QString transportProto;
    QString subnetAddress;
    QString subnetMask;
    QString subnetCidr;
    QString udp2rawPublicPort;
    QString udp2rawInternalPort;
    QString udp2rawPassword;
    QString udp2rawRawMode;
    bool isThirdPartyConfig = false;
    
    QJsonObject toJson() const;
    static WireGuardServerConfig fromJson(const QJsonObject& json);
    
    bool hasEqualServerSettings(const WireGuardServerConfig& other) const;
};

struct WireGuardClientConfig {
    QString nativeConfig;
    QString hostName;
    int port;
    QString clientIp;
    QString clientPrivateKey;
    QString clientPublicKey;
    QString serverPublicKey;
    QString presharedKey;
    QString clientId;
    QStringList allowedIps;
    QString persistentKeepAlive;
    QString mtu;
    QString udp2rawPublicPort;
    QString udp2rawInternalPort;
    QString udp2rawPassword;
    QString udp2rawRawMode;
    QString udp2rawRemoteHost;
    QString udp2rawRemotePort;
    bool isObfuscationEnabled = false;
    
    QJsonObject toJson() const;
    static WireGuardClientConfig fromJson(const QJsonObject& json);
};

struct WireGuardProtocolConfig {
    WireGuardServerConfig serverConfig;
    std::optional<WireGuardClientConfig> clientConfig;
    
    QJsonObject toJson() const;
    static WireGuardProtocolConfig fromJson(const QJsonObject& json);
    
    bool hasClientConfig() const;
    void setClientConfig(const WireGuardClientConfig& config);
    void clearClientConfig();
};

} // namespace amnezia

#endif // WIREGUARDPROTOCOLCONFIG_H
