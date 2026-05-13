#include "wireGuardProtocolConfig.h"

#include <QJsonDocument>
#include <QJsonArray>

#include "../../../core/utils/protocolEnum.h"
#include "../../../core/protocols/protocolUtils.h"
#include "../../../core/utils/constants/configKeys.h"
#include "../../../core/utils/constants/protocolConstants.h"

using namespace amnezia;
using namespace ProtocolUtils;
namespace amnezia
{

QJsonObject WireGuardServerConfig::toJson() const
{
    QJsonObject obj;
    
    if (!port.isEmpty()) {
        obj[configKey::port] = port;
    }
    if (!transportProto.isEmpty()) {
        obj[configKey::transportProto] = transportProto;
    }
    if (!subnetAddress.isEmpty()) {
        obj[configKey::subnetAddress] = subnetAddress;
    }
    if (!subnetMask.isEmpty()) {
        obj[configKey::subnetMask] = subnetMask;
    }
    if (!subnetCidr.isEmpty()) {
        obj[configKey::subnetCidr] = subnetCidr;
    }
    if (!udp2rawPublicPort.isEmpty()) {
        obj[configKey::udp2rawPublicPort] = udp2rawPublicPort;
    }
    if (!udp2rawInternalPort.isEmpty()) {
        obj[configKey::udp2rawInternalPort] = udp2rawInternalPort;
    }
    if (!udp2rawPassword.isEmpty()) {
        obj[configKey::udp2rawPassword] = udp2rawPassword;
    }
    if (!udp2rawRawMode.isEmpty()) {
        obj[configKey::udp2rawRawMode] = udp2rawRawMode;
    }
    if (udp2rawImplementationVersion > 0) {
        obj[configKey::udp2rawImplementationVersion] = udp2rawImplementationVersion;
    }
    
    if (isThirdPartyConfig) {
        obj[configKey::isThirdPartyConfig] = isThirdPartyConfig;
    }
    
    return obj;
}

WireGuardServerConfig WireGuardServerConfig::fromJson(const QJsonObject& json)
{
    WireGuardServerConfig config;
    
    config.port = json.value(configKey::port).toString();
    config.transportProto = json.value(configKey::transportProto).toString();
    config.subnetAddress = json.value(configKey::subnetAddress).toString();
    config.subnetMask = json.value(configKey::subnetMask).toString();
    config.subnetCidr = json.value(configKey::subnetCidr).toString();
    config.udp2rawPublicPort = json.value(configKey::udp2rawPublicPort).toString();
    config.udp2rawInternalPort = json.value(configKey::udp2rawInternalPort).toString();
    config.udp2rawPassword = json.value(configKey::udp2rawPassword).toString();
    config.udp2rawRawMode = json.value(configKey::udp2rawRawMode).toString();
    config.udp2rawImplementationVersion = json.value(configKey::udp2rawImplementationVersion).toInt(0);
    
    config.isThirdPartyConfig = json.value(configKey::isThirdPartyConfig).toBool(false);
    
    return config;
}

bool WireGuardServerConfig::hasEqualServerSettings(const WireGuardServerConfig& other) const
{
    return subnetAddress == other.subnetAddress && port == other.port &&
           udp2rawPublicPort == other.udp2rawPublicPort &&
           udp2rawInternalPort == other.udp2rawInternalPort &&
           udp2rawPassword == other.udp2rawPassword &&
           udp2rawRawMode == other.udp2rawRawMode &&
           udp2rawImplementationVersion == other.udp2rawImplementationVersion;
}

QJsonObject WireGuardClientConfig::toJson() const
{
    QJsonObject obj;
    
    if (!nativeConfig.isEmpty()) {
        obj[configKey::config] = nativeConfig;
    }
    if (!hostName.isEmpty()) {
        obj[configKey::hostName] = hostName;
    }
    if (port > 0) {
        obj[configKey::port] = port;
    }
    if (!clientIp.isEmpty()) {
        obj[configKey::clientIp] = clientIp;
    }
    if (!clientPrivateKey.isEmpty()) {
        obj[configKey::clientPrivKey] = clientPrivateKey;
    }
    if (!clientPublicKey.isEmpty()) {
        obj[configKey::clientPubKey] = clientPublicKey;
    }
    if (!serverPublicKey.isEmpty()) {
        obj[configKey::serverPubKey] = serverPublicKey;
    }
    if (!presharedKey.isEmpty()) {
        obj[configKey::pskKey] = presharedKey;
    }
    if (!clientId.isEmpty()) {
        obj[configKey::clientId] = clientId;
    }
    
    if (!allowedIps.isEmpty()) {
        QJsonArray arr;
        for (const QString& ip : allowedIps) {
            arr.append(ip);
        }
        obj[configKey::allowedIps] = arr;
    }
    if (!persistentKeepAlive.isEmpty()) {
        obj[configKey::persistentKeepAlive] = persistentKeepAlive;
    }
    if (!mtu.isEmpty()) {
        obj[configKey::mtu] = mtu;
    }
    if (!udp2rawPublicPort.isEmpty()) {
        obj[configKey::udp2rawPublicPort] = udp2rawPublicPort;
    }
    if (!udp2rawInternalPort.isEmpty()) {
        obj[configKey::udp2rawInternalPort] = udp2rawInternalPort;
    }
    if (!udp2rawPassword.isEmpty()) {
        obj[configKey::udp2rawPassword] = udp2rawPassword;
    }
    if (!udp2rawRawMode.isEmpty()) {
        obj[configKey::udp2rawRawMode] = udp2rawRawMode;
    }
    if (!udp2rawRemoteHost.isEmpty()) {
        obj[configKey::udp2rawRemoteHost] = udp2rawRemoteHost;
    }
    if (!udp2rawRemotePort.isEmpty()) {
        obj[configKey::udp2rawRemotePort] = udp2rawRemotePort;
    }
    
    if (isObfuscationEnabled) {
        obj[configKey::isObfuscationEnabled] = isObfuscationEnabled;
    }
    
    return obj;
}

WireGuardClientConfig WireGuardClientConfig::fromJson(const QJsonObject& json)
{
    WireGuardClientConfig config;
    
    config.nativeConfig = json.value(configKey::config).toString();
    config.hostName = json.value(configKey::hostName).toString();
    config.port = json.value(configKey::port).toInt(0);
    config.clientIp = json.value(configKey::clientIp).toString();
    config.clientPrivateKey = json.value(configKey::clientPrivKey).toString();
    config.clientPublicKey = json.value(configKey::clientPubKey).toString();
    config.serverPublicKey = json.value(configKey::serverPubKey).toString();
    config.presharedKey = json.value(configKey::pskKey).toString();
    config.clientId = json.value(configKey::clientId).toString();
    
    QJsonArray allowedIpsArr = json.value(configKey::allowedIps).toArray();
    for (const QJsonValue& val : allowedIpsArr) {
        config.allowedIps.append(val.toString());
    }
    config.persistentKeepAlive = json.value(configKey::persistentKeepAlive).toString();
    config.mtu = json.value(configKey::mtu).toString();
    config.udp2rawPublicPort = json.value(configKey::udp2rawPublicPort).toString();
    config.udp2rawInternalPort = json.value(configKey::udp2rawInternalPort).toString();
    config.udp2rawPassword = json.value(configKey::udp2rawPassword).toString();
    config.udp2rawRawMode = json.value(configKey::udp2rawRawMode).toString();
    config.udp2rawRemoteHost = json.value(configKey::udp2rawRemoteHost).toString();
    config.udp2rawRemotePort = json.value(configKey::udp2rawRemotePort).toString();
    
    config.isObfuscationEnabled = json.value(configKey::isObfuscationEnabled).toBool(false);
    
    return config;
}

QJsonObject WireGuardProtocolConfig::toJson() const
{
    QJsonObject obj = serverConfig.toJson();
    
    if (clientConfig.has_value()) {
        QJsonObject clientJson = clientConfig->toJson();
        obj[configKey::lastConfig] = QString::fromUtf8(QJsonDocument(clientJson).toJson(QJsonDocument::Compact));
    }
    
    return obj;
}

WireGuardProtocolConfig WireGuardProtocolConfig::fromJson(const QJsonObject& json)
{
    WireGuardProtocolConfig config;
    
    config.serverConfig = WireGuardServerConfig::fromJson(json);
    
    QString lastConfigStr = json.value(configKey::lastConfig).toString();
    if (!lastConfigStr.isEmpty()) {
        QJsonDocument doc = QJsonDocument::fromJson(lastConfigStr.toUtf8());
        if (doc.isObject()) {
            config.clientConfig = WireGuardClientConfig::fromJson(doc.object());
        }
    }
    
    return config;
}

bool WireGuardProtocolConfig::hasClientConfig() const
{
    return clientConfig.has_value();
}

void WireGuardProtocolConfig::setClientConfig(const WireGuardClientConfig& config)
{
    clientConfig = config;
}

void WireGuardProtocolConfig::clearClientConfig()
{
    clientConfig.reset();
}

} // namespace amnezia
