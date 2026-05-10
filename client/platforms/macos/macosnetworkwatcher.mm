/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "macosnetworkwatcher.h"
#include "leakdetector.h"
#include "logger.h"

#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QTimer>
#include <iostream>
#include <pthread.h>

#import <CoreWLAN/CoreWLAN.h>
#import <Network/Network.h>

namespace
{
    Logger logger("MacOSNetworkWatcher");
    constexpr int kPathStabilizeDelayMs = 1500;
    constexpr int kPathEventFallbackMs = 10000;
}

// Global variables for CFRunLoop thread
static pthread_t g_powerThread;
static CFRunLoopRef g_powerRunLoop = nullptr;
static bool g_shouldStopPowerThread = false;
static PowerNotificationsListener *g_powerListener = nullptr;

// Thread function for dedicated CFRunLoop
void *powerMonitoringThread(void *arg)
{
    logger.debug() << "Power monitoring thread started";

    PowerNotificationsListener *listener = static_cast<PowerNotificationsListener *>(arg);

    // Get the runloop for this thread
    g_powerRunLoop = CFRunLoopGetCurrent();

    // Register for power notifications in this thread
    listener->registerForNotifications();

    // Run the CFRunLoop - this will block until CFRunLoopStop is called
    while (!g_shouldStopPowerThread) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, true);
    }

    // Cleanup
    listener->cleanup();
    g_powerRunLoop = nullptr;

    logger.debug() << "Power monitoring thread finished";
    return nullptr;
}

@interface MacOSNetworkWatcherDelegate : NSObject <CWEventDelegate> {
    MacOSNetworkWatcher *m_watcher;
}
@end

@implementation MacOSNetworkWatcherDelegate

- (id)initWithObject:(MacOSNetworkWatcher *)watcher
{
    self = [super init];
    if (self) {
        m_watcher = watcher;
    }
    return self;
}

- (void)bssidDidChangeForWiFiInterfaceWithName:(NSString *)interfaceName
{
    logger.debug() << "BSSID changed!" << QString::fromNSString(interfaceName);

    if (m_watcher) {
        m_watcher->checkInterface();
        m_watcher->scheduleNetworkChanged(QString::fromNSString(interfaceName));
    }
}

@end

void PowerNotificationsListener::registerForNotifications()
{
    logger.debug() << "Registering for system power notifications in dedicated thread";

    rootPowerDomain = IORegisterForSystemPower(this, &notifyPortRef, sleepWakeupCallBack, &notifierObj);
    if (rootPowerDomain == IO_OBJECT_NULL) {
        logger.error() << "Failed to register for system power notifications!";
        return;
    }

    // Add the notification port to the current runloop (dedicated thread)
    CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPortRef), kCFRunLoopCommonModes);
    logger.debug() << "Power notifications registered successfully";
}

void PowerNotificationsListener::cleanup()
{
    if (notifyPortRef != nullptr) {
        CFRunLoopRemoveSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPortRef),
                              kCFRunLoopCommonModes);
        IONotificationPortDestroy(notifyPortRef);
        notifyPortRef = nullptr;
    }

    if (notifierObj != IO_OBJECT_NULL) {
        IODeregisterForSystemPower(&notifierObj);
        notifierObj = IO_OBJECT_NULL;
    }

    if (rootPowerDomain != IO_OBJECT_NULL) {
        IOServiceClose(rootPowerDomain);
        rootPowerDomain = IO_OBJECT_NULL;
    }
}

void PowerNotificationsListener::sleepWakeupCallBack(void *refParam, io_service_t service, natural_t messageType,
                                                     void *messageArgument)
{
    Q_UNUSED(service)

    auto listener = static_cast<PowerNotificationsListener *>(refParam);

    logger.debug() << "Power callback received, messageType:" << messageType;
    switch (messageType) {
    case kIOMessageCanSystemSleep:
        /* Idle sleep is about to kick in. This message will not be sent for forced sleep.
         * Applications have a chance to prevent sleep by calling IOCancelPowerChange.
         * Most applications should not prevent idle sleep. Power Management waits up to
         * 30 seconds for you to either allow or deny idle sleep. If you don’t acknowledge
         * this power change by calling either IOAllowPowerChange or IOCancelPowerChange,
         * the system will wait 30 seconds then go to sleep.
         */

        logger.debug() << "System power message: can system sleep?";

        // Uncomment to cancel idle sleep
        // IOCancelPowerChange(thiz->rootPowerDomain, reinterpret_cast<long>(messageArgument));

        // Allow idle sleep
        IOAllowPowerChange(listener->rootPowerDomain, reinterpret_cast<long>(messageArgument));
        break;

    case kIOMessageSystemWillNotSleep:
        /* Announces that the system has retracted a previous attempt to sleep; it
         * follows `kIOMessageCanSystemSleep`.
         */
        logger.debug() << "System power message: system will NOT sleep.";
        break;

    case kIOMessageSystemWillSleep:
        /* The system WILL go to sleep. If you do not call IOAllowPowerChange or
         * IOCancelPowerChange to acknowledge this message, sleep will be delayed by
         * 30 seconds.
         *
         * NOTE: If you call IOCancelPowerChange to deny sleep it returns kIOReturnSuccess,
         * however the system WILL still go to sleep.
         */

        logger.debug() << "System power message: system WILL sleep";
        IOAllowPowerChange(listener->rootPowerDomain, reinterpret_cast<long>(messageArgument));
        break;

    case kIOMessageSystemWillPowerOn:
        /* Announces that the system is beginning to power the device tree; most devices
         * are still unavailable at this point.
         */
        /* From the documentation:
         *
         * - kIOMessageSystemWillPowerOn is delivered at early wakeup time, before most hardware
         * has been powered on. Be aware that any attempts to access disk, network, the display,
         * etc. may result in errors or blocking your process until those resources become
         * available.
         *
         * So we do NOT log this event.
         */
        break;

    case kIOMessageSystemHasPoweredOn:
        /* Announces that the system and its devices have woken up. */
        logger.debug() << "System has powered on - scheduling wakeup signal after path is ready";
        if (listener->m_watcher) {
            QMetaObject::invokeMethod(
                    listener->m_watcher, [watcher = listener->m_watcher]() { watcher->scheduleWakeup(); },
                    Qt::QueuedConnection);
        }
        break;

    default:
        logger.debug() << "System power message: other event: " << messageType;
        /* Not a system sleep and wake notification. */
        break;
    }
}

MacOSNetworkWatcher::MacOSNetworkWatcher(QObject *parent) : IOSNetworkWatcher(parent), m_powerlistener(this)
{
    MZ_COUNT_CTOR(MacOSNetworkWatcher);
}

MacOSNetworkWatcher::~MacOSNetworkWatcher()
{
    MZ_COUNT_DTOR(MacOSNetworkWatcher);

    // Stop the dedicated power monitoring thread
    if (g_powerListener) {
        logger.debug() << "Stopping dedicated power monitoring thread";
        g_shouldStopPowerThread = true;

        if (g_powerRunLoop) {
            CFRunLoopStop(g_powerRunLoop);
        }

        // Wait for thread to finish
        pthread_join(g_powerThread, nullptr);
        g_powerListener = nullptr;
    }

    stopPathMonitor();

    if (m_delegate) {
        if (CWWiFiClient *client = CWWiFiClient.sharedWiFiClient) {
            [client stopMonitoringAllEventsAndReturnError:nullptr];
        } else {
            logger.warning() << "Unable to retrieve the CWWiFiClient shared instance during cleanup";
        }

        [static_cast<MacOSNetworkWatcherDelegate *>(m_delegate) dealloc];
        m_delegate = nullptr;
    }
}

void MacOSNetworkWatcher::start()
{
    NetworkWatcherImpl::start();

    startPathMonitor();
    checkInterface();

    if (m_delegate) {
        logger.debug() << "Delegate already registered";
        return;
    }

    // Start dedicated power monitoring thread with CFRunLoop
    if (!g_powerListener) {
        g_powerListener = &m_powerlistener;
        g_shouldStopPowerThread = false;

        int result = pthread_create(&g_powerThread, nullptr, powerMonitoringThread, &m_powerlistener);
        if (result != 0) {
            logger.error() << "Failed to create power monitoring thread:" << result;
            g_powerListener = nullptr;
        } else {
            logger.debug() << "Power monitoring enabled";
        }
    }

    CWWiFiClient *client = CWWiFiClient.sharedWiFiClient;
    if (!client) {
        logger.error() << "Unable to retrieve the CWWiFiClient shared instance";
        return;
    }

    logger.debug() << "Registering delegate";
    m_delegate = [[MacOSNetworkWatcherDelegate alloc] initWithObject:this];
    [client setDelegate:static_cast<MacOSNetworkWatcherDelegate *>(m_delegate)];
    [client startMonitoringEventWithType:CWEventTypeBSSIDDidChange error:nullptr];

    logger.debug() << "MacOSNetworkWatcher started successfully";
}

void MacOSNetworkWatcher::startPathMonitor()
{
    if (m_pathMonitor != nullptr) {
        return;
    }

    auto pathMonitor = nw_path_monitor_create();
    m_pathMonitor = pathMonitor;
    nw_path_monitor_set_queue(pathMonitor, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    QPointer<MacOSNetworkWatcher> watcher(this);
    nw_path_monitor_set_update_handler(pathMonitor, ^(nw_path_t _Nonnull path) {
        if (!watcher) {
            return;
        }

        const bool pathReady = isSatisfiedExternalPath(path);
        const QString signature = pathSignature(path);

        QMetaObject::invokeMethod(
                watcher,
                [watcher, pathReady, signature]() {
                    if (!watcher) {
                        return;
                    }

                    const bool hadInitialPath = watcher->m_hasInitialPath;
                    const bool changed = watcher->m_lastPathSignature != signature;

                    watcher->m_hasInitialPath = true;
                    watcher->m_hasSatisfiedPath = pathReady;
                    watcher->m_lastPathSignature = signature;

                    if (pathReady && hadInitialPath && changed) {
                        logger.debug() << "Network path changed:" << signature;
                        emit watcher->networkChanged(signature);
                    }

                    if (pathReady) {
                        watcher->maybeEmitPendingPathEvent();
                    }
                },
                Qt::QueuedConnection);
    });
    nw_path_monitor_start(pathMonitor);
}

void MacOSNetworkWatcher::stopPathMonitor()
{
    if (m_pathMonitor == nullptr) {
        return;
    }

    auto pathMonitor = static_cast<nw_path_monitor_t>(m_pathMonitor);
    nw_path_monitor_cancel(pathMonitor);
    nw_release(pathMonitor);
    m_pathMonitor = nullptr;
}

void MacOSNetworkWatcher::scheduleWakeup()
{
    if (!isActive()) {
        return;
    }

    m_pendingWakeup = true;
    QTimer::singleShot(kPathStabilizeDelayMs, this, [this]() { maybeEmitPendingPathEvent(); });
    QTimer::singleShot(kPathEventFallbackMs, this, [this]() {
        if (!m_pendingWakeup) {
            return;
        }

        logger.debug() << "Emitting wakeup after path-ready fallback timeout";
        m_pendingWakeup = false;
        emit wakeup();
    });
}

void MacOSNetworkWatcher::scheduleNetworkChanged(const QString &reason)
{
    if (!isActive()) {
        return;
    }

    m_pendingNetworkChangedReason = reason;
    QTimer::singleShot(kPathStabilizeDelayMs, this, [this]() { maybeEmitPendingPathEvent(); });
    QTimer::singleShot(kPathEventFallbackMs, this, [this, reason]() {
        if (m_pendingNetworkChangedReason != reason) {
            return;
        }

        logger.debug() << "Emitting networkChanged after path-ready fallback timeout";
        m_pendingNetworkChangedReason.clear();
        emit networkChanged(reason);
    });
}

void MacOSNetworkWatcher::maybeEmitPendingPathEvent()
{
    if (!m_hasSatisfiedPath) {
        return;
    }

    if (m_pendingWakeup) {
        logger.debug() << "Emitting wakeup after network path became ready";
        m_pendingWakeup = false;
        emit wakeup();
    }

    if (!m_pendingNetworkChangedReason.isEmpty()) {
        const QString reason = m_pendingNetworkChangedReason;
        logger.debug() << "Emitting networkChanged after network path became ready:" << reason;
        m_pendingNetworkChangedReason.clear();
        emit networkChanged(reason);
    }
}

bool MacOSNetworkWatcher::isSatisfiedExternalPath(void *rawPath)
{
    auto path = static_cast<nw_path_t>(rawPath);
    if (path == nil || nw_path_get_status(path) != nw_path_status_satisfied) {
        return false;
    }

    return nw_path_uses_interface_type(path, nw_interface_type_wifi)
            || nw_path_uses_interface_type(path, nw_interface_type_wired)
            || nw_path_uses_interface_type(path, nw_interface_type_cellular);
}

QString MacOSNetworkWatcher::pathSignature(void *rawPath)
{
    auto path = static_cast<nw_path_t>(rawPath);
    if (path == nil) {
        return QStringLiteral("path:nil");
    }

    QStringList parts;
    parts << QStringLiteral("status:%1").arg(static_cast<int>(nw_path_get_status(path)));
    parts << QStringLiteral("wifi:%1").arg(nw_path_uses_interface_type(path, nw_interface_type_wifi));
    parts << QStringLiteral("wired:%1").arg(nw_path_uses_interface_type(path, nw_interface_type_wired));
    parts << QStringLiteral("cellular:%1").arg(nw_path_uses_interface_type(path, nw_interface_type_cellular));
    parts << QStringLiteral("expensive:%1").arg(nw_path_is_expensive(path));
    if (@available(macOS 10.15, *)) {
        parts << QStringLiteral("constrained:%1").arg(nw_path_is_constrained(path));
    }
    return parts.join('|');
}

void MacOSNetworkWatcher::checkInterface()
{
    logger.debug() << "Checking interface";

    if (!isActive()) {
        logger.debug() << "Feature disabled";
        return;
    }

    // Use wdutil to get reliable WiFi information
    QProcess process;
    process.start("wdutil", QStringList() << "info");
    if (!process.waitForFinished(5000)) {
        process.kill();
        process.waitForFinished(1000);
        logger.debug() << "wdutil timed out";
        return;
    }

    QString output = process.readAllStandardOutput();
    QString errorOutput = process.readAllStandardError();

    logger.debug() << "wdutil exit code:" << process.exitCode();

    if (process.exitCode() != 0) {
        logger.debug() << "wdutil failed with exit code:" << process.exitCode();
        return;
    }

    // Parse wdutil output to find WiFi connection info
    QStringList lines = output.split('\n');
    QString ssid, interfaceName, security;
    bool wifiSectionFound = false;

    for (int i = 0; i < lines.size(); i++) {
        QString trimmedLine = lines[i].trimmed();

        if (trimmedLine == "WIFI") {
            wifiSectionFound = true;
            continue;
        }

        if (wifiSectionFound) {
            // Stop parsing when we reach next section header (all caps after separator line)
            if (trimmedLine.startsWith("————————")) {
                if (i + 1 < lines.size()) {
                    QString nextLine = lines[i + 1].trimmed();
                    if (!nextLine.isEmpty() && nextLine.length() > 2 && nextLine.toUpper() == nextLine
                        && nextLine != "WIFI") {
                        break;
                    }
                }
                continue; // Skip separator lines
            }

            if (trimmedLine.startsWith("Interface Name")) {
                QStringList parts = trimmedLine.split(":");
                if (parts.size() >= 2) {
                    interfaceName = parts[1].trimmed();
                }
            } else if (trimmedLine.startsWith("SSID")) {
                QStringList parts = trimmedLine.split(":");
                if (parts.size() >= 2) {
                    ssid = parts[1].trimmed();
                }
            } else if (trimmedLine.startsWith("Security")) {
                QStringList parts = trimmedLine.split(":");
                if (parts.size() >= 2) {
                    security = parts[1].trimmed();
                }
            }
        }
    }

    if (!ssid.isEmpty() && !interfaceName.isEmpty()) {
        logger.debug() << "Found active WiFi connection on" << interfaceName << "SSID:" << ssid
                       << "Security:" << security;
    } else {
        logger.debug() << "No active WiFi connection found";
    }
}
