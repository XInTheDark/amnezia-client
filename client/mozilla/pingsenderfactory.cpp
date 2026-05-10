/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "pingsenderfactory.h"

#include <QtGlobal>

#if defined(MZ_LINUX) || defined(MZ_ANDROID) || defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
    #  include "platforms/linux/linuxpingsender.h"
#elif defined(MZ_MACOS) || defined(MZ_IOS) || defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    #  include "platforms/macos/macospingsender.h"
#elif defined(MZ_WINDOWS) || defined(Q_OS_WINDOWS)
    #  include "platforms/windows/windowspingsender.h"
#elif defined(MZ_WASM) || defined(UNIT_TEST)
    #  include "platforms/dummy/dummypingsender.h"
#else
    #  error "Unsupported platform"
#endif

PingSender* PingSenderFactory::create(const QHostAddress& source,
                                      QObject* parent) {
#if defined(MZ_LINUX) || defined(MZ_ANDROID) || defined(Q_OS_LINUX) || defined(Q_OS_ANDROID)
    return new LinuxPingSender(source, parent);
#elif defined(MZ_MACOS) || defined(MZ_IOS) || defined(Q_OS_MACOS) || defined(Q_OS_IOS)
    return new MacOSPingSender(source, parent);
#elif defined(MZ_WINDOWS) || defined(Q_OS_WINDOWS)
    return new WindowsPingSender(source, parent);
#else
    return new DummyPingSender(source, parent);
#endif
}
