/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "macospingsender.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/errno.h>
#include <unistd.h>

#include <QSocketNotifier>
#include <QtEndian>

#include "leakdetector.h"
#include "logger.h"

namespace {

Logger logger("MacOSPingSender");

int identifier() { return (getpid() & 0xFFFF); }

};  // namespace

MacOSPingSender::MacOSPingSender(const QHostAddress& source, QObject* parent)
    : PingSender(parent) {
  MZ_COUNT_CTOR(MacOSPingSender);

  if (getuid()) {
    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  } else {
    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  }
  if (m_socket < 0) {
    logger.error() << "Socket creation failed";
    return;
  }

  quint32 ipv4addr = INADDR_ANY;
  if (!source.isNull()) {
    ipv4addr = source.toIPv4Address();
  }
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_len = sizeof(addr);
  addr.sin_addr.s_addr = qToBigEndian<quint32>(ipv4addr);

  if (bind(m_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    logger.error() << "bind error:" << strerror(errno);
    return;
  }

  m_notifier = new QSocketNotifier(m_socket, QSocketNotifier::Read, this);
  connect(m_notifier, &QSocketNotifier::activated, this,
          &MacOSPingSender::socketReady);
  m_valid = true;
}

MacOSPingSender::~MacOSPingSender() {
  MZ_COUNT_DTOR(MacOSPingSender);
  if (m_socket >= 0) {
    close(m_socket);
  }
}

bool MacOSPingSender::isValid() { return m_valid; }

void MacOSPingSender::sendPing(const QHostAddress& dest, quint16 sequence) {
  if (!m_valid) {
    logger.error() << "Attempted to send ping with invalid socket.";
    emit criticalPingError();
    return;
  }

  quint32 ipv4dest = dest.toIPv4Address();
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_len = sizeof(addr);
  addr.sin_addr.s_addr = qToBigEndian<quint32>(ipv4dest);

  struct icmp packet;
  bzero(&packet, sizeof packet);
  packet.icmp_type = ICMP_ECHO;
  packet.icmp_id = identifier();
  packet.icmp_seq = htons(sequence);
  packet.icmp_cksum = inetChecksum(&packet, sizeof(packet));

  if (sendto(m_socket, (char*)&packet, sizeof(packet), MSG_NOSIGNAL,
             (struct sockaddr*)&addr, sizeof(addr)) != sizeof(packet)) {
    logger.error() << "ping sending failed:" << strerror(errno);
    emit criticalPingError();
    return;
  }
}

void MacOSPingSender::socketReady() {
  struct msghdr msg;
  bzero(&msg, sizeof(msg));

  struct sockaddr_in addr;
  msg.msg_name = (caddr_t)&addr;
  msg.msg_namelen = sizeof(addr);

  struct iovec iov;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  u_char packet[IP_MAXPACKET];
  iov.iov_base = packet;
  iov.iov_len = IP_MAXPACKET;

  ssize_t rc = recvmsg(m_socket, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (rc <= 0) {
    logger.error() << "Recvmsg failed:" << strerror(errno);
    return;
  }

  const struct icmp* icmp = nullptr;
  ssize_t icmpLength = rc;

  if (rc >= static_cast<ssize_t>(sizeof(struct ip))) {
    struct ip* ip = (struct ip*)packet;
    const int hlen = ip->ip_hl << 2;
    if (ip->ip_v == 4 && hlen >= static_cast<int>(sizeof(struct ip)) &&
        rc >= hlen + static_cast<int>(ICMP_MINLEN)) {
      icmp = (struct icmp*)(((char*)packet) + hlen);
      icmpLength = rc - hlen;
    }
  }

  if (!icmp) {
    if (rc < static_cast<ssize_t>(ICMP_MINLEN)) {
      logger.error() << "Received short ICMP packet";
      return;
    }
    icmp = (struct icmp*)packet;
  }

  if (icmpLength < static_cast<ssize_t>(ICMP_MINLEN)) {
    logger.error() << "Received short ICMP payload";
    return;
  }

  const bool identifierMatches = icmp->icmp_id == identifier();
  const bool datagramSocketOwnsReplies = getuid() != 0;

  if (icmp->icmp_type == ICMP_ECHOREPLY &&
      (identifierMatches || datagramSocketOwnsReplies)) {
    emit recvPing(ntohs(icmp->icmp_seq));
  }
}
