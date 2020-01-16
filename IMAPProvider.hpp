/*
 * Copyright [2020] <Zachary Tipnis> – All Rights Reserved
 *
 * The use (including but not limited to modification and
 * distribution) of this source file and its contents shall
 * be governed by the terms of the MIT License.
 *
 * You should have received a copy of the MIT License with
 * this file. If not, please write to "zatipnis@icloud.com"
 * or visit: https://zacharytipnis.com
 *
 */

#include <tls.h>

#include <SocketPool.hpp>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <boost/log/trivial.hpp>

#include "ClientStateModel.hpp"
#include "ConfigModel.hpp"
#include "Helpers.hpp"
#include "WordList.hpp"


#ifndef __IMAP_PROVIDERS__
#define __IMAP_PROVIDERS__

namespace IMAPProvider {
template <class AuthP, class DataP>
class IMAPProvider : public Pollster::Handler {
 private:
  const ConfigModel& config;
  static std::map<int, ClientStateModel<AuthP> > states;
  struct tls* tls;
  struct tls_config* t_conf = tls_config_new();
  // ANY STATE
  void CAPABILITY(int rfd, const std::string& tag) const;
  void NOOP(int rfd, const std::string& tag) const {
    OK(rfd, tag, "NOOP executed successfully");
  }
  void LOGOUT(int rfd, const std::string& tag) const;
  // UNAUTHENTICATED
  void STARTTLS(int rfd, const std::string& tag) const;
  void AUTHENTICATE(int rfd, const std::string& tag, const std::string&) const;
  void LOGIN(int rfd, const std::string& tag, const std::string&, const std::string&) const;
  // AUTENTICATED
  void SELECT(int rfd, const std::string& tag, const std::string&) const;
  void EXAMINE(int rfd, const std::string& tag, const std::string&) const;
  void CREATE(int rfd, const std::string& tag, const std::string&) const;
  void DELETE(int rfd, const std::string& tag, const std::string&) const;
  void RENAME(int rfd, const std::string& tag, const std::string& mailbox,
              const std::string& name) const;
  void SUBSCRIBE(int rfd, const std::string& tag, const std::string& mailbox) const;
  void UNSUBSCRIBE(int rfd, const std::string& tag, const std::string& mailbox) const;
  void LIST(int rfd, const std::string& tag, const std::string& reference,
            const std::string& name) const;
  void LSUB(int rfd, const std::string& tag, const std::string& reference,
            const std::string& name) const;
  void STATUS(int rfd, const std::string& tag, const std::string& mailbox,
              const std::string& datareq) const;
  void APPEND(int rfd, const std::string& tag, const std::string& mailbox, const std::string& flags,
              const std::string& msgsize) const;
  // SELECTED
  void CHECK(int rfd, const std::string& tag) const;
  void CLOSE(int rfd, const std::string& tag) const;
  void UNSELECT(int rfd, const std::string& tag) const;
  void EXPUNGE(int rfd, const std::string& tag) const;
  void SEARCH(int rfd, const std::string& tag) const;
  void STORE(int rfd, const std::string& tag) const;
  void COPY(int rfd, const std::string& tag) const;
  void UID(int rfd, const std::string& tag) const;
  static void newDataAvailable(int rfd, const std::vector<std::string>& data) {
    for (const std::string& d : data) respond(rfd, "*", "", d);
  }

  std::pair<size_t, const std::string> receive(int fd) const {
    std::string data(8193, 0);
    int rcvd;
    if (states[fd].state() != UNENC) {
      rcvd = tls_read(states[fd].tls, &data[0], 8912);
    } else {
      rcvd = recv(fd, &data[0], 8192, MSG_DONTWAIT);
    }
    data.resize(rcvd);
    return {rcvd, data.c_str()};
  }

  // RESPONSES
  static inline void respond(int rfd, const std::string& tag, const std::string& code,
                             const std::string& message) {
    std::stringstream msg;
    msg << tag << " " << code << " " << message << std::endl;
    if (states[rfd].tls == NULL) {
      sendMsg(rfd, msg.str());
    } else {
      sendMsg(states[rfd].tls, msg.str());
    }
  }

  void OK(int rfd, const std::string& tag, const std::string& message) const {
    respond(rfd, tag, "OK", message + " " + states[rfd].get_uuid());
  }
  void NO(int rfd, const std::string& tag, const std::string& message) const {
    respond(rfd, tag, "NO", message + " " + states[rfd].get_uuid());
  }
  void BAD(int rfd, const std::string& tag, const std::string& message) const {
    respond(rfd, tag, "BAD", message + " " + states[rfd].get_uuid());
  }
  void PREAUTH(int rfd, const std::string& tag, const std::string& message) const {
    respond(rfd, tag, "PREAUTH", message + " " + states[rfd].get_uuid());
  }
  void BYE(int rfd, const std::string& tag, const std::string& message) const {
    respond(rfd, tag, "BYE", message + " " + states[rfd].get_uuid());
  }
  void route(int fd, const std::string& tag, const std::string& command,
             const WordList& args) const;
  void parse(int fd, const std::string& message) const;
  void tls_setup();
  void tls_cleanup();
  AuthenticationModel& AP = AuthenticationModel::getInst<AuthP>();
  DataModel& DP = DataModel::getInst<DataP>();

 public:
  IMAPProvider(ConfigModel& cfg) : config(cfg) {
    static int ctr = 0;
    BOOST_LOG_TRIVIAL(trace) << "New IMAPProvider Initialized (n: " << ++ctr << ", addr: " << this << ")";
    if (cfg.secure || cfg.starttls) tls_setup();
  }
  ~IMAPProvider() { if(config.secure || config.starttls) tls_cleanup(); }
  void operator()(int fd) const;
  void disconnect(int fd, const std::string& reason) const;
  void connect(int fd) const;
};
}  // namespace IMAPProvider
#include "IMAPProvider.impl"
#endif