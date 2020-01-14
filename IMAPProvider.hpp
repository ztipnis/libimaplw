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
  void CAPABILITY(int rfd, std::string tag) const;
  void NOOP(int rfd, std::string tag) const {
    OK(rfd, tag, "NOOP executed successfully");
  }
  void LOGOUT(int rfd, std::string tag) const;
  // UNAUTHENTICATED
  void STARTTLS(int rfd, std::string tag) const;
  void AUTHENTICATE(int rfd, std::string tag, std::string) const;
  void LOGIN(int rfd, std::string tag, std::string, std::string) const;
  // AUTENTICATED
  void SELECT(int rfd, std::string tag, std::string) const;
  void EXAMINE(int rfd, std::string tag, std::string) const;
  void CREATE(int rfd, std::string tag, std::string) const;
  void DELETE(int rfd, std::string tag, std::string) const;
  void RENAME(int rfd, std::string tag, std::string mailbox,
              std::string name) const;
  void SUBSCRIBE(int rfd, std::string tag, std::string mailbox) const;
  void UNSUBSCRIBE(int rfd, std::string tag, std::string mailbox) const;
  void LIST(int rfd, std::string tag, std::string reference,
            std::string name) const;
  void LSUB(int rfd, std::string tag, std::string reference,
            std::string name) const;
  void STATUS(int rfd, std::string tag, std::string mailbox,
              std::string datareq) const;
  void APPEND(int rfd, std::string tag, std::string mailbox, std::string flags,
              std::string msgsize) const;
  // SELECTED
  void CHECK(int rfd, std::string tag) const;
  void CLOSE(int rfd, std::string tag) const;
  void UNSELECT(int rfd, std::string tag) const;
  void EXPUNGE(int rfd, std::string tag) const;
  void SEARCH(int rfd, std::string tag) const;
  void STORE(int rfd, std::string tag) const;
  void COPY(int rfd, std::string tag) const;
  void UID(int rfd, std::string tag) const;
  static void newDataAvailable(int rfd, std::vector<std::string> data) {
    for (std::string d : data) respond(rfd, "*", "", d);
  }

  std::pair<size_t, std::string> receive(int fd) const {
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
  static inline void respond(int rfd, std::string tag, std::string code,
                             std::string message) {
    std::stringstream msg;
    msg << tag << " " << code << " " << message << std::endl;
    if (states[rfd].tls == NULL) {
      sendMsg(rfd, msg.str());
    } else {
      sendMsg(states[rfd].tls, msg.str());
    }
  }

  void OK(int rfd, std::string tag, std::string message) const {
    respond(rfd, tag, "OK", message + " " + states[rfd].get_uuid());
  }
  void NO(int rfd, std::string tag, std::string message) const {
    respond(rfd, tag, "NO", message + " " + states[rfd].get_uuid());
  }
  void BAD(int rfd, std::string tag, std::string message) const {
    respond(rfd, tag, "BAD", message + " " + states[rfd].get_uuid());
  }
  void PREAUTH(int rfd, std::string tag, std::string message) const {
    respond(rfd, tag, "PREAUTH", message + " " + states[rfd].get_uuid());
  }
  void BYE(int rfd, std::string tag, std::string message) const {
    respond(rfd, tag, "BYE", message + " " + states[rfd].get_uuid());
  }
  void route(int fd, std::string tag, std::string command,
             const WordList& args) const;
  void parse(int fd, std::string message) const;
  void tls_setup();
  void tls_cleanup();
  AuthenticationModel& AP = AuthenticationModel::getInst<AuthP>();
  DataModel& DP = DataModel::getInst<DataP>();

 public:
  IMAPProvider(ConfigModel& cfg) : config(cfg) {
    if (cfg.secure || cfg.starttls) tls_setup();
  }
  ~IMAPProvider() { tls_cleanup(); }
  void operator()(int fd) const;
  void disconnect(int fd, const std::string& reason) const;
  void connect(int fd) const;
};
}  // namespace IMAPProvider
template <class AuthP, class DataP>
std::map<int, typename IMAPProvider::ClientStateModel<AuthP> >
    IMAPProvider::IMAPProvider<AuthP, DataP>::states;
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::operator()(int fd) const {
  auto rec = receive(fd);
  int rcvd = rec.first;
  std::string data = rec.second;
  if (rcvd == -1) {
    disconnect(fd, "Unable to read from socket");
  } else {
    parse(fd, data);
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::disconnect(
    int fd, const std::string& reason) const {
  if (reason != "") {
    BYE(fd, "*", reason);
  }
  if (states[fd].tls != NULL) {
    tls_close(states[fd].tls);
    tls_free(states[fd].tls);
  }
  states.erase(fd);
  close(fd);
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::connect(int fd) const {
  states.erase(fd);
  if (config.secure) {
    if (tls_accept_socket(tls, &states[fd].tls, fd) < 0) {
      disconnect(fd, "TLS Negotiation Failed");
    } else {
      if (tls_handshake(states[fd].tls) < 0) {
        disconnect(fd, "TLS Negotiation Failed");
      } else {
        states[fd].starttls();
      }
    }
  }
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int getaddr = getpeername(fd, (struct sockaddr*)&addr, &addrlen);
  std::string address(inet_ntoa(addr.sin_addr));
  OK(fd, "*", "Welcome to IMAPlw. IMAP ready for requests from " + address);
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::tls_setup() {
  if(t_conf == NULL){
    const char* err = tls_config_error(t_conf);
    throw std::runtime_error(err);
  }
  tls = tls_server();
  unsigned int protocols = 0;
  if (tls_config_parse_protocols(&protocols, config.versions) < 0) {
    printf("tls_config_parse_protocols error\n");
  }
  tls_config_set_protocols(t_conf, protocols);
  if (tls_config_set_ciphers(t_conf, config.ciphers) < 0) {
    printf("tls_config_set_ciphers error\n");
  }
  if (tls_config_set_key_file(t_conf, config.keypath) < 0) {
    printf("tls_config_set_key_file error\n");
  }
  if (tls_config_set_cert_file(t_conf, config.certpath) < 0) {
    printf("tls_config_set_cert_file error\n");
  }
  if (tls_configure(tls, t_conf) < 0) {
    printf("tls_configure error: %s\n", tls_error(tls));
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::tls_cleanup() {
  if (t_conf != NULL) {
    tls_config_free(t_conf);
  }
  if (tls != NULL) {
    tls_close(tls);
    tls_free(tls);
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::route(
    int fd, std::string tag, std::string command, const WordList& args) const {
  std::transform(
      command.begin(), command.end(), command.begin(),
      ::toupper);  // https://stackoverflow.com/questions/735204/convert-a-string-in-c-to-upper-case

  // UNENC, UNAUTH, AUTH, SELECTED
  if (command == "CAPABILITY") {
    CAPABILITY(fd, tag);
  } else if (command == "NOOP") {
    NOOP(fd, tag);
  } else if (command == "LOGOUT") {
    LOGOUT(fd, tag);
  } else /* UNAUTHENTICATED */ if (command == "STARTTLS") {
    if (states[fd].state() == UNAUTH) {
      STARTTLS(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "AUTHENTICATE") {
    if (states[fd].state() == UNAUTH || states[fd].state() == UNENC) {
      AUTHENTICATE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "LOGIN") {
    if (states[fd].state() == UNAUTH) {
      LOGIN(fd, tag, args[0], args.rest(1));
    } else if(states[fd].state() == UNENC) {
      BAD(fd, tag, "Sorry PLAINTEXT Authentication is deprecated when unencrypted. Use AUTHENTICATE instead.");
    }else{
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else /* AUTHENTICATED */ if (command == "SELECT") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      SELECT(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "EXAMINE") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      EXAMINE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "CREATE") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      CREATE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "DELETE") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      DELETE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "RENAME") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      RENAME(fd, tag, args[0], args.rest(1));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "SUBSCRIBE") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      SUBSCRIBE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "UNSUBSCRIBE") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      UNSUBSCRIBE(fd, tag, args.rest(0));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "LIST") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      LIST(fd, tag, args[0], args.rest(1));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "LSUB") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      LSUB(fd, tag, args[0], args.rest(1));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "STATUS") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      STATUS(fd, tag, args[0], args.rest(1));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "APPEND") {
    if (states[fd].state() == AUTH || states[fd].state() == SELECTED) {
      APPEND(fd, tag, args[0], args[1], args.rest(2));
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else /* SELECTED */ if (command == "CHECK") {
    if (states[fd].state() == SELECTED) {
      CHECK(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "CLOSE") {
    if (states[fd].state() == SELECTED) {
      CLOSE(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "UNSELECT") {
    if (states[fd].state() == SELECTED) {
      UNSELECT(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "EXPUNGE") {
    if (states[fd].state() == SELECTED) {
      EXPUNGE(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "SEARCH") {
    if (states[fd].state() == SELECTED) {
      SEARCH(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "STORE") {
    if (states[fd].state() == SELECTED) {
      STORE(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "COPY") {
    if (states[fd].state() == SELECTED) {
      COPY(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else if (command == "UID") {
    if (states[fd].state() == SELECTED) {
      UID(fd, tag);
    } else {
      BAD(fd, tag, "Command Not Allowed At This Time.");
    }
  } else {
    BAD(fd, tag, "Command \"" + command + "\" NOT FOUND");
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::parse(
    int fd, std::string message) const {
  WordList args(message);

  if (args.size() >= 2) {
    route(fd, args[0], args[1], WordList(args.rest(2)));
  } else {
    BAD(fd, "*", "Unable to parse command \"" + message + "\"");
  }
}

// IMAP COMMANDS:
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CAPABILITY(
    int rfd, std::string tag) const {
  if (config.starttls && !config.secure && (states[rfd].state() == UNENC)) {
    respond(rfd, "*", "CAPABILITY", "IMAP4rev1 UTF8=ONLY STARTTLS LOGINDISABLED");
  } else if (states[rfd].state() == UNAUTH || states[rfd].state() == UNENC) {
    respond(rfd, "*", "CAPABILITY", "IMAP4rev1 UTF8=ONLY " + AP.capabilityString);
  } else {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 UTF8=ONLY COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
  }
  OK(rfd, tag, "CAPABILITY Success.");
}
// NOOP ABOVE //

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGOUT(int rfd,
                                                      std::string tag) const {
  BYE(rfd, "*", "LOGOUT initated by client");
  OK(rfd, tag, "LOGOUT Success.");
  disconnect(rfd, "");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STARTTLS(int rfd,
                                                        std::string tag) const {
  if (config.starttls && !config.secure && (states[rfd].state() == UNENC)) {
    OK(rfd, tag, "Begin TLS Negotiation Now");
    if (tls_accept_socket(tls, &states[rfd].tls, rfd) < 0) {
      BAD(rfd, "*", "tls_accept_socket error");
    } else {
      if (tls_handshake(states[rfd].tls) < 0) {
        BAD(rfd, "*", "tls_handshake error");
      } else {
        states[rfd].starttls();
      }
    }
  } else {
    BAD(rfd, tag, "STARTTLS Disabled");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::AUTHENTICATE(
    int rfd, std::string tag, std::string mechanism) const {
  if (states[rfd].state() != UNAUTH || states[rfd].state() == UNENC) {
    BAD(rfd, tag, "Already in Authenticated State");
  }
  std::transform(mechanism.begin(), mechanism.end(), mechanism.begin(),
                 ::toupper);
  if (mechanism == "PLAIN") {
    respond(rfd, "+", "", "Go Ahead");
    auto rec = receive(rfd);
    int rcvd = rec.first;
    std::string data = rec.second;
    if (rcvd < 6) {
      NO(rfd, tag, "Authentication Failed");
    } else {
      std::string decoded_data = base64_decode(data);
      std::string nullSepStr = decoded_data.substr(1, std::string::npos);
      std::size_t seploc = nullSepStr.find('\0');
      if (seploc == std::string::npos) {
        NO(rfd, tag, "Authentication Failed");
      } else {
        std::string username = nullSepStr.substr(0, seploc),
                    password = nullSepStr.substr(seploc + 1, std::string::npos);
        if (states[rfd].authenticate(username, password)) {
          respond(rfd, "*", "CAPABILITY",
                  "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
          OK(rfd, tag, "AUTHENTICATE Success. Welcome " + username);
        }
      }
    }

  } else
    try {
      if (states[rfd].SASL(mechanism)) {
        respond(rfd, "*", "CAPABILITY",
                "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
        OK(rfd, tag, "AUTHENTICATE Success.");
      }
    } catch (const std::exception& excp) {
      NO(rfd, tag, excp.what());
    }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGIN(
    int rfd, std::string tag, std::string username,
    std::string password) const {
  if (states[rfd].authenticate(username, password)) {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
    OK(rfd, tag, "LOGIN Success.");
  } else {
    NO(rfd, tag, "[AUTHENTICATIONFAILED] Invalid Credentials");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SELECT(
    int rfd, std::string tag, std::string mailbox) const {
  states[rfd].select(mailbox);
  auto onData = std::bind(newDataAvailable, rfd, std::placeholders::_1);
  states[rfd].isSubscribedToChanges =
      DP.subscribe(states[rfd].getUser(), mailbox, onData);
  selectResp r = DP.select(states[rfd].getUser(), mailbox);
  respond(rfd, "*", "FLAGS", r.flags);
  respond(rfd, "*", std::to_string(r.exists), "EXISTS");
  respond(rfd, "*", std::to_string(r.recent), "RECENT");
  OK(rfd, "*", "[UNSEEN " + std::to_string(r.unseen) + "]");
  OK(rfd, "*", "[PERMANENTFLAGS " + r.permanentFlags + "]");
  OK(rfd, "*", "[UIDNEXT " + std::to_string(r.uidnext) + "]");
  OK(rfd, "*", "[UIDVALIDITY " + std::to_string(r.uidvalid) + "]");
  OK(rfd, tag, r.accessType + " SELECT Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXAMINE(
    int rfd, std::string tag, std::string mailbox) const {
  states[rfd].select(mailbox);
  selectResp r = DP.select(states[rfd].getUser(), mailbox);
  respond(rfd, "*", "FLAGS", r.flags);
  respond(rfd, "*", std::to_string(r.exists), "EXISTS");
  respond(rfd, "*", std::to_string(r.recent), "RECENT");
  OK(rfd, "*", "[UNSEEN " + std::to_string(r.unseen) + "]");
  OK(rfd, "*", "[PERMANENTFLAGS " + r.permanentFlags + "]");
  OK(rfd, "*", "[UIDNEXT " + std::to_string(r.uidnext) + "]");
  OK(rfd, "*", "[UIDVALIDITY " + std::to_string(r.uidvalid) + "]");
  OK(rfd, tag, "[READ-ONLY] EXAMINE Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CREATE(
    int rfd, std::string tag, std::string mailbox) const {
  if (DP.createMbox(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, "CREATE Success");
  } else {
    NO(rfd, tag, "CREATE failed to create new mailbox");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::DELETE(
    int rfd, std::string tag, std::string mailbox) const {
  if (DP.hasSubFolders(states[rfd].getUser(), mailbox)) {
    if (DP.hasAttrib(states[rfd].getUser(), mailbox, "\\NoSelect")) {
      NO(rfd, tag, "MAILBOX in not deletable");
    } else {
      DP.clear(states[rfd].getUser(), mailbox);
      DP.addAttrib(states[rfd].getUser(), mailbox, "\\NoSelect");
      OK(rfd, tag, "DELETE Success.");
    }
  } else {
    if (DP.rmFolder(states[rfd].getUser(), mailbox))
      OK(rfd, tag, "DELETE Success.");
    else
      NO(rfd, tag, "DELETE Failed.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::RENAME(int rfd, std::string tag,
                                                      std::string mailbox,
                                                      std::string name) const {
  if (DP.rename(states[rfd].getUser(), mailbox, name)) {
    OK(rfd, tag, "RENAME Success.");
  } else {
    NO(rfd, tag, "RENAME Failed.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SUBSCRIBE(
    int rfd, std::string tag, std::string mailbox) const {
  if (DP.addSub(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, " Success.");
  } else {
    NO(rfd, tag, " Failed.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UNSUBSCRIBE(
    int rfd, std::string tag, std::string mailbox) const {
  if (DP.rmSub(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, " Success.");
  } else {
    NO(rfd, tag, " Failed.");
  }
}

std::string join(const std::vector<std::string>& itms, std::string delimiter) {
  std::string buffer;
  for (int i = 0; i < itms.size() - 1; i++) {
    buffer += itms[i] + delimiter;
  }
  if (itms.size() - 1 >= 0) {
    buffer += itms[(itms.size() - 1)];
  }
  return buffer;
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LIST(int rfd, std::string tag,
                                                    std::string reference,
                                                    std::string name) const {
  char* ref = new char[reference.length()];
  strncpy(ref, reference.c_str(), reference.length());
  char* mboxs = new char[name.length()];
  strncpy(mboxs, name.c_str(), name.length());
  std::vector<std::string> mboxPath;
  if (mboxs[0] != '/') {
    while (const char* token = strtok_r(ref, "/.", &ref)) {
      mboxPath.push_back(std::string(token));
    }
  }
  while (const char* token = strtok_r(mboxs, "/.", &mboxs)) {
    mboxPath.push_back(std::string(token));
  }
  std::vector<mailbox> lres;
  DP.list(states[rfd].getUser(), join(mboxPath, "/"), lres);
  delete[] ref;
  delete[] mboxs;
  if (lres.size() > 0) {
    for (auto box : std::as_const(lres)) {
      std::stringstream listres;
      listres << "(";
      for (auto flag : std::as_const(box.flags)) listres << flag << " ";
      listres << "\b"
              << ") "
              << "\"/\"" << box.path;
      respond(rfd, "*", "LIST", listres.str());
    }
    OK(rfd, tag, "LIST Success.");
  } else {
    NO(rfd, tag, "LIST No Such Folder.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LSUB(int rfd, std::string tag,
                                                    std::string reference,
                                                    std::string name) const {
  char* ref = new char[reference.length()];
  strncpy(ref, reference.c_str(), reference.length());
  char* mboxs = new char[name.length()];
  strncpy(mboxs, name.c_str(), name.length());
  std::vector<std::string> mboxPath;
  if (mboxs[0] != '/') {
    while (const char* token = strtok_r(ref, "/.", &ref)) {
      mboxPath.push_back(std::string(token));
    }
  }
  while (const char* token = strtok_r(mboxs, "/.", &mboxs)) {
    mboxPath.push_back(std::string(token));
  }
  std::vector<mailbox> lres;
  DP.lsub(states[rfd].getUser(), join(mboxPath, "/"), lres);
  delete[] ref;
  delete[] mboxs;
  if (lres.size() > 0) {
    for (auto box : std::as_const(lres)) {
      std::stringstream listres;
      listres << "(";
      for (auto flag : std::as_const(box.flags)) listres << flag << " ";
      listres << "\b"
              << ") "
              << "\"/\"" << box.path;
      respond(rfd, "*", "LSUB", listres.str());
    }
    OK(rfd, tag, "LSUB Success.");
  } else {
    NO(rfd, tag, "LSUB No Such Folder.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STATUS(
    int rfd, std::string tag, std::string mailbox, std::string datareq) const {
  if (DP.mailboxExists(states[rfd].getUser(), mailbox)) {
    const char* request = datareq.c_str();
    std::string paramstr(8192, 0);
    sscanf(request, "%*[(] %[^()] %*[)])", &paramstr[0]);
    WordList params(paramstr.c_str());
    std::stringstream ret;
    ret << "(";
    for (std::string param : params) {
      if (param == "MESSAGES") {
        ret << "MESSAGES " << DP.messages(states[rfd].getUser(), mailbox)
            << " ";
      } else if (param == "RECENT") {
        ret << "RECENT " << DP.recent(states[rfd].getUser(), mailbox) << " ";
      } else if (param == "UIDNEXT") {
        ret << "UIDNEXT " << DP.uidnext(states[rfd].getUser(), mailbox) << " ";
      } else if (param == "UIDVALIDITY") {
        ret << "UIDVALIDITY " << DP.uidvalid(states[rfd].getUser(), mailbox)
            << " ";
      } else if (param == "UNSEEN") {
        ret << "UNSEEN " << DP.unseen(states[rfd].getUser(), mailbox) << " ";
      }
    }
    if (params.size() > 0) {
      ret.seekp(-1, ret.cur);
    }
    ret << ")";
    respond(rfd, "*", "STATUS", ret.str());
    OK(rfd, tag, "STATUS Success.");
  } else {
    NO(rfd, tag, "STATUS Failed. No Status for that name.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::APPEND(
    int rfd, std::string tag, std::string mailbox, std::string flags,
    std::string msgsize) const {
  if (!DP.mailboxExists(states[rfd].getUser(), mailbox)) {
    NO(rfd, tag, "[TRYCREATE] APPEND Failed.");
  } else {
    respond(rfd, "+", "", "Go Ahead");
    int rcvd = 0;
    int msg_sz = 0;
    sscanf(msgsize.c_str(), "{%d}", &msg_sz);
    std::string data(msg_sz + 1, 0);
    std::stringstream buffer;
    for (int total_rcvd = 0; total_rcvd < msg_sz; total_rcvd += rcvd) {
      auto rec = receive(rfd);
      rcvd = rec.first;
      std::string data = rec.second;
      buffer << data;
    }
    std::string dat = buffer.str();
    DP.append(states[rfd].getUser(), mailbox, dat);
    OK(rfd, tag, "APPEND Success.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CHECK(int rfd,
                                                     std::string tag) const {
  OK(rfd, tag, "CHECK Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CLOSE(
    int rfd, std::string tag) const {
  std::vector<std::string> v;
  DP.expunge(states[rfd].getUser(), states[rfd].getMBox(), v);
  states[rfd].unselect();
  OK(rfd,tag, "CLOSE Success.");
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UNSELECT(
    int rfd, std::string tag) const {
  states[rfd].unselect();
  OK(rfd,tag, "UNSELECT Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXPUNGE(int rfd,
                                                       std::string tag) const {
  std::vector<std::string> expunged;
  DP.expunge(states[rfd].getUser(), states[rfd].getMBox(), expunged);
  for(std::string uid : expunged){
    respond(rfd, "*", uid, "EXPUNGE");
  }
  OK(rfd, tag, "EXPUNGE Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SEARCH(int rfd,
                                                      std::string tag) const {

}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STORE(int rfd,
                                                     std::string tag) const {}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::COPY(int rfd,
                                                    std::string tag) const {}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UID(int rfd,
                                                   std::string tag) const {}

#endif