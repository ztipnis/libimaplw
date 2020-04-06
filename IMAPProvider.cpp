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
#include <functional>
#include <unordered_map>
#include <variant>
#include <regex>
#include <unistd.h>
#include "Message.hpp"

template <class AuthP, class DataP>
std::map<int, typename IMAPProvider::ClientStateModel<AuthP> >
IMAPProvider::IMAPProvider<AuthP, DataP>::states;
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::operator()(int fd) const {
  auto rec = receive(fd);
  int rcvd = rec.first;
  std::string recData = rec.second;
  std::stringstream data(recData);
  if (rcvd == -1) {
    disconnect(fd, "Unable to read from socket");
  } else {
    for(std::string line; std::getline(data, line);)
      parse(fd,line);
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::disconnect(
  int fd, const std::string& reason) const {
  BOOST_LOG_TRIVIAL(debug) << " [UUID: " << states[fd].get_uuid() << "] Disconnected" << (reason == "" ? "" : ": " + reason);
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
      int hndshk = tls_handshake(states[fd].tls);
      struct timespec tim, tim2;
      while(hndshk == TLS_WANT_POLLIN || hndshk == TLS_WANT_POLLOUT) {
        usleep(1000);
        hndshk = tls_handshake(states[fd].tls);
      }
      if (hndshk < 0) {
        disconnect(fd, "TLS Negotiation Failed");
      } else {
        states[fd].starttls();
      }
    }
  }
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  int getaddr = getpeername(fd, (struct sockaddr*)&addr, &addrlen);
  if (getaddr == -1) {
    BAD(fd, "*",
        "Welcome to IMAPlw. IMAP ready for requests from [error... Peer "
        "Address Not Found]");
    return;
  }
  std::string address(inet_ntoa(addr.sin_addr));
  BOOST_LOG_TRIVIAL(debug) << "New Connection from " << address
                           << " [UUID: " << states[fd].get_uuid() << "]";
  OK(fd, "*", "Welcome to IMAPlw. IMAP ready for requests from " + address);
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::tls_setup() {
  if (t_conf == NULL) {
    const char* err = tls_config_error(t_conf);
    if (err == NULL)
      throw std::runtime_error("TLS Out of Memory Exception");
    else
      throw std::runtime_error(err);
  }
  tls = tls_server();
  unsigned int protocols = 0;
  if (tls_config_parse_protocols(&protocols, config.versions) < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "tls_config_parse_protocols error";
  }
  tls_config_set_protocols(t_conf, protocols);
  if (tls_config_set_ciphers(t_conf, config.ciphers) < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "tls_config_set_ciphers error";
  }
  if (tls_config_set_key_file(t_conf, config.keypath) < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "tls_config_set_key_file error";
  }
  if (tls_config_set_cert_file(t_conf, config.certpath) < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "tls_config_set_cert_file error";
  }
  if (tls_configure(tls, t_conf) < 0) {
    BOOST_LOG_TRIVIAL(fatal) << "tls_configure error: %" << tls_error(tls);
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
  int fd, const std::string& tag, const std::string& cmd,
  const WordList& args) const {
  std::string command(cmd);
  std::transform(
    command.begin(), command.end(), command.begin(),
    ::toupper); // https://stackoverflow.com/questions/735204/convert-a-string-in-c-to-upper-case
  BOOST_LOG_TRIVIAL(trace) << states[fd].get_uuid() << " : " << command;
  typedef decltype(&IMAPProvider::CAPABILITY) one;
  typedef decltype(&IMAPProvider::AUTHENTICATE) two;
  typedef decltype(&IMAPProvider::LOGIN) three;
  typedef decltype(&IMAPProvider::APPEND) four;
  typedef std::variant<one, two, three, four> variedFunc;

  static std::unordered_map<std::string, variedFunc> routeMap = {
    {"CAPABILITY", &IMAPProvider::CAPABILITY},
    {"NOOP", &IMAPProvider::NOOP},
    {"LOGOUT", &IMAPProvider::LOGOUT},
    {"STARTTLS", &IMAPProvider::STARTTLS},
    {"AUTHENTICATE", &IMAPProvider::AUTHENTICATE},
    {"LOGIN", &IMAPProvider::LOGIN},
    {"SELECT", &IMAPProvider::SELECT},
    {"EXAMINE", &IMAPProvider::EXAMINE},
    {"CREATE", &IMAPProvider::CREATE},
    {"DELETE", &IMAPProvider::DELETE},
    {"RENAME", &IMAPProvider::RENAME},
    {"SUBSCRIBE", &IMAPProvider::SUBSCRIBE},
    {"UNSUBSCRIBE", &IMAPProvider::UNSUBSCRIBE},
    {"LIST", &IMAPProvider::LIST},
    {"LSUB", &IMAPProvider::LSUB},
    {"STATUS", &IMAPProvider::STATUS},
    {"APPEND", &IMAPProvider::APPEND},
    {"CHECK", &IMAPProvider::CHECK},
    {"CLOSE", &IMAPProvider::CLOSE},
    {"UNSELECT", &IMAPProvider::UNSELECT},
    {"EXPUNGE", &IMAPProvider::EXPUNGE},
    {"SEARCH", &IMAPProvider::SEARCH},
    {"FETCH", &IMAPProvider::FETCH},
    {"STORE", &IMAPProvider::STORE},
    {"COPY", &IMAPProvider::COPY},
    {"UID", &IMAPProvider::UID},
    {"COMPRESS", &IMAPProvider::COMPRESS}
  };
  static std::unordered_map<std::string, IMAPState_t> routeMinState = {
    {"CAPABILITY", UNENC}, {"NOOP", UNENC},         {"LOGOUT", UNENC},
    {"STARTTLS", UNENC},   {"AUTHENTICATE", UNENC}, {"LOGIN", UNENC},
    {"SELECT", AUTH},      {"EXAMINE", AUTH},       {"CREATE", AUTH},
    {"DELETE", AUTH},      {"RENAME", AUTH},        {"SUBSCRIBE", AUTH},
    {"UNSUBSCRIBE", AUTH}, {"LIST", AUTH},          {"LSUB", AUTH},
    {"STATUS", AUTH},      {"APPEND", AUTH},        {"CHECK", SELECTED},
    {"CLOSE", SELECTED},   {"UNSELECT", SELECTED},  {"EXPUNGE", SELECTED},
    {"SEARCH", SELECTED},  {"FETCH", SELECTED},  {"STORE", SELECTED},
    {"COPY", SELECTED},    {"UID", SELECTED}};
  auto found = routeMap.find(command);
  if (found != routeMap.end()) {
    if (!found->second.valueless_by_exception()) {
      auto ptr = &(found->second);
      if (auto fnVal = std::get_if<one>(ptr)) {
        auto fn = *fnVal;
        if (states[fd].state() >= routeMinState[command]) {
          (this->*fn)(fd, tag);
        } else {
          NO(fd, tag, "Command " + command + " Not Allowed At This Time.");
        }
      } else if (auto fnVal = std::get_if<two>(ptr)) {
        auto fn = *fnVal;
        if (states[fd].state() >= routeMinState[command]) {
          (this->*fn)(fd, tag, args.rest(0));
        } else {
          NO(fd, tag, "Command " + command + " Not Allowed At This Time.");
        }
      } else if (auto fnVal = std::get_if<three>(ptr)) {
        auto fn = *fnVal;
        if (states[fd].state() >= routeMinState[command]) {
          (this->*fn)(fd, tag, args[0], args.rest(1));
        } else {
          NO(fd, tag, "Command " + command + " Not Allowed At This Time.");
        }
      } else if (auto fnVal = std::get_if<four>(ptr)) {
        auto fn = *fnVal;
        if (states[fd].state() >= routeMinState[command]) {
          (this->*fn)(fd, tag, args[0], args[1], args.rest(2));
        } else {
          NO(fd, tag, "Command " + command + " Not Allowed At This Time.");
        }
      } else {
        throw std::runtime_error(
                "Mapping command to function failed. This should never happen...");
      }
    }
  } else {
    BOOST_LOG_TRIVIAL(debug)
            << "Command " << cmd << " Not Found [UUID: " << states[fd].get_uuid()
            << "]";
    BAD(fd, tag, "Command " + cmd + " Not Found.");
  }
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::parse(
  int fd, const std::string& message) const {
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
  int rfd, const std::string& tag) const {
  if (config.starttls && !config.secure && (states[rfd].state() == UNENC)) {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 UTF8=ONLY STARTTLS LOGINDISABLED", states[rfd].isCompressed());
  } else if (states[rfd].state() == UNAUTH || states[rfd].state() == UNENC) {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 UTF8=ONLY " + AP.capabilityString,states[rfd].isCompressed());
  } else {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 UTF8=ONLY UNSELECT MOVE SPECIAL-USE",states[rfd].isCompressed());
  }
  OK(rfd, tag, "CAPABILITY Success.");
}
// NOOP ABOVE //

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGOUT(
  int rfd, const std::string& tag) const {
  BYE(rfd, "*", "LOGOUT initated by client");
  OK(rfd, tag, "LOGOUT Success.");
  disconnect(rfd, "");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STARTTLS(
  int rfd, const std::string& tag) const {
  if (config.starttls && !config.secure && (states[rfd].state() == UNENC)) {
    OK(rfd, tag, "Begin TLS Negotiation Now");
    if (tls_accept_socket(tls, &states[rfd].tls, rfd) < 0) {
      BAD(rfd, "*", "tls_accept_socket error");
    } else {
      int hndshk = tls_handshake(states[rfd].tls);
      while(hndshk == TLS_WANT_POLLIN || hndshk == TLS_WANT_POLLOUT) {
        usleep(10000);
        hndshk = tls_handshake(states[rfd].tls);
      }
      if (hndshk < 0) {
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
  int rfd, const std::string& tag, const std::string& mech) const {
  std::string mechanism(mech);
  if (states[rfd].state() != UNAUTH || states[rfd].state() == UNENC) {
    BAD(rfd, tag, "Already in Authenticated State");
  }
  std::transform(mechanism.begin(), mechanism.end(), mechanism.begin(),
                 ::toupper);
  if (mechanism == "PLAIN") {
    respond(rfd, "+", "", "Go Ahead",states[rfd].isCompressed());
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
                  "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE", states[rfd].isCompressed());
          OK(rfd, tag, "AUTHENTICATE Success. Welcome " + username);
        } else {
          BOOST_LOG_TRIVIAL(warning)
                  << "FAILED LOGIN ATTEMPT BY " << states[rfd].get_uuid();
          NO(rfd, tag, "[AUTHENTICATIONFAILED] Invalid Credentials");
        }
      }
    }

  } else
    try {
      if (states[rfd].SASL(mechanism)) {
        respond(rfd, "*", "CAPABILITY",
                "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE", states[rfd].isCompressed());
        OK(rfd, tag, "AUTHENTICATE Success.");
      }
    } catch (const std::exception& excp) {
      BOOST_LOG_TRIVIAL(warning)
              << "FAILED LOGIN ATTEMPT BY " << states[rfd].get_uuid();
      NO(rfd, tag, excp.what());
    }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGIN(
  int rfd, const std::string& tag, const std::string& username,
  const std::string& password) const {
  if (states[rfd].authenticate(username, password)) {
    respond(rfd, "*", "CAPABILITY",
            "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE", states[rfd].isCompressed());
    OK(rfd, tag, "LOGIN Success.");
  } else {
    BOOST_LOG_TRIVIAL(warning)
            << "FAILED LOGIN ATTEMPT BY " << states[rfd].get_uuid();
    NO(rfd, tag, "[AUTHENTICATIONFAILED] Invalid Credentials");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SELECT(
  int rfd, const std::string& tag, const std::string& mailbox) const {
  states[rfd].select(mailbox);
  auto onData = std::bind(newDataAvailable, rfd, states[rfd].isCompressed(), std::placeholders::_1);
  states[rfd].isSubscribedToChanges =
    DP.subscribe(states[rfd].getUser(), mailbox, onData);
  selectResp r = DP.select(states[rfd].getUser(), mailbox);
  respond(rfd, "*", "FLAGS", r.flags, states[rfd].isCompressed());
  respond(rfd, "*", std::to_string(r.exists), "EXISTS", states[rfd].isCompressed());
  respond(rfd, "*", std::to_string(r.recent), "RECENT", states[rfd].isCompressed());
  OK(rfd, "*", "[UNSEEN " + std::to_string(r.unseen) + "]");
  OK(rfd, "*", "[PERMANENTFLAGS " + r.permanentFlags + "]");
  OK(rfd, "*", "[UIDNEXT " + std::to_string(r.uidnext) + "]");
  OK(rfd, "*", "[UIDVALIDITY " + std::to_string(r.uidvalid) + "]");
  OK(rfd, tag, r.accessType + " SELECT Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXAMINE(
  int rfd, const std::string& tag, const std::string& mailbox) const {
  states[rfd].select(mailbox);
  selectResp r = DP.select(states[rfd].getUser(), mailbox);
  respond(rfd, "*", "FLAGS", r.flags, states[rfd].isCompressed());
  respond(rfd, "*", std::to_string(r.exists), "EXISTS", states[rfd].isCompressed());
  respond(rfd, "*", std::to_string(r.recent), "RECENT", states[rfd].isCompressed());
  OK(rfd, "*", "[UNSEEN " + std::to_string(r.unseen) + "]");
  OK(rfd, "*", "[PERMANENTFLAGS " + r.permanentFlags + "]");
  OK(rfd, "*", "[UIDNEXT " + std::to_string(r.uidnext) + "]");
  OK(rfd, "*", "[UIDVALIDITY " + std::to_string(r.uidvalid) + "]");
  OK(rfd, tag, "[READ-ONLY] EXAMINE Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CREATE(
  int rfd, const std::string& tag, const std::string& mailbox) const {
  if (DP.createMbox(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, "CREATE Success");
  } else {
    NO(rfd, tag, "CREATE failed to create new mailbox");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::DELETE(
  int rfd, const std::string& tag, const std::string& mailbox) const {
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
void IMAPProvider::IMAPProvider<AuthP, DataP>::RENAME(
  int rfd, const std::string& tag, const std::string& mailbox,
  const std::string& name) const {
  if (DP.rename(states[rfd].getUser(), mailbox, name)) {
    OK(rfd, tag, "RENAME Success.");
  } else {
    NO(rfd, tag, "RENAME Failed.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SUBSCRIBE(
  int rfd, const std::string& tag, const std::string& mailbox) const {
  if (DP.addSub(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, " Success.");
  } else {
    NO(rfd, tag, " Failed.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UNSUBSCRIBE(
  int rfd, const std::string& tag, const std::string& mailbox) const {
  if (DP.rmSub(states[rfd].getUser(), mailbox)) {
    OK(rfd, tag, " Success.");
  } else {
    NO(rfd, tag, " Failed.");
  }
}


template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LIST(
  int rfd, const std::string& tag, const std::string& reference,
  const std::string& name) const {
  std::string ref = reference;
  char* cref = &ref[0];
  std::string mboxs = name;
  char* cmboxs = &mboxs[0];
  std::vector<std::string> mboxPath;
  if (mboxs[0] != '/') {
    while (const char* token = strtok_r(cref, "/.", &cref)) {
      mboxPath.push_back(std::string(token));
    }
  }
  while (const char* token = strtok_r(cmboxs, "/.", &cmboxs)) {
    mboxPath.push_back(std::string(token));
  }
  std::vector<mailbox> lres;
  auto joined = join(mboxPath, "/");
  DP.list(states[rfd].getUser(), joined, lres);
  if (lres.size() > 0) {
    for (auto box : std::as_const(lres)) {
      std::stringstream listres;
      listres << "(";
      for (auto flag : std::as_const(box.flags)) listres << flag << " ";
      listres << "\b"
              << ") "
              << "\"/\"" << box.path;
      respond(rfd, "*", "LIST", listres.str(), states[rfd].isCompressed());
    }
    OK(rfd, tag, "LIST Success.");
  } else {
    NO(rfd, tag, "LIST No Such Folder.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LSUB(
  int rfd, const std::string& tag, const std::string& reference,
  const std::string& name) const {
  // char* ref = new char[reference.length()];
  std::string ref = reference;
  char* cref = &ref[0];
  std::string mboxs = name;
  char* cmboxs = &mboxs[0];
  std::vector<std::string> mboxPath;
  if (mboxs[0] != '/') {
    while (const char* token = strtok_r(cref, "/.", &cref)) {
      mboxPath.push_back(std::string(token));
    }
  }
  while (const char* token = strtok_r(cmboxs, "/.", &cmboxs)) {
    mboxPath.push_back(std::string(token));
  }
  std::vector<mailbox> lres;
  DP.lsub(states[rfd].getUser(), join(mboxPath, "/"), lres);
  if (lres.size() > 0) {
    for (auto box : std::as_const(lres)) {
      std::stringstream listres;
      listres << "(";
      for (auto flag : std::as_const(box.flags)) listres << flag << " ";
      listres << "\b"
              << ") "
              << "\"/\"" << box.path;
      respond(rfd, "*", "LSUB", listres.str(), states[rfd].isCompressed());
    }
    OK(rfd, tag, "LSUB Success.");
  } else {
    NO(rfd, tag, "LSUB No Such Folder.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STATUS(
  int rfd, const std::string& tag, const std::string& mailbox,
  const std::string& datareq) const {
  if (DP.mailboxExists(states[rfd].getUser(), mailbox)) {
    const char* request = datareq.c_str();
    std::string paramstr(8192, 0);
    sscanf(request, "%*[(] %8192[^()] %*[)])", &paramstr[0]);
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
    respond(rfd, "*", "STATUS", ret.str(), states[rfd].isCompressed());
    OK(rfd, tag, "STATUS Success.");
  } else {
    NO(rfd, tag, "STATUS Failed. No Status for that name.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::APPEND(
  int rfd, const std::string& tag, const std::string& mailbox,
  const std::string& flags, const std::string& msgsize) const {
  if (!DP.mailboxExists(states[rfd].getUser(), mailbox)) {
    NO(rfd, tag, "[TRYCREATE] APPEND Failed.");
  } else {
    respond(rfd, "+", "", "Go Ahead", states[rfd].isCompressed());
    int rcvd = 0;
    int msg_sz = 0;
    sscanf(msgsize.c_str(), "{%d}", &msg_sz);
    std::stringstream buffer;
    for (int total_rcvd = 0; total_rcvd < msg_sz; total_rcvd += rcvd) {
      auto rec = receive(rfd);
      rcvd = rec.first;
      buffer << rec.second;
    }
    std::string dat = buffer.str();
    DP.append(states[rfd].getUser(), mailbox, dat);
    OK(rfd, tag, "APPEND Success.");
  }
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CHECK(
  int rfd, const std::string& tag) const {
  OK(rfd, tag, "CHECK Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CLOSE(
  int rfd, const std::string& tag) const {
  std::vector<std::string> v;
  DP.expunge(states[rfd].getUser(), states[rfd].getMBox(), v);
  states[rfd].unselect();
  OK(rfd, tag, "CLOSE Success.");
}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UNSELECT(
  int rfd, const std::string& tag) const {
  states[rfd].unselect();
  OK(rfd, tag, "UNSELECT Success.");
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXPUNGE(
  int rfd, const std::string& tag) const {
  std::vector<std::string> expunged;
  DP.expunge(states[rfd].getUser(), states[rfd].getMBox(), expunged);
  for (std::string uid : expunged) {
    respond(rfd, "*", uid, "EXPUNGE", states[rfd].isCompressed());
  }
  OK(rfd, tag, "EXPUNGE Success.");
}


std::string nextQuery(WordList& args_r){
  if(args_r.length() > 0) {
    std::string query = args_r.pop(0);
    std::transform(query.begin(), query.end(), query.begin(), ::toupper);
    /**
     * <num... >
     * ALL
     * ANSWERED
     * BCC <str>
     * BEFORE <date>
     * BODY <str>
     * CC <str>
     * DELETED
     * DRAFT
     * FLAGGED
     * FROM <str>
     * HEADER <field><str>
     */
    if(query == "ALL" || query == "ANSWERED" || query == "DELETED" || query == "DRAFT" || query == "FLAGGED") {
      return query;
    }else if(isNumeric(query)) {
      std::string ret(query);
      while(args_r.length() > 0 && isNumeric(args_r[0])) {
        ret += " " + args_r.pop(0);
      }
      return ret;
    }else if(query == "BCC" || query == "BEFORE" || query == "BODY" || query == "CC" || query == "FROM") {
      return query + " " + nextQuery(args_r);
    }else if(query == "HEADER") {
      return query + " " + nextQuery(args_r) + " " + nextQuery(args_r);
    }else return query;
  }else return "\0";
}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SEARCH(
  int rfd, const std::string& tag, const std::string& query) const {
  WordList qarg(query);
  std::string _query;
  std::vector<std::string> v;
  while(_query != "\0" && qarg.length() > 0){
    _query.clear();
    _query = nextQuery(qarg);
    BOOST_LOG_TRIVIAL(debug) << _query;
    v.push_back(_query);
  }
  std::vector<int> ret;
  if(DP.search(states[rfd].getUser(), states[rfd].getMBox(), v, ret)){
    std::vector<std::string> ret_s;
    std::transform(ret.begin(), ret.end(), std::back_inserter(ret_s), [](const int i){
      return std::to_string(i);
    });
    std::string ranges = join(ret_s, " ");
    respond(rfd, "*", "SEARCH", ranges, states[rfd].isCompressed());
    OK(rfd,tag, "SEARCH Success.");
  }else{
    NO(rfd, tag, "SEARCH Failed. Query Invalid.");
  }
}


template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::FETCH(
  int rfd, const std::string& tag, const std::string& args) const {
  static const std::regex requestParseFormat("^(\\d):?(\\d?) \\(?((?:(?:[^\\[]+)(?:\\[[^\\]]+\\])?(?:<\\d+>)?)+)\\)?$");
  std::smatch requestParseResults;
  if(std::regex_match(args, requestParseResults, requestParseFormat) && requestParseResults.size() == 4){
    //Query matched
    //requestParseResults[0] is full string
    int start = std::stoi(requestParseResults[1]),
    end = requestParseResults[2] != "" ? std::stoi(requestParseResults[2]) : -1;
    std::string query(requestParseResults[3]);
    static const std::regex queryParseFormat("(?:(?:BODY(?:.PEEK)?\\[[\\(\\)\\w\\d. ]+\\])|[\\w\\d.]+)(?:<\\d+\\.?\\d*>)?");
    std::sregex_iterator qBegin(query.cbegin(), query.cend(), queryParseFormat), qEnd;
    for(auto iter = qBegin; iter != qEnd; iter++){
      // Message fetched = 
    }

    



  }else{
    BAD(rfd, tag, "FETCH Failed. Bad Format.");
  }


}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STORE(
  int rfd, const std::string& tag) const {

}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::COPY(
  int rfd, const std::string& tag) const {

}

template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UID(
  int rfd, const std::string& tag) const {

}
template <class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::COMPRESS(
  int rfd, const std::string& tag, const std::string& type) const {
  if(states[rfd].isCompressed()) {
    BAD(rfd, tag, "[COMPRESSIONACTIVE] Compression already enabled.");
  }else{
    OK(rfd, tag, "COMPRESS Success. Compression now active.");
    states[rfd].isCompressed() = true;
  }
}
