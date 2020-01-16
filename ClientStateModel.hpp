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

#include "AuthenticationModel.hpp"
#include "Helpers.hpp"

#ifndef __IMAP_CLIENT_STATE__
#define __IMAP_CLIENT_STATE__

namespace IMAPProvider {
typedef enum { UNENC = 0, UNAUTH = 1, AUTH = 2, SELECTED = 3 } IMAPState_t;
template <typename A>
class ClientStateModel {
 private:
  std::string uuid;
  bool encrypted;
  bool authenticated;
  std::string user;
  bool selected;
  std::string mbox;

 public:
  bool isSubscribedToChanges = false;
  struct tls* tls = NULL;
  ClientStateModel() {
    encrypted = false;
    authenticated = false;
    user = "";
    selected = false;
    mbox = "";
    uuid = gen_uuid(15);
  }
  const IMAPState_t state() const {
    if (!encrypted && !authenticated) {
      return UNENC;
    } else if (authenticated) {
      if (selected) {
        return SELECTED;
      } else {
        return AUTH;
      }
    } else {
      return UNAUTH;
    }
  }
  void starttls() { encrypted = true; }
  void logout() {
    authenticated = false;
    user = "";
  }
  const std::string getUser() const { return user; }
  const std::string getMBox() const { return mbox; }
  const std::string get_uuid() const { return uuid; }
  bool SASL(std::string mechanism) {
    AuthenticationModel& provider = AuthenticationModel::getInst<A>();
    user = provider.SASL(tls, mechanism);
    authenticated = (user == "");
    return (user == "");
  }
  bool authenticate(const std::string& username, const std::string& password) {
    AuthenticationModel& provider = AuthenticationModel::getInst<A>();
    if (provider.lookup(username) == false) {
      return false;
    }
    if (provider.authenticate(username, password)) {
      authenticated = true;
      user = username;
      return true;
    }
    return false;
  }
  void select(std::string mailbox) {
    mbox = mailbox;
    selected = true;
  }
  void unselect(){
    mbox = "";
    selected = false;
  }
};
}  // namespace IMAPProvider

#endif