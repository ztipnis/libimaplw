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

#ifndef __IMAP__AUTH_PROVIDER__
#define __IMAP__AUTH_PROVIDER__

namespace IMAPProvider {
class AuthenticationModel {
 public:
  virtual bool lookup(const std::string& username) = 0;
  virtual bool authenticate(const std::string& username, const std::string& password) = 0;
  virtual const std::string SASL(struct tls* fd, const std::string& mechanism) = 0;
  const std::string capabilityString;
  template <typename T>
  static AuthenticationModel& getInst() {
    static T m_Inst;
    return m_Inst;
  }

 private:
  AuthenticationModel(AuthenticationModel const&) = delete;
  AuthenticationModel& operator=(AuthenticationModel const&) = delete;

 protected:
  explicit AuthenticationModel(const std::string& capabilities)
      : capabilityString(capabilities) {}
};
}  // namespace IMAPProvider

#endif