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
#import <string>
#import <utility>
#import <vector>

#import "Helpers.hpp"
#ifndef __IMAP_DATA_PROVIDER__
#define __IMAP_DATA_PROVIDER__

namespace IMAPProvider {
// DataModel Subclass must provide init() to initialize m_Inst and implement all
// public functions.
class DataModel {
 public:
  template <typename T>
  static DataModel& getInst() {
    static T m_Inst;
    return m_Inst;
  }
  virtual selectResp select(const std::string& user,
                            const std::string& mailbox) = 0;
  virtual int messages(const std::string& user, const std::string& mailbox) = 0;
  virtual int recent(const std::string& user, const std::string& mailbox) = 0;
  virtual unsigned long uidnext(const std::string& user,
                                const std::string& mailbox) = 0;
  virtual unsigned long uidvalid(const std::string& user,
                                 const std::string& mailbox) = 0;
  virtual int unseen(const std::string& user, const std::string& mailbox) = 0;
  virtual bool createMbox(const std::string& user,
                          const std::string& mailbox) = 0;
  virtual bool hasSubFolders(const std::string& user,
                             const std::string& mailbox) = 0;
  virtual bool hasAttrib(const std::string& user, const std::string& mailbox,
                         const std::string& attrib) = 0;
  virtual bool addAttrib(const std::string& user, const std::string& mailbox,
                         const std::string& attrib) = 0;
  virtual bool rmFolder(const std::string& user,
                        const std::string& mailbox) = 0;
  virtual bool clear(const std::string& user, const std::string& mailbox) = 0;
  virtual bool rename(const std::string& user, const std::string& mailbox,
                      const std::string& name) = 0;
  virtual bool addSub(const std::string& user, const std::string& mailbox) = 0;
  virtual bool rmSub(const std::string& user, const std::string& mailbox) = 0;
  virtual bool list(const std::string& user, const std::string& mailbox,
                    std::vector<struct mailbox>& lres) = 0;
  virtual bool lsub(const std::string& user, const std::string& mailbox,
                    std::vector<struct mailbox>& lres) = 0;
  virtual bool mailboxExists(const std::string& user,
                             const std::string& mailbox) = 0;
  virtual bool append(const std::string& user, const std::string& mailbox,
                      const std::string& messageData) = 0;
  virtual bool expunge(const std::string& user, const std::string& mailbox, std::vector<std::string>& expunged) = 0;
  virtual bool subscribe(
      const std::string& user, const std::string& mailbox,
      std::function<void(std::vector<std::string>)> callback) {
    return false;
  }  // note, function passed by value in order to preserve temporary std::bind
     // value
 private:
  DataModel(DataModel const&) = delete;
  DataModel& operator=(DataModel const&) = delete;

 protected:
  DataModel() {}
};

}  // namespace IMAPProvider

#endif