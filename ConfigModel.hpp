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

#ifndef __IMAP_CONFIG__
#define __IMAP_CONFIG__

namespace IMAPProvider {
class ConfigModel {
 public:
  const bool secure;
  const bool starttls;
  const char* ciphers;
  const char* versions;
  const char* keypath;
  const char* certpath;
  ConfigModel(bool _secure, bool _starttls, const char* _versions,
              const char* _ciphers, const char* _keypath, const char* _certpath)
      : secure(_secure),
        starttls(_starttls),
        ciphers(_ciphers),
        versions(_versions),
        keypath(_keypath),
        certpath(_certpath) {}
};
}  // namespace IMAPProvider

#endif
