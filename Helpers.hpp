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

#include <sys/socket.h>
#include <tls.h>
#include <uuid/uuid.h>

#include <algorithm>
#include <vector>
#include <map>

#ifndef __IMAP_HELPERS__
#define __IMAP_HELPERS__

std::string gen_uuid(int len) {
  uuid_t id;
  uuid_generate((unsigned char *)&id);
  srand(1);
  std::string uuid(len, 0);
  uuid[len] = '\0';
  const char alphanum[36] = {'1', '2', '3', '4', '5', '6', '7', '8', '9',
                             '0', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                             'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                             'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
  for (int i = 0; i < len; i++) {
    srand(reinterpret_cast<unsigned int &>(id[i % 16]) + rand());
    uuid[i] = alphanum[rand() % 36];
  }
  return uuid;
}

inline void sendMsg(int fd, const std::string &data) {
#ifndef SO_NOSIGPIPE
  send(fd, &data[0], data.length(), MSG_DONTWAIT | MSG_NOSIGNAL);
#else
  send(fd, &data[0], data.length(), MSG_DONTWAIT);
#endif
}
inline void sendMsg(struct tls *fd, const std::string &data) {
  tls_write(fd, &data[0], data.length());
}
struct mailbox {
  std::string path;
  std::vector<std::string> flags;
};

struct selectResp {
  std::string flags;
  int exists;
  int recent;
  int unseen;
  std::string permanentFlags;
  long uidnext;
  long uidvalid;
  std::string accessType;
};

struct searchCriterion{
  std::vector<std::string> flags;
  std::vector<std::string> notFlags;
  std::map<std::string, std::string> fieldContains;
  std::map<std::string, std::string> fieldNotContains;
  

};

std::string base64_decode(const std::string &in) {
  std::string out;

  std::vector<int> T(256, -1);
  for (int i = 0; i < 64; i++)
    T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] =
        i;

  int val = 0, valb = -8;
  for (char c : in) {
    if (T[c] == -1) break;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      out.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

#endif