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
#include <sstream>
#include <boost/log/trivial.hpp>
#include <miniz.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <poll.h>

#ifndef __IMAP_HELPERS__
#define __IMAP_HELPERS__

#define ifThenElse(a,b,c) (a ? b : c)
#define __min__(a,b) ( a < b ? a : b)
#define __max__(a,b) ( a > b ? a : b)

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

inline int sendMsg(int fd, const std::string &data) {
  // std::signal(SIGPIPE, SIG_IGN);
  #ifndef SO_NOSIGPIPE
    int i = send(fd, &data[0], data.length(), MSG_DONTWAIT | MSG_NOSIGNAL);
  #else
    int i = send(fd, &data[0], data.length(), MSG_DONTWAIT);
  #endif
    BOOST_LOG_TRIVIAL(trace) <<"SEND call to socket " << fd << " Returned:" << i << " " << (errno != 0 ? strerror(errno) : "");
    return (i < 0 ? errno : 0);
}
inline int sendMsg(struct tls *fd, int fdn, const std::string &data) {
  std::signal(SIGPIPE, SIG_IGN);
  int i = tls_write(fd, &data[0], data.length());
  if(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT){
    struct pollfd pfd[1];
    pfd[0].fd = fdn;
    if(i == TLS_WANT_POLLOUT){
      pfd[0].events = POLLOUT;
    }else if(i == TLS_WANT_POLLIN){
      pfd[0].events = POLLIN;
    }else return (i < 0 ? errno : 0);
    poll(pfd, 1, 0); 
    i = tls_write(fd, &data[0], data.length());
  }
  BOOST_LOG_TRIVIAL(trace) <<"SEND call to socket " << fd << " Returned:" << i << " " << (errno != 0 ? strerror(errno) : "");
  return (i < 0 ? errno : 0);
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

template <class T>
std::string join(const T& itms,
                 const std::string& delimiter) {
  std::string buffer;
  if(itms.size() <= 1){
    if(itms.size() == 1){
      return itms[0];
    }else{
      return "";
    }
  }
  for (int i = 0; i < itms.size() - 1; i++) {
    buffer += itms[i] + delimiter;
  }
  int sz = itms.size() - 1;
  if (sz >= 0) {
    buffer += itms[(itms.size() - 1)];
  }
  return buffer;
}

bool isNumeric(const std::string& s){
  if(s.length() < 1)
    return false;
  else
    return std::all_of(s.begin(), s.end(), [](const unsigned char c){
      return std::isdigit(c);
    });
}
bool isRange(const std::string& s){
  if(s.length() < 1)
    return false;
  else
    return std::all_of(s.begin(), s.end(), [](const unsigned char c){
      return (std::isdigit(c) || c == '-');
    });
}

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

#define Z_BUF_SIZE (1024*1024)
const std::string deflate(const std::string& data, const int level){
  z_stream strm = {0};
  std::string outbuf(Z_BUF_SIZE, 0);
  std::string inbuf(__min__(Z_BUF_SIZE, data.length()), 0);
  std::stringstream buf;
  strm.next_out = reinterpret_cast<unsigned char*>(&outbuf[0]);
  strm.avail_out = Z_BUF_SIZE;
  strm.next_in = reinterpret_cast<unsigned char*>(&inbuf[0]);
  strm.avail_in = 0;

  uint remaining = data.length();

  if(deflateInit(&strm, level) != Z_OK){
    BOOST_LOG_TRIVIAL(error) << "Unable to init deflate";
    return data;
  }
  while(1){
    if(!strm.avail_in){
      uint bytesToRead = __min__(Z_BUF_SIZE, remaining);
      inbuf = data.substr(data.length() - remaining, bytesToRead);
      strm.next_in = reinterpret_cast<unsigned char*>(&inbuf[0]);
      strm.avail_in = bytesToRead;
      remaining -= bytesToRead;
    }
    int status = deflate(&strm, ifThenElse(remaining, Z_NO_FLUSH, Z_FINISH));
    if(status == Z_STREAM_END || (!strm.avail_out)){
      // Output buffer is full, or compression is done.
      uint n = Z_BUF_SIZE - strm.avail_out;
      buf << outbuf.substr(0,n);
      std::fill(outbuf.begin(), outbuf.end(), 0);
      strm.next_out = reinterpret_cast<unsigned char*>(&outbuf[0]);
      strm.avail_out = Z_BUF_SIZE;
    }
    if(status == Z_STREAM_END)
      break;
    else if(status != Z_OK)
      BOOST_LOG_TRIVIAL(error) << "Deflate status not 'OK'";
      return data;
  }
  if(deflateEnd(&strm) != Z_OK){
    BOOST_LOG_TRIVIAL(warning) << "zlib unable to cleanup deflate stream";
  }
  std::string ret = buf.str();
  if(ret.length() != strm.total_out){
    BOOST_LOG_TRIVIAL(error) << "Output size mismatch - Expected: " << strm.total_out << " Got: " << ret.length(); 
  }
  BOOST_LOG_TRIVIAL(trace) << "DEFLATE: " << ((ret.length() * 100) / data.length()) << "%" << ret;
  return ret;
}

const std::string inflate(const std::string& data){
  z_stream strm = {0};
  std::string outbuf(Z_BUF_SIZE, 0);
  std::string inbuf(Z_BUF_SIZE, 0);
  std::stringstream buf;
  strm.next_out = reinterpret_cast<unsigned char*>(&outbuf[0]);
  strm.avail_out = Z_BUF_SIZE;
  strm.next_in = reinterpret_cast<unsigned char*>(&inbuf[0]);
  strm.avail_in = 0;
  uint remaining = data.length();
  if(inflateInit(&strm) != Z_OK){
    throw std::runtime_error("Unable to inflate command data: Init failed.\n");
  }
  while(remaining > 0){
    std::cout << strm.avail_in + remaining << std::endl;
    if(strm.avail_in <= 0){
      uint bytesToRead = __min__(Z_BUF_SIZE, remaining);
      inbuf = data.substr(data.length() - remaining, bytesToRead);
      strm.next_in = reinterpret_cast<unsigned char*>(&inbuf[0]);
      strm.avail_in = bytesToRead;
      remaining -= bytesToRead;
    }
    int status = ::inflate(&strm, Z_SYNC_FLUSH);
    if ((status == Z_STREAM_END) || (!strm.avail_out)){
        // Output buffer is full, or decompression is done
      uint n = Z_BUF_SIZE - strm.avail_out;
      buf << outbuf.substr(0,n);
      std::fill(outbuf.begin(), outbuf.end(), 0);
      strm.next_out = reinterpret_cast<unsigned char*>(&outbuf[0]);
      strm.avail_out = Z_BUF_SIZE;
    }
    if(status == Z_STREAM_END){
      break;
    }
    else if(status != Z_OK){
      return "";
    }
   
  }
  BOOST_LOG_TRIVIAL(trace) << buf.str();
  if(inflateEnd(&strm) != Z_OK){
    BOOST_LOG_TRIVIAL(warning) << "zlib unable to cleanup inflate stream";
  }
  BOOST_LOG_TRIVIAL(trace) << buf.str();
  std::string ret(buf.str());
  if(ret.length() != strm.total_out){
    BOOST_LOG_TRIVIAL(error) << "Output size mismatch - Expected: " << strm.total_out << " Got: " << ret.length(); 
  }
  BOOST_LOG_TRIVIAL(trace) << buf.str();
  return ret;
}


#endif