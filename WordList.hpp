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

#include <sstream>
#include <string>
#include <vector>
#include <iomanip>

#ifndef __H_WORDLIST__
#define __H_WORDLIST__

class WordList {
 private:
  std::vector<std::string> words;

 public:
  using iterator = std::vector<std::string>::iterator;

  explicit WordList(std::string s) {
    std::stringstream ss(s);
    std::string sn;
    while (ss >> std::quoted(sn)) words.push_back(sn);
  }

  iterator begin(){ return words.begin(); }
  iterator end(){ return words.end(); }

  size_t size() const { return words.size(); }
  size_t length() const { return size(); }
  std::string pop(int idx){
    assert(idx < words.size());
    auto iter = words.begin() + idx;
    std::string ret = *iter;
    words.erase(iter);
    return ret;
  }
  std::string operator[](int n) const {
    if (n >= words.size()) return "";
    return words[n];
  }
  std::string getWords(unsigned int from, int n) const {
    std::stringstream ss;
    if (from + n >= words.size()) {
      n = words.size() - from;
    }
    if (n < 0) return "";
    for (int i = from; i < from + n - 1; i++) {
      ss << words[i] << " ";
    }
    ss << words[from + n - 1];
    return ss.str();
  }
  std::string rest(unsigned int from) const {
    return getWords(from, words.size() - from);
  }
};
#endif