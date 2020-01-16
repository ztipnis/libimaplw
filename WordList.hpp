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

#ifndef __H_WORDLIST__
#define __H_WORDLIST__

class WordList {
 private:
  std::vector<std::string> words;

 public:
  WordList(std::string s) {
    std::stringstream ss(s);
    std::string sn;
    while (ss >> sn) words.push_back(sn);
  }
  size_t size() const { return words.size(); }
  std::string operator[](int n) const {
    if (n >= words.size()) return "";
    return words[n];
  }
  std::string getWords(unsigned int from, unsigned int n) const {
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
  std::vector<std::string>::iterator begin() { return words.begin(); }
  std::vector<std::string>::iterator end() { return words.end(); }
};
#endif