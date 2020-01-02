#import <string>
#import <vector>
#import <sstream>

class WordList{
private:
	std::vector<std::string> words;
public:
	WordList(std::string s){
		std::stringstream ss(s);
		std::string sn;
		while(ss >> sn)
			words.push_back(sn);
	}
	size_t size() const{
		return words.size();
	}
	std::string operator[](int n) const{
		if(n >= words.size()) return "";
		return words[n];
	}
	std::string getWords(unsigned int from, unsigned int n) const{
		std::stringstream ss;
		if(from + n >= words.size()){
			n = words.size() - from;
		}
		if(n < 0) return "";
		for(int i = from; i < from + n - 1; i++){
			ss << words[i] << " ";
		}
		ss << words[from + n - 1];
		return ss.str();
	}
	std::string rest(unsigned int from) const{
		return getWords(from, words.size() - from);
	}
};