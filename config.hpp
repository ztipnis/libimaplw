#ifndef __IMAP_CONFIG__
#define __IMAP_CONFIG__

namespace IMAPProvider{
	class Config{
	public:
		const bool secure;
		const bool starttls;
		const char* ciphers;
		const char* versions;
		const char* keypath;
		const char* certpath;
		Config(bool _secure,  bool _starttls, const char* _versions, const char* _ciphers, const char* _keypath, const char* _certpath) : secure(_secure), starttls(_starttls), versions(_versions),ciphers(_ciphers), keypath(_keypath), certpath(_certpath){}
	};
}

#endif