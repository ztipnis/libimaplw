#ifndef __IMAP__AUTH_PROVIDER__
#define __IMAP__AUTH_PROVIDER__

class AuthenticationProvider {
public:
	virtual bool lookup(std::string username) = 0;
	virtual bool authenticate(std::string username, std::string password) = 0;
	template <class T> static AuthenticationProvider& getInst(){
		static T m_Inst;
		return m_Inst;
	}
private:
	AuthenticationProvider(AuthenticationProvider const&) = delete;
	AuthenticationProvider& operator=(AuthenticationProvider const&) = delete;
	AuthenticationProvider() = delete;
};


#endif