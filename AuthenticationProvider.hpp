#ifndef __IMAP__AUTH_PROVIDER__
#define __IMAP__AUTH_PROVIDER__

class AuthenticationProvider {
public:
	virtual bool lookup(std::string username) = 0;
	virtual bool authenticate(std::string username, std::string password) = 0;
	virtual std::string SASL(struct tls* fd, std::string mechanism) = 0;
	const std::string capabilityString;
	template <typename T> static AuthenticationProvider& getInst(){
		static T m_Inst;
		return m_Inst;
	}
private:
	AuthenticationProvider(AuthenticationProvider const&) = delete;
	AuthenticationProvider& operator=(AuthenticationProvider const&) = delete;
protected:
	AuthenticationProvider(std::string capabilities) : capabilityString(capabilities){}
};


#endif