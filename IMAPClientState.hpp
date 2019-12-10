#import "Helpers.hpp"
#import "AuthenticationProvider.hpp"

#ifndef __IMAP_CLIENT_STATE__
#define __IMAP_CLIENT_STATE__

namespace IMAPProvider{
	typedef enum { UNENC, UNAUTH, AUTH, SELECTED } IMAPState_t;
	template <class A>
	class IMAPClientState {
	private:
		std::string uuid;
		bool encrypted;
		bool authenticated;
		std::string user;
		bool selected;
		std::string mbox;
		
	public:
		struct tls *tls = NULL;
		IMAPClientState(){
			encrypted = false;
			authenticated = false;
			user = "";
			selected = false;
			mbox = "";
			uuid = gen_uuid(15);
		}
		const IMAPState_t state() const{
			if(!encrypted){
				return UNENC;
			}else if(authenticated){
				if(selected){
					return SELECTED;
				}else{
					return AUTH;
				}
			}else{
				return UNAUTH;
			}
		}
		void starttls(){
			encrypted = true;
		}
		void logout(){
			authenticated = false;
			user = "";
		}
		const std::string getUser() const{
			return user;
		}
		const std::string getMBox() const{
			return mbox;
		}
		const std::string get_uuid() const{
			return uuid;
		}
		void SASL(std::string mechanism){
			AuthenticationProvider& provider = AuthenticationProvider::getInst<A>();
			user = provider.SASL(tls, mechanism);
			authenticated = true;
		}
		bool authenticate(const std::string& username, const std::string& password){
			AuthenticationProvider& provider = AuthenticationProvider::getInst<A>();
			if(provider.lookup(username) == false){
				return false;
			}
			if(provider.authenticate(username, password)){
				authenticated = true;
				user = username;
				return true;
			}
			return false;
		}
		void select(std::string mailbox){
			mbox = mailbox;
		}
	};
}

#endif