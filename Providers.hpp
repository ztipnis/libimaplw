#import <string>
#import <map>
#import <sstream>
#import <tls.h>
#import <SocketPool.hpp>
#import "IMAPClientState.hpp"
#import "Helpers.hpp"
#import "config.hpp"

#ifndef __IMAP_PROVIDERS__
#define __IMAP_PROVIDERS__

namespace IMAPProvider{
	template <class AuthP, class DataP>
	class IMAPProvider: public Pollster::Handler{
	private:
		const Config &config;
		static std::map<int, IMAPClientState<AuthP> > states;
		struct tls *tls = NULL;
		struct tls_config *t_conf = NULL;
		//ANY STATE
		void CAPABILITY(int rfd, std::string tag) const;
		void NOOP(int rfd, std::string tag) const{ OK(rfd, tag, "NOOP executed successfully"); }
		void LOGOUT(int rfd) const;
		//UNAUTHENTICATED
		void STARTTLS(int rfd, std::string tag) const;
		void AUTHENTICATE(int rfd) const;
		void LOGIN(int rfd) const;
		 //AUTENTICATED
		void SELECT(int rfd) const;
		void EXAMINE(int rfd) const;
		void CREATE(int rfd) const;
		void DELETE(int rfd) const;
		void RENAME(int rfd) const;
		void SUBSCRIBE(int rfd) const;
		void UNSUBSCRIBE(int rfd) const;
		void LIST(int rfd) const;
		void LSUB(int rfd) const;
		void STATUS(int rfd) const;
		void APPEND(int rfd) const;
		//SELECTED
		void CHECK(int rfd) const;
		void CLOSE(int rfd) const;
		void EXPUNGE(int rfd) const;
		void SEARCH(int rfd) const;
		void STORE(int rfd) const;
		void COPY(int rfd) const;
		void UID(int rfd) const;


		//RESPONSES
		inline void respond(int rfd, std::string tag, std::string code, std::string message) const{
			if(states[rfd].tls == NULL){
				sendMsg(rfd, tag + " "+ code +" " + message + "\n");
			}else{
				sendMsg(states[rfd].tls, tag + " "+ code +" " + message + "\n");
			}
		}

		void OK(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "OK", message + " " + states[rfd].get_uuid()); }
		void NO(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "NO", message); }
		void BAD(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "BAD", message); }
		void PREAUTH(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "PREAUTH", message); }
		void BYE(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "BYE", message); }
		void route(int fd, std::string tag, std::string command, std::string args) const;
		void parse(int fd, std::string message) const;
		void tls_setup();
		void tls_cleanup();
	public:
		IMAPProvider(Config &cfg) : config(cfg){ if(cfg.secure || cfg.starttls) tls_setup(); }
		~IMAPProvider(){ tls_cleanup(); }
		void operator()(int fd) const;
		void disconnect(int fd, const std::string &reason) const;
		void connect(int fd) const;
	};
}
template<class AuthP, class DataP>
std::map<int, typename IMAPProvider::IMAPClientState<AuthP> > IMAPProvider::IMAPProvider<AuthP, DataP>::states;
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::operator()(int fd) const{
	std::string data(8193, 0);
	int rcvd;
	if(states[fd].state() != UNENC){
		rcvd = tls_read(states[fd].tls, &data[0], 8912);
	}else{
		rcvd= recv(fd, &data[0], 8192, MSG_DONTWAIT);
	}
	if( rcvd == -1){
		disconnect(fd, "Unable to read from socket");
	}else{
		data.resize(rcvd);
		parse(fd, data);
	}
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::disconnect(int fd, const std::string &reason) const{
	BYE(fd, "*", reason);
	if(states[fd].tls !=  NULL){
		tls_close(states[fd].tls);
		tls_free(states[fd].tls);
	}
	states.erase(fd);
	close(fd);
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::connect(int fd) const{
	if(config.secure){
		if(tls_accept_socket(tls, &states[fd].tls, fd) < 0) {
			disconnect(fd, "TLS Negotiation Failed");
		}else{
			if(tls_handshake(states[fd].tls) < 0){
				disconnect(fd, "TLS Negotiation Failed");
			}else{
				states[fd].starttls();
			}
		}
	}
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	int getaddr = getpeername(fd, (struct sockaddr *) &addr, &addrlen);
	std::string address(inet_ntoa(addr.sin_addr));
	OK(fd, "*", "Welcome to IMAPlw. IMAP ready for requests from " + address);
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::tls_setup(){
	t_conf = tls_config_new();
	tls = tls_server();
	unsigned int protocols = 0;
	if(tls_config_parse_protocols(&protocols, config.versions) < 0){
		printf("tls_config_parse_protocols error\n");
	}
	tls_config_set_protocols(t_conf, protocols);
	if(tls_config_set_ciphers(t_conf, config.ciphers) < 0) {
		printf("tls_config_set_ciphers error\n");
	}
	if(tls_config_set_key_file(t_conf, config.keypath) < 0) {
		printf("tls_config_set_key_file error\n");
	}
	if(tls_config_set_cert_file(t_conf, config.certpath) < 0) {
		printf("tls_config_set_cert_file error\n");
	}
	if(tls_configure(tls, t_conf) < 0) {
		printf("tls_configure error: %s\n", tls_error(tls));
	}
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::tls_cleanup(){
	if(t_conf != NULL){
		tls_config_free(t_conf);
	}
	if(tls != NULL){
		tls_close(tls);
		tls_free(tls);
	}
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CAPABILITY(int rfd, std::string tag) const{
	if(config.starttls && !config.secure && (states[rfd].state() == UNENC)){
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 STARTTLS");
	}else{
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 ");
	}
	OK(rfd, tag, "CAPABILITY executed successfully");
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STARTTLS(int rfd, std::string tag) const{
	if(config.starttls && !config.secure && (states[rfd].state() == UNENC)){
		OK(rfd, tag, "Begin TLS Negotiation Now");
		if(tls_accept_socket(tls, &states[rfd].tls, rfd) < 0) {
			BAD(rfd, "*", "tls_accept_socket error");
		}else{
			if(tls_handshake(states[rfd].tls) < 0){
				BAD(rfd, "*", "tls_handshake error");
			}else{
				states[rfd].starttls();
			}
		}
	}else{
		BAD(rfd, tag, "STARTTLS Disabled");
	}
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::route(int fd, std::string tag, std::string command, std::string args) const{
	std::transform(command.begin(), command.end(),command.begin(), ::toupper); //https://stackoverflow.com/questions/735204/convert-a-string-in-c-to-upper-case
	if(command == "CAPABILITY"){
		CAPABILITY(fd, tag);
	}else if(command == "STARTTLS"){
		STARTTLS(fd, tag);
	}else{
		BAD(fd, tag, "Command \"" + command + "\" NOT FOUND");
	}
}
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::parse(int fd, std::string message) const{
	std::stringstream mstream(message);
	std::string tag, command, args;
	if(mstream >> tag >> command){
		if(mstream >> args){
			route(fd, tag, command, args);
		}else{
			route(fd, tag, command, "");
		}
	}else{
		BAD(fd, "*", "Unable to parse command");
	}
}

#endif












