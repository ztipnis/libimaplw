#import <string>
#import <map>
#import <sstream>
#import <tls.h>
#include <utility>
#include <type_traits>
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
		void LOGOUT(int rfd, std::string tag) const;
		//UNAUTHENTICATED
		void STARTTLS(int rfd, std::string tag) const;
		void AUTHENTICATE(int rfd, std::string tag, std::string) const;
		void LOGIN(int rfd, std::string tag, std::string, std::string) const;
		 //AUTENTICATED
		void SELECT(int rfd, std::string tag, std::string) const;
		void EXAMINE(int rfd, std::string tag, std::string) const;
		void CREATE(int rfd, std::string tag, std::string) const;
		void DELETE(int rfd, std::string tag, std::string) const;
		void RENAME(int rfd, std::string tag, std::string mailbox, std::string name) const;
		void SUBSCRIBE(int rfd, std::string tag, std::string mailbox) const;
		void UNSUBSCRIBE(int rfd, std::string tag, std::string mailbox) const;
		void LIST(int rfd, std::string tag, std::string reference, std::string name) const;
		void LSUB(int rfd, std::string tag, std::string reference, std::string name) const;
		void STATUS(int rfd, std::string tag, std::string mailbox, std::string datareq) const;
		void APPEND(int rfd, std::string tag, std::string mailbox, std::string flags, std::string msgsize) const;
		//SELECTED
		void CHECK(int rfd, std::string tag) const;
		void CLOSE(int rfd, std::string tag) const;
		void EXPUNGE(int rfd, std::string tag) const;
		void SEARCH(int rfd, std::string tag) const;
		void STORE(int rfd, std::string tag) const;
		void COPY(int rfd, std::string tag) const;
		void UID(int rfd, std::string tag) const;


		//RESPONSES
		inline void respond(int rfd, std::string tag, std::string code, std::string message) const{
			std::stringstream msg;
			msg << tag << " " << code << " " << message << std::endl;
 			if(states[rfd].tls == NULL){
				sendMsg(rfd, msg.str());
			}else{
				sendMsg(states[rfd].tls, msg.str());
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
		AuthenticationProvider& AP = AuthenticationProvider::getInst<AuthP>();
		DataProvider& DP = DataProvider::getInst<DataP>();

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
	if(reason != ""){
		BYE(fd, "*", reason);
	}
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
void IMAPProvider::IMAPProvider<AuthP, DataP>::route(int fd, std::string tag, std::string command, std::string args) const{
	std::transform(command.begin(), command.end(),command.begin(), ::toupper); //https://stackoverflow.com/questions/735204/convert-a-string-in-c-to-upper-case
	if(command == "CAPABILITY"){
		CAPABILITY(fd, tag);
	}else if(command == "NOOP"){
		NOOP(fd, tag);
	}else if(command == "LOGOUT"){
		LOGOUT(fd,tag);
	}else if(command == "STARTTLS"){
		STARTTLS(fd,tag);
	}else if(command == "AUTHENTICATE"){
		AUTHENTICATE(fd,tag, args);
	}else if(command == "LOGIN"){
		LOGIN(fd,tag);
	}else if(command == "SELECT"){
		SELECT(fd,tag);
	}else if(command == "EXAMINE"){
		EXAMINE(fd,tag);
	}else if(command == "CREATE"){
		CREATE(fd,tag);
	}else if(command == "DELETE"){
		DELETE(fd,tag);
	}else if(command == "RENAME"){
		RENAME(fd,tag);
	}else if(command == "SUBSCRIBE"){
		SUBSCRIBE(fd,tag);
	}else if(command == "UNSUBSCRIBE"){
		UNSUBSCRIBE(fd,tag);
	}else if(command == "LIST"){
		LIST(fd,tag);
	}else if(command == "LSUB"){
		LSUB(fd,tag);
	}else if(command == "STATUS"){
		STATUS(fd,tag);
	}else if(command == "APPEND"){
		APPEND(fd,tag);
	}else if(command == "CHECK"){
		CHECK(fd,tag);
	}else if(command == "CLOSE"){
		CLOSE(fd,tag);
	}else if(command == "EXPUNGE"){
		EXPUNGE(fd,tag);
	}else if(command == "SEARCH"){
		SEARCH(fd,tag);
	}else if(command == "STORE"){
		STORE(fd,tag);
	}else if(command == "COPY"){
		COPY(fd,tag);
	}else if(command == "UID"){
		UID(fd,tag);
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

// IMAP COMMANDS:
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CAPABILITY(int rfd, std::string tag) const{
	if(config.starttls && !config.secure && (states[rfd].state() == UNENC)){
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 STARTTLS LOGINDISABLED");
	}else if(!(states[rfd].state() == UNAUTH)){
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 " + AP.capabilityString);
	}else{
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
	}
	OK(rfd, tag, "CAPABILITY Success.");
}
// NOOP ABOVE //

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGOUT(int rfd, std::string tag) const{
	BYE(rfd, "*", "LOGOUT initated by client");
	OK(rfd, tag, "LOGOUT Success.");
	disconnect(rfd, "");
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
void IMAPProvider::IMAPProvider<AuthP, DataP>::AUTHENTICATE(int rfd, std::string tag, std::string mechanism) const {
	if(states[rfd].state() != UNAUTH){
		BAD(rfd, tag, "Already in Authenticated State");
	}
	try{
		states[rfd].SASL(mechanism);
	}catch (const std::exception& excp) {
		NO(rfd, tag, excp.what());
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGIN(int rfd, std::string tag, std::string username, std::string password) const{
	if(states[rfd].authenticate(username,password)){
		 CAPABILITY(rfd, "*");
	}else{
		NO(rfd, tag, "[AUTHENTICATIONFAILED] Invalid Credentials");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SELECT(int rfd, std::string tag, std::string mailbox) const{
	states[rfd].select(mailbox);
	respond(rfd, "*", "FLAGS", DP.flags(states[rfd].getUser(), mailbox));
	respond(rfd, "*", std::to_string(DP.exists(states[rfd].getUser(), mailbox)), "EXISTS");
	respond(rfd, "*", std::to_string(DP.recent(states[rfd].getUser(), mailbox)), "RECENT");
	OK(rfd, "*", "[UNSEEN "+std::to_string(DP.unseen(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, "*", "[PERMANENTFLAGS "+DP.permanentFlags(states[rfd].getUser(), mailbox)+"]");
	OK(rfd, "*", "[UIDNEXT "+std::to_string(DP.uidnext(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, "*", "[UIDVALIDITY "+std::to_string(DP.uidvalid(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, tag, DP.accessType(states[rfd].getUser(), mailbox) + " SELECT Success.");
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXAMINE(int rfd, std::string tag, std::string mailbox) const{
	respond(rfd, "*", "FLAGS", DP.flags(states[rfd].getUser(), mailbox));
	respond(rfd, "*", std::to_string(DP.exists(states[rfd].getUser(), mailbox)), "EXISTS");
	respond(rfd, "*", std::to_string(DP.recent(states[rfd].getUser(), mailbox)), "RECENT");
	OK(rfd, "*", "[UNSEEN "+std::to_string(DP.unseen(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, "*", "[PERMANENTFLAGS "+DP.permanentFlags(states[rfd].getUser(), mailbox)+"]");
	OK(rfd, "*", "[UIDNEXT "+std::to_string(DP.uidnext(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, "*", "[UIDVALIDITY "+std::to_string(DP.uidvalid(states[rfd].getUser(), mailbox))+"]");
	OK(rfd, tag, "[READ-ONLY] EXAMINE Success.");
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CREATE(int rfd, std::string tag, std::string mailbox) const{
	if(DP.createMbox(states[rfd].getUser(), mailbox)){
		OK(rfd, tag, "CREATE Success");
	}else{
		NO(rfd, tag, "CREATE failed to create new mailbox");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::DELETE(int rfd, std::string tag, std::string mailbox) const{
	if(DP.hasSubFolders(states[rfd].getUser(), mailbox)){
		if(DP.hasAttrib(states[rfd].getUser(), mailbox, "\\NoSelect")){
			NO(rfd, tag, "MAILBOX in not deletable");
		}else{
			DP.clear(states[rfd].getUser(), mailbox);
			DP.addAttrib(states[rfd].getUser(), mailbox, "\\NoSelect");
			OK(rfd, tag, "DELETE Success.");
		}
	}else{
		if(DP.rmFolder(states[rfd].getUser(), mailbox))
			OK(rfd,tag,"DELETE Success.");
		else
			NO(rfd, tag, "DELETE Failed.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::RENAME(int rfd, std::string tag, std::string mailbox, std::string name) const{
	if(DP.rename(states[rfd].getUser(), mailbox, name)){
		OK(rfd, tag, "RENAME Success.");
	}else{
		NO(rfd, tag, "RENAME Failed.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SUBSCRIBE(int rfd, std::string tag, std::string mailbox) const{
	if(DP.addSub(states[rfd].getUser(), mailbox)){
		OK(rfd, tag, " Success.");
	}else{
		NO(rfd, tag, " Failed.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UNSUBSCRIBE(int rfd, std::string tag, std::string mailbox) const{
	if(DP.rmSub(states[rfd].getUser(), states[rfd].getUser(), mailbox)){
		OK(rfd, tag, " Success.");
	}else{
		NO(rfd, tag, " Failed.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LIST(int rfd, std::string tag, std::string reference, std::string name) const{
	char* ref = new char[reference.length()];
	strncpy(ref,reference.c_str(), reference.length());
	char* mboxs = new char[name.length()];
	strncpy(mboxs,name.c_str(), name.length());
	std::vector<std::string> mboxPath;
	if(mboxs[0] != '/'){
		while(const char* token = strtok_r(ref, "/.", &ref)){
			mboxPath.push_back(std::string(token));
		}
	}
	while(const char* token = strtok_r(mboxs, "/.", &mboxs)){
		mboxPath.push_back(std::string(token));
	}
	std::vector<mailbox> lres;
	DP.list(states[rfd].getUser(), mboxPath, lres);
	delete[] ref;
	delete[] mboxs;
	if(lres.size() > 0){
		for(auto box : std::as_const(lres)){
			std::stringstream listres;
			listres << "(";
			for(auto flag : std::as_const(box.flags))
				listres << flag << " ";
			listres << "\b" << ") " << "\"/\"" << box.path;
			respond(rfd, "*", "LIST", listres.str());
		} 
		OK(rfd, tag, "LIST Success.");
	}else{
		NO(rfd, tag, "LIST No Such Folder.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LSUB(int rfd, std::string tag, std::string reference, std::string name) const{
	char* ref = new char[reference.length()];
	strncpy(ref,reference.c_str(), reference.length());
	char* mboxs = new char[name.length()];
	strncpy(mboxs,name.c_str(), name.length());
	std::vector<std::string> mboxPath;
	if(mboxs[0] != '/'){
		while(const char* token = strtok_r(ref, "/.", &ref)){
			mboxPath.push_back(std::string(token));
		}
	}
	while(const char* token = strtok_r(mboxs, "/.", &mboxs)){
		mboxPath.push_back(std::string(token));
	}
	std::vector<mailbox> lres;
	DP.lsub(states[rfd].getUser(), mboxPath, lres);
	delete[] ref;
	delete[] mboxs;
	if(lres.size() > 0){
		for(auto box : std::as_const(lres)){
			std::stringstream listres;
			listres << "(";
			for(auto flag : std::as_const(box.flags))
				listres << flag << " ";
			listres << "\b" << ") " << "\"/\"" << box.path;
			respond(rfd, "*", "LSUB", listres.str());
		} 
		OK(rfd, tag, "LSUB Success.");
	}else{
		NO(rfd, tag, "LSUB No Such Folder.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STATUS(int rfd, std::string tag, std::string mailbox, std::string datareq) const{
	if(DP.mailboxExists(states[rfd].getUser(), mailbox)){
		std::stringstream resp;
		resp << mailbox << " (";

		resp << ")";
		OK(rfd, tag, "STATUS Success.");
	}else{
		NO(rfd, tag, "STATUS Failed. No Status for that name.");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::APPEND(int rfd, std::string tag, std::string mailbox, std::string flags, std::string msgsize) const{
	if(!DP.mailboxExists(states[rfd].getUser(), mailbox)){
		NO(rfd, tag, "[TRYCREATE] APPEND Failed.");
	}else{
		respond(rfd, "+", "", "Go Ahead");
		int rcvd = 0;
		int msg_sz;
		sscanf(msgsize.c_str(), "%*s %u %*s", &msg_sz);
		std::string data(msg_sz + 1, 0);
		std::stringstream buffer;
		for(int total_recv = 0; total_recv < msg_sz; total_recv += rcvd){
			if(states[rfd].state() != UNENC){
				rcvd = tls_read(states[rfd].tls, &data[0], msg_sz - total_recv);
			}else{
				rcvd= recv(rfd, &data[0], msg_sz - total_recv, MSG_DONTWAIT);
			}
			buffer << data;
		}
		DP.append(states[rfd].getUser(), mailbox, buffer.str());
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CHECK(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CLOSE(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXPUNGE(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SEARCH(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::STORE(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::COPY(int rfd, std::string tag) const{}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::UID(int rfd, std::string tag) const{}






#endif