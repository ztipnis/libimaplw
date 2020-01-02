#import <string>
#import <map>
#import <sstream>
#import <tls.h>
#include <utility>
#include <type_traits>
#include <functional>
#import <SocketPool.hpp>
#import "WordList.hpp"
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
		static void newDataAvailable(int rfd, std::vector<std::string> data){ for(std::string d : data) respond(rfd, "*", "", d); }


		//RESPONSES
		static inline void respond(int rfd, std::string tag, std::string code, std::string message){
			std::stringstream msg;
			msg << tag << " " << code << " " << message << std::endl;
 			if(states[rfd].tls == NULL){
				sendMsg(rfd, msg.str());
			}else{
				sendMsg(states[rfd].tls, msg.str());
			}
		}

		void OK(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "OK", message + " " + states[rfd].get_uuid()); }
		void NO(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "NO", message + " " + states[rfd].get_uuid()); }
		void BAD(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "BAD", message + " " + states[rfd].get_uuid()); }
		void PREAUTH(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "PREAUTH", message + " " + states[rfd].get_uuid()); }
		void BYE(int rfd, std::string tag, std::string message) const{ respond(rfd, tag, "BYE", message + " " + states[rfd].get_uuid()); }
		void route(int fd, std::string tag, std::string command, const WordList& args) const;
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
void IMAPProvider::IMAPProvider<AuthP, DataP>::route(int fd, std::string tag, std::string command, const WordList& args) const{
	std::transform(command.begin(), command.end(),command.begin(), ::toupper); //https://stackoverflow.com/questions/735204/convert-a-string-in-c-to-upper-case

	if(command == "CAPABILITY"){
		CAPABILITY(fd, tag);
	}else if(command == "NOOP"){
		NOOP(fd, tag);
	}else if(command == "LOGOUT"){
		LOGOUT(fd,tag);
	}else /* UNAUTHENTICATED */ if(command == "STARTTLS"){
		STARTTLS(fd,tag);
	}else if(command == "AUTHENTICATE"){
		AUTHENTICATE(fd,tag, args.rest(0));
	}else if(command == "LOGIN"){
		LOGIN(fd,tag,args[0], args.rest(1));
	}else  /* AUTHENTICATED */ if(command == "SELECT"){
		SELECT(fd,tag, args.rest(0));
	}else if(command == "EXAMINE"){
		EXAMINE(fd,tag, args.rest(0));
	}else if(command == "CREATE"){
		CREATE(fd,tag, args.rest(0));
	}else if(command == "DELETE"){
		DELETE(fd,tag,args.rest(0));
	}else if(command == "RENAME"){
		RENAME(fd,tag,args[0],args.rest(1));
	}else if(command == "SUBSCRIBE"){
		SUBSCRIBE(fd,tag, args.rest(0));
	}else if(command == "UNSUBSCRIBE"){
		UNSUBSCRIBE(fd,tag, args.rest(0));
	}else if(command == "LIST"){
		LIST(fd,tag, args[0], args.rest(1));
	}else if(command == "LSUB"){
		LSUB(fd,tag, args[0], args.rest(1));
	}else if(command == "STATUS"){
		STATUS(fd,tag, args[0], args.rest(1));
	}else if(command == "APPEND"){
		APPEND(fd,tag, args[0], args[2], args.rest(2));
	}else /* SELECTED */ if(command == "CHECK"){
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
	WordList args(message);

	if(args.size() >= 2){
		route(fd, args[0], args[1], WordList(args.rest(2)));
	}else{
		BAD(fd, "*", "Unable to parse command \"" + message + "\"");
	}
}

// IMAP COMMANDS:
template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::CAPABILITY(int rfd, std::string tag) const{
	if(config.starttls && !config.secure && (states[rfd].state() == UNENC)){
		respond(rfd, "*", "CAPABILITY", "IMAP4rev1 STARTTLS LOGINDISABLED");
	}else if(states[rfd].state() == UNAUTH){
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

std::string base64_decode(const std::string &in) {

    std::string out;

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i; 

    int val=0, valb=-8;
    for (char c : in) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::AUTHENTICATE(int rfd, std::string tag, std::string mechanism) const {
	if(states[rfd].state() != UNAUTH){
		BAD(rfd, tag, "Already in Authenticated State");
	}
	std::transform(mechanism.begin(), mechanism.end(),mechanism.begin(), ::toupper);
	if(mechanism == "PLAIN"){
		respond(rfd, "+", "", "Go Ahead");
		std::string data(8193, 0);
		int rcvd;
		if(states[rfd].state() != UNENC){
			rcvd = tls_read(states[rfd].tls, &data[0], 8912);
		}else{
			rcvd= recv(rfd, &data[0], 8192, MSG_DONTWAIT);
		}
		if(rcvd < 6){
			NO(rfd, tag, "Authentication Failed");
		}else{
			std::string decoded_data = base64_decode(data);
			std::string nullSepStr = decoded_data.substr(1,std::string::npos);
			std::size_t seploc = nullSepStr.find('\0');
			if(seploc == std::string::npos){
				NO(rfd, tag, "Authentication Failed");
			}else{
				std::string username = nullSepStr.substr(0,seploc),
							password = nullSepStr.substr(seploc+1, std::string::npos);
				if(states[rfd].authenticate(username,password)){
					respond(rfd, "*", "CAPABILITY", "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
		 			OK(rfd, tag, "AUTHENTICATE Success.");
				}
			}
		}

	}else
	try{
		if(states[rfd].SASL(mechanism)){
			respond(rfd, "*", "CAPABILITY", "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
		 	OK(rfd, tag, "AUTHENTICATE Success.");
		}
	}catch (const std::exception& excp) {
		NO(rfd, tag, excp.what());
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::LOGIN(int rfd, std::string tag, std::string username, std::string password) const{
	if(states[rfd].authenticate(username,password)){
		 respond(rfd, "*", "CAPABILITY", "IMAP4rev1 COMPRESS=DEFLATE UNSELECT MOVE SPECIAL-USE");
		 OK(rfd, tag, "LOGIN Success.");
	}else{
		NO(rfd, tag, "[AUTHENTICATIONFAILED] Invalid Credentials");
	}
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::SELECT(int rfd, std::string tag, std::string mailbox) const{
	states[rfd].select(mailbox);
	auto onData = std::bind(newDataAvailable, rfd, std::placeholders::_1);
	states[rfd].isSubscribedToChanges = DP.subscribe(states[rfd].getUser(), mailbox, onData);
	selectResp r = DP.select(states[rfd].getUser(), mailbox);
	respond(rfd, "*", "FLAGS", r.flags);
	respond(rfd, "*", std::to_string(r.exists), "EXISTS");
	respond(rfd, "*", std::to_string(r.recent), "RECENT");
	OK(rfd, "*", "[UNSEEN "+std::to_string(r.unseen)+"]");
	OK(rfd, "*", "[PERMANENTFLAGS "+r.permanentFlags+"]");
	OK(rfd, "*", "[UIDNEXT "+std::to_string(r.uidnext)+"]");
	OK(rfd, "*", "[UIDVALIDITY "+std::to_string(r.uidvalid)+"]");
	OK(rfd, tag, r.accessType + " SELECT Success.");
}

template<class AuthP, class DataP>
void IMAPProvider::IMAPProvider<AuthP, DataP>::EXAMINE(int rfd, std::string tag, std::string mailbox) const{
	states[rfd].select(mailbox);
	selectResp r = DP.select(states[rfd].getUser(), mailbox);
	respond(rfd, "*", "FLAGS", r.flags);
	respond(rfd, "*", std::to_string(r.exists), "EXISTS");
	respond(rfd, "*", std::to_string(r.recent), "RECENT");
	OK(rfd, "*", "[UNSEEN "+std::to_string(r.unseen)+"]");
	OK(rfd, "*", "[PERMANENTFLAGS "+r.permanentFlags+"]");
	OK(rfd, "*", "[UIDNEXT "+std::to_string(r.uidnext)+"]");
	OK(rfd, "*", "[UIDVALIDITY "+std::to_string(r.uidvalid)+"]");
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
	if(DP.rmSub(states[rfd].getUser(), mailbox)){
		OK(rfd, tag, " Success.");
	}else{
		NO(rfd, tag, " Failed.");
	}
}

std::string join(const std::vector<std::string> &itms, std::string delimiter){
	std::string buffer;
	for(int i = 0; i < itms.size() - 1; i++){
		buffer += itms[i] + delimiter;
	}
	if(itms.size() - 1 >= 0){
		buffer += itms[(itms.size() - 1)];
	}
	return buffer;
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
	DP.list(states[rfd].getUser(), join(mboxPath, "/"), lres);
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
	DP.lsub(states[rfd].getUser(), join(mboxPath, "/"), lres);
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
		sscanf(msgsize.c_str(), "{%d}", &msg_sz);
		std::string data(msg_sz + 1, 0);
		std::stringstream buffer;
		for(int total_recv = 0; total_recv < msg_sz; total_recv += rcvd){
			if(states[rfd].state() != UNENC){
				rcvd = tls_read(states[rfd].tls, &data[0], msg_sz - total_recv);
			}else{
				rcvd= recv(rfd, &data[0], msg_sz - total_recv, 0);
			}
			buffer << data;
		}
		std::string dat = buffer.str();
		DP.append(states[rfd].getUser(), mailbox, dat);
		OK(rfd, tag, "APPEND Success. data: " + dat);
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