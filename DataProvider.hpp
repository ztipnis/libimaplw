#import <string>
#import <vector>
#import <utility>
#include <functional>
#import "Helpers.hpp"
#ifndef __IMAP_DATA_PROVIDER__
#define __IMAP_DATA_PROVIDER__

//Dataprovider Subclass must provide init() to initialize m_Inst and implement all public functions.
class DataProvider {
public:
	template <typename T> static DataProvider& getInst(){
		static T m_Inst;
		return m_Inst;
	}
	virtual selectResp select(const std::string& user, const std::string& mailbox) = 0;
	virtual bool createMbox(const std::string& user, const std::string& mailbox) = 0;
	virtual bool hasSubFolders(const std::string& user, const std::string& mailbox) = 0;
	virtual bool hasAttrib(const std::string& user, const std::string& mailbox, const std::string& attrib) = 0;
	virtual bool addAttrib(const std::string& user, const std::string& mailbox, const std::string& attrib) = 0;
	virtual bool rmFolder(const std::string& user, const std::string& mailbox) = 0;
	virtual bool clear(const std::string& user, const std::string& mailbox) = 0;
	virtual bool rename(const std::string& user, const std::string& mailbox, const std::string& name) = 0;
	virtual bool addSub(const std::string& user, const std::string& mailbox) = 0;
	virtual bool rmSub(const std::string& user, const std::string& mailbox) = 0;
	virtual bool list(const std::string& user, const std::string& mailbox, std::vector<struct mailbox>& lres) = 0;
	virtual bool lsub(const std::string& user, const std::string& mailbox, std::vector<struct mailbox>& lres) = 0;
	virtual bool mailboxExists(const std::string& user, const std::string& mailbox) = 0;
	virtual bool append(const std::string& user, const std::string& mailbox, const std::string& messageData) = 0;
	virtual bool subscribe(const std::string& user, const std::string& mailbox, std::function<void(std::vector<std::string>)> callback){ return false; } //note, function passed by value in order to preserve temporary std::bind value
private:
	DataProvider(DataProvider const&) = delete;
	DataProvider& operator=(DataProvider const&) = delete;
protected:
	DataProvider(){}
};


#endif