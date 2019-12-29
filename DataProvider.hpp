#import <string>
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
	virtual std::string flags(std::string& user, std::string& mailbox) = 0;
	virtual int exists(std::string& user, std::string& mailbox) = 0;
	virtual int recent(std::string& user, std::string& mailbox) = 0;
	virtual int unseen(std::string& user, std::string& mailbox) = 0;
	virtual std::string permanentFlags(std::string& user, std::string& mailbox) = 0;
	virtual long uidnext(std::string& user, std::string& mailbox) = 0;
	virtual long uidvalid(std::string& user, std::string& mailbox) = 0;
	virtual std::string accessType(std::string& user, std::string& mailbox) = 0;
	virtual bool createMbox(std::string& user, std::string& mailbox) = 0;
	virtual bool hasSubFolders(std::string& user, std::string& mailbox) = 0;
	virtual bool hasAttrib(std::string& user, std::string& mailbox, std::string& attrib) = 0;
	virtual bool addAttrib(std::string& user, std::string& mailbox, std::string& attrib) = 0;
	virtual bool rmFolder(std::string& user, std::string& mailbox) = 0;
	virtual bool clear(std::string& user, std::string& mailbox) = 0;
	virtual bool rename(std::string& user, std::string& mailbox, std::string& name) = 0;
	virtual bool addSub(std::string& user, std::string& mailbox) = 0;
	virtual bool rmSub(std::string& user, std::string& mailbox) = 0;
	virtual bool list(std::string& user, std::string& mailbox, std::vector<struct mailbox>& lres) = 0;
	virtual bool lsub(std::string& user, std::string& mailbox, std::vector<struct mailbox>& lres) = 0;
	virtual bool mailboxExists(std::string& user, std::string& mailbox) = 0;
	virtual bool append(std::string& user, std::string& mailbox, std::string& messageData) = 0;
private:
	DataProvider(DataProvider const&) = delete;
	DataProvider& operator=(DataProvider const&) = delete;
protected:
	DataProvider();
};


#endif