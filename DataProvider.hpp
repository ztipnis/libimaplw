#import <string>
#ifndef __IMAP_DATA_PROVIDER__
#define __IMAP_DATA_PROVIDER__

//Dataprovider Subclass must provide init() to initialize m_Inst and implement all public functions.
class DataProvider {
public:
	template <class T> static DataProvider& getInst(){
		static T m_Inst;
		return m_Inst;
	}
	virtual std::string flags(std::string mailbox) = 0;
	virtual int exists(std::string mailbox) = 0;
	virtual int recent(std::string mailbox) = 0;
	virtual int unseen(std::string mailbox) = 0;
	virtual std::string permanentFlags(std::string mailbox) = 0;
	virtual long uidnext(std::string mailbox) = 0;
	virtual long uidvalid(std::string mailbox) = 0;
	virtual std::string accessType(std::string mailbox) = 0;
	virtual bool createMbox(std::string) = 0;
	template <class T> static DataProvider& getInst(){
		static T m_Inst;
		return m_Inst;
	}
private:
	DataProvider(DataProvider const&) = delete;
	DataProvider& operator=(DataProvider const&) = delete;
protected:
	DataProvider();
};


#endif