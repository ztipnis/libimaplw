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
	virtual std::string get() = 0;
private:
	DataProvider(DataProvider const&) = delete;
	DataProvider& operator=(DataProvider const&) = delete;
	DataProvider() = delete;
};


#endif