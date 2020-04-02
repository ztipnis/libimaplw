#include <mimetic/mimetic.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <functional>
#include <algorithm>
#include <iterator>
#include <cctype>
#include <initializer_list>
// #include "Helpers.hpp"
#include "infix_ostream_iterator.hpp"




namespace IMAPProvider {

const std::string enquote(const std::string& unquoted);
const std::string fieldElseNil(const mimetic::Header& header, const std::string& field);
const std::string mailboxToString(const mimetic::Mailbox& mbx);
const std::string addrToString(const mimetic::Address& addr);
const std::string fieldToString();
const std::string mimeEntityToString(const mimetic::MimeEntity& me, bool extensions = true);
//Message class
class Message{
private:
	mimetic::MimeEntity __message__;
	const long __uid__;
	const std::string __date__;
	std::vector<std::string> __flags__;
public:
	explicit Message(std::istream& body, const long uid, const std::string& date, const std::vector<std::string>& flags)
	: __message__(body), __uid__(uid), __date__(date), __flags__(flags)
	{}
	explicit Message(std::istream& body, const long uid, const std::string& date, std::initializer_list<std::string> flags)
	: __message__(body), __uid__(uid), __date__(date), __flags__(flags)
	{}
	const std::string body() const{return mimeEntityToString(__message__, false);}
	const std::string body(const std::string& section, int origin) const;
	const std::string bodyStructure() const{return mimeEntityToString(__message__, true);}
	const std::string envelope() const;
	// const std::string flags() const {return "(" + join(__flags__, " ") + ")";}
	const std::string internalDate() const {return __date__;}
	const std::string size() const {return std::to_string(__message__.size());}
	const std::string uid() const {return std::to_string(__uid__);}
	void print(std::ostream& s){ s << __message__; }

};

const std::string Message::envelope() const{
	const mimetic::Header& header = __message__.header();
	auto getField = std::bind(fieldElseNil,header,std::placeholders::_1);
	std::stringstream message_stream;
	std::ostream_iterator<std::string> endpoint(message_stream, "");
	message_stream << "(" << getField("Date")
	<< " " << getField("Subject");

	if(header.from().size() > 0){
		message_stream << " (";
		std::transform(header.from().cbegin(), header.from().cend(), endpoint, mailboxToString);
		message_stream << ")";
	}else{
		message_stream << " NIL";
	}

	if(header.sender().mailbox().empty() || header.sender().domain().empty()){
		message_stream << " (";
		std::transform(header.from().cbegin(), header.from().cend(), endpoint, mailboxToString);
		message_stream << ")";
	}else{
		message_stream <<" (" << mailboxToString(header.sender()) << ")";
	}
	


	if(header.replyto().size() > 0){
		message_stream << " (";
		std::transform(header.replyto().cbegin(), header.replyto().cend(), endpoint, addrToString);
		message_stream << ")";
	}else{
		message_stream << " (";
		std::transform(header.from().cbegin(), header.from().cend(), endpoint, mailboxToString);
		message_stream << ")";
	}

	if(header.to().size() > 0){
		message_stream << " (";
		std::transform(header.to().cbegin(), header.to().cend(), endpoint, addrToString);
		message_stream << ")";
	}else{
		message_stream << " NIL";
	}

	if(header.cc().size() > 0){
		message_stream << " (";
		std::transform(header.cc().cbegin(), header.cc().cend(), endpoint, addrToString);
		message_stream << ")";
	}else{
		message_stream << " NIL";
	}

	if(header.bcc().size() > 0){
		message_stream << " (";
		std::transform(header.bcc().cbegin(), header.bcc().cend(), endpoint, addrToString);
		message_stream << ")";
	}else{
		message_stream << " NIL";
	}
	message_stream << " " << getField("In-Reply-To")
	<< " " << getField("Message-Id") << ")";
	return message_stream.str();

}







const std::string enquote(const std::string& unquoted){
	std::ostringstream ss;
	ss << std::quoted(unquoted);
	return ss.str();
}

const std::string fieldElseNil(const mimetic::Header& header, const std::string& field){
	if(header.hasField(field)){
		const std::string fieldString(header.field(field).value());
		return !fieldString.empty() ? enquote(fieldString) : "NIL";
	}else{
		return "NIL";
	}
}

const std::string mailboxToString(const mimetic::Mailbox& mbx){
	#define emptyelsenil(s) ((s.empty()) ? std::string("NIL") : s)
	std::stringstream addr_;
	addr_ << "(" << emptyelsenil(mbx.label()) << " "
		  << emptyelsenil(mbx.sourceroute()) << " "
		  << emptyelsenil(mbx.mailbox()) << " "
		  << emptyelsenil(mbx.domain()) << ")";
	#undef emptyelsenil
	return addr_.str();
}

const std::string addrToString(const mimetic::Address& addr){
	if(addr.isGroup()){
		mimetic::Group gr = addr.group();
		std::stringstream addr_;
		addr_ << "(NIL NIL " << gr.name() <<" NIL)";
		std::cout << gr.size() << std::endl;
		std::string last;
		for (mimetic::Mailbox mailbox: gr){
			last = mailboxToString(mailbox);
			addr_ << " " << last;
		}
		if(last != "(NIL NIL NIL NIL)")
			addr_ << "(NIL NIL NIL NIL)";
		return addr_.str();
	}else{
		mimetic::Mailbox mbx = addr.mailbox();
		return mailboxToString(mbx);
	}
}
#define strUpper(strin, output) std::transform( strin.cbegin() , strin.cend(), std::back_inserter(output), [](unsigned char c){return std::toupper(c);})
const std::string fieldToString(const mimetic::FieldParam& fP){
	std::string s;
	strUpper(fP.name(), s);
	return enquote(s) + " " + enquote(fP.value());
	
}

const std::string mimeEntityToString(const mimetic::MimeEntity& me, bool extensions){
	const mimetic::Header& header = me.header();
	const mimetic::Body& body = me.body();
	const mimetic::ContentType& cType = header.contentType();
	std::stringstream struc;
	struc << "(";
	if(cType.isMultipart()){
		//multipart ([parts] [alternative/mixed/related/unknown])
		const mimetic::MimeEntityList& parts = body.parts();
		std::transform(
			parts.cbegin(),
			parts.cend(),
			std::ostream_iterator<std::string>(struc, ""),
			[extensions](const mimetic::MimeEntity *m){
				return mimeEntityToString(*m, extensions);
			}
		);
		std::string mpType;
		strUpper(cType.subtype(), mpType);
		struc << " " << enquote(mpType);
		if(extensions){
			//((param list), disp)
			if(cType.paramList().size() > 0){
				struc << " (";
				std::transform(
					cType.paramList().cbegin(),
					cType.paramList().cend(),
					infix_ostream_iterator<std::string>(struc, " "),
					[](const mimetic::FieldParam fp){ return fieldToString(fp); }
				);
				struc << ")";
			}else{
				struc << " NIL";
			}
			if(header.contentDisposition().type() != ""){
				std::string dispType;
				strUpper(header.contentDisposition().type(), dispType);
				struc << " (" << enquote(dispType);
				if(header.contentDisposition().paramList().size() > 0){
					struc << " (";
					std::transform(
						header.contentDisposition().paramList().cbegin(),
						header.contentDisposition().paramList().cend(),
						infix_ostream_iterator<std::string>(struc, " "),
						[](const mimetic::FieldParam fp){ return fieldToString(fp); }
					);
					struc << ")";
				}else{
					struc << " NIL";
				}
				struc <<")";
			}else{
				struc << " NIL";
			}
		}
	}else{
		// //non-multipart (type, subtype, params, id, desc, encoding, size)
		std::string type, subtype;
		strUpper(cType.type(), type);
		strUpper(cType.subtype(), subtype);
		struc << enquote(type) << " " << enquote(subtype);
		if(cType.paramList().size() > 0){
			struc << " (";
			std::transform(
				cType.paramList().cbegin(),
				cType.paramList().cend(),
				infix_ostream_iterator<std::string>(struc, " "),
				[](const mimetic::FieldParam fp){ return fieldToString(fp); }
			);
			struc << ")";
		}else{
			struc << " NIL";
		}

		if(header.contentId().str() != ""){
			struc << " " << enquote(header.contentId().str());
		}else{
			struc << " NIL";
		}

		if(header.contentId().str() != ""){
			struc << " " << enquote(header.contentId().str());
		}else{
			struc << " NIL";
		}
		if(header.contentDescription().str() != ""){
			struc << " " << enquote(header.contentDescription().str());
		}else{
			struc << " NIL";
		}
		if(header.contentTransferEncoding().str() != ""){
			std::string s(enquote(header.contentTransferEncoding().str()));
			std::for_each(s.begin(), s.end(), [](char &c){c = std::toupper(c); });
			struc << " " << s;
		}else{
			struc << " NIL";
		}
		struc << " " << me.size();

		if(type == "TEXT"){
			std::stringstream part;
			part << me;
			std::istreambuf_iterator<char> start(part), end;
			int lines = std::count(start, end, '\n');
			struc << " " << lines + 1;
			//lines
		}else if(type == "MESSAGE"){
			//envelope
			//body structure
			//lines
			std::stringstream part;
			part << me;
			std::istreambuf_iterator<char> start(part), end;
			int lines = std::count(start, end, '\n');
			Message m(part, 0,"",{});
			struc << m.envelope() << " " << m.bodyStructure() << " " << lines;
		}
		if(extensions){
			if(header.hasField("Content-MD5")){
				struc << " " << header.field("Content-MD5");
			}else{
				struc << " NIL";
			}
			if(header.contentDisposition().type() != ""){
				std::string dispType;
				strUpper(header.contentDisposition().type(), dispType);
				struc << " (" << enquote(dispType);
				if(header.contentDisposition().paramList().size() > 0){
					struc << " (";
					std::transform(
						header.contentDisposition().paramList().cbegin(),
						header.contentDisposition().paramList().cend(),
						infix_ostream_iterator<std::string>(struc, " "),
						[](const mimetic::FieldParam fp){ return fieldToString(fp); }
					);
					struc << ")";
				}else{
					struc << " NIL";
				}
				struc <<")";
			}else{
				struc << " NIL";
			}
		}
	}
	struc << ")";

	return struc.str();
}
#undef strUpper

const std::string Message::body(const std::string& section, int origin) const{
	std::stringstream
}


} // IMAPProvider