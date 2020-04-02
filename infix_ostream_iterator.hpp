#include <ostream>
#include <iterator>

#ifndef __INFIX_OPERATOR__
#define __INFIX_OPERATOR__
template<class T, class CharT = char, class Traits = std::char_traits<CharT> >
class infix_ostream_iterator: public std::iterator<std::output_iterator_tag,void,void,void,void>{
private:
    bool first;
    typedef std::basic_ostream<CharT,Traits> ostream_type;
    ostream_type& os;
    const CharT* delim;
    typedef infix_ostream_iterator<T,CharT,Traits> this_type;
public:
    infix_ostream_iterator(ostream_type& _os_): os(_os_), first(true), delim(0){}
    infix_ostream_iterator(ostream_type& _os_, const CharT* _delim_): os(_os_), first(true), delim(_delim_){}
    this_type& operator=(const T& value){
        if(!first && delim != 0){
            os << delim;
        }
        os << value;
        first = false;
        return *this;
    }
    this_type& operator*(){ return *this; }
    this_type& operator++(){ return *this; }
    this_type& operator++(int){ return *this; }

};
#endif