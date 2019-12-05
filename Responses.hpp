struct SELECTResp
{
	std::string Flags;
	int exists;
	int recent;
	int unseen;
	std::string pFlags;
	uint32_t uidNext;
	uint32_t uidValid;

};

struct 