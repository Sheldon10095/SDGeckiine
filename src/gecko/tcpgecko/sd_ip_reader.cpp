#include "sd_ip_reader.h"

char ipFromSd_gecko[16];
bool hasReadIP_gecko = false;

void initializeUDPLog() {
	if (!hasReadIP_gecko) {
		log_printf("Reading ip from sd card\n");
		hasReadIP_gecko = true;

		std::string ipFilePath = std::string(SD_PATH) + WIIU_PATH + "/" + IP_TXT;

		CFile file(ipFilePath, CFile::ReadOnly);
		if (!file.isOpen()) {
			log_printf("File %s not found, using hard-coded\n", ipFilePath.c_str());
			log_init(COMPUTER_IP_ADDRESS);
			return;
		}

		std::string strBuffer;
		strBuffer.resize(file.size());
		file.read((u8 *) &strBuffer[0], strBuffer.size());

		if (strBuffer.length() >= sizeof(ipFromSd_gecko)) {
			log_printf("Loading ip from sd failed. String was too long: %s\n", strBuffer.c_str());
			return;
		}

		memcpy(ipFromSd_gecko, strBuffer.c_str(), strBuffer.length());
		ipFromSd_gecko[strBuffer.length()] = 0;

		log_printf("Successfully read ip from sd! ip is: %s\n", ipFromSd_gecko);

		log_init(ipFromSd_gecko);
	}

	if (strlen(ipFromSd_gecko) > 0) {
		log_init(ipFromSd_gecko);
	}
}