#ifndef IP_PACKET_H
#define IP_PACKET_H

#include <cstdint>
#include <vector>
#include <string>

class IpPacket
{
	public:
		IpPacket(uint16_t sourcePort, uint16_t destinationPort,
				  const std::vector<uint8_t> &payload);

		explicit IpPacket(const std::vector<uint8_t> &buffer);

		/*!
		 * \brief Convert this packet into bytes.
		 *
		 * \param[out] buffer
		 * The buffer which will be filled with bytes repesenting this packet.
		 * Note that the bytes will be in network-byte-order.
		 */
		void toBuffer(std::vector<uint8_t> &buffer) const;

		void toString(std::string &packetString) const;

		uint8_t version() const;
		uint8_t internetHeaderLength() const;
		uint8_t differentiatedServicesCodePoint() const;
		uint8_t explicitCongestionNotification() const;
		uint16_t packetLength() const;
		uint16_t identification() const;
		uint8_t flags() const;
		uint16_t fragmentOffset() const;
		uint8_t timeToLive() const;
		uint8_t protocol() const;
		uint16_t headerChecksum() const;
		uint32_t sourceIpAddress() const;
		uint32_t destinationIpAddress() const;
		const std::vector<uint32_t>& options() const;
		const std::vector<uint8_t>& payload() const;

	private:
		uint8_t m_version; // Bits 0-3
		uint8_t m_internetHeaderLength; // Bits 4-7
		uint8_t m_differentiatedServicesCodePoint; // Bits 8-13
		uint8_t m_explicitCongestionNotification; // Bits 14-15
		uint16_t m_packetLength; // Bits 16-31
		uint16_t m_identification; // Bits 32-47
		uint8_t m_flags; // Bits 48-50
		uint16_t m_fragmentOffset; // Bits 51-63
		uint8_t m_timeToLive; // Bits 64-71
		uint8_t m_protocol; // Bits 72-79
		uint16_t m_headerChecksum; // Bits 80-95
		uint32_t m_sourceIpAddress; // Bits 96-127
		uint32_t m_destinationIpAddress; // Bits 128-159
		std::vector<uint32_t> m_options; // Bits 160-variable length
		std::vector<uint8_t> m_payload; // End of options and on
};

#endif // IP_PACKET_H
