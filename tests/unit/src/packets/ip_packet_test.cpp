#include <gtest/gtest.h>

#include "ip_packet.h"

// Verify that parsing a IP packet from a buffer works as expected.
TEST(IpPacket, Parse)
{
	uint8_t version = 4; // IPv4
	uint8_t internetHeaderLength = 8;
	uint8_t differentiatedServicesCodePoint = 0;
	uint8_t explicitCongestionNotification = 0;
	uint16_t packetLength = 35;
	uint16_t identification = 0;
	uint8_t flags = 1;
	uint16_t fragmentOffset = 0;
	uint8_t timeToLive = 1;
	uint8_t protocol = 1;
	uint16_t headerChecksum = 0;
	uint32_t sourceIpAddress = 5;
	uint32_t destinationIpAddress = 6;
	std::vector<uint32_t> options{1, 2, 3};
	std::vector<uint8_t> payload{4, 5, 6};

	std::vector<uint8_t> buffer = {
		static_cast<uint8_t>((version << 4) | (internetHeaderLength & 0x0f)),

		static_cast<uint8_t>((differentiatedServicesCodePoint << 2) | (explicitCongestionNotification & 0x03)),

		static_cast<uint8_t>(packetLength >> 8),
		static_cast<uint8_t>(packetLength & 0x00ff),

		static_cast<uint8_t>(identification >> 8),
		static_cast<uint8_t>(identification & 0x00ff),

		static_cast<uint8_t>((flags << 5) | ((fragmentOffset & 0x1f00) >> 8)),
		static_cast<uint8_t>(fragmentOffset & 0x00ff),

		timeToLive,
		protocol,

		static_cast<uint8_t>(headerChecksum >> 8),
		static_cast<uint8_t>(headerChecksum & 0x00ff),

		static_cast<uint8_t>(sourceIpAddress >> 24),
		static_cast<uint8_t>(sourceIpAddress >> 16),
		static_cast<uint8_t>(sourceIpAddress >> 8),
		static_cast<uint8_t>(sourceIpAddress & 0x000000ff),

		static_cast<uint8_t>(destinationIpAddress >> 24),
		static_cast<uint8_t>(destinationIpAddress >> 16),
		static_cast<uint8_t>(destinationIpAddress >> 8),
		static_cast<uint8_t>(destinationIpAddress & 0x000000ff),

		static_cast<uint8_t>(options[0] >> 24),
		static_cast<uint8_t>(options[0] >> 16),
		static_cast<uint8_t>(options[0] >> 8),
		static_cast<uint8_t>(options[0] & 0x000000ff),

		static_cast<uint8_t>(options[1] >> 24),
		static_cast<uint8_t>(options[1] >> 16),
		static_cast<uint8_t>(options[1] >> 8),
		static_cast<uint8_t>(options[1] & 0x000000ff),

		static_cast<uint8_t>(options[2] >> 24),
		static_cast<uint8_t>(options[2] >> 16),
		static_cast<uint8_t>(options[2] >> 8),
		static_cast<uint8_t>(options[2] & 0x000000ff),

		payload[0],
		payload[1],
		payload[2],
	};

	IpPacket packet(buffer);

	EXPECT_EQ(version, packet.version());
	EXPECT_EQ(internetHeaderLength, packet.internetHeaderLength());
	EXPECT_EQ(differentiatedServicesCodePoint, packet.differentiatedServicesCodePoint());
	EXPECT_EQ(explicitCongestionNotification, packet.explicitCongestionNotification());
	EXPECT_EQ(packetLength, packet.packetLength());
	EXPECT_EQ(identification, packet.identification());
	EXPECT_EQ(flags, packet.flags());
	EXPECT_EQ(fragmentOffset, packet.fragmentOffset());
	EXPECT_EQ(timeToLive, packet.timeToLive());
	EXPECT_EQ(protocol, packet.protocol());
	EXPECT_EQ(headerChecksum, packet.headerChecksum());
	EXPECT_EQ(sourceIpAddress, packet.sourceIpAddress());
	EXPECT_EQ(destinationIpAddress, packet.destinationIpAddress());
	EXPECT_EQ(options, packet.options());
	EXPECT_EQ(payload, packet.payload());
}
