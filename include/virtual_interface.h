#ifndef VIRTUAL_INTERFACE_H
#define VIRTUAL_INTERFACE_H

#include <string>

#include "types.h"

namespace Overpass
{
	class VirtualInterfaceException : public Exception
	{
		public:
			VirtualInterfaceException(const std::string &what);
	};

	/*!
	 * \brief Create virtual network interface.
	 *
	 * \param[in,out] interfaceName
	 * Set to desired interface name (or template, e.g. "eth%d"), and it will be
	 * set to the actual interface name when it's created.
	 *
	 * \param[out] interfaceFileDescriptor
	 * The file descriptor representing the virtual interface. Allows for reading
	 * and writing raw packets.
	 *
	 * \exception VirtualInterfaceException
	 * If interface can't be created.
	 */
	void createVirtualInterface(std::string &interfaceName,
	                            int &interfaceFileDescriptor);

	/*!
	 * \brief Assign an IPv4 address and netmask to a given network interface.
	 *
	 * \param[in] interfaceName
	 * The name of the interface to modify.
	 *
	 * \param[in] ipAddress
	 * IP address to use for the interface.
	 *
	 * \param[in] netmask
	 * Netmask to use for the interface.
	 *
	 * \exception VirtualInterfaceException
	 * If settings could not be applied.
	 */
	void assignDeviceAddress(const std::string &interfaceName,
	                         const std::string &ipAddress,
	                         const std::string &netmask);
}

#endif // VIRTUAL_INTERFACE_H
