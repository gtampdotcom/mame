#include "emu.h"
#include "video.h"

#include "9918a.h"
#include "f18a.h"

DEFINE_DEVICE_TYPE(NABU_VIDEO_PORT, bus::nabu::video_port_device, "nabu_video_port", "NABU PC Video Port")

namespace bus::nabu {
//**************************************************************************
//  NABU VIDEO PORT DEVICE
//**************************************************************************

//-------------------------------------------------
//  video_port_device - constructor
//-------------------------------------------------
video_port_device::video_port_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
	device_t(mconfig, NABU_VIDEO_PORT, tag, owner, clock),
	device_single_card_slot_interface<video_card_interface>(mconfig, *this),
	m_int_handler(*this)
{
}

//-------------------------------------------------
//  device_start - device-specific startup
//-------------------------------------------------

void video_port_device::device_start()
{
	// resolve callbacks
	m_int_handler.resolve_safe();
}

uint8_t video_port_device::io_read(offs_t offset)
{
	video_card_interface *const intf(get_card_device());
	if (intf) {
		return intf->read(offset);
	}
	return 0xFF;
}

void video_port_device::io_write(offs_t offset, uint8_t data)
{
	video_card_interface *const intf(get_card_device());
	if (intf) {
		intf->write(offset, data);
	}
}

//**************************************************************************
//  VIDEO CARD INTERFACE
//**************************************************************************

//-------------------------------------------------
//  video_card_interface - constructor
//-------------------------------------------------

video_card_interface::video_card_interface(const machine_config &mconfig, device_t &device) :
	device_interface(device, "nabu_video")
{
	m_slot = dynamic_cast<video_port_device *>(device.owner());
}

void video_card_devices(video_port_device &device)
{
	device.option_add("tms9918a", NABU_TMS9918A_CARD);
	device.option_add("f18a", NABU_F18A_CARD);
	device.option_add("pico9918", NABU_PICO9918_CARD);
	device.option_add("pico9918pro", NABU_PICO9918PRO_CARD);
}

}
