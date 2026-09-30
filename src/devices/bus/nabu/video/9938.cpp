#include "emu.h"
#include "9938.h"

//**************************************************************************
//  DEVICE DEFINITIONS
//**************************************************************************

DEFINE_DEVICE_TYPE(NABU_TMS9938_CARD, bus::nabu::tms9938_card_device, "nabu_tms9938_display", "NABU TMS9938 Display")

namespace bus::nabu {

tms9938_card_device::tms9938_card_device(const machine_config &mconfig, const char *tag, device_t *owner, uint32_t clock) :
	device_t(mconfig, NABU_TMS9938_CARD, tag, owner, clock),
	video_card_interface(mconfig, *this),
	m_screen(*this, "screen"),
	m_v9938(*this, "tms9938")
{
}

//-------------------------------------------------
//  device_add_mconfig - add device configuration
//-------------------------------------------------

void tms9938_card_device::device_add_mconfig(machine_config &config)
{
	// Video hardware
	SCREEN(config, m_screen, SCREEN_TYPE_RASTER);

	V9938(config, m_v9938, 21.477272_MHz_XTAL);
	m_v9938->set_screen(m_screen);
	m_v9938->set_vram_size(0x4000);
	m_v9938->int_cb().set(*m_slot, FUNC(video_port_device::int_w));
}

//-------------------------------------------------
//  device_start - device-specific startup
//-------------------------------------------------

void tms9938_card_device::device_start()
{
}

//-------------------------------------------------
//  device_reset - device-specific reset
//-------------------------------------------------

void tms9938_card_device::device_reset()
{
}

uint8_t tms9938_card_device::read(offs_t offset)
{
	return m_v9938->read(offset);
}

void tms9938_card_device::write(offs_t offset, uint8_t data)
{
	m_v9938->write(offset, data);
}

} // namespace bus::nabu

