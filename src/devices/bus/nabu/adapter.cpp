// license:BSD-3-Clause
// copyright-holders:Brian Johnson
/*******************************************************************
 *
 * NABU PC - Network Adapter Settop Box
 *
 *******************************************************************/

#include "emu.h"
#include "adapter.h"

#include "emuopts.h"
#include "osdfile.h"
#include "hashing.h"
#include "unzip.h"

#define VERBOSE 0
#include "logmacro.h"


//**************************************************************************
//  NABU PC NETWORK ADAPTER DEVICE
//**************************************************************************

DEFINE_DEVICE_TYPE(NABU_NETWORK_LOCAL_ADAPTER, bus::nabu::network_adapter_local, "nabu_net_local_adapter", "NABU Network Adapter - Local")
DEFINE_DEVICE_TYPE(NABU_NETWORK_REMOTE_ADAPTER, bus::nabu::network_adapter_remote, "nabu_net_remote_adapter", "NABU Network Adapter - Remote")

namespace bus::nabu {

//**************************************************************************
//  SEGMENT FILE LOADING
//**************************************************************************

std::error_condition network_adapter_base::segment_file::generate_time_segment()
{
	uint8_t buffer[9];
	auto now = std::chrono::system_clock::now();
	auto tim = std::chrono::system_clock::to_time_t(now);
	auto localtime = std::localtime(&tim);

	buffer[0] = 0x02;
	buffer[1] = 0x02;
	buffer[2] = localtime->tm_wday + 1;
	buffer[3] = 0x54;   // 1984 forever
	buffer[4] = localtime->tm_mon + 1;
	buffer[5] = localtime->tm_mday;
	buffer[6] = localtime->tm_hour;
	buffer[7] = localtime->tm_min;
	buffer[8] = localtime->tm_sec;
	return parse_raw_segment(0x7fffff, buffer, 9);
}


std::error_condition network_adapter_base::segment_file::parse_pak_segment(const uint8_t *data, size_t length)
{
	bool done = false;
	size_t offset = 0;
	uint16_t blk_sz;
	uint16_t crc;
	pak current;

	pak_list.clear();

	while (!done) {
		blk_sz =  (data[offset + 1] & 0xff) << 8;
		blk_sz |= (data[offset] & 0xff);
		crc = 0xffff;
		if (blk_sz > 1009) {
			return std::errc::value_too_large;
		}
		memcpy(&current, data + offset, 2 + blk_sz);
		for (int i = 2; i < blk_sz; ++i) {
			crc = update_crc(crc, ((char *)&current)[i]);
		}
		crc ^= 0xffff;
		current.data[blk_sz - 18] = (crc >> 8) & 0xFF;
		current.data[blk_sz - 17] = crc & 0xFF;
		pak_list.push_back(current);
		offset += blk_sz + 2;
		if (offset >= length - 1 || current.type & 0x10)
			done = true;
	}
	return std::error_condition();
}

std::error_condition network_adapter_base::segment_file::parse_raw_segment(uint32_t segment_id, const uint8_t *data, size_t length)
{
	util::core_file::ptr fd;
	pak current;
	uint64_t offset = 0;
	size_t actual;
	uint16_t crc;
	uint8_t npak = 0;
	std::error_condition err;

	pak_list.clear();

	err = util::core_file::open_ram(data, length, OPEN_FLAG_READ, fd);
	if (err)
		return err;

	memset(current.data, 0, 993);
	current.segment_id[0] = (segment_id & 0xFF0000) >> 16;
	current.segment_id[1] = (segment_id & 0x00FF00) >> 8;
	current.segment_id[2] = (segment_id & 0xF000FF);
	current.owner         = 0x01;
	current.tier[0]       = 0x7f;
	current.tier[1]       = 0xff;
	current.tier[2]       = 0xff;
	current.tier[3]       = 0xff;
	current.mbytes[0]     = 0x7f;
	current.mbytes[1]     = 0x80;
	err = fd->read_at(offset, current.data, 991, actual);
	do {
		crc = 0xffff;
		if (err) {
			return err;
		}
		if (actual > 0) {
			current.length = actual + 18;
			current.packet_number = npak;
			current.pak_number[0] = npak;
			current.pak_number[1] = 0;
			current.type = 0x20;
			if (offset == 0)
				current.type |= 0x81;
			if (actual < 991)
				current.type |= 0x10;
			current.offset[0] = ((offset) >> 8) & 0xFF;
			current.offset[1] = offset & 0xFF;
			for (int i = 2; i < actual + 18; ++i) {
				crc = update_crc(crc, ((char *)&current)[i]);
			}
			crc ^= 0xffff;
			current.data[actual] = (crc >> 8) & 0xFF;
			current.data[actual + 1] = crc & 0xFF;
			pak_list.push_back(current);
			offset = (++npak * 991);
			memset(current.data, 0, 991);
			err = fd->read_at(offset, current.data, 991, actual);
		}
	} while(actual > 0);

	return err;
}

const network_adapter_base::segment_file::pak& network_adapter_base::segment_file::operator[](const int index) const
{
	assert(index >= 0 && index < size());

	return pak_list[index];
}

// crc16 calculation
uint16_t network_adapter_base::segment_file::update_crc(uint16_t crc, uint8_t data)
{
	uint8_t bc;

	bc = (crc >> 8) ^ data;

	crc <<= 8;
	crc ^= crc_table[bc];

	return crc;
}

//**************************************************************************
//  INPUT PORTS
//**************************************************************************

// CONFIG
static INPUT_PORTS_START( nabu_network_adapter_base )
	PORT_START("CONFIG")
	PORT_CONFNAME(0x01, 0x00, "Prompt for channel?")
	PORT_CONFSETTING(0x01, "Yes")
	PORT_CONFSETTING(0x00, "No")
INPUT_PORTS_END

//**************************************************************************
//  DEVICE INITIALIZATION - Base
//**************************************************************************

network_adapter_base::network_adapter_base(machine_config const &mconfig, device_type type, char const *tag, device_t *owner, uint32_t clock)
	: device_t(mconfig, type, tag, owner, clock)
	, device_buffered_serial_interface(mconfig, *this)
	, device_rs232_port_interface(mconfig, *this)
	, m_config(*this, "CONFIG")
	, m_segment(0)
	, m_segment_length(0)
	, m_segment_type(segment_type::PAK)
	, m_channel(0)
	, m_packet(0)
	, m_state(state::IDLE)
	, m_substate(0)
	, m_pak_offset(0)
	, m_segment_timer(nullptr)
{
}

void network_adapter_base::device_start()
{
	m_segment_timer = timer_alloc(FUNC(network_adapter_base::segment_tick), this);

	m_segment_data = std::make_unique<uint8_t[]>(0x10000);;

	save_item(NAME(m_state));
	save_item(NAME(m_substate));
	save_item(NAME(m_channel));
	save_item(NAME(m_packet));
	save_item(NAME(m_segment));
	save_item(NAME(m_segment_length));
	save_item(NAME(m_segment_type));
	save_item(NAME(m_pak_offset));
	save_pointer(NAME(m_segment_data), 0x10000);
}

void network_adapter_base::device_reset()
{
	m_state = state::IDLE;
	m_substate = 0;
	// initialise state
	clear_fifo();

	// configure device_buffered_serial_interface
	set_data_frame(START_BIT_COUNT, DATA_BIT_COUNT, PARITY, STOP_BITS);
	set_rate(BAUD);
	receive_register_reset();
	transmit_register_reset();
}

//**************************************************************************
//  DEVICE CONFIGURATION - Base
//**************************************************************************

ioport_constructor network_adapter_base::device_input_ports() const
{
	return INPUT_PORTS_NAME( nabu_network_adapter_base );
}

//**************************************************************************
//  SERIAL PROTOCOL - Base
//**************************************************************************

WRITE_LINE_MEMBER(network_adapter_base::input_txd)
{
	device_buffered_serial_interface::rx_w(state);
}

void network_adapter_base::tra_callback()
{
	output_rxd(transmit_register_get_data_bit());
}

void network_adapter_base::received_byte(uint8_t byte)
{
	LOG("Received Byte 0x%02X\n", byte);
	switch (m_state) {
	case state::IDLE:
		idle(byte);
		break;
	case state::CHANNEL_REQUEST:
		channel_request(byte);
		break;
	case state::SEGMENT_REQUEST:
		segment_request(byte);
		break;
	case state::SETSTATUS_REQUEST:
		set_status(byte);
		break;
	case state::GETSTATUS_REQUEST:
		get_status(byte);
		break;
	case state::SEND_SEGMENT:
		send_segment(byte);
		break;
	}
}

//**************************************************************************
//  STATE MACHINE - Base
//**************************************************************************

void network_adapter_base::idle(uint8_t byte)
{
	m_substate = 0;
	switch (byte) {
	case 0x85:
		transmit_byte(0x10);
		transmit_byte(0x06);
		m_state = state::CHANNEL_REQUEST;
		break;
	case 0x84:
		transmit_byte(0x10);
		transmit_byte(0x06);
		m_state = state::SEGMENT_REQUEST;
		break;
	case 0x83:
		transmit_byte(0x10);
		transmit_byte(0x06);
		transmit_byte(0xE4);
		break;
	case 0x82:
		transmit_byte(0x10);
		transmit_byte(0x06);
		m_state = state::GETSTATUS_REQUEST;
		break;
	case 0x81:
		transmit_byte(0x10);
		transmit_byte(0x06);
		m_state = state::SETSTATUS_REQUEST;
		break;
	}

}

void network_adapter_base::set_status(uint8_t byte)
{
	if (m_substate == 1) {
		transmit_byte(0xE4);
		m_state = state::IDLE;
	}
	++m_substate;

}

void network_adapter_base::get_status(uint8_t byte)
{
	if (byte == 0x01) {
		transmit_byte(bool(m_config->read() & 1) ? 0x9F : 0x1F);
	}
	transmit_byte(0x10);
	transmit_byte(0xE1);
	m_state = state::IDLE;
}

void network_adapter_base::channel_request(uint8_t byte)
{
	if (m_substate == 0) {
		m_channel = (m_channel & 0xFF00) | (byte);
	} else if (m_substate == 1) {
		m_channel = (m_channel & 0xFF) | (byte << 8);
		transmit_byte(0xE4);
		LOG("Channel: 0x%04X\n", m_channel);
		m_state = state::IDLE;
	}
	++m_substate;
}

void network_adapter_base::segment_request(uint8_t byte)
{
	static uint32_t segment_id = 0;

	if (m_substate == 0) {
		m_packet = byte;
	} else if (m_substate == 1) {
		segment_id = (segment_id & 0xFFFF00) | (byte);
	} else if (m_substate == 2) {
		segment_id = (segment_id & 0xFF00FF) | (byte << 8);
	} else if (m_substate == 3) {
		segment_id = (segment_id & 0xFFFF) | (byte << 16);
		transmit_byte(0xE4);
		if (!load_segment(segment_id)) {
			transmit_byte(0x91);
			m_state = state::SEND_SEGMENT;
			m_substate = 0;
			m_segment = segment_id;
			LOG("Segment: 0x%06X, Packet: 0x%02X\n", m_segment, m_packet);
			return;
		} else {
			transmit_byte(0x90);
			m_state = state::IDLE;
			LOG("Segment 0x%06X not found\n", segment_id);
			m_segment = 0;
		}
	}
	++m_substate;
}

void network_adapter_base::send_segment(uint8_t byte)
{
	if (m_substate == 0) {
		if (byte != 0x10) {
			LOG("Expecting byte 0x10 got %02X, restarting.\n", byte);
			m_state = state::IDLE;
			m_substate = 0;
			return;
		}
	} else if (m_substate == 1) {
		if (byte != 0x06) {
			LOG("Expecting byte 0x06 got %02X, restarting.\n", byte);
			m_state = state::IDLE;
			m_substate = 0;
			return;
		}
		m_pak_offset = 0;
		if (!parse_segment(m_segment_data.get(), m_segment_length)) {
			m_segment_timer->adjust(attotime::zero, 0, attotime::from_hz(5'500));
			LOG("Segment sending, returning to idle state\n");
		} else {
			LOG("Failed to find segment: %06d, restarting\n", m_segment);
			transmit_byte(0x10);
			transmit_byte(0x06);
			transmit_byte(0xE4);
		}
		m_state = state::IDLE;
	}

	++m_substate;
}

TIMER_CALLBACK_MEMBER(network_adapter_base::segment_tick)
{
		char * data = (char*)&m_pakcache[m_packet];
		data += 2;
		if (data[m_pak_offset] == 0x10) {
			transmit_byte(data[m_pak_offset]);
		}
		transmit_byte(data[m_pak_offset++]);
		if (m_pak_offset >= m_pakcache[m_packet].length) {
			transmit_byte(0x10);
			transmit_byte(0xe1);
			m_segment_timer->reset();
		}
}

std::error_condition network_adapter_base::parse_segment(const uint8_t *data, size_t length)
{
	if (m_segment == 0x7fffff) {
		return m_pakcache.generate_time_segment();
	}

	if (m_segment_type == segment_type::NABU) {
		return m_pakcache.parse_raw_segment(m_segment, data, length);
	}

	return m_pakcache.parse_pak_segment(data, length);
}


//**************************************************************************
//  DEVICE INITIALIZATION - Local
//**************************************************************************

network_adapter_local::network_adapter_local(machine_config const &mconfig, char const *tag, device_t *owner, uint32_t clock)
	: network_adapter_base(mconfig, NABU_NETWORK_LOCAL_ADAPTER, tag, owner, clock)
	, device_image_interface(mconfig, *this)
	, m_loose(false)
{
}

void network_adapter_local::device_start()
{
	network_adapter_base::device_start();

	save_item(NAME(m_loose));
}

image_init_result network_adapter_local::call_load()
{
	m_segment_length = 0;
	m_loose = false;

	if (is_filetype("npz")) {
		return image_init_result::PASS;
	}
	if (is_filetype("nabu") || is_filetype("pak")) {
		m_loose = true;
		return image_init_result::PASS;
	}
	seterror(image_error::INVALIDIMAGE);
	return image_init_result::FAIL;
}

void network_adapter_local::call_unload()
{
	m_segment_length = 0;
	m_loose = false;
}

// Read a bare .nabu segment file into the segment buffer
std::error_condition network_adapter_local::read_segment_file(const std::string &path, uint8_t type)
{
	util::core_file::ptr fd;
	std::uint64_t length;
	std::size_t actual;

	std::error_condition err = util::core_file::open(path, OPEN_FLAG_READ, fd);
	if (!err) {
		err = fd->length(length);
	}
	if (!err && (length == 0 || length > 0x10000)) {
		err = std::errc::file_too_large;
	}
	if (!err) {
		err = fd->read_at(0, m_segment_data.get(), std::size_t(length), actual);
	}
	if (!err && actual != length) {
		err = std::errc::io_error;
	}

	m_segment_length = err ? 0 : uint32_t(length);
	if (!err) {
		m_segment_type = type;
	}
	return err;
}

// Load a segment when a bare .nabu or .pak file is mounted: the mounted file is the
// boot segment (000001) whatever it is called, and any other segment is looked up as
// XXXXXX.pak or XXXXXX.nabu in the same folder.
std::error_condition network_adapter_local::load_loose_segment(uint32_t segment_id)
{
	const std::string path(filename());

	if (segment_id == 0x000001) {
		return read_segment_file(path, is_filetype("pak") ? segment_type::PAK : segment_type::NABU);
	}

	const size_t sep = path.find_last_of("/\\");
	const std::string dir = (sep == std::string::npos) ? std::string() : path.substr(0, sep + 1);
	const std::string mounted = (sep == std::string::npos) ? path : path.substr(sep + 1);

	std::string found;
	uint8_t type = segment_type::NABU;
	if (!find_segment_file(dir, mounted, segment_id, found, type)) {
		return std::errc::no_such_file_or_directory;
	}
	return read_segment_file(dir + found, type);
}

namespace {

std::string lowercase(std::string s)
{
	for (char &c : s) {
		c = char(std::tolower((unsigned char)c));
	}
	return s;
}

bool ends_with(const std::string &s, const char *suffix)
{
	const size_t n = strlen(suffix);
	return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

// name without its extension and without a trailing 6 digit hex segment number,
// e.g. "https-cloud.nabu.ca-cycle 1 raw-000001" -> "https-cloud.nabu.ca-cycle 1 raw-"
std::string segment_prefix(const std::string &lname, size_t ext_len)
{
	const std::string stem = lname.substr(0, lname.size() - ext_len);
	if (stem.size() >= 6 && stem.find_first_not_of("0123456789abcdef", stem.size() - 6) == std::string::npos) {
		return stem.substr(0, stem.size() - 6);
	}
	return std::string();
}

} // anonymous namespace

// Find the file holding a segment in the folder of the mounted file.  A segment is any
// .pak or .nabu file whose name ends in its 6 digit hex number, so both plain names
// (000002.pak) and saved downloads (HTTPS-CLOUD.NABU.CA-CYCLE 1 RAW-000002.PAK) work.
// Files with the same prefix as the mounted one win, then .pak over .nabu.
bool network_adapter_local::find_segment_file(const std::string &dir, const std::string &mounted, uint32_t segment_id, std::string &name, uint8_t &type)
{
	osd::directory::ptr d = osd::directory::open(dir.empty() ? "." : dir);
	if (!d) {
		return false;
	}

	const std::string wanted = lowercase(util::string_format("%06X", segment_id));
	const std::string lmounted = lowercase(mounted);
	const std::string mounted_prefix = segment_prefix(lmounted, ends_with(lmounted, ".nabu") ? 5 : 4);

	int best = -1;
	while (const osd::directory::entry *e = d->read()) {
		if (e->type != osd::directory::entry::entry_type::FILE) {
			continue;
		}

		const std::string lname = lowercase(e->name);
		const bool pak = ends_with(lname, ".pak");
		if (!pak && !ends_with(lname, ".nabu")) {
			continue;
		}

		const size_t ext_len = pak ? 4 : 5;
		const std::string stem = lname.substr(0, lname.size() - ext_len);
		if (stem.size() < 6 || stem.compare(stem.size() - 6, 6, wanted) != 0) {
			continue;
		}
		// the number must stand alone, not be the tail of a longer one
		if (stem.size() > 6 && std::isalnum((unsigned char)stem[stem.size() - 7])) {
			continue;
		}

		const int score = (segment_prefix(lname, ext_len) == mounted_prefix ? 2 : 0) + (pak ? 1 : 0);
		if (score > best) {
			best = score;
			name = e->name;
			type = pak ? segment_type::PAK : segment_type::NABU;
		}
	}
	return best >= 0;
}

// Load Segment from local npz file
std::error_condition network_adapter_local::load_segment(uint32_t segment_id)
{
	segment_id &= 0xFFFFFF;

	if (m_loose) {
		if ((m_segment_length != 0 && (segment_id == m_segment)) || segment_id == 0x7fffff) {
			return std::error_condition();
		}
		return load_loose_segment(segment_id);
	}

	util::core_file::ptr proxy;
	std::error_condition err;
	util::archive_file::ptr zipfile;
	std::string segment_filename;

	if ((m_segment_length != 0 && (segment_id == m_segment)) || segment_id == 0x7fffff) {
		return std::error_condition();
	}

	err = util::core_file::open_proxy(image_core_file(), proxy);
	if (err) {
		m_segment_length = 0;
		return err;
	}

	err = util::archive_file::open_zip(std::move(proxy), zipfile);
	if (err) {
		m_segment_length = 0;
		return err;
	}

	segment_filename = util::string_format("%06X.pak", segment_id);
	m_segment_type = segment_type::PAK;

	if (zipfile->search(segment_filename, false) < 0) {
		segment_filename = util::string_format("%06X.nabu", segment_id);
		m_segment_type = segment_type::NABU;
		if (zipfile->search(segment_filename, false) < 0) {
			m_segment_length = 0;
			return std::errc::no_such_file_or_directory;
		}
	}

	// determine the uncompressed length
	uint64_t uncompressed_length_uint64 = zipfile->current_uncompressed_length();
	size_t uncompressed_length = (size_t)uncompressed_length_uint64;
	if (uncompressed_length != uncompressed_length_uint64) {
		m_segment_length = 0;
		return std::errc::not_enough_memory;
	}

	if (uncompressed_length > 0x10000) {
		m_segment_length = 0;
		return std::errc::file_too_large;
	}

	// prepare a buffer for the segment file
	m_segment_length = uncompressed_length;;

	err = zipfile->decompress(&m_segment_data[0], m_segment_length);
	if (err) {
		m_segment_length = 0;
	}

	return err;
}


//**************************************************************************
//  DEVICE INITIALIZATION - Remote
//**************************************************************************
static INPUT_PORTS_START( nabu_network_adapter_remote )
	PORT_INCLUDE( nabu_network_adapter_base )
	PORT_MODIFY("CONFIG")
	PORT_CONFNAME(0x0E, 0x02, "Network Cycle")
	PORT_CONFSETTING(0x02, "Cycle 1")
	PORT_CONFSETTING(0x04, "Cycle 2")
	PORT_CONFSETTING(0x06, "Cycle 3")
	PORT_CONFSETTING(0x08, "Cycle 4")
INPUT_PORTS_END

network_adapter_remote::network_adapter_remote(machine_config const &mconfig, char const *tag, device_t *owner, uint32_t clock)
	: network_adapter_base(mconfig, NABU_NETWORK_REMOTE_ADAPTER, tag, owner, clock)
	, device_image_interface(mconfig, *this)
{
}

image_init_result network_adapter_remote::call_load()
{
	m_httpclient = std::make_unique<webpp::http_client>(filename());

	return image_init_result::PASS;
}

void network_adapter_remote::device_start()
{
	network_adapter_base::device_start();

	save_item(NAME(m_cycle));
}

void network_adapter_remote::device_reset()
{
	network_adapter_base::device_reset();

	if (filename() == nullptr) {
		load("cloud.nabu.ca");
	}

	m_cycle = (m_config->read()  >> 1 ) & 7;
}

ioport_constructor network_adapter_remote::device_input_ports() const
{
	return INPUT_PORTS_NAME( nabu_network_adapter_remote );
}

// Load segment from Remote Server (cloud.nabu.ca)
std::error_condition network_adapter_remote::load_segment(uint32_t segment_id)
{
	uint32_t content_length = 0;
	std::string url;
	std::shared_ptr<webpp::http_client::Response> resp;

	segment_id &= 0xFFFFFF;

	if ((m_segment_length != 0 && (segment_id == m_segment)) || segment_id == 0x7fffff) {
		return std::error_condition();
	}

	std::string segment_filename = util::string_format("%06X.pak", segment_id);

	if (m_cycle == 1) {
		url = util::string_format("/cycle%%201%%20raw/%s", segment_filename);
	} else if (m_cycle == 2) {
		url = util::string_format("/cycle%%202%%20raw/%s", segment_filename);
	} else if (m_cycle == 3) {
		url = util::string_format("/cycle%%203%%20raw/%s", segment_filename);
	} else {
		url = util::string_format("/cycle%%204%%20raw/%s", segment_filename);
	}

	resp = m_httpclient->request("GET", url);
	if (resp->status_code != "200 OK") {
		m_segment_length = 0;
		return std::errc::no_such_file_or_directory;
	}

	auto header_it = resp->header.find("Content-Length");
	if (header_it != resp->header.end()) {
		content_length = stoull(header_it->second);
	}
	if (content_length == 0 || content_length > 0x10000) {
		m_segment_length = 0;
		return std::errc::file_too_large;
	}
	resp->content.read(reinterpret_cast<char *>(&m_segment_data[0]), content_length);
	if (!resp->content) {
		m_segment_length = 0;
		return std::errc::io_error;
	}
	return std::error_condition();
}

} // bus::nabupc
