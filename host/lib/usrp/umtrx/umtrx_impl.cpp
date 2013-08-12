// Copyright 2012-2013 Fairwaves LLC
// Copyright 2010-2011 Ettus Research LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
#include "umtrx_impl.hpp"
#include "lms_regs.hpp"
#include "umtrx_regs.hpp"
#include "../usrp2/fw_common.h"
#include "../../transport/super_recv_packet_handler.hpp"
#include "../../transport/super_send_packet_handler.hpp"
#include "apply_corrections.hpp"
#include <uhd/utils/log.hpp>
#include <uhd/utils/msg.hpp>
#include <uhd/exception.hpp>
#include <uhd/transport/if_addrs.hpp>
#include <uhd/transport/udp_zero_copy.hpp>
#include <uhd/types/ranges.hpp>
#include <uhd/exception.hpp>
#include <uhd/utils/static.hpp>
#include <uhd/utils/byteswap.hpp>
#include <uhd/utils/safe_call.hpp>
#include <boost/format.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio.hpp> //used for htonl and ntohl

static int verbosity = 0;

using namespace uhd;
using namespace uhd::usrp;
using namespace uhd::transport;
namespace asio = boost::asio;

/***********************************************************************
 * Discovery over the udp transport
 **********************************************************************/

static device_addrs_t usrp2_find_generic(const device_addr_t &hint_, const char * usrp_type, const usrp2_ctrl_id_t ctrl_id_request, const usrp2_ctrl_id_t ctrl_id_response) {
    //handle the multi-device discovery
    device_addrs_t hints = separate_device_addr(hint_);
    if (hints.size() > 1){
        device_addrs_t found_devices;
        BOOST_FOREACH(const device_addr_t &hint_i, hints){
            device_addrs_t found_devices_i = usrp2_find_generic(hint_i, usrp_type, ctrl_id_request, ctrl_id_response);
            if (found_devices_i.size() != 1) throw uhd::value_error(str(boost::format(
                "Could not resolve device hint \"%s\" to a single device."
            ) % hint_i.to_string()));
            found_devices.push_back(found_devices_i[0]);
        }
        return device_addrs_t(1, combine_device_addrs(found_devices));
    }

    //initialize the hint for a single device case
    UHD_ASSERT_THROW(hints.size() <= 1);
    hints.resize(1); //in case it was empty
    device_addr_t hint = hints[0];
    device_addrs_t usrp2_addrs;

    //return an empty list of addresses when type is set to non-usrp2
    if (hint.has_key("type") and hint["type"] != usrp_type) return usrp2_addrs;

    //if no address was specified, send a broadcast on each interface
    if (not hint.has_key("addr")){
        BOOST_FOREACH(const if_addrs_t &if_addrs, get_if_addrs()){
            //avoid the loopback device
            if (if_addrs.inet == asio::ip::address_v4::loopback().to_string()) continue;

            //create a new hint with this broadcast address
            device_addr_t new_hint = hint;
            new_hint["addr"] = if_addrs.bcast;

            //call discover with the new hint and append results
            device_addrs_t new_usrp2_addrs = usrp2_find_generic(new_hint, usrp_type, ctrl_id_request, ctrl_id_response);
            usrp2_addrs.insert(usrp2_addrs.begin(),
                new_usrp2_addrs.begin(), new_usrp2_addrs.end()
            );
        }
        return usrp2_addrs;
    }

    //Create a UDP transport to communicate:
    //Some devices will cause a throw when opened for a broadcast address.
    //We print and recover so the caller can loop through all bcast addrs.
    udp_simple::sptr udp_transport;
    try{
        udp_transport = udp_simple::make_broadcast(hint["addr"], BOOST_STRINGIZE(USRP2_UDP_CTRL_PORT));
    }
    catch(const std::exception &e){
        UHD_MSG(error) << boost::format("Cannot open UDP transport on %s\n%s") % hint["addr"] % e.what() << std::endl;
        return usrp2_addrs; //dont throw, but return empty address so caller can insert
    }

    //send a hello control packet
    usrp2_ctrl_data_t ctrl_data_out = usrp2_ctrl_data_t();
    ctrl_data_out.proto_ver = uhd::htonx<boost::uint32_t>(USRP2_FW_COMPAT_NUM);
    ctrl_data_out.id = uhd::htonx<boost::uint32_t>(ctrl_id_request);
    udp_transport->send(boost::asio::buffer(&ctrl_data_out, sizeof(ctrl_data_out)));

    //loop and recieve until the timeout
    boost::uint8_t usrp2_ctrl_data_in_mem[udp_simple::mtu]; //allocate max bytes for recv
    const usrp2_ctrl_data_t *ctrl_data_in = reinterpret_cast<const usrp2_ctrl_data_t *>(usrp2_ctrl_data_in_mem);
    while(true){
        size_t len = udp_transport->recv(asio::buffer(usrp2_ctrl_data_in_mem));
        if (len > offsetof(usrp2_ctrl_data_t, data) and ntohl(ctrl_data_in->id) == ctrl_id_response) {

            //make a boost asio ipv4 with the raw addr in host byte order
            device_addr_t new_addr;
            new_addr["type"] = usrp_type;
            //We used to get the address from the control packet.
            //Now now uses the socket itself to yield the address.
            //boost::asio::ip::address_v4 ip_addr(ntohl(ctrl_data_in->data.ip_addr));
            //new_addr["addr"] = ip_addr.to_string();
            new_addr["addr"] = udp_transport->get_recv_addr();

            //Attempt to read the name from the EEPROM and perform filtering.
            //This operation can throw due to compatibility mismatch.
            try{
                usrp2_iface::sptr iface = usrp2_iface::make(udp_simple::make_connected(
                    new_addr["addr"], BOOST_STRINGIZE(USRP2_UDP_CTRL_PORT)
                ));
                if (iface->is_device_locked()) continue; //ignore locked devices
                mboard_eeprom_t mb_eeprom = iface->mb_eeprom;
                new_addr["name"] = mb_eeprom["name"];
                new_addr["serial"] = mb_eeprom["serial"];
            }
            catch(const std::exception &){
                //set these values as empty string so the device may still be found
                //and the filter's below can still operate on the discovered device
                new_addr["name"] = "";
                new_addr["serial"] = "";
            }

            //filter the discovered device below by matching optional keys
            if (
                (not hint.has_key("name")   or hint["name"]   == new_addr["name"]) and
                (not hint.has_key("serial") or hint["serial"] == new_addr["serial"])
            ){
                usrp2_addrs.push_back(new_addr);
            }

            //dont break here, it will exit the while loop
            //just continue on to the next loop iteration
        }
        if (len == 0) break; //timeout
    }

    return usrp2_addrs;
}

/***********************************************************************
 * Make
 **********************************************************************/
static device::sptr umtrx_make(const device_addr_t &device_addr){
    return device::sptr(new umtrx_impl(device_addr));
}

static device_addrs_t umtrx_find(const device_addr_t &hint_) {
    return usrp2_find_generic(hint_, (char *)"umtrx", UMTRX_CTRL_ID_REQUEST, UMTRX_CTRL_ID_RESPONSE);
}

UHD_STATIC_BLOCK(register_umtrx_device){
    device::register_device(&umtrx_find, &umtrx_make);
}

/***********************************************************************
 * MTU Discovery
 **********************************************************************/
struct mtu_result_t{
    size_t recv_mtu, send_mtu;
};

static mtu_result_t determine_mtu(const std::string &addr, const mtu_result_t &user_mtu){
    udp_simple::sptr udp_sock = udp_simple::make_connected(
        addr, BOOST_STRINGIZE(USRP2_UDP_CTRL_PORT)
    );

    //The FPGA offers 4K buffers, and the user may manually request this.
    //However, multiple simultaneous receives (2DSP slave + 2DSP master),
    //require that buffering to be used internally, and this is a safe setting.
    std::vector<boost::uint8_t> buffer(std::max(user_mtu.recv_mtu, user_mtu.send_mtu));
    usrp2_ctrl_data_t *ctrl_data = reinterpret_cast<usrp2_ctrl_data_t *>(&buffer.front());
    static const double echo_timeout = 0.020; //20 ms

    //test holler - check if its supported in this fw version
    ctrl_data->id = htonl(USRP2_CTRL_ID_HOLLER_AT_ME_BRO);
    ctrl_data->proto_ver = htonl(USRP2_FW_COMPAT_NUM);
    ctrl_data->data.echo_args.len = htonl(sizeof(usrp2_ctrl_data_t));
    udp_sock->send(boost::asio::buffer(buffer, sizeof(usrp2_ctrl_data_t)));
    udp_sock->recv(boost::asio::buffer(buffer), echo_timeout);
    if (ntohl(ctrl_data->id) != USRP2_CTRL_ID_HOLLER_BACK_DUDE)
        throw uhd::not_implemented_error("holler protocol not implemented");

    size_t min_recv_mtu = sizeof(usrp2_ctrl_data_t), max_recv_mtu = user_mtu.recv_mtu;
    size_t min_send_mtu = sizeof(usrp2_ctrl_data_t), max_send_mtu = user_mtu.send_mtu;

    while (min_recv_mtu < max_recv_mtu){

        size_t test_mtu = (max_recv_mtu/2 + min_recv_mtu/2 + 3) & ~3;

        ctrl_data->id = htonl(USRP2_CTRL_ID_HOLLER_AT_ME_BRO);
        ctrl_data->proto_ver = htonl(USRP2_FW_COMPAT_NUM);
        ctrl_data->data.echo_args.len = htonl(test_mtu);
        udp_sock->send(boost::asio::buffer(buffer, sizeof(usrp2_ctrl_data_t)));

        size_t len = udp_sock->recv(boost::asio::buffer(buffer), echo_timeout);

        if (len >= test_mtu) min_recv_mtu = test_mtu;
        else                 max_recv_mtu = test_mtu - 4;

    }

    while (min_send_mtu < max_send_mtu){

        size_t test_mtu = (max_send_mtu/2 + min_send_mtu/2 + 3) & ~3;

        ctrl_data->id = htonl(USRP2_CTRL_ID_HOLLER_AT_ME_BRO);
        ctrl_data->proto_ver = htonl(USRP2_FW_COMPAT_NUM);
        ctrl_data->data.echo_args.len = htonl(sizeof(usrp2_ctrl_data_t));
        udp_sock->send(boost::asio::buffer(buffer, test_mtu));

        size_t len = udp_sock->recv(boost::asio::buffer(buffer), echo_timeout);
        if (len >= sizeof(usrp2_ctrl_data_t)) len = ntohl(ctrl_data->data.echo_args.len);

        if (len >= test_mtu) min_send_mtu = test_mtu;
        else                 max_send_mtu = test_mtu - 4;
    }

    mtu_result_t mtu;
    mtu.recv_mtu = min_recv_mtu;
    mtu.send_mtu = min_send_mtu;
    return mtu;
}

/***********************************************************************
 * Helpers
 **********************************************************************/
static zero_copy_if::sptr make_xport(
    const std::string &addr,
    const std::string &port,
    const device_addr_t &hints,
    const std::string &filter
){

    //only copy hints that contain the filter word
    device_addr_t filtered_hints;
    BOOST_FOREACH(const std::string &key, hints.keys()){
        if (key.find(filter) == std::string::npos) continue;
        filtered_hints[key] = hints[key];
    }

    //make the transport object with the filtered hints
    zero_copy_if::sptr xport = udp_zero_copy::make(addr, port, filtered_hints);

    //Send a small data packet so the umtrx knows the udp source port.
    //This setup must happen before further initialization occurs
    //or the async update packets will cause ICMP destination unreachable.
    static const boost::uint32_t data[2] = {
        uhd::htonx(boost::uint32_t(0 /* don't care seq num */)),
        uhd::htonx(boost::uint32_t(USRP2_INVALID_VRT_HEADER))
    };
    transport::managed_send_buffer::sptr send_buff = xport->get_send_buff();
    std::memcpy(send_buff->cast<void*>(), &data, sizeof(data));
    send_buff->commit(sizeof(data));

    return xport;
}

/***********************************************************************
 * Structors
 **********************************************************************/
umtrx_impl::umtrx_impl(const device_addr_t &_device_addr)
    : _mcr(26e6/2) // sample rate = ref_clk / 2
{
    UHD_MSG(status) << "Opening a UmTRX device..." << std::endl;
    device_addr_t device_addr = _device_addr;

    //setup the dsp transport hints (default to a large recv buff)
    if (not device_addr.has_key("recv_buff_size")){
        #if defined(UHD_PLATFORM_MACOS) || defined(UHD_PLATFORM_BSD)
            //limit buffer resize on macos or it will error
            device_addr["recv_buff_size"] = "1e6";
        #elif defined(UHD_PLATFORM_LINUX) || defined(UHD_PLATFORM_WIN32)
            //set to half-a-second of buffering at max rate
            device_addr["recv_buff_size"] = "50e6";
        #endif
    }
    if (not device_addr.has_key("send_buff_size")){
        //The buffer should be the size of the SRAM on the device,
        //because we will never commit more than the SRAM can hold.
        device_addr["send_buff_size"] = boost::lexical_cast<std::string>(UMTRX_SRAM_BYTES);
    }

    device_addrs_t device_args = separate_device_addr(device_addr);

    //extract the user's requested MTU size or default
    mtu_result_t user_mtu;
    user_mtu.recv_mtu = size_t(device_addr.cast<double>("recv_frame_size", udp_simple::mtu));
    user_mtu.send_mtu = size_t(device_addr.cast<double>("send_frame_size", udp_simple::mtu));

    try{
        //calculate the minimum send and recv mtu of all devices
        mtu_result_t mtu = determine_mtu(device_args[0]["addr"], user_mtu);
        for (size_t i = 1; i < device_args.size(); i++){
            mtu_result_t mtu_i = determine_mtu(device_args[i]["addr"], user_mtu);
            mtu.recv_mtu = std::min(mtu.recv_mtu, mtu_i.recv_mtu);
            mtu.send_mtu = std::min(mtu.send_mtu, mtu_i.send_mtu);
        }

        device_addr["recv_frame_size"] = boost::lexical_cast<std::string>(mtu.recv_mtu);
        device_addr["send_frame_size"] = boost::lexical_cast<std::string>(mtu.send_mtu);

        UHD_MSG(status) << boost::format("Current recv frame size: %d bytes") % mtu.recv_mtu << std::endl;
        UHD_MSG(status) << boost::format("Current send frame size: %d bytes") % mtu.send_mtu << std::endl;
    }
    catch(const uhd::not_implemented_error &){
        //just ignore this error, makes older fw work...
    }

    device_args = separate_device_addr(device_addr); //update args for new frame sizes

    ////////////////////////////////////////////////////////////////////
    // create controller objects and initialize the properties tree
    ////////////////////////////////////////////////////////////////////
    _tree = property_tree::make();
    _tree->create<std::string>("/name").set("UmTRX Device");

    for (size_t mbi = 0; mbi < device_args.size(); mbi++){
        const device_addr_t device_args_i = device_args[mbi];
        const std::string mb = boost::lexical_cast<std::string>(mbi);
        const std::string addr = device_args_i["addr"];
        const fs_path mb_path = "/mboards/" + mb;

        ////////////////////////////////////////////////////////////////
        // create the iface that controls i2c, spi, uart, and wb
        ////////////////////////////////////////////////////////////////
        _mbc[mb].iface = usrp2_iface::make(udp_simple::make_connected(
            addr, BOOST_STRINGIZE(USRP2_UDP_CTRL_PORT)
        ));
        _tree->create<std::string>(mb_path / "name").set(_mbc[mb].iface->get_cname());
        _tree->create<std::string>(mb_path / "fw_version").set(_mbc[mb].iface->get_fw_version_string());

        //check the fpga compatibility number
        const boost::uint32_t fpga_compat_num = _mbc[mb].iface->peek32(U2_REG_COMPAT_NUM_RB);
        boost::uint16_t fpga_major = fpga_compat_num >> 16, fpga_minor = fpga_compat_num & 0xffff;
        if (fpga_major == 0){ //old version scheme
            fpga_major = fpga_minor;
            fpga_minor = 0;
        }
        if (fpga_major != USRP2_FPGA_COMPAT_NUM){
            throw uhd::runtime_error(str(boost::format(
                "\nPlease update the firmware and FPGA images for your device.\n"
                "See the application notes for UmTRX for instructions.\n"
                "Expected FPGA compatibility number %d, but got %d:\n"
                "The FPGA build is not compatible with the host code build.\n"
                "%s\n"
            ) % int(USRP2_FPGA_COMPAT_NUM) % fpga_major % _mbc[mb].iface->images_warn_help_message()));
        }
        _tree->create<std::string>(mb_path / "fpga_version").set(str(boost::format("%u.%u") % fpga_major % fpga_minor));

        //lock the device/motherboard to this process
        _mbc[mb].iface->lock_device(true);

        ////////////////////////////////////////////////////////////////
        // construct transports for RX and TX DSPs
        ////////////////////////////////////////////////////////////////
        UHD_LOG << "Making transport for RX DSP0..." << std::endl;
        _mbc[mb].rx_dsp_xports.push_back(make_xport(
            addr, BOOST_STRINGIZE(USRP2_UDP_RX_DSP0_PORT), device_args_i, "recv"
        ));
        UHD_LOG << "Making transport for RX DSP1..." << std::endl;
        _mbc[mb].rx_dsp_xports.push_back(make_xport(
            addr, BOOST_STRINGIZE(USRP2_UDP_RX_DSP1_PORT), device_args_i, "recv"
        ));
        UHD_LOG << "Making transport for TX DSP0..." << std::endl;
        _mbc[mb].tx_dsp_xports.push_back(make_xport(
            addr, BOOST_STRINGIZE(USRP2_UDP_TX_DSP0_PORT), device_args_i, "send"
        ));
        UHD_LOG << "Making transport for Control..." << std::endl;
        _mbc[mb].fifo_ctrl_xport = make_xport(
            addr, BOOST_STRINGIZE(USRP2_UDP_FIFO_CRTL_PORT), device_addr_t(), ""
        );
        UHD_LOG << "Making transport for TX DSP1..." << std::endl;
        _mbc[mb].tx_dsp_xports.push_back(make_xport(
            addr, BOOST_STRINGIZE(USRP2_UDP_TX_DSP1_PORT), device_args_i, "send"
        ));
        //set the filter on the router to take dsp data from this port
        _mbc[mb].iface->poke32(U2_REG_ROUTER_CTRL_PORTS, ((uint32_t)USRP2_UDP_FIFO_CRTL_PORT << 16) | USRP2_UDP_TX_DSP0_PORT);
        _mbc[mb].iface->poke32(U2_REG_ROUTER_CTRL_PORTS+8, ((uint32_t)USRP2_UDP_TX_DSP1_PORT << 16));

        //create the fifo control interface for high speed register access
        _mbc[mb].fifo_ctrl = usrp2_fifo_ctrl::make(_mbc[mb].fifo_ctrl_xport);
        switch(_mbc[mb].iface->get_rev()){
        case usrp2_iface::USRP_N200:
        case usrp2_iface::USRP_N210:
        case usrp2_iface::USRP_N200_R4:
        case usrp2_iface::USRP_N210_R4:
        case usrp2_iface::UMTRX_REV0:
            _mbc[mb].wbiface = _mbc[mb].fifo_ctrl;
            _mbc[mb].spiface = _mbc[mb].fifo_ctrl;
            break;
        default:
            _mbc[mb].wbiface = _mbc[mb].iface;
            _mbc[mb].spiface = _mbc[mb].iface;
            break;
        }

        ////////////////////////////////////////////////////////////////
        // setup the mboard eeprom
        ////////////////////////////////////////////////////////////////
        _tree->create<mboard_eeprom_t>(mb_path / "eeprom")
            .set(_mbc[mb].iface->mb_eeprom)
            .subscribe(boost::bind(&umtrx_impl::set_mb_eeprom, this, mb, _1));

        ////////////////////////////////////////////////////////////////
        // create clock control objects
        ////////////////////////////////////////////////////////////////
//        _mbc[mb].clock = umtrx_clock_ctrl::make(_mbc[mb].iface);
        _tree->create<double>(mb_path / "tick_rate")
            .publish(boost::bind(&umtrx_impl::get_master_clock_rate, this))
            .subscribe(boost::bind(&umtrx_impl::update_tick_rate, this, _1));

        ////////////////////////////////////////////////////////////////
        // reset LMS chips
        ////////////////////////////////////////////////////////////////

        {
            const boost::uint32_t clock_ctrl = _mbc[mb].iface->peek32(U2_REG_MISC_CTRL_CLOCK);
            _mbc[mb].iface->poke32(U2_REG_MISC_CTRL_CLOCK, clock_ctrl & ~(LMS1_RESET|LMS2_RESET));
            _mbc[mb].iface->poke32(U2_REG_MISC_CTRL_CLOCK, clock_ctrl |  (LMS1_RESET|LMS2_RESET));
        }

        ////////////////////////////////////////////////////////////////
        // create (fake) daughterboard entries
        ////////////////////////////////////////////////////////////////
        _mbc[mb].dbc["A"];
        _mbc[mb].dbc["B"];

        ////////////////////////////////////////////////////////////////
        // create codec control objects
        ////////////////////////////////////////////////////////////////
        BOOST_FOREACH(const std::string &db, _mbc[mb].dbc.keys()){
            const fs_path rx_codec_path = mb_path / "rx_codecs" / db;
            const fs_path tx_codec_path = mb_path / "tx_codecs" / db;
            _tree->create<int>(rx_codec_path / "gains"); //phony property so this dir exists
            _tree->create<int>(tx_codec_path / "gains"); //phony property so this dir exists
            // TODO: Implement "gains" as well
            _tree->create<std::string>(tx_codec_path / "name").set("LMS_TX");
            _tree->create<std::string>(rx_codec_path / "name").set("LMS_RX");
        }

        ////////////////////////////////////////////////////////////////
        // create gpsdo control objects
        ////////////////////////////////////////////////////////////////
        if (_mbc[mb].iface->mb_eeprom["gpsdo"] == "internal"){
            _mbc[mb].gps = gps_ctrl::make(udp_simple::make_uart(udp_simple::make_connected(
                addr, BOOST_STRINGIZE(umtrx_UDP_UART_GPS_PORT)
            )));
            if(_mbc[mb].gps->gps_detected()) {
                BOOST_FOREACH(const std::string &name, _mbc[mb].gps->get_sensors()){
                    _tree->create<sensor_value_t>(mb_path / "sensors" / name)
                        .publish(boost::bind(&gps_ctrl::get_sensor, _mbc[mb].gps, name));
                }
            }
        }

        ////////////////////////////////////////////////////////////////
        // and do the misc mboard sensors
        ////////////////////////////////////////////////////////////////
//        _tree->create<sensor_value_t>(mb_path / "sensors/mimo_locked")
//            .publish(boost::bind(&umtrx_impl::get_mimo_locked, this, mb));
        _tree->create<sensor_value_t>(mb_path / "sensors/ref_locked");
//            .publish(boost::bind(&umtrx_impl::get_ref_locked, this, mb));

        ////////////////////////////////////////////////////////////////
        // create frontend control objects
        ////////////////////////////////////////////////////////////////
        _mbc[mb].rx_fes.push_back(rx_frontend_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_RX_FRONT)
        ));
        _mbc[mb].tx_fes.push_back(tx_frontend_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_TX_FRONT0)
        ));
        _mbc[mb].rx_fes.push_back(rx_frontend_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_RX_FRONT1)
        ));
        _mbc[mb].tx_fes.push_back(tx_frontend_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_TX_FRONT1)
        ));

        _tree->create<subdev_spec_t>(mb_path / "rx_subdev_spec")
            .subscribe(boost::bind(&umtrx_impl::update_rx_subdev_spec, this, mb, _1));
        _tree->create<subdev_spec_t>(mb_path / "tx_subdev_spec")
            .subscribe(boost::bind(&umtrx_impl::update_tx_subdev_spec, this, mb, _1));

        BOOST_FOREACH(const std::string &db, _mbc[mb].dbc.keys()){
            const fs_path rx_fe_path = mb_path / "rx_frontends" / db;
            const fs_path tx_fe_path = mb_path / "tx_frontends" / db;
            const rx_frontend_core_200::sptr rx_fe = (db=="A")?_mbc[mb].rx_fes[0]:_mbc[mb].rx_fes[1];
            const tx_frontend_core_200::sptr tx_fe = (db=="A")?_mbc[mb].tx_fes[0]:_mbc[mb].tx_fes[1];

        _tree->create<std::complex<double> >(rx_fe_path / "dc_offset" / "value")
                .coerce(boost::bind(&rx_frontend_core_200::set_dc_offset, rx_fe, _1))
            .set(std::complex<double>(0.0, 0.0));
        _tree->create<bool>(rx_fe_path / "dc_offset" / "enable")
                .subscribe(boost::bind(&rx_frontend_core_200::set_dc_offset_auto, rx_fe, _1))
            .set(true);
        _tree->create<std::complex<double> >(rx_fe_path / "iq_balance" / "value")
                .subscribe(boost::bind(&rx_frontend_core_200::set_iq_balance, rx_fe, _1))
                .set(std::polar<double>(0.0, 0.0));
        _tree->create<std::complex<double> >(tx_fe_path / "dc_offset" / "value")
                .coerce(boost::bind(&tx_frontend_core_200::set_dc_offset, tx_fe, _1))
            .set(std::complex<double>(0.0, 0.0));
        _tree->create<std::complex<double> >(tx_fe_path / "iq_balance" / "value")
                .subscribe(boost::bind(&tx_frontend_core_200::set_iq_balance, tx_fe, _1))
                .set(std::polar<double>(0.0, 0.0));
        }

        ////////////////////////////////////////////////////////////////
        // create rx dsp control objects
        ////////////////////////////////////////////////////////////////
        _mbc[mb].rx_dsps.push_back(rx_dsp_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_RX_DSP0), U2_REG_SR_ADDR(SR_RX_CTRL0), USRP2_RX_SID_BASE + 0, true
        ));
        _mbc[mb].rx_dsps.push_back(rx_dsp_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_RX_DSP1), U2_REG_SR_ADDR(SR_RX_CTRL1), USRP2_RX_SID_BASE + 1, true
        ));
        for (size_t dspno = 0; dspno < _mbc[mb].rx_dsps.size(); dspno++){
            _mbc[mb].rx_dsps[dspno]->set_link_rate(USRP2_LINK_RATE_BPS);
            _tree->access<double>(mb_path / "tick_rate")
                .subscribe(boost::bind(&rx_dsp_core_200::set_tick_rate, _mbc[mb].rx_dsps[dspno], _1));
            fs_path rx_dsp_path = mb_path / str(boost::format("rx_dsps/%u") % dspno);
            _tree->create<meta_range_t>(rx_dsp_path / "rate/range")
                .publish(boost::bind(&rx_dsp_core_200::get_host_rates, _mbc[mb].rx_dsps[dspno]));
            _tree->create<double>(rx_dsp_path / "rate/value")
                .set(1e6) //some default
                .coerce(boost::bind(&rx_dsp_core_200::set_host_rate, _mbc[mb].rx_dsps[dspno], _1))
                .subscribe(boost::bind(&umtrx_impl::update_rx_samp_rate, this, mb, dspno, _1));
            _tree->create<double>(rx_dsp_path / "freq/value")
                .coerce(boost::bind(&rx_dsp_core_200::set_freq, _mbc[mb].rx_dsps[dspno], _1));
            _tree->create<meta_range_t>(rx_dsp_path / "freq/range")
                .publish(boost::bind(&rx_dsp_core_200::get_freq_range, _mbc[mb].rx_dsps[dspno]));
            _tree->create<stream_cmd_t>(rx_dsp_path / "stream_cmd")
                .subscribe(boost::bind(&rx_dsp_core_200::issue_stream_command, _mbc[mb].rx_dsps[dspno], _1));
        }

        ////////////////////////////////////////////////////////////////
        // create tx dsp control objects
        ////////////////////////////////////////////////////////////////
        _mbc[mb].tx_dsps.push_back(tx_dsp_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_TX_DSP0), U2_REG_SR_ADDR(SR_TX_CTRL0), USRP2_TX_ASYNC_SID_BASE+0
        ));
        _mbc[mb].tx_dsps.push_back(tx_dsp_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_TX_DSP1), U2_REG_SR_ADDR(SR_TX_CTRL1), USRP2_TX_ASYNC_SID_BASE+1
        ));
        for (size_t dspno = 0; dspno < _mbc[mb].tx_dsps.size(); dspno++){
            _mbc[mb].tx_dsps[dspno]->set_link_rate(USRP2_LINK_RATE_BPS);
        _tree->access<double>(mb_path / "tick_rate")
                .subscribe(boost::bind(&tx_dsp_core_200::set_tick_rate, _mbc[mb].tx_dsps[dspno], _1));
            fs_path tx_dsp_path = mb_path / str(boost::format("tx_dsps/%u") % dspno);
            _tree->create<meta_range_t>(tx_dsp_path / "rate/range")
                .publish(boost::bind(&tx_dsp_core_200::get_host_rates, _mbc[mb].tx_dsps[dspno]));
            _tree->create<double>(tx_dsp_path / "rate/value")
            .set(1e6) //some default
                .coerce(boost::bind(&tx_dsp_core_200::set_host_rate, _mbc[mb].tx_dsps[dspno], _1))
                .subscribe(boost::bind(&umtrx_impl::update_tx_samp_rate, this, mb, dspno, _1));
            _tree->create<double>(tx_dsp_path / "freq/value")
                .coerce(boost::bind(&tx_dsp_core_200::set_freq, _mbc[mb].tx_dsps[dspno], _1));
            _tree->create<meta_range_t>(tx_dsp_path / "freq/range")
                .publish(boost::bind(&tx_dsp_core_200::get_freq_range, _mbc[mb].tx_dsps[dspno]));
        }

        //setup dsp flow control
        const double ups_per_sec = device_args_i.cast<double>("ups_per_sec", 20);
        const size_t send_frame_size = _mbc[mb].tx_dsp_xports[0]->get_send_frame_size();
        const double ups_per_fifo = device_args_i.cast<double>("ups_per_fifo", 8.0);
        _mbc[mb].tx_dsps[0]->set_updates(
            (ups_per_sec > 0.0)? size_t(get_master_clock_rate()/*approx tick rate*//ups_per_sec) : 0,
            (ups_per_fifo > 0.0)? size_t(UMTRX_SRAM_BYTES/ups_per_fifo/send_frame_size) : 0
        );
        _mbc[mb].tx_dsps[1]->set_updates(
            (ups_per_sec > 0.0)? size_t(get_master_clock_rate()/*approx tick rate*//ups_per_sec) : 0,
            (ups_per_fifo > 0.0)? size_t(UMTRX_SRAM_BYTES/ups_per_fifo/send_frame_size) : 0
        );

        ////////////////////////////////////////////////////////////////
        // create time control objects
        ////////////////////////////////////////////////////////////////
        time64_core_200::readback_bases_type time64_rb_bases;
        time64_rb_bases.rb_hi_now = U2_REG_TIME64_HI_RB_IMM;
        time64_rb_bases.rb_lo_now = U2_REG_TIME64_LO_RB_IMM;
        time64_rb_bases.rb_hi_pps = U2_REG_TIME64_HI_RB_PPS;
        time64_rb_bases.rb_lo_pps = U2_REG_TIME64_LO_RB_PPS;
        _mbc[mb].time64 = time64_core_200::make(
            _mbc[mb].wbiface, U2_REG_SR_ADDR(SR_TIME64), time64_rb_bases, mimo_clock_sync_delay_cycles
        );
        _tree->access<double>(mb_path / "tick_rate")
            .subscribe(boost::bind(&time64_core_200::set_tick_rate, _mbc[mb].time64, _1));
        _tree->create<time_spec_t>(mb_path / "time/now")
            .publish(boost::bind(&time64_core_200::get_time_now, _mbc[mb].time64))
            .subscribe(boost::bind(&time64_core_200::set_time_now, _mbc[mb].time64, _1));
        _tree->create<time_spec_t>(mb_path / "time/pps")
            .publish(boost::bind(&time64_core_200::get_time_last_pps, _mbc[mb].time64))
            .subscribe(boost::bind(&time64_core_200::set_time_next_pps, _mbc[mb].time64, _1));
        //setup time source props
        _tree->create<std::string>(mb_path / "time_source/value")
            .subscribe(boost::bind(&time64_core_200::set_time_source, _mbc[mb].time64, _1));
        _tree->create<std::vector<std::string> >(mb_path / "time_source/options")
            .publish(boost::bind(&time64_core_200::get_time_sources, _mbc[mb].time64));
        //setup reference source props
        _tree->create<std::string>(mb_path / "clock_source/value");
        //    .subscribe(boost::bind(&usrp2_impl::update_clock_source, this, mb, _1));
        std::vector<std::string> clock_sources = boost::assign::list_of("internal")("external")("mimo");
        if (_mbc[mb].gps and _mbc[mb].gps->gps_detected()) clock_sources.push_back("gpsdo");
        _tree->create<std::vector<std::string> >(mb_path / "clock_source/options").set(clock_sources);
        //plug timed commands into tree here
        switch(_mbc[mb].iface->get_rev()){
        case usrp2_iface::USRP_N200:
        case usrp2_iface::USRP_N210:
        case usrp2_iface::USRP_N200_R4:
        case usrp2_iface::USRP_N210_R4:
        case usrp2_iface::UMTRX_REV0:
            _tree->create<time_spec_t>(mb_path / "time/cmd")
                .subscribe(boost::bind(&usrp2_fifo_ctrl::set_time, _mbc[mb].fifo_ctrl, _1));
        default: break; //otherwise, do not register
        }
        _tree->access<double>(mb_path / "tick_rate")
            .subscribe(boost::bind(&usrp2_fifo_ctrl::set_tick_rate, _mbc[mb].fifo_ctrl, _1));

        ////////////////////////////////////////////////////////////////////
        // create user-defined control objects
        ////////////////////////////////////////////////////////////////////
        _mbc[mb].user = user_settings_core_200::make(_mbc[mb].wbiface, U2_REG_SR_ADDR(SR_USER_REGS));
        _tree->create<user_settings_core_200::user_reg_t>(mb_path / "user/regs")
            .subscribe(boost::bind(&user_settings_core_200::set_reg, _mbc[mb].user, _1));

        ////////////////////////////////////////////////////////////////
        // create dboard control objects
        ////////////////////////////////////////////////////////////////

        // LMS dboard do not have physical eeprom so we just hardcode values from host/lib/usrp/dboard/db_lms.cpp
        dboard_eeprom_t rx_db_eeprom, tx_db_eeprom, gdb_eeprom;
        rx_db_eeprom.id = 0xfa07;
        rx_db_eeprom.revision = _mbc[mb].iface->mb_eeprom["revision"];
        tx_db_eeprom.id = 0xfa09;
        tx_db_eeprom.revision = _mbc[mb].iface->mb_eeprom["revision"];
        //gdb_eeprom.id = 0x0000;

        BOOST_FOREACH(const std::string &board, _mbc[mb].dbc.keys()){
            // Different serial numbers for each LMS on a UmTRX.
            // This is required to properly correlate calibration files to LMS chips.
            rx_db_eeprom.serial = _mbc[mb].iface->mb_eeprom["serial"] + "." + board;
            tx_db_eeprom.serial = _mbc[mb].iface->mb_eeprom["serial"] + "." + board;

            //create dboard interface
            _mbc[mb].dbc[board].dboard_iface = make_umtrx_dboard_iface(
_mbc[mb].iface/*i2c*/,
 _mbc[mb].spiface,
 board,
 2*get_master_clock_rate()); // ref_clk = 2 * sample rate
            _mbc[mb].dbc[board].dboard_manager = dboard_manager::make(
            rx_db_eeprom.id, tx_db_eeprom.id, gdb_eeprom.id,
                _mbc[mb].dbc[board].dboard_iface, _tree->subtree(mb_path / "dboards" / board)
        );

            //create the properties and register subscribers
            _tree->create<dboard_eeprom_t>(mb_path / "dboards" / board / "rx_eeprom")
                .set(rx_db_eeprom);

            _tree->create<dboard_eeprom_t>(mb_path / "dboards" / board / "tx_eeprom")
                .set(tx_db_eeprom);

            _tree->create<dboard_eeprom_t>(mb_path / "dboards" / board / "gdb_eeprom")
                .set(gdb_eeprom);
            
            _tree->create<dboard_iface::sptr>(mb_path / "dboards" / board / "iface").set(_mbc[mb].dbc[board].dboard_iface);

        //bind frontend corrections to the dboard freq props
            const fs_path db_tx_fe_path = mb_path / "dboards" / board / "tx_frontends";
        BOOST_FOREACH(const std::string &name, _tree->list(db_tx_fe_path)){
            _tree->access<double>(db_tx_fe_path / name / "freq" / "value")
                    .subscribe(boost::bind(&umtrx_impl::set_tx_fe_corrections, this, mb, board, _1));
        }
            const fs_path db_rx_fe_path = mb_path / "dboards" / board / "rx_frontends";
        BOOST_FOREACH(const std::string &name, _tree->list(db_rx_fe_path)){
            _tree->access<double>(db_rx_fe_path / name / "freq" / "value")
                    .subscribe(boost::bind(&umtrx_impl::set_rx_fe_corrections, this, mb, board, _1));
        }

            //set Tx DC calibration values, which are read from mboard EEPROM
            if (_mbc[mb].iface->mb_eeprom.has_key("tx-vga1-dc-i") and not _mbc[mb].iface->mb_eeprom["tx-vga1-dc-i"].empty()) {
                BOOST_FOREACH(const std::string &name, _tree->list(db_tx_fe_path)){
                    _tree->access<uint8_t>(db_tx_fe_path / name / "lms6002d/tx_dc_i/value")
                        .set(boost::lexical_cast<int>(_mbc[mb].iface->mb_eeprom["tx-vga1-dc-i"]));
                }
            }
            if (_mbc[mb].iface->mb_eeprom.has_key("tx-vga1-dc-q") and not _mbc[mb].iface->mb_eeprom["tx-vga1-dc-q"].empty()) {
                BOOST_FOREACH(const std::string &name, _tree->list(db_tx_fe_path)){
                    _tree->access<uint8_t>(db_tx_fe_path / name / "lms6002d/tx_dc_q/value")
                        .set(boost::lexical_cast<int>(_mbc[mb].iface->mb_eeprom["tx-vga1-dc-q"]));
                }
            }
        }

        //set TCXO DAC calibration value, which is read from mboard EEPROM
        if (_mbc[mb].iface->mb_eeprom.has_key("tcxo-dac") and not _mbc[mb].iface->mb_eeprom["tcxo-dac"].empty()) {
            _tree->create<uint16_t>(mb_path / "tcxo_dac/value")
                .subscribe(boost::bind(&umtrx_impl::set_tcxo_dac, this, mb, _1))
                .set(boost::lexical_cast<uint16_t>(_mbc[mb].iface->mb_eeprom["tcxo-dac"]));
        }
    }

    //initialize io handling
    this->io_init();

    //do some post-init tasks
    this->update_rates();
    BOOST_FOREACH(const std::string &mb, _mbc.keys()){
        fs_path root = "/mboards/" + mb;

        //reset cordic rates and their properties to zero
        BOOST_FOREACH(const std::string &name, _tree->list(root / "rx_dsps")){
            _tree->access<double>(root / "rx_dsps" / name / "freq" / "value").set(0.0);
        }
        BOOST_FOREACH(const std::string &name, _tree->list(root / "tx_dsps")){
            _tree->access<double>(root / "tx_dsps" / name / "freq" / "value").set(0.0);
        }

        _tree->access<subdev_spec_t>(root / "rx_subdev_spec").set(subdev_spec_t("A:" + _tree->list(root / "dboards/A/rx_frontends").at(0)));
        _tree->access<subdev_spec_t>(root / "tx_subdev_spec").set(subdev_spec_t("A:" + _tree->list(root / "dboards/A/tx_frontends").at(0)));
        _tree->access<std::string>(root / "clock_source/value").set("internal");
        _tree->access<std::string>(root / "time_source/value").set("none");

        //GPS installed: use external ref, time, and init time spec
        if (_mbc[mb].gps and _mbc[mb].gps->gps_detected()){
            _mbc[mb].time64->enable_gpsdo();
            UHD_MSG(status) << "Setting references to the internal GPSDO" << std::endl;
            _tree->access<std::string>(root / "time_source/value").set("gpsdo");
            _tree->access<std::string>(root / "clock_source/value").set("gpsdo");
            UHD_MSG(status) << "Initializing time to the internal GPSDO" << std::endl;
            _mbc[mb].time64->set_time_next_pps(time_spec_t(time_t(_mbc[mb].gps->get_sensor("gps_time").to_int()+1)));
        }
    }

}

umtrx_impl::~umtrx_impl(void){UHD_SAFE_CALL(
    BOOST_FOREACH(const std::string &mb, _mbc.keys()){
        _mbc[mb].tx_dsps[0]->set_updates(0, 0);
        _mbc[mb].tx_dsps[1]->set_updates(0, 0);
    }
)}

void umtrx_impl::set_mb_eeprom(const std::string &mb, const uhd::usrp::mboard_eeprom_t &mb_eeprom){
    mb_eeprom.commit(*(_mbc[mb].iface), "UMTRX");
}

void umtrx_impl::set_rx_fe_corrections(const std::string &mb, const std::string &board, const double lo_freq){
    apply_rx_fe_corrections(this->get_tree()->subtree("/mboards/" + mb), board, lo_freq);
}

void umtrx_impl::set_tx_fe_corrections(const std::string &mb, const std::string &board, const double lo_freq){
    apply_tx_fe_corrections(this->get_tree()->subtree("/mboards/" + mb), board, lo_freq);
}

void umtrx_impl::set_tcxo_dac(const std::string &mb, const uint16_t val){
    if (verbosity>0) printf("umtrx_impl::set_tcxo_dac(%d)\n", val);
    _mbc[mb].iface->send_zpu_action(UMTRX_ZPU_REQUEST_SET_VCTCXO_DAC, val);
}

uint16_t umtrx_impl::get_tcxo_dac(const std::string &mb){
    uint16_t val = _mbc[mb].iface->send_zpu_action(UMTRX_ZPU_REQUEST_GET_VCTCXO_DAC, 0);
    if (verbosity>0) printf("umtrx_impl::get_tcxo_dac(): %d\n", val);
    return (uint16_t)val;
}
