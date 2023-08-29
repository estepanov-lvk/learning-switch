#include "LearningSwitch.hpp"

#include "PacketParser.hpp"
#include "api/Packet.hpp"
#include "apps/host-manager/include/HostManager.hpp"
#include <cstdint>
#include <lib/ipv4addr.hpp>
#include <of13/of13match.hh>
#include <of13/openflow-13.h>
#include <oxm/openflow_basic.hh>
#include <runos/core/logging.hpp>

#include <sstream>
#include <experimental/random>
#include <ctime>
#include <string>

namespace runos {

REGISTER_APPLICATION(LearningSwitch, {"controller",
                                "switch-manager",
                                "topology",
                                "host-manager",
                                "link-discovery",
                                ""})

std::string PrettyIP(uint32_t ip) {
    return std::to_string(ip & 0x000000ff) + "."
        + std::to_string((ip & 0x0000ff00) >> 8) + "."
        + std::to_string((ip & 0x00ff0000) >> 16) + "."
        + std::to_string((ip & 0xff000000) >> 24);
}

void LearningSwitch::init(Loader* loader, const Config& config)
{
    std::srand(std::time(nullptr));
    switch_manager_ = SwitchManager::get(loader);
    connect(switch_manager_, &SwitchManager::switchUp,
            this, &LearningSwitch::onSwitchUp);
    host_manager_ = HostManager::get(loader);
    topology_ = Topology::get(loader);
    QObject* ld = ILinkDiscovery::get(loader);
    link_discovery_ = dynamic_cast<ILinkDiscovery*>(ld);

    handler_ = Controller::get(loader)->register_handler(
    [=](of13::PacketIn& pi, OFConnectionPtr ofconn) mutable -> bool
    {
        // LOG(INFO) << "got packetin";
        PacketParser pp(pi);
        runos::Packet& pkt(pp);

        // LOG(INFO) << "type " << std::hex << pkt.load(oxm::eth_type());
        uint32_t ip_dst;
        if (pkt.test(oxm::eth_type() == 0x0800)) {
            ip_dst = pkt.load(oxm::ipv4_dst());
        } else if (pkt.test(oxm::eth_type() == 0x0806)) {
            ip_dst = pkt.load(oxm::arp_tpa());
        } else {
            // LOG(INFO) << "unknown packet type, dropping";
            return false;
        }
        ip_dst = htonl(ip_dst);
        // LOG(INFO) << "got dst ip " << PrettyIP(ip_dst);

        auto host_info = host_manager_->getHost(ipv4addr(htonl(ip_dst)));

        if (host_info != nullptr || ip_dst == 0) {
            uint32_t ip_src;
            if (pkt.test(oxm::eth_type() == 0x0800)) {
                ip_src = pkt.load(oxm::ipv4_src());
            } else if (pkt.test(oxm::eth_type() == 0x0806)) {
                ip_src = pkt.load(oxm::arp_spa());
            }
            set_path(ipv4addr(htonl(ip_src)), ipv4addr(ip_dst), pkt.load(oxm::in_port()));
            send_unicast(host_info->switchID(), host_info->switchPort(), pi);
        } else {
            for (const auto& switch_ptr : switch_manager_->switches()) {
                send_broadcast(switch_ptr->dpid(), pi);
            }
        }

        return false;
    }, -10);
}

void LearningSwitch::onSwitchUp(SwitchPtr sw)
{
    of13::FlowMod fm;
    fm.command(of13::OFPFC_ADD);
    fm.table_id(0);
    fm.priority(1);
    of13::ApplyActions applyActions;
    of13::OutputAction output_action(of13::OFPP_CONTROLLER, 0xFFFF);
    applyActions.add_action(output_action);
    fm.add_instruction(applyActions);
    sw->connection()->send(fm);
}

void LearningSwitch::send_unicast(uint32_t dpid, uint32_t port,
                            const of13::PacketIn& pi)
{
    // LOG(INFO) << "sending to dpid " << dpid << " port " << port;
    of13::PacketOut po;
    po.data(pi.data(), pi.data_len());
    of13::OutputAction output_action(port, of13::OFPCML_NO_BUFFER);
    po.add_action(output_action);
    auto sw = switch_manager_->switch_(dpid);
    // LOG(INFO) << "got switch";
    auto conn = sw->connection();
    // LOG(INFO) << "got conn";
    if (!conn->alive()) {
        // LOG(INFO) << "CONN IS BROKEN";
    }
    conn->send(po);
    // LOG(INFO) << "sent packet";
}

void LearningSwitch::send_broadcast(uint32_t dpid, const of13::PacketIn& pi)
{
    // LOG(INFO) << "broadcast dpid " << dpid;
    of13::PacketOut po;
    po.data(pi.data(), pi.data_len());
    //po.in_port(in_port_);
    auto switch_ptr = switch_manager_->switch_(dpid);
    auto switch_links = link_discovery_->links();
    for (const auto& port_ptr : switch_ptr->ports()) {
        if (port_ptr->number() == 4294967294) {
            continue;
        }
        bool send_msg = true;
        for (const auto& link : switch_links) {
            if (link.source.dpid == dpid && link.source.port == port_ptr->number()) {
                send_msg = false;
                break;
            }
            if (link.target.dpid == dpid && link.target.port == port_ptr->number()) {
                send_msg = false;
                break;
            }
        }
        if (send_msg) {
            of13::OutputAction output_action(port_ptr->number(), of13::OFPCML_NO_BUFFER);
            po.add_action(output_action);
            // LOG(INFO) << "sent to port " << port_ptr->number();
        }
    }
    //of13::OutputAction output_action(of13::OFPP_ALL, of13::OFPCML_NO_BUFFER);
    switch_ptr->connection()->send(po);
}

void LearningSwitch::set_path(ipv4addr src, ipv4addr dst, uint32_t in_port) {
    uint32_t route_id;
    auto dst_dpid = host_manager_->getHost(ipv4addr(htonl(uint32_t(dst))))->switchID();
    auto dst_port = host_manager_->getHost(ipv4addr(htonl(uint32_t(dst))))->switchPort();
    auto src_dpid = host_manager_->getHost(ipv4addr(htonl(uint32_t(src))))->switchID();
    auto src_port = host_manager_->getHost(ipv4addr(htonl(uint32_t(src))))->switchPort();
    // LOG(INFO) << "setting path from " << src_dpid << ":" << src_port << " to " << dst_dpid << ":" << dst_port;
    auto route_id_raw = routes_db_.getRoute(src_dpid, dst_dpid);
    if (route_id_raw != boost::none) {
        route_id = *route_id_raw;
    } else {
        route_id = topology_->newRoute(src_dpid, dst_dpid, route_selector::metrics=MetricsFlag::Hop);
    }
    auto path = topology_->getFirstWorkPath(route_id);

    /*
    for (const auto& rule : path) {
        LOG(INFO) << "to " << rule.dpid << " port " << rule.port;
    }
    */

    for (int i = 0; i < path.size(); i += 2) {
        set_rule(path[i].dpid, path[i].port, Proto::IP, src, dst, in_port, src_dpid);
        set_rule(path[i].dpid, path[i].port, Proto::ARP, src, dst, in_port, src_dpid);
    }

    set_rule(dst_dpid, dst_port, Proto::IP, src, dst, in_port, src_dpid);
    set_rule(dst_dpid, dst_port, Proto::ARP, src, dst, in_port, src_dpid);
}

void LearningSwitch::set_rule(uint32_t dpid, uint32_t output_port, Proto proto,
    ipv4addr src_addr, ipv4addr dst_addr, uint32_t in_port, uint32_t in_dpid)
{
    of13::FlowMod fm;
    fm.command(of13::OFPFC_ADD);
    fm.table_id(0);
    fm.priority(2);
    std::stringstream ss;
    fm.idle_timeout(uint64_t(100));
    fm.hard_timeout(uint64_t(100));
    uint64_t random_id = std::experimental::randint(0ull, 1ull << 32);
    auto new_cookie = (random_id << 32) | (in_port << 16) | in_dpid;
    // LOG(INFO) << "in_dpid " << in_dpid << " in_port " << in_port;
    fm.cookie(new_cookie);
    fm.flags(of13::OFPFF_SEND_FLOW_REM);

    if (proto == Proto::IP) {
        fm.add_oxm_field(new of13::EthType{0x0800});
        fm.add_oxm_field(new of13::IPv4Src{
                fluid_msg::IPAddress(uint32_t(src_addr))});
        fm.add_oxm_field(new of13::IPv4Dst{
                fluid_msg::IPAddress(uint32_t(dst_addr))});
    } else if (proto == Proto::ARP) {
        fm.add_oxm_field(new of13::EthType{0x0806});
        fm.add_oxm_field(new of13::ARPSPA{
                fluid_msg::IPAddress(uint32_t(src_addr))});
        fm.add_oxm_field(new of13::ARPTPA{
                fluid_msg::IPAddress(uint32_t(dst_addr))});
    }

    of13::ApplyActions applyActions;
    of13::OutputAction output_action(output_port, of13::OFPCML_NO_BUFFER);
    applyActions.add_action(output_action);
    fm.add_instruction(applyActions);
    switch_manager_->switch_(dpid)->connection()->send(fm);
}

void RoutesDatabase::setRoute(uint64_t from, uint64_t to, uint32_t id) {
    //boost::shared_lock<boost::shared_mutex> lock(mutex_);
    routes_[from][to] = id;
}

boost::optional<uint32_t> RoutesDatabase::getRoute(uint64_t from, uint64_t to) {
    //boost::shared_lock<boost::shared_mutex> lock(mutex_);
    auto it1 = routes_.find(from);
    if (it1 == routes_.end()) {
        return boost::none;
    } 
    auto it2 = routes_[from].find(to);
    if (it2 == routes_[from].end()) {
        return boost::none;
    } 
    return it2->second;
}

} // namespace runos
