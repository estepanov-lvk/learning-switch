#pragma once

#include "Application.hpp"
#include "Loader.hpp"
#include "SwitchManager.hpp"
#include "Topology.hpp"
#include "ILinkDiscovery.hpp"
#include "api/SwitchFwd.hpp"
#include "oxm/openflow_basic.hh"

#include <boost/optional.hpp>
#include <boost/thread.hpp>

#include "../../host-manager/include/HostManager.hpp"

#include <cstdint>
#include <lib/ethaddr.hpp>
#include <lib/ipv4addr.hpp>
#include <lib/qt_executor.hpp>
#include <unordered_set>
#include <unordered_map>

namespace runos {

using SwitchPtr = safe::shared_ptr<Switch>;
namespace of13 = fluid_msg::of13;

enum class Proto {
    IP,
    ARP,
};

class RoutesDatabase {
public:
    void setRoute(uint64_t from, uint64_t to, uint32_t id);
    boost::optional<uint32_t> getRoute(uint64_t from, uint64_t to);

private:
    boost::shared_mutex mutex_;
    std::unordered_map<uint64_t,
            std::unordered_map<uint64_t, uint32_t>> routes_;
};

class LearningSwitch : public Application
{
    Q_OBJECT
    SIMPLE_APPLICATION(LearningSwitch, "learning-switch")
public:
    void init(Loader* loader, const Config& config) override;

protected slots:
    void onSwitchUp(SwitchPtr sw);

private:
    OFMessageHandlerPtr handler_;
    SwitchManager* switch_manager_;
    HostManager* host_manager_;
    Topology* topology_;
    ILinkDiscovery* link_discovery_;
    RoutesDatabase routes_db_;
    qt_executor executor{this};

    boost::shared_mutex mutex_;
    std::unordered_set<ethaddr> macs_to_resolve_;

    void send_unicast(uint32_t dpid, uint32_t port, of13::PacketIn* pi);
    void send_broadcast(uint32_t dpid, const of13::PacketIn& pi);

    void set_path(ipv4addr src, ipv4addr dst, uint32_t in_port);
    void set_rule(uint32_t dpid, uint32_t output_port, Proto proto, ipv4addr src_addr, 
                  ipv4addr dst_addr, uint32_t in_port, uint32_t in_dpid);
};

} // namespace runos
