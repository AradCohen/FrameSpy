#include <iostream>

#include <tcp.h>
#include <packet_sender.h>
#include <ethernetII.h>
#include <rawpdu.h>
#include "tins/sniffer.h"
using namespace Tins;
#include "pfs/procfs.hpp"
#include "PidCollector.h"


int main() {
    int pid = 3711;

    std::cout << "opening a sniffer" << std::endl;
//    SnifferConfiguration config;
//    config.set_filter("tcp");

    Sniffer sniffer("ens33");

    PacketSender sender;
    NetworkInterface out_iface("new");
    std::vector<__ino_t> inodes;
    std::vector<u_int16_t> ports;

    while (true) {

        PDU *packet = sniffer.next_packet();
        TCP *tcp_layer = packet->find_pdu<TCP>();

        if (tcp_layer != NULL) {

            if (tcp_layer->flags() == TCP::SYN) {
                auto task = pfs::procfs().get_task(pid);
                auto fds = task.get_fds();
                for (auto fd: fds) {
                    auto st = fd.second.get_target_stat();
                    inodes.push_back(st.st_ino);
                }
                auto sockets_for_pid = pfs::procfs().get_net().get_tcp();

                for (auto socket: sockets_for_pid) {
                    if (std::find(inodes.begin(), inodes.end(), socket.inode) != inodes.end()) {
                        ports.push_back(socket.local_port);
                    }
                }
            }

            u_int16_t sport = tcp_layer->sport();
            u_int16_t dport = tcp_layer->dport();
            if (std::find(ports.begin(), ports.end(), sport) != ports.end() ||
                std::find(ports.begin(), ports.end(), dport) != ports.end()) {
                PDU *pdu_payload = tcp_layer->inner_pdu();
                if (pdu_payload == NULL) {

                    sender.send(*packet, out_iface);
                } else {
                    auto payload = packet->rfind_pdu<RawPDU>();

                    if (payload.size() <= 1400) {

                        sender.send(*packet, out_iface);
                    } else {
                        auto payload_bytes = payload.payload();
                        u_int32_t start_seq = tcp_layer->seq();

                        for (int byte_idx = 0; byte_idx <= payload_bytes.size(); byte_idx += 1400) {
                            u_int32_t curr_size =
                                    payload_bytes.size() - byte_idx > 1400 ? 1400 : payload_bytes.size() - byte_idx;
                            u_int8_t *curr_payload = (u_int8_t *) calloc(curr_size, 1);
                            std::copy(payload_bytes.begin() + byte_idx,
                                      payload_bytes.begin() + byte_idx + curr_size, curr_payload);
                            tcp_layer->inner_pdu(RawPDU(curr_payload, curr_size));

                            tcp_layer->seq(start_seq + byte_idx);
                            sender.send(*packet, out_iface);


                        }
                    }
                }

                delete packet;
            }
        }
    }
}