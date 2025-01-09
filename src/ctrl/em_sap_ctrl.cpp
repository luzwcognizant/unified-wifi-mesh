/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "em_sap_ctrl.h"
#include "al_service_access_point.hpp"

int em_sap_ctrl_t::execute(AlServiceAccessPoint* sap)
{
    bool wait = false;

    while (1) {
        AlServiceDataUnit receivedData1000 = sap->serviceAccessPointDataIndication();
        std::cout << "Ctrl received the message successfully!" << std::endl;
        std::cout << "Received payload:" << std::endl;
        std::vector<unsigned char> payload = receivedData1000.getPayload();
        for (auto byte : payload) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;

        em_event_t *tmp = get_event();
        memcpy(tmp, payload.data(), payload.size() * sizeof(unsigned char));
        
        switch (get_event()->type) {
            case em_event_type_bus:
                wait = m_ctrl.io_process(get_event());
                break;

            default:
                wait = false;
                break;
        }

        if (wait == false) {
            send_result(sap, em_cmd_out_status_other);
        }
    }

    return 0;
}

int em_sap_ctrl_t::send_result(AlServiceAccessPoint* sap, em_cmd_out_status_t status)
{
    em_status_string_t str; 
    char *tmp;

    tmp = m_cmd.status_to_string(status, str);

    AlServiceDataUnit sdu;
    sdu.setSourceAlMacAddress({0x11, 0x11, 0x11, 0x11, 0x11, 0x11});
    sdu.setDestinationAlMacAddress({0x66, 0x66, 0x66, 0x66, 0x66, 0x66});

    std::vector<unsigned char> payload;
    for (int i = 0; i < strlen(tmp); i++) {
        payload.push_back(tmp[i]);
    }
    sdu.setPayload(payload);

    sap->serviceAccessPointDataRequest(sdu);
    std::cout << "Ctrl sent the message successfully!" << std::endl;
    std::cout << "Sent payload:" << std::endl;
    for (auto byte : payload) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    return 0;
}

em_sap_ctrl_t::em_sap_ctrl_t()
{
    dm_easy_mesh_t dm;

    m_cmd.init(&dm);
    snprintf(m_sock_path, sizeof(m_sock_path), "%s_%s", EM_PATH_PREFIX, EM_CTRL_PATH);
}