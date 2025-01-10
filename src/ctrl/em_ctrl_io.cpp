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
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include "em_ctrl.h"
#include "em_cmd_ctrl.h"
#include "em_sap_ctrl.h"
#include "al_service_access_point.hpp"

#define SOCKET_PATH "/tmp/tunnel_2_in"

bool em_ctrl_t::io_process(em_event_t *evt)
{
    em_event_t *e;
    em_bus_event_t *bevt;
    bool should_wait;

    bevt = &evt->u.bevt;
    //em_cmd_t::dump_bus_event(bevt);

    e = (em_event_t *)malloc(sizeof(em_event_t));
    memcpy(e, evt, sizeof(em_event_t));

    push_to_queue(e);

    // check if the server should wait
    should_wait = false;

    switch (evt->type) {
        case em_event_type_bus:
            bevt = &evt->u.bevt;
            if (bevt->type != em_bus_event_type_dm_commit) {
                should_wait = true;
            }
            break;
    }

    return should_wait;
}

void em_ctrl_t::io(void *data, bool input)
{
    char *str = (char *)data;
    m_ctrl_cmd->execute(str);
}

AlServiceAccessPoint* em_ctrl_t::al_sap_register()
{
    std::string customSocketPath = SOCKET_PATH;
    AlServiceAccessPoint* sap = new AlServiceAccessPoint(customSocketPath);

    AlServiceRegistrationRequest registrationRequest(ServiceOperation::SO_ENABLE, ServiceType::SAP_TUNNEL_CLIENT);
    sap->serviceAccessPointRegistrationRequest(registrationRequest);
    std::cout << "Ctrl sent the registration request successfully!";

    AlServiceRegistrationResponse registrationResponse = sap->serviceAccessPointRegistrationResponse();
    std::cout << "Ctrl received the registration response successfully!";

    std::cout << "Registration completed with MAC Address: ";
    for (auto byte : registrationResponse.getAlMacAddressLocal()) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    //verify the result
    //messag id range for controller in this case

    return sap;
}

void em_ctrl_t::al_sap_io(void *data, bool input)
{
    char *str = (char *)data;
    m_ctrl_sap->execute(str);
}
