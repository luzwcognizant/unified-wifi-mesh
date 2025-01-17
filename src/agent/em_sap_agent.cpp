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
#include "em_agent.h"
#include "em_sap_agent.h"
#include "al_service_access_point.hpp"

extern AlServiceAccessPoint* g_sap;

em_cmd_t em_sap_agent_t::m_client_cmd_spec[] = {
    em_cmd_t(em_cmd_type_none,em_cmd_params_t{0, {"", "", "", "", ""}, "none"}),
    em_cmd_t(em_cmd_type_dev_init,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:Network"}),
    em_cmd_t(em_cmd_type_cfg_renew, em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:Renew"}),
    em_cmd_t(em_cmd_type_vap_config,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:BssConfig"}),
    em_cmd_t(em_cmd_type_sta_list,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:StaList"}),
    em_cmd_t(em_cmd_type_ap_cap_query,em_cmd_params_t{1, {"", "", "", "", ""}, "wfa-dataelements:CapReport"}),
    em_cmd_t(em_cmd_type_max,em_cmd_params_t{0, {"", "", "", "", ""}, "max"}),
};

int em_sap_agent_t::execute(em_long_string_t result)
{
    bool wait = false;
    unsigned char *tmp;

    m_cmd.reset();

    while (1) {
        AlServiceDataUnit sdu = g_sap->serviceAccessPointDataIndication();
        std::cout << "Agent received the message successfully!" << std::endl;
        std::cout << "Received payload:" << std::endl;
        std::vector<unsigned char> payload = sdu.getPayload();
        for (auto byte : payload) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << std::endl;

        tmp = (unsigned char *)get_event();
        memcpy(tmp, payload.data(), sizeof(em_event_t));

        switch (get_event()->type) {
            case em_event_type_bus:
                wait = m_agent.agent_input(get_event());
                break;

            default:
                wait = false;
                break;
        }

        if (wait == false) {
            send_result(em_cmd_out_status_other);
        }

        m_cmd.reset();
    }

    return 0;
}

int em_sap_agent_t::send_result(em_cmd_out_status_t status)
{
    em_status_string_t str; 
    char *tmp;

    tmp = m_cmd.status_to_string(status, str);

    AlServiceDataUnit sdu;
    sdu.setSourceAlMacAddress({0x11, 0x11, 0x11, 0x11, 0x11, 0x11});
    sdu.setDestinationAlMacAddress({0x22, 0x22, 0x22, 0x22, 0x22, 0x22});

    std::vector<unsigned char> payload;
    for (int i = 0; i < strlen(tmp); i++) {
        payload.push_back(tmp[i]);
    }
    sdu.setPayload(payload);

    g_sap->serviceAccessPointDataRequest(sdu);
    std::cout << "Agent sent the message successfully!" << std::endl;
    std::cout << "Sent payload:" << std::endl;
    for (auto byte : payload) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    return 0;
}

em_event_t *em_sap_agent_t::create_event(char *buff)
{
    // here is the entry point of RBUS subdocuments
    em_cmd_type_t   type = em_cmd_type_none;
    cJSON *obj, *child_obj;
    char *tmp;
    em_cmd_t    *cmd;
    unsigned int idx;
    em_event_t *evt;
    em_bus_event_t *bevt;

    if ((obj = cJSON_Parse(buff)) == NULL) {
        printf("%s:%d: Failed to parse JSON object\n", __func__, __LINE__);
        return NULL;
    }

    idx = 0; type = em_sap_agent_t::m_client_cmd_spec[idx].get_type();
    cmd = &em_sap_agent_t::m_client_cmd_spec[idx];
    while (type != em_cmd_type_max) {
        //cmd = &em_sap_agent_t::m_client_cmd_spec[idx];

        if (cmd->get_svc() != em_service_type_agent) {
            idx++;
            cmd = &em_sap_agent_t::m_client_cmd_spec[idx];
            type = em_sap_agent_t::m_client_cmd_spec[idx].get_type(); continue;
        }

        tmp = (char *)cmd->get_arg();

        if ((child_obj = cJSON_GetObjectItem(obj, tmp)) != NULL) {
            break;
        }

        idx++;
        type = em_sap_agent_t::m_client_cmd_spec[idx].get_type();
        cmd = &em_sap_agent_t::m_client_cmd_spec[idx];
    }

    cJSON_Delete(obj);

    if ((type == em_cmd_type_none) || (type >= em_cmd_type_max)) {
        printf("%s:%d: type invalid=%d\n", __func__, __LINE__,type);
        return NULL;
    }

    evt = (em_event_t *)malloc(sizeof(em_event_t));
    evt->type = em_event_type_bus;
    bevt = &evt->u.bevt;

    switch (type) {
        case em_cmd_type_dev_init:  
            bevt->type = em_bus_event_type_dev_init;
            break;

        case em_cmd_type_sta_list:
            bevt->type = em_bus_event_type_sta_list;
            break;

        case em_cmd_type_ap_cap_query:
            bevt->type = em_bus_event_type_ap_cap_query;
            break;

	    case em_cmd_type_client_cap_query:
	        bevt->type = em_bus_event_type_client_cap_query;
	        break;

        case em_cmd_type_cfg_renew:
            bevt->type = em_bus_event_type_cfg_renew;
            break;
       
         default:
            break;
    }

    memcpy(&bevt->params, &cmd->m_param, sizeof(em_cmd_params_t));
    memcpy(&bevt->u.subdoc.buff, buff, EM_SUBDOC_BUFF_SZ-1);
    bevt->u.subdoc.sz = strlen(buff);   
    return evt;
}

em_sap_agent_t::em_sap_agent_t(em_cmd_t& obj)
{
    memcpy(&m_cmd.m_param, &obj.m_param, sizeof(em_cmd_params_t));
}

em_sap_agent_t::em_sap_agent_t(em_cmd_type_t type)
{
    memcpy(&m_cmd.m_param, &em_sap_agent_t::m_client_cmd_spec[type].m_param, sizeof(em_cmd_params_t));
}

em_sap_agent_t::em_sap_agent_t()
{
    snprintf(m_sock_path, sizeof(m_sock_path), "%s_%s", EM_PATH_PREFIX, EM_AGENT_PATH);
}
