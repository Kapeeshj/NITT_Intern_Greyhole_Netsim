

/****************************************************
         This file contains code for generation of Malicious Node(GreyHole) for networks running AODV in Layer3.
		 This works only for UDP and not for TCP.
		 
		 
		 The function fn_NetSim_AODV_MaliciousNode(NetSim_EVENTDETAILS*) 
		 return 1 when the deviceID is the malicious node which is mentioned in the if statement in the function definition.

		 
		 The function fn_NetSim_AODV_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*)
		 adds the target address of the AODV RREQ it receives to its route cache so as to create a false route from 
		 the Source node to target node


		 The function fn_NetSim_AODV_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*)
		 Process the Data Packet received by the Malicious Node. It does not call the NetworkOut Event and destroys 
		 the packet, thus giving false acknowledge replies.

		 Code Flow - 
		 If The Node is a Malicious Node, Then when a Route Request is Received, the Function adds the route from itself 
		 to the target in the route cache and sends a false route reply.
		 When a malicious node receives a data packet, it gives acknowledge reply and frees the packet.
		  
		 


*****************************************************/


	/* Malicious Node */


#include "main.h"
#include "AODV.h"
#include "List.h"
#define MALICIOUS_NODE1 4

int fn_NetSim_AODV_MaliciousNode(NetSim_EVENTDETAILS* );
int fn_NetSim_AODV_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*);
int fn_NetSim_AODV_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*);


#define GREYHOLE_NODE_ID 4  // Change this to your malicious node ID
#define DROP_PROBABILITY 0.5  // 50% chance to drop a data packet

int fn_NetSim_AODV_IsGreyholeNode(NetSim_EVENTDETAILS* pstruEventDetails)
{
    return pstruEventDetails->nDeviceId == GREYHOLE_NODE_ID;
}

// Called during data packet processing
int fn_NetSim_AODV_GreyholeHandleData(NetSim_EVENTDETAILS* pstruEventDetails)
{
    if (!fn_NetSim_AODV_IsGreyholeNode(pstruEventDetails)) return 0;

    if (pstruEventDetails->pPacket->nPacketType == PacketType_App)
    {
        double r = (double)rand() / RAND_MAX; // Random value between 0 and 1

        if (r < DROP_PROBABILITY)
        {
            // Drop the packet
            AODV_DEV_VAR(pstruEventDetails->nDeviceId)->aodvMetrics.packetDropped++;
            fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
            return 1;
        }
        else
        {
            // Forward the packet normally
            return 0;
        }
    }

    return 0;
}
