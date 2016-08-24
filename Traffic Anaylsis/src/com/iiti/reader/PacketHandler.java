package com.iiti.reader;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class PacketHandler<T> implements PcapPacketHandler<T>{

	private List<PcapPacket> packets = new ArrayList<PcapPacket>();
	public List<PcapPacket> getPackets(){
		return packets;
	}
	@Override
	public void nextPacket(PcapPacket packet, T arg1) {
		packets.add(packet);		
	}
}