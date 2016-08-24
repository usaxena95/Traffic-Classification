package com.iiti.main;

import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;

import com.iiti.reader.PacketOffline;

public class Main {
	public static void main(String[] args) {
		PacketOffline offline = new PacketOffline();
		List<PcapPacket> packets= offline.read("random_test_for_java.pcapng");
		
		Ip4 ip = new Ip4();
		for(PcapPacket packet:packets){
			if (packet.hasHeader(Ip4.ID)) {
				packet.getHeader(ip);
				String sourceIP = FormatUtils.ip(packet.getHeader(ip).source());
				String destinationIP = FormatUtils.ip(packet.getHeader(ip).destination());

				System.out.println(" srcIP=" + sourceIP + "\tdstIP="
						+ destinationIP + "\tcaplen="
						+ packet.getCaptureHeader().caplen());
			}
		}
		System.out.println(packets.size());
	}
}