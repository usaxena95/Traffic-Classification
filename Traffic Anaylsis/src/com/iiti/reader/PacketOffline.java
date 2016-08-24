package com.iiti.reader;

import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;

public class PacketOffline {
	public List<PcapPacket> read(final String captureFile, final int maxPackets) {
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(captureFile, errbuf);
		if (pcap == null) {
			System.err.printf("Error while opening file: " + errbuf.toString());
			return null;
		}
		PacketHandler<String> packetHandler = new PacketHandler<String>();
		pcap.loop(maxPackets, packetHandler, "jNetPcap");
		pcap.close();
		return packetHandler.getPackets();
	}

	public List<PcapPacket> read(final String captureFile) {
		return read(captureFile, 1000000000);
	}
}
