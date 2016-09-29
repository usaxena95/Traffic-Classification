package com.iiti.reader;

import java.util.HashMap;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;

public class OfflinePacketReader {
	static HashMap<String, List<PcapPacket>> cache = new HashMap<String, List<PcapPacket>>();

	public List<PcapPacket> read(final String captureFile, final int maxPackets) {

		if (cache.containsKey(captureFile)) {
			System.out.println("Pcap cache HIT for file " + captureFile);
			return cache.get(captureFile);
		}
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(captureFile, errbuf);
		if (pcap == null) {
			System.err.printf("Error while opening file: " + errbuf.toString());
			return null;
		}
		PacketHandler<String> packetHandler = new PacketHandler<String>();
		pcap.loop(maxPackets, packetHandler, "jNetPcap");
		pcap.close();

		cache.put(captureFile, packetHandler.getPackets());
		System.out.println("Pcap cache MISS");
		return packetHandler.getPackets();
	}

	public List<PcapPacket> read(final String captureFile) {
		return read(captureFile, 50000);
	}
}