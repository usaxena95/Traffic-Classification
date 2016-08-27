package com.iiti.analytics;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.iiti.reader.OfflinePacketReader;

public class Metrics {
	PrintWriter output;
	String fileName;
	public Metrics(String fileName) {
		this.fileName = fileName;
		try {
			output = new PrintWriter(new BufferedWriter(new FileWriter(
					new File(fileName))));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private String stars(double f) {
		int y = (int) (f * 50);
		String star = "";
		for (int i = 0; i < y; ++i) {
			star += "*";
		}
		int percent = (int) (f * 100);
		return percent + "%\t" + star;
	}

	void display(int[] frequency, String packetFileName, int blockSize) {
		int maxFrequency = 0;
		int totalPackets = 0;
		for (int i = 0; i < frequency.length; ++i) {
			maxFrequency = Math.max(maxFrequency, frequency[i]);
			totalPackets += frequency[i];
		}
		output.println("\n\n-----------------------------\n"
				+ "Results for File = \n" + packetFileName);
		for (int i = 0; i < frequency.length; ++i) {
			output.println("" + i * blockSize + "-"
					+ (i * blockSize + blockSize - 1) + "\t"
					+ stars(frequency[i] * 1.0 / totalPackets));
		}
	}

	public void packetLenthVsFrequency(String packetFileName, int numberOfBlocks) {
		System.out.println("\nprcoessing pac len frequency\n" + packetFileName);
		OfflinePacketReader offline = new OfflinePacketReader();

		List<PcapPacket> packets = offline.read(packetFileName);
		int maxPacketSize = 0;
		for (PcapPacket packet : packets) {
			maxPacketSize = Math.max(maxPacketSize, packet.getCaptureHeader()
					.caplen());
		}
		maxPacketSize = Math.min(maxPacketSize, 1500);
		int blockSize = (int) Math.ceil(maxPacketSize * 1.0 / numberOfBlocks);
		int frequency[] = new int[numberOfBlocks + 1];
		Ip4 ip = new Ip4();
		for (PcapPacket packet : packets) {
			if (packet.hasHeader(Ip4.ID)) {
				packet.getHeader(ip);
				int caplen = packet.getCaptureHeader().caplen();
				if (caplen <= maxPacketSize)
					frequency[caplen / blockSize]++;
			}
		}
		display(frequency, packetFileName, blockSize);
	}

	public void ratioTransportLayerHeader(String packetFileName) {
		System.out.println("\nprcoessing Transport Layer Headersfor\n"
				+ packetFileName);
		OfflinePacketReader offline = new OfflinePacketReader();

		List<PcapPacket> packets = offline.read(packetFileName);
		Tcp tcp = new Tcp();
		Udp udp = new Udp();
		int tcpOccurence = 0;
		int udpOccurence = 0;
		for (PcapPacket packet : packets) {
			if (packet.hasHeader(tcp)) {
				++tcpOccurence;
			}
			if(packet.hasHeader(udp)){
				++udpOccurence;
			}
		}
		double total = udpOccurence + tcpOccurence;
		output.println("************************************");
		output.println("Tcp Udp Ratio for file = \n");
		output.println(packetFileName);
		output.println("Tcp = " + tcpOccurence + "\t(" + (100.0 * tcpOccurence/total)+"%)");
		output.println("Ucp = " + udpOccurence + "\t(" + (100.0 * udpOccurence/total)+"%)");
		output.println("\n\n");
	}

	void somethin() {

		String packetFileName = "";
		OfflinePacketReader offline = new OfflinePacketReader();
		List<PcapPacket> packets = offline.read(packetFileName);
		Ip4 ip = new Ip4();
		for (PcapPacket packet : packets) {
			String sourceIP = FormatUtils.ip(packet.getHeader(ip).source());
			String destinationIP = FormatUtils.ip(packet.getHeader(ip)
					.destination());

			System.out.println(" srcIP=" + sourceIP + "\tdstIP="
					+ destinationIP + "\tcaplen="
					+ packet.getCaptureHeader().caplen());
		}
	}

	public void close() {
		System.out.println(fileName + " done");
		output.close();
	}
}
