package com.iiti.analytics;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.iiti.reader.OfflinePacketReader;

public class Metrics {
	PrintWriter output;
	String fileName;
	HashSet<String> loginservers;

	void addLoginServers(int from, int to, String S, int efrom, int eto) {
		for (int i = from; i <= to; i++) {
			loginservers.add(S + i);
		}
		for (int i = efrom; i <= eto; i++) {
			loginservers.remove(S + i);
		}
	}

	public int getPayloadSize(JPacket p) {
		JBuffer buffer = p.getHeader(new Payload());
		return (buffer != null) ? buffer.size() : 0;
	}

	public int getPayloadSize(PcapPacket p) {
		JBuffer buffer = p.getHeader(new Payload());
		return (buffer != null) ? buffer.size() : 0;
	}

	public Metrics(String fileName) {
		loginservers = new HashSet<String>();
		this.fileName = fileName;
		try {
			output = new PrintWriter(new BufferedWriter(new FileWriter(
					new File(fileName))));
		} catch (IOException e) {
			e.printStackTrace();
		}
		addLoginServers(140, 166, "64.4.23.", 163, 164);
		addLoginServers(12, 38, "65.55.223.", 35, 36);
		addLoginServers(12, 38, "111.221.74.", 35, 36);
		addLoginServers(140, 166, "111.221.77.", 163, 164);
		addLoginServers(140, 166, "157.55.56.", 163, 164);
		addLoginServers(140, 166, "157.55.130.", 163, 164);
		addLoginServers(140, 166, "157.55.235.", 163, 164);
		addLoginServers(12, 38, "157.56.52.", 35, 36);
		addLoginServers(140, 166, "213.199.179.", 163, 164);
		for (String s : loginservers) {
			System.out.println(s);
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
		maxPacketSize = 100;// Math.min(maxPacketSize, 1500);
		int blockSize = 1;// (int) Math.ceil(maxPacketSize * 1.0 /
							// numberOfBlocks);
		int frequency[] = new int[numberOfBlocks + 1];
		Ip4 ip = new Ip4();
		// Tcp tcp = new Tcp();
		for (PcapPacket packet : packets) {
			if (packet.hasHeader(Ip4.ID) && packet.hasHeader(Udp.ID)) {
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
			if (packet.hasHeader(udp)) {
				++udpOccurence;
			}
		}
		double total = udpOccurence + tcpOccurence;
		output.println("************************************");
		output.println("Tcp Udp Ratio for file = \n");
		output.println(packetFileName);
		output.println("Tcp = " + tcpOccurence + "\t("
				+ (100.0 * tcpOccurence / total) + "%)");
		output.println("Ucp = " + udpOccurence + "\t("
				+ (100.0 * udpOccurence / total) + "%)");
		output.println("\n\n");
	}

	public void packetsPerFlow(String packetFileName) {
		output.println("************************************");
		output.println("packets Per Flow for file = \n");
		output.println(packetFileName);
		output.println("\n\n");

		System.out.println("\nprcoessing packets for flow\n" + packetFileName);
		List<PcapPacket> packets = (new OfflinePacketReader())
				.read(packetFileName);
		final Map<JFlowKey, JFlow> flows = new HashMap<JFlowKey, JFlow>();
		for (PcapPacket packet : packets) {
			if (!packet.hasHeader(Udp.ID) && !packet.hasHeader(Tcp.ID))
				continue;
			final JFlowKey key = packet.getState().getFlowKey();
			JFlow flow = flows.get(key);
			if (flow == null) {
				flows.put(key, flow = new JFlow(key));
			}
			flow.add(new PcapPacket(packet));
		}
		for (JFlow flow : flows.values()) {
			output.println("\nFlow = " + flow);

			if (flow.isReversable()) {
				List<JPacket> forward = flow.getForward();

				output.print("Forward: ");
				for (JPacket p : forward) {
					output.printf("%d, ", getPayloadSize(p));
				}
				output.println();
				output.print("Reverse: ");

				List<JPacket> reverse = flow.getReverse();
				for (JPacket p : reverse) {
					output.printf("%d, ", getPayloadSize(p));
				}
			} else {
				output.print("Irreversible: ");
				for (JPacket p : flow.getAll()) {
					output.printf("%d, ", getPayloadSize(p));
				}
			}
			output.println();
		}
	}

	public void specialUdpPacketLengths(String packetFileName) {
		output.println("************************************");
		output.println("Special udp packet lengths");
		output.println(packetFileName);
		output.println("\n\n");

		HashSet<Integer> special = new HashSet<Integer>();
		special.add(11);
		special.add(18);
		special.add(26);

		System.out.println("\nprcoessing packets for flow\n" + packetFileName);
		List<PcapPacket> packets = (new OfflinePacketReader())
				.read(packetFileName);
		int udp = 0;
		int occ = 0;
		for (int specialSize : special) {
			for (PcapPacket p : packets) {
				if (p.hasHeader(new Ip4()) && p.hasHeader(Udp.ID)) {
					++udp;
				}
				if ((p.hasHeader(Udp.ID)) && specialSize == getPayloadSize(p)) {
					// output.println(FormatUtils.ip(p.getHeader(new Ip4())
					// .source())
					// + " -> "
					// + FormatUtils.ip(p.getHeader(new Ip4())
					// .destination()));
					++occ;
				}
			}
		}
		output.println("total number of udp packets = " + udp);
		output.println("total number of special packets length = " + occ);
	}

	public int findAfter(int index, List<Integer> list, int find) {
		if (index < 0)
			return -10;
		for (int i = index; i < list.size(); ++i) {
			if (list.get(i) == find)
				return i;
		}
		return -10;
	}

	public void payloadLenth_Patterns(int maximumGap, String packetFileName,
			boolean checkFlowDirection, int... pattern) {
		output.println("************************************************************************");
		output.print("Pattern of Payload to search = ");
		for (int p : pattern)
			output.print(p + ", ");
		output.println();
		output.println("File name=\t" + packetFileName);
		System.out.println("\nPattern of Payload\n" + packetFileName);

		List<PcapPacket> packets = (new OfflinePacketReader())
				.read(packetFileName);
		List<Integer> payloads = new ArrayList<Integer>();
		List<Integer> lastPacketNumber = new ArrayList<Integer>();
		List<String> source = new ArrayList<String>();
		List<String> destination = new ArrayList<String>();
		HashSet<Integer> distinctOccurrences = new HashSet<Integer>();

		for (PcapPacket p : packets) {
			// if (p.hasHeader(Ip4.ID)
			// && (p.hasHeader(Tcp.ID) || p.hasHeader(Udp.ID))) {
			if (p.hasHeader(Tcp.ID)) {
				payloads.add(getPayloadSize(p));
				source.add(FormatUtils.ip(p.getHeader(new Ip4()).source()));
				destination.add(FormatUtils.ip(p.getHeader(new Ip4())
						.destination()));
			}
		}
		output.println("total number of packets = " + payloads.size());
		for (int i = 0; i < payloads.size();) {
			int last = i;
			List<Integer> matchingPackets = new ArrayList<Integer>();
			boolean valid = true;
			for (int j = 0; j < pattern.length; ++j) {
				int next = findAfter(last, payloads, Math.abs(pattern[j]));
				matchingPackets.add(next);
				last = next + 1;
			}

			int len = matchingPackets.size();
			if (matchingPackets.get(len - 1) < 0)
				break;
			i = matchingPackets.get(0) + 1;

			if (matchingPackets.get(len - 1) - matchingPackets.get(0) >= maximumGap)
				valid = false;
			for (int j = 1; valid && j < matchingPackets.size(); ++j) {
				int v = matchingPackets.get(j);
				int u = matchingPackets.get(j - 1);
				if (pattern[j] * pattern[j - 1] > 0) {
					// both same direction
					if (!source.get(u).equals(source.get(v))
							|| !destination.get(u).equals(destination.get(v))) {
						valid = false;
					}
				} else {
					// both different direction
					if (!source.get(u).equals(destination.get(v))
							|| !destination.get(u).equals(source.get(v))) {
						valid = false;
					}
				}
			}
			if (valid || !checkFlowDirection) {
				// for (int j = 0; j < matchingPackets.size(); ++j) {
				// output.print(matchingPackets.get(j) + "|");
				// }
				// output.println();
				int p = matchingPackets.get(matchingPackets.size() - 1);
				if (!distinctOccurrences.contains(p)) {
					lastPacketNumber.add(p);
					distinctOccurrences.add(p);
				}
			}
		}
		output.println("The pattern was found at followig intervals");
		for (int x : lastPacketNumber) {
			output.print(x + ", ");
		}
		output.println();
		output.println("Total Number of distinct Occurrences = "
				+ distinctOccurrences.size());
		output.println("\n\n");
	}

	public void skypepayload(String packetFileName) {
		System.out.println("\nprcoessing Transport Layer Headersfor\n"
				+ packetFileName);
		OfflinePacketReader offline = new OfflinePacketReader();

		output.println("************************************");
		output.println("UDP Payload Extraction = \n");
		output.println(packetFileName);
		byte[] dip = new byte[4];
		boolean thirdByte = false;
		List<PcapPacket> packets = offline.read(packetFileName);
		for (PcapPacket packet : packets) {
			if (packet.hasHeader(Udp.ID)) {
				JBuffer buffer = packet.getHeader(new Payload());
				if (buffer != null && buffer.size() > 2) {
					if (buffer.getByte(2) == 2) {
						thirdByte = true;
					}
				}
			}
			if (thirdByte && packet.hasHeader(Tcp.ID)) {
				dip = packet.getHeader(new Ip4()).destination();
				if (loginservers.contains(dip)) {
					output.println(FormatUtils.ip(dip) + "::"
							+ packet.getHeader(new Tcp()).source());
				}
			}
		}

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
