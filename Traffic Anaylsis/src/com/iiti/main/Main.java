package com.iiti.main;

import java.io.IOException;
import java.util.List;

import com.iiti.analytics.Metrics;
import com.iiti.utils.ReadAllFileName;

public class Main {
	public static List<String> packetFiles;
	static {
		System.out.println("Analysis begins here");
		packetFiles = (new ReadAllFileName()).getAllFileName();
	}

	public static void packetLength_Vs_Frequency() {
		Metrics metric = new Metrics("Packet LengthVs Frequency.txt");
		for (String packetFile : packetFiles) {
			metric.packetLenthVsFrequency(packetFile, 110);
		}
		metric.close();
	}

	public static void Transport_Layer_Header_Ratio() {
		Metrics metric = new Metrics("Transport Layer Header Ratio.txt");
		for (String packetFile : packetFiles) {
			metric.ratioTransportLayerHeader(packetFile);
		}
		metric.close();
	}

	public static void udp_payload() {
		Metrics metric = new Metrics("udp payload.txt");
		for (String packetFile : packetFiles) {
			metric.skypepayload(packetFile);
		}
		metric.close();
	}

	public static void packet_per_flow() {
		Metrics metric = new Metrics("packet per flow.txt");
		for (String packetFile : packetFiles) {
			metric.packetsPerFlow(packetFile);
		}
		metric.close();
	}

	public static void Payloads_of_Special_packet_length() {
		Metrics metric = new Metrics("Payloads of Special packet length.txt");
		for (String packetFile : packetFiles) {
			metric.specialUdpPacketLengths(packetFile);
		}
		metric.close();
	}

	public static void PayloadLenth_Patterns() {
		Metrics metric = new Metrics("Sequences of Payload lenght.txt");
		for (String packetFile : packetFiles) {
			metric.payloadLenth_Patterns(40, packetFile, true, 3, 10, -4, -2);
		}
		for (String packetFile : packetFiles) {
			metric.payloadLenth_Patterns(40, packetFile, true, 5, -5);
		}
		for (String packetFile : packetFiles) {
			metric.payloadLenth_Patterns(40, packetFile, true, 4, 104, -4, -12, 4, 272);
		}
		for (String packetFile : packetFiles) {
			metric.payloadLenth_Patterns(150, packetFile, true, 41, -3, -144, 4);
		}
		metric.close();
	}

	public static void main(String[] args) throws IOException {
		PayloadLenth_Patterns();
	//	Payloads_of_Special_packet_length();
	}
}