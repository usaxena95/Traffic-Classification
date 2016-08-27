package com.iiti.main;

import java.io.IOException;
import java.util.List;

import com.iiti.analytics.Metrics;
import com.iiti.utils.ReadAllFileName;

public class Main {
	public static void main(String[] args) throws IOException {
		System.out.println("Analysis begins here");
		List<String> packetFiles = (new ReadAllFileName()).getAllFileName();
		Metrics metric = new Metrics("Packet Length.txt");
		for (String packetFile : packetFiles) {
			metric.packetLenthVsFrequency(packetFile,35);
		}
		metric.close();
		metric = new Metrics("Transport Layer Header Ratio.txt");
		for (String packetFile : packetFiles) {
			metric.ratioTransportLayerHeader(packetFile);
		}
		metric.close();
	}
}