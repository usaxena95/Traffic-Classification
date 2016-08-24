package com.iiti.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class ReadAllFileName {
	private List<String> packetFileNames = new ArrayList<String>();

	private void dfs(String currentDirectory) {
		String result = null;
		try {
			Process p = Runtime.getRuntime().exec("ls " + currentDirectory);

			BufferedReader stdInput = new BufferedReader(new InputStreamReader(
					p.getInputStream()));

			BufferedReader stdError = new BufferedReader(new InputStreamReader(
					p.getErrorStream()));

			while ((result = stdInput.readLine()) != null) {
				if (result.toLowerCase().contains("pcap")) {
					packetFileNames.add(currentDirectory + result);
				} else {
					dfs(currentDirectory + result + "/");
				}
			}
			while ((result = stdError.readLine()) != null) {
				System.out.println(result);
			}
		} catch (IOException e) {
			System.out.println("Excepción some: ");
			e.printStackTrace();
			System.exit(-1);
		}
	}

	public ReadAllFileName() {
		dfs("packets/");
	}
	public List<String> getAllFileName(){
		return packetFileNames;
	}
}
