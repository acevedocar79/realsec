/*
 * Copyright (c) 2017 Anzen Soluciones S.A. de C.V. Mexico D.F. All rights reserved. THIS
 * SOFTWARE IS CONFIDENTIAL INFORMATION PROPIETARY OF ANZEN SOLUCIONES. THIS INFORMATION
 * SHOULD NOT BE DISCLOSED AND MAY ONLY BE USED IN ACCORDANCE THE TERMS DETERMINED BY THE
 * COMPANY ITSELF.
 */
package es.anzen.real;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Random;

import javax.net.SocketFactory;

/**
 * <p>
 * TODO [Add comments of the class]
 * </p>
 * @author acevedito @version real @since real @category
 */
public class CryptosecLANService {
	private String servidorIP;
	private int port = 0;
	private Socket ClientSk;
	private byte[] response;
	private int headerLen = 0;

	public byte[] getResponse() {
		return response;
	}

	public CryptosecLANService(String server, int port, int headerLen) throws SocketException, IOException {
		servidorIP = server;
		this.port = port;
		this.headerLen = headerLen;

		OpenConnection();
	}

	private void OpenConnection() throws SocketException, IOException {
		SocketFactory socketFactory = SocketFactory.getDefault();

		ClientSk = socketFactory.createSocket(servidorIP, port);
		ClientSk.setSoTimeout(80000);
	}

	public void CloseConnection() throws IOException {
		ClientSk.close();
	}

	public void commandExecution(String command) throws IOException, CryptosecLANException {
		String auxStrLen = null;
		String alphabet = new String("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
		int n = alphabet.length();
		String header = new String();
		Random r = new Random();

		if ((command == null) || (command.length() < 4)) {
			throw new CryptosecLANException("20000000");
		}

		response = null;

		for (int i = 0; i < headerLen; i++) {
			header = header + alphabet.charAt(r.nextInt(n));
		}
		auxStrLen = Integer.toString((header + command).length(), 10);
		auxStrLen = ("000000" + auxStrLen).substring(auxStrLen.length());

		sendCommand(auxStrLen + header + command);
		recvResponse();
	}

	private void sendCommand(String command) throws IOException {
		DataOutputStream dataoutputstream = new DataOutputStream(ClientSk.getOutputStream());
		dataoutputstream.write(command.getBytes());
	}

	private void recvResponse() throws IOException, CryptosecLANException {
		byte[] length = new byte[6];
		byte[] bresponse = null;
		String slenresponse = null;
		int retbytes = 0;
		int auxbytes = 0;

		DataInputStream commandresponse;

		commandresponse = new DataInputStream(ClientSk.getInputStream());
		commandresponse.read(length, 0, 6);
		slenresponse = new String(length);

		int responseLength = Integer.parseInt(slenresponse);
		bresponse = new byte[responseLength];

		response = new byte[responseLength + 6];

		while (auxbytes != responseLength) {
			retbytes = commandresponse.read(bresponse, auxbytes, responseLength - auxbytes);
			if (retbytes == -1) {
				throw new CryptosecLANException("50000000");
			}
			auxbytes += retbytes;
		}

		System.arraycopy(length, 0, response, 0, length.length);
		System.arraycopy(bresponse, 0, response, length.length, bresponse.length);

		parseResponse();
	}

	private void parseResponse() throws CryptosecLANException {
		int responseLen = response.length;
		byte[] localerror = null;
		byte[] noerror = { 48, 48, 48, 48, 48, 48, 48, 48 };

		if (responseLen < 6 + headerLen + 4 + 8) {
			throw new CryptosecLANException("10000000");
		}

		localerror = Arrays.copyOfRange(response, 6 + headerLen + 4, 6 + headerLen + 4 + 8);

		System.out.println("Antes del error");
		System.out.println(Thread.currentThread().getName());

		if (!Arrays.equals(noerror, localerror)) {
			throw new CryptosecLANException(new String(localerror));
		}

		response = Arrays.copyOfRange(response, 6 + headerLen + 4 + 8, response.length);
	}
}
