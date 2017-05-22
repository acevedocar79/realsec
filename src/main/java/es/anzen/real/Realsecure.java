/*
 * Copyright (c) 2017 Anzen Soluciones S.A. de C.V. Mexico D.F. All rights reserved. THIS
 * SOFTWARE IS CONFIDENTIAL INFORMATION PROPIETARY OF ANZEN SOLUCIONES. THIS INFORMATION
 * SHOULD NOT BE DISCLOSED AND MAY ONLY BE USED IN ACCORDANCE THE TERMS DETERMINED BY THE
 * COMPANY ITSELF.
 */
package es.anzen.real;

import java.io.IOException;
import java.net.SocketException;
import java.util.Arrays;

/**
 * <p>
 * </p>
 * 
 * @author acevedito 
 * @version real 
 * @since real 
 * @category
 */
public class Realsecure {
	public final int SINGLE_DES = 16;
	public final int DOUBLE_DES = 32;
	public final int TRIPLE_DES = 48;
//	private final int DES_DATABLOCK = 8;
	private final char[] HEX_CHARS = "0123456789ABCDEF".toCharArray();
	public final int CBC = 0;
	public final int ECB = 1;
	public final int ENCRYPT = 1;
	public final int DECRYPT = 0;
	String server;
	int port = 0;
	int headerLen = 3;
	private CryptosecLANService service;

	private String UcharToAscii(byte[] buf) {
		if (buf == null) {
			return null;
		}
		char[] chars = new char[2 * buf.length];
		for (int i = 0; i < buf.length; i++) {
			chars[(2 * i)] = HEX_CHARS[((buf[i] & 0xF0) >>> 4)];
			chars[(2 * i + 1)] = HEX_CHARS[(buf[i] & 0xF)];
		}
		return new String(chars);
	}

	private static byte[] AsciiToChar(String In) {
		int n = 0;
		char aux = '\000';
		int i = 0;
		int j = 0;

		byte[] output = new byte[In.length() / 2];

		n = 0;
		for (j = 0; n < In.length(); j++) {
			output[j] = 0;

			for (i = 0; i < 2; i++) {
				int tmp42_40 = j;
				byte[] tmp42_38 = output;
				tmp42_38[tmp42_40] = ((byte) (tmp42_38[tmp42_40] << 4));
				aux = In.charAt(n + i);
				aux = (char) (aux < 'A' ? aux - '0' : aux - '7');
				output[j] = ((byte) (aux & 0xF | output[j]));
			}
			n += 2;
		}

		return output;
	}

	public Realsecure(String server, int port, int headerLen) {
		this.server = server;
		this.port = port;
		this.headerLen = headerLen;
	}

	public void OpenConnectionCLAN() throws SocketException, IOException {
		service = new CryptosecLANService(server, port, headerLen);
	}

	public void CloseConnectionCLAN() throws IOException {
		service.CloseConnection();
	}

	public byte[] protectPassword(String key, String kcv, String password) throws CryptosecLANException, IOException {
		return protectPassword(key, kcv, password.getBytes());
	}

	public byte[] protectPassword(String key, String kcv, byte[] password) throws CryptosecLANException, IOException {
		String localCommand = null;
		byte[] localResponse = null;

		if ((key.length() != 16) && (key.length() != 32) && (key.length() != 48)) {
			throw new CryptosecLANException("Error 0x60000000. Invalid Key Length.");
		}
		if (password.length == 0) {
			throw new CryptosecLANException("Error 0x60000002. The current password is empty.");
		}

		localCommand = "0904";
		localCommand = localCommand + "D00" + key.length() + key + "L17";

		if ((kcv == null) || (kcv.length() == 0)) {
			localCommand = localCommand + "00";
		} else {
			localCommand = localCommand + "06" + kcv;
		}

		localCommand = localCommand + "H" + new StringBuilder("0000").append(Integer.toString(password.length * 2, 10))
				.toString().substring(Integer.toString(password.length * 2, 10).length());

		localCommand = localCommand + UcharToAscii(password);

		System.out.println("protectPassword: " + Thread.currentThread().getName());
		service.commandExecution(localCommand);
		localResponse = service.getResponse();

		if (localResponse != null) {
			return AsciiToChar(new String(Arrays.copyOfRange(localResponse, 4, localResponse.length)));
		}
		return null;
	}

	public int verifyPassword(String key, String kcv, String passwordToVerify, String currentPassword)
			throws CryptosecLANException, IOException {
		return verifyPassword(key, kcv, passwordToVerify.getBytes(), currentPassword);
	}

	public int verifyPassword(String key, String kcv, byte[] passwordToVerify, String currentPassword)
			throws CryptosecLANException, IOException {
		String localCommand = null;
		byte[] localResponse = null;

		if ((key.length() != 16) && (key.length() != 32) && (key.length() != 48)) {
			throw new CryptosecLANException("Error 0x60000000. Invalid Key Length.");
		}
		if (passwordToVerify.length == 0) {
			throw new CryptosecLANException("Error 0x60000001. The password to be verified is empty.");
		}
		if (currentPassword.length() == 0) {
			throw new CryptosecLANException("Error 0x60000002. The current password is empty.");
		}

		localCommand = "0905";
		localCommand = localCommand + "D00" + key.length() + key + "L17";

		if (kcv.length() != 0) {
			localCommand = localCommand + "06" + kcv;
		} else {
			localCommand = localCommand + "00";
		}

		localCommand = localCommand + "H"
				+ new StringBuilder("0000").append(Integer.toString(currentPassword.length() * 2, 10)).toString()
						.substring(Integer.toString(currentPassword.length() * 2, 10).length());

		localCommand = localCommand + UcharToAscii(currentPassword.getBytes());

		localCommand = localCommand + "01";

		localCommand = localCommand
				+ new StringBuilder("0000").append(Integer.toString(passwordToVerify.length * 2, 10)).toString()
						.substring(Integer.toString(passwordToVerify.length * 2, 10).length());

		localCommand = localCommand + UcharToAscii(passwordToVerify);

		service.commandExecution(localCommand);
		localResponse = service.getResponse();

		if (localResponse != null) {
			return Arrays.equals(localResponse, "1".getBytes()) ? 1 : 0;
		}
		return -1;
	}

	private byte[] CryptoProcess(String key, String kcv, int direction, int mode, byte[] initVector, byte[] data)
			throws CryptosecLANException, IOException {
		String localCommand = null;
		byte[] localResponse = null;

		if ((key.length() != 16) && (key.length() != 32) && (key.length() != 48)) {
			throw new CryptosecLANException("Error 0x60000006. Invalid Key Length.");
		}

		if (data.length % 8 != 0) {
			throw new CryptosecLANException("Error 0x60000010. Wrong data length.");
		}

		if (mode > 1) {
			throw new CryptosecLANException("Error 0x60000003. Invalid mode.");
		}

		if (mode == 0) {
			if ((initVector == null) || (initVector.length != 8)) {
				throw new CryptosecLANException("Error 0x60000008. Invalid initialization vector.");
			}
		}

		localCommand = "0903";

		localCommand = localCommand + "D00" + key.length() + key + "L07";

		if ((kcv != null) && (kcv.length() != 0)) {
			localCommand = localCommand + "06" + kcv;
		} else {
			localCommand = localCommand + "00";
		}

		if (direction == 1) {
			localCommand = localCommand + "1";
		} else {
			localCommand = localCommand + "0";
		}

		localCommand = localCommand + mode;

		if (mode == 0) {
			localCommand = localCommand + UcharToAscii(initVector);
		}

		localCommand = localCommand + new StringBuilder("000000").append(Integer.toString(data.length * 2, 10))
				.toString().substring(Integer.toString(data.length * 2, 10).length());

		localCommand = localCommand + UcharToAscii(data);

		service.commandExecution(localCommand);
		localResponse = service.getResponse();

		return AsciiToChar(new String(Arrays.copyOfRange(localResponse, 6, localResponse.length)));
	}

	public byte[] EncryptData(String key, String kcv, int mode, byte[] initVector, String sensitiveData)
			throws CryptosecLANException, IOException {
		return EncryptData(key, kcv, mode, initVector, sensitiveData.getBytes());
	}

	public byte[] EncryptData(String key, String kcv, int mode, byte[] initVector, byte[] sensitiveData)
			throws CryptosecLANException, IOException {
		return CryptoProcess(key, kcv, 1, mode, initVector, sensitiveData);
	}

	public byte[] DecryptData(String key, String kcv, int mode, byte[] initVector, byte[] encryptedData)
			throws CryptosecLANException, IOException {
		return CryptoProcess(key, kcv, 0, mode, initVector, encryptedData);
	}
}
