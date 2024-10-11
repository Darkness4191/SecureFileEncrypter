package de.dragon.main.encryption;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

/**
 * @author Dragon777 / Darkness4191
 * @version 10.0
 */

public class EncryptedOutputStream extends OutputStream {

	private OutputStreamWriter output;
	private Cipher cipher;
	private ArrayList<Character> buffer;

	public EncryptedOutputStream(OutputStream output, byte[] key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		SecretKeySpec seckey = new SecretKeySpec(key, 0, key.length, "AES");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		this.cipher.init(Cipher.ENCRYPT_MODE, seckey, ivSpec);
		this.output = new OutputStreamWriter(new CipherOutputStream(output, cipher), StandardCharsets.ISO_8859_1);
		this.buffer = new ArrayList<>();
	}

	@Override
	public void write(byte[] b) throws IOException {
		write(b, 0, b.length);
	}

	@Override
	public void write(byte[] b, int offset, int length) throws IOException {
		for(int i = offset; i < length; i++) {
			buffer.add((char) b[i]);
		}
	}

	@Override
	public void write(int b) throws IOException {
		buffer.add((char) b);
	}

	public void write(String s) throws IOException, InvalidKeyException {
		this.write(s.toCharArray());
	}

	public void write(char[] chars, int offset, int length) throws IOException {
		for(int i = offset; i < length; i++) {
			buffer.add(chars[i]);
		}
	}

	public void write(char[] chars) throws IOException {
		this.write(chars, 0, chars.length);
	}

	@Override
	public void flush() throws IOException {
		try {
			char[] charBuffer = new char[cipher.getBlockSize()];
			charBuffer = flushFitting(charBuffer);

			output.write(charBuffer);

			output.flush();
			buffer.clear();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	public void flushNoPadding() throws IOException {
		try {
			char[] charBuffer = new char[cipher.getBlockSize()];
			charBuffer = flushFitting(charBuffer);
			buffer = new ArrayList<>(charBuffer.length);

			for(char c : charBuffer) {
				buffer.add(c);
			}

			output.flush();
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	private char[] flushFitting(char[] chars) throws IllegalBlockSizeException, BadPaddingException, IOException {
		int j = 0;
		for(int i = 0; i < buffer.size(); i++, j++) {
			if(i != 0 && i % cipher.getBlockSize() * 1D == 0) {
				output.write(chars);
				chars = new char[cipher.getBlockSize()];
				j = 0;
			}
			chars[j] = buffer.get(i);
		}

		char[] r = new char[j];
		for(int i = 0; i < j; i++) {
			r[i] = chars[i];
		}
		return r;
	}

	@Override
	public void close() throws IOException {
		output.close();
	}
}
