package de.dragon.main.encryption;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Dragon777 / Darkness4191
 * @version 10.0
 */

public class DecryptedInputStream extends InputStream {

    private InputStreamReader input;
    private CharBuffer buffer;
    private Cipher cipher;

    public DecryptedInputStream(InputStream input, byte[] key, byte[] iv) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        SecretKeySpec seckey = new SecretKeySpec(key, 0, key.length, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        this.cipher.init(Cipher.DECRYPT_MODE, seckey, ivSpec);
        this.input = new InputStreamReader(new CipherInputStream(input, cipher), StandardCharsets.ISO_8859_1);
    }

    @Override
    public int read() throws IOException {
        return input.read();
    }

    public boolean hasRemaining() throws IOException {
        return buffer != null && buffer.hasRemaining() || input.ready();
    }

    public int read(char[] array) throws IOException {
        return input.read(array);
    }
}
