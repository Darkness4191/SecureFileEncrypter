package de.dragon.main.encryption;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author Dragon777 / Darkness4191
 * @version 10.0
 */

public class Hash {

    public static byte[] doHashPBKDF2(String s) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        KeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        return factory.generateSecret(spec).getEncoded();
    }

    public static byte[] doHashPBKDF2(String s, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        return factory.generateSecret(spec).getEncoded();
    }

    public static byte[] doHashSHA256(String s) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] doHashSHA128(String s) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return MessageDigest.getInstance("SHA-1").digest(s.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] doHashSHA256(String s, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(salt);
        return digest.digest(s.getBytes(StandardCharsets.UTF_8));
    }

}
