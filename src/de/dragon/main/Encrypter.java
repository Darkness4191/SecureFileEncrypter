package de.dragon.main;

import de.dragon.UsefulThings.console.Progressbar;
import de.dragon.UsefulThings.encryption.EncryptedOutputStream;
import de.dragon.UsefulThings.encryption.Hash;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.beans.Encoder;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class Encrypter {

    public Encrypter(File f, String password, boolean override) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        String enter = "" + ((char) 10);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);

        String encodedVersion = new String(Base64.getEncoder().encode(Hash.doHashSHA256(Main.VERSION_STRING)));
        String encodedSalt = new String(Base64.getEncoder().encode(salt));
        String encodediv = new String(Base64.getEncoder().encode(iv));
        String encodedInfo = new String(Base64.getEncoder().encode((encodedVersion + enter + encodediv + enter + encodedSalt).getBytes(StandardCharsets.UTF_8)));
        String passwordHash = new String(Base64.getEncoder().encode(Hash.doHashSHA256(password, salt)));

        byte[] key = Hash.doHashPBKDF2(password, salt);

        File output = new File(f.getAbsoluteFile().getParentFile().getAbsolutePath() + File.separator + f.getName().split("[.]")[0].replace(" ", "_") + ".SFE");
        while(output.exists() && !override) {
            Scanner scan = new Scanner(System.in);
            System.out.print(String.format("File %s already exists, do you want to override it? (y/n): ", output.getAbsolutePath()));
            String ans = scan.next();
            if(ans.equals("y")) {
                output.createNewFile();
                scan.close();
                break;
            } else if(ans.equals("n")) {
                scan.close();
                return;
            }
            scan.close();
        }

        FileOutputStream stream = new FileOutputStream(output);
        OutputStreamWriter writer1 = new OutputStreamWriter(stream, "ISO-8859-1");
        writer1.write(encodedInfo + enter);
        writer1.flush();

        EncryptedOutputStream writer = new EncryptedOutputStream(stream, key, iv);
        InputStreamReader reader = new InputStreamReader(new FileInputStream(f), StandardCharsets.ISO_8859_1);
        writer.write(passwordHash + enter);
        writer.write(f.getName() + enter);

        Progressbar bar = new Progressbar(System.out, true);

        long size = f.length();
        char[] buffer = new char[16 * 1024];
        int s = 0;
        int rounds = 0;
        while((s = reader.read(buffer)) > 0) {
            bar.update((rounds * buffer.length * 1D + s) / size);
            writer.write(buffer, 0, s);
            writer.flushNoPadding();
            rounds++;
        }

        bar.finish();

        writer.flush();
        writer.close();
        writer1.close();
        reader.close();

        System.out.println("File encrypted!");
    }

}
