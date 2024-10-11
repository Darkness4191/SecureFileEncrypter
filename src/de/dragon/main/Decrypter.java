package de.dragon.main;

import de.dragon.main.encryption.DecryptedInputStream;
import de.dragon.main.encryption.Hash;
import de.dragon.main.ui.Progressbar;

import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class Decrypter {

    public Decrypter(File f, String password, boolean override) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InterruptedException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        String enter = "" + ((char) 10);

        InputStreamReader reader = new InputStreamReader(new FileInputStream(f), "ISO-8859-1");
        String meta = Main.readNextInfo(reader);
        String[] decodedMeta = new String(Base64.getDecoder().decode(meta)).split(enter);
        String version = decodedMeta[0];
        String iv = decodedMeta[1];
        String salt = decodedMeta[2];

        if(!version.equals(new String(Base64.getEncoder().encode(Hash.doHashSHA256(Main.VERSION_STRING))))) {
            System.out.println("Can't complete: The file has been encrypted with another version of SFE!");
            return;
        }

        byte[] decodedSalt = Base64.getDecoder().decode(salt);
        byte[] decodediv = Base64.getDecoder().decode(iv);
        byte[] key = Hash.doHashPBKDF2(password, decodedSalt);

        FileInputStream stream = new FileInputStream(f);
        stream.skip(meta.length() + 1 * enter.length());
        DecryptedInputStream inputStream = new DecryptedInputStream(stream, key, decodediv);
        String pass = Main.readNextInfo(inputStream);
        String filename = Main.readNextInfo(inputStream);

        String passwordHash = new String(Base64.getEncoder().encode(Hash.doHashSHA256(password, decodedSalt)));

        if(!pass.equals(passwordHash)) {
            System.out.println("Wrong password!");
            return;
        }

        File output = new File(f.getAbsoluteFile().getParentFile().getAbsolutePath() + File.separator + filename);

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

        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(output), StandardCharsets.ISO_8859_1);
        Progressbar bar = new Progressbar(System.out, true);

        long size = f.length();
        char[] buffer = new char[512];
        int s = 0;
        int rounds = 0;
        while((s = inputStream.read(buffer)) > 0) {
            bar.update((rounds * buffer.length * 1D + s) / size);
            writer.write(buffer, 0, s);
            writer.flush();
            rounds++;
        }

        bar.finish();
        writer.flush();
        writer.close();
        inputStream.close();
        reader.close();

        System.out.println("File decrypted!");
    }

}
