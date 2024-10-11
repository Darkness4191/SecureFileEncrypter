package de.dragon.main;

import de.dragon.UsefulThings.console.Progressbar;
import de.dragon.UsefulThings.encryption.DecryptedInputStream;
import de.dragon.UsefulThings.encryption.Hash;
import de.dragon.UsefulThings.ut;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Scanner;

public class Name {

    public Name(File f) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InterruptedException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        String enter = "" + ((char) 10);

        System.out.print("Password for file: ");
        String password = new String(System.console().readPassword());

        InputStreamReader reader = new InputStreamReader(new FileInputStream(f), "ISO-8859-1");
        String meta = ut.readNextInfo(reader);
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
        byte[] key = new Hash().doHashSHA256(password, decodedSalt);

        FileInputStream stream = new FileInputStream(f);
        stream.skip(meta.length() + 1 * enter.length());
        DecryptedInputStream inputStream = new DecryptedInputStream(stream, key, decodediv);
        String pass = ut.readNextInfo(inputStream);
        String filename = ut.readNextInfo(inputStream);
        String passwordHash = new String(Base64.getEncoder().encode(new Hash().doHashPBKDF2(password, decodedSalt)));

        if(!pass.equals(passwordHash)) {
            System.out.println("Wrong password!");
            return;
        }

        System.out.println("File was once named: " + filename);

        inputStream.close();
        reader.close();
    }

}
