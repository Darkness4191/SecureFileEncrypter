package de.dragon.main;

import de.dragon.main.encryption.DecryptedInputStream;
import de.dragon.main.encryption.Hash;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Base64;

public class Main {

    public static final String VERSION_STRING = "v3";

    public static void main(String[] args) {
        try {
            new Main(args);
        } catch (Exception e) {
            System.out.println("Error: " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    public Main(String[] args) throws Exception {
        if(args.length > 0) {
            String cmd = args[0];
            if(cmd.equals("--encrypt") || cmd.equals("-e")) {
                String filename = args[1];

                System.out.print("Password for file: ");
                String password = new String(System.console().readPassword());
                System.out.print("Retype password: ");
                String passwordre = new String(System.console().readPassword());
                String passwordHash = new String(Base64.getEncoder().encode(Hash.doHashSHA256(password)));
                String passwordHashre = new String(Base64.getEncoder().encode(Hash.doHashSHA256(passwordre)));
                if(!passwordHashre.equals(passwordHash)) {
                    System.out.println("The two passwords are not the same!");
                    return;
                }

                File f = new File(filename);
                if(f.exists() && !f.isDirectory()) {
                    new Encrypter(f, password, false);
                } else {
                    System.out.println("Error: File doesn't exist or is a Directory");
                }
            } else if(cmd.equals("--decrypt") || cmd.equals("-d")) {
                String filename = args[1];

                System.out.print("Password for file: ");
                String password = new String(System.console().readPassword());

                File f = new File(filename);
                if(f.exists() && !f.isDirectory()) {
                    new Decrypter(f, password, false);
                } else {
                    System.out.println("Error: File doesn't exist or is a Directory");
                }
            } else if(cmd.equals("--name") || cmd.equals("-n")) {
                String filename = args[1];

                File f = new File(filename);
                if(f.exists() && !f.isDirectory()) {
                    new Name(f);
                } else {
                    System.out.println("Error: File doesn't exist or is a Directory");
                }
            } else if(cmd.equals("--help") || cmd.equals("-?")) {
                System.out.println( "   _____ ______ ______     ____  \n" +
                        "  / ____|  ____|  ____|   |___ \\ \n" +
                        " | (___ | |__  | |__ ______ __) |\n" +
                        "  \\___ \\|  __| |  __|______|__ < \n" +
                        "  ____) | |    | |____     ___) |\n" +
                        " |_____/|_|    |______|   |____/ \n");
                System.out.println("List of commands: ");
                System.out.println("--encrypt/-e <file> | encrypts a file with SFE-3");
                System.out.println("--decrypt/-d <file> | decrypts a .SFE3 file");
                System.out.println("--name/-n <file> | returns the true filename of a .SFE3 file");
                System.out.println("--help/-? | shows this list\n");
            } else {
                System.out.println("Unknown command: Use option --help to view all commands");
            }
        } else {
            System.out.println("Please provide at least one argument!");
        }
    }

    public static String readNextInfo(InputStreamReader reader) throws IOException {
        String buffer = "";
        boolean bool = true;
        while (bool) {
            int b;
            b = reader.read();
            if (b == 10) {
                return buffer;
            } else if (b == -1) {
                return buffer;
            } else {
                buffer += (char) b;
            }
        }

        return buffer;
    }

    public static String readNextInfo(DecryptedInputStream reader) throws IOException {
        String buffer = "";
        boolean bool = true;
        while (bool) {
            int b;
            b = reader.read();
            if (b == 10) {
                return buffer;
            } else if (b == -1) {
                return buffer;
            } else if(b != 0){
                buffer += (char) b;
            }
        }

        return buffer;
    }

}
