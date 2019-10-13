import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private static SecretKeySpec secretKey;
    private static byte[] key;

    public static String getHash(String input)
    {
        try {
            // getInstance() method is called with algorithm SHA-512
            MessageDigest md = MessageDigest.getInstance("SHA-512");

            // digest() method is called
            // to calculate message digest of the input string
            // returned as array of byte
            byte[] messageDigest = md.digest(input.getBytes());

            // Convert byte array into signum representation
            BigInteger no = new BigInteger(1, messageDigest);

            // Convert message digest into hex value
            String hashtext = no.toString(16);

            // Add preceding 0s to make it 32 bit
            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }

            // return the HashText
            return hashtext;
        }

        // For specifying wrong message digest algorithms
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setKey(String myKey) {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String encrypt(String strToEncrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt(String strToDecrypt, String secret) {
        try {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, InterruptedException {
        SecureRandom secRan = new SecureRandom();
        Scanner sc = new Scanner(System.in);
        double Adash = 0;
        try {
            InetAddress host = InetAddress.getLocalHost();
            Socket socket = new Socket(host.getHostName(), 9876);
            System.out.println("Connecting to server");
            System.out.println("Just connected to " + socket.getRemoteSocketAddress());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            String pstr, gstr, Astr;

            // Declare p, g, and Key of client
            int p = 59;
            int g = 13;
            int a = secRan.nextInt(10) + 1;
            double serverB;

            pstr = Integer.toString(p);
            oos.writeObject(pstr); // Sending p

            gstr = Integer.toString(g);
            oos.writeObject(gstr); // Sending g

            double A = ((Math.pow(g, a)) % p); // calculation of A
            Astr = Double.toString(A);
            oos.writeObject(Astr); // Sending A

            // Client's Private Key
            System.out.println("\nFrom Client : Private Key = " + a);

            serverB = Double.parseDouble((String) ois.readObject());
            System.out.println("From Server : Public Key = " + serverB);

            Adash = ((Math.pow(serverB, a)) % p); // calculation of Adash

            System.out.println("Secret Key to perform Symmetric Encryption = " + Adash);

            final String secretKey = Double.toString(Adash);
            String send = "";
            String outmsg="";
            while (true) {
                System.out.print("\nYou: ");
                outmsg = sc.nextLine();
                send = outmsg+"&&"+getHash(outmsg);
                oos.writeObject(Server.encrypt(send, secretKey));
                if (outmsg.equalsIgnoreCase("exit")) break;
                String recvd = Server.decrypt((String) ois.readObject(),secretKey);
                String[] message= recvd.split("&&");
                if(!getHash(message[0]).equals(message[1])) System.out.println("Authentication failed!!!");
                System.out.println("\nServer: " + message[0]);
                if (message[0].equalsIgnoreCase("exit")) break;
            }
            ois.close();
            oos.close();
            socket.close();
            System.out.println("Connection terminated");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
