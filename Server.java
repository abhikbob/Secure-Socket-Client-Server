import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


public class Server {
    private static ServerSocket server;
    private static int port = 9876;
    private static SecretKeySpec secretKey;
    private static byte[] key;

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

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        SecureRandom secRan = new SecureRandom();
        double Bdash = 0;
        Scanner sc = new Scanner(System.in);
        server = new ServerSocket(port);
        String send = "";
        System.out.println("Waiting for client");
        Socket socket = server.accept();
        System.out.println("Just connected to " + socket.getRemoteSocketAddress());
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        try {
            int port = 8088;
            int b = secRan.nextInt(10) + 1;
            double clientP, clientG, clientA, B;
            String Bstr;

            // Server's Private Key
            System.out.println("\nFrom Server : Private Key = " + b);
            // Accepts the data from client
            clientP = Integer.parseInt((String) ois.readObject()); // to accept p
            System.out.println("From Client : P = " + clientP);

            clientG = Integer.parseInt((String) ois.readObject()); // to accept g
            System.out.println("From Client : G = " + clientG);

            clientA = Double.parseDouble((String) ois.readObject()); // to accept A
            System.out.println("From Client : Public Key = " + clientA);

            B = ((Math.pow(clientG, b)) % clientP); // calculation of B
            Bstr = Double.toString(B);

            oos.writeObject(Bstr); // Sending B

            Bdash = ((Math.pow(clientA, b)) % clientP); // calculation of Bdash

            System.out.println("Secret Key to perform Symmetric Encryption = " + Bdash);
        } catch (SocketTimeoutException s) {
            System.out.println("Socket timed out!");
        } catch (IOException e) {
        }

        final String secretKey = Double.toString(Bdash);

        while (true) {
            String message = (String) ois.readObject();
            System.out.println("\nClient(Encrypted): " + message);
            System.out.println("Client(Decrypted): " + Server.decrypt(message, secretKey));
            if (Server.decrypt(message, secretKey).equalsIgnoreCase("exit")) break;
            System.out.print("\nYou: ");
            send = sc.nextLine();
            oos.writeObject(Server.encrypt(send, secretKey));
            if (send.equalsIgnoreCase("exit")) break;
        }
        ois.close();
        oos.close();
        socket.close();
        System.out.println("Server closed");
        server.close();
    }

}
