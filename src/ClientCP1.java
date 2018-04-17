import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class ClientCP1 {
    private static String theStringToCheck = "";

	public static void main(String[] args) {

    	String filename = "rrlong.txt";
        int sum = 0;

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {
			System.out.println("Establishing connection to server...");
			String hostName = "10.12.16.24";
			// Connect to server and get the input and output streams
			clientSocket = new Socket(hostName, 4321);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

            Random random = new Random();
            theStringToCheck = String.valueOf(random.nextInt());
            System.out.println("I'm sending server a nonce...");
            toServer.writeInt(2); // packet type for nonce
            toServer.writeInt(theStringToCheck.getBytes().length); // send num of bytes in nonce
            toServer.write(theStringToCheck.getBytes()); // send nonce itself
            toServer.flush();

            // verifying bob's signed certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream fis = new FileInputStream("CA.crt");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            PublicKey CAKey = CAcert.getPublicKey();  //CA's public key

            InputStream ServerCertInput = new FileInputStream("ServerCert.crt");
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(ServerCertInput);
            PublicKey serverPublicKey = ServerCert.getPublicKey();  //server's public key

            CAcert.checkValidity();
            ServerCert.verify(CAKey);
            System.out.println("I have the server's public key now...");

            // receive authentication message and decrypt

            int lengthOfBytes = fromServer.readInt();
            byte[] encryptedServerMessage = new byte[lengthOfBytes];
            int readBytes = fromServer.read( encryptedServerMessage );

            if(readBytes != lengthOfBytes){
                TimeUnit.SECONDS.sleep(1); // waits for server to finish writing the bytes
            }

            // decrypt server message with server's public key
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            byte[] decryptedServerMessage = dcipher.doFinal(encryptedServerMessage);
            String serverMessage = new String(decryptedServerMessage);

            System.out.println("Original nonce: " + theStringToCheck);
            System.out.println("Server's version: " + serverMessage);
            if(serverMessage.equals(theStringToCheck)){
                System.out.println("Verification success: Server is who he says he is.");
            }else{
                System.out.println("Man in the middle attack!!!! Trudy alert!!!!");
				System.out.println("Terminating...");
				return;
            }

            System.out.println("Sending file...");

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey); // using the server's public key to encrypt the file
            byte[] encryptedFileName = cipher.doFinal(filename.getBytes());

            // Send the filename
            toServer.writeInt(0); // packet type = filename
            toServer.writeInt(encryptedFileName.length);
            toServer.write(encryptedFileName);
            toServer.flush();

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            byte [] fromFileBuffer = new byte[117];

            // Send the file

            for (boolean fileEnded = false; !fileEnded;) {
                numBytes = bufferedFileInputStream.read(fromFileBuffer);
                fileEnded = numBytes < 117;
                sum += numBytes;

                byte[] encryptedBuffer = cipher.doFinal(fromFileBuffer); // we encrypt the block before sending it
                toServer.writeInt(1); // packet type = file
                toServer.writeInt(numBytes);
                toServer.write(encryptedBuffer);
                toServer.flush();

            }
            System.out.println("Panggang lo thx");
            bufferedFileInputStream.close();
            fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
        System.out.println("Total number of bytes: " + sum);
    }

}
