import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class ClientCP2 {
    private static String theStringToCheck = "";

	public static void main(String[] args) {

    	String filename = "rr.txt";

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

            // generating a nonce
            Random random = new Random();
            theStringToCheck = String.valueOf(random.nextInt());

            // sending the nonce
            System.out.println("I'm sending server a nonce...");
            toServer.writeInt(2); // packet type for nonce
            toServer.writeInt(theStringToCheck.getBytes().length); // send num of bytes in nonce
            toServer.write(theStringToCheck.getBytes()); // send nonce itself
            toServer.flush();

			// initialising certs and keys
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream fis = new FileInputStream("CA.crt");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            PublicKey CAKey = CAcert.getPublicKey();  //CA's public key

            InputStream ServerCertInput = new FileInputStream("ServerCert.crt");
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(ServerCertInput);
            PublicKey serverPublicKey = ServerCert.getPublicKey();  //server's public key

            // decipher
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            // cipher
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey); // using the server's public key to encrypt the file

            // verifying bob's signed certificate
            CAcert.checkValidity();
            ServerCert.verify(CAKey);
            System.out.println("I have the server's public key now...");

            // receive bob's encrypted version of nonce
            int lengthOfBytes = fromServer.readInt();
            byte[] encryptedServerMessage = new byte[lengthOfBytes];
            fromServer.readFully(encryptedServerMessage, 0, lengthOfBytes);

            // decrypt bob's nonce with his public key
            byte[] decryptedServerMessage = dcipher.doFinal(encryptedServerMessage);
            String serverMessage = new String(decryptedServerMessage);

            System.out.println("Original nonce: " + theStringToCheck);
            System.out.println("Server's version: " + serverMessage);
            if(serverMessage.equals(theStringToCheck)){
                System.out.println("Verification success: Server is who he says he is.");
            }else{
                System.out.println("Verification failure: Man in the middle attack!!!! Trudy alert!!!!");
				System.out.println("Terminating...");
				return;
            }

            // generating session key
            System.out.println("Sending shared key...");
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecretKey sharedKey = keyGen.generateKey();

            // sending shared session key
            byte[] encryptedKey = cipher.doFinal(sharedKey.getEncoded());
            toServer.writeInt(3); // packet type = filename
            toServer.writeInt(encryptedKey.length);
            toServer.write(encryptedKey);
            toServer.flush();

            System.out.println("shared key is: " + sharedKey.toString());

            // cipher for shared session key
            Cipher fasterCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            fasterCipher.init(Cipher.ENCRYPT_MODE, sharedKey);

            // encrypting filename
            byte[] encryptedFileName = fasterCipher.doFinal(filename.getBytes());

            System.out.println("Sending file...");

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

                byte[] encryptedBuffer = fasterCipher.doFinal(fromFileBuffer); // we encrypt the block before sending it
                toServer.writeInt(1); // packet type = file
                toServer.writeInt(numBytes);
                toServer.write(encryptedBuffer);
                toServer.flush();

            }
            System.out.println("Panggang lo 2.0 thx");
            bufferedFileInputStream.close();
            fileInputStream.close();

			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

}
