import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class ClientCP2 {
    private static String theStringToCheck = "";

	public static void main(String[] args) {

    	String filename = "rrlong.txt";
        String serverCertName = "theCert.crt";
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

            System.out.println("I'm asking for bob's certificate...");
            File serverCert = new File(serverCertName); // file to store server's cert

            if(!serverCert.exists()){
                boolean createdFile = serverCert.createNewFile();
                if(!createdFile){
                    System.out.println("Failed to create new file");
                    throw new IOException("Failed to create certificate");
                }

                FileOutputStream fileOutputStream = new FileOutputStream(serverCert);
                BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
                toServer.writeInt(4); // packet type for nonce


                System.out.println("Bob is sending his cert...");
                int serverNumBytes = 0;
                for (boolean finishedSending = false; !finishedSending;) {
                    serverNumBytes = fromServer.readInt();
                    finishedSending = serverNumBytes < 117;

                    byte[] bobBuffer = new byte[serverNumBytes];
                    fromServer.readFully(bobBuffer, 0 , serverNumBytes);
                    bufferedFileOutputStream.write(bobBuffer, 0, serverNumBytes);

                } fromServer.skipBytes(117-serverNumBytes);

                System.out.println("Received bob's cert...");
                bufferedFileOutputStream.close();
            }

            Random random = new Random();
            theStringToCheck = String.valueOf(random.nextInt());
            System.out.println("I'm sending bob a nonce...");
            toServer.writeInt(2); // packet type for nonce
            toServer.writeInt(theStringToCheck.getBytes().length); // send num of bytes in nonce
            toServer.write(theStringToCheck.getBytes()); // send nonce itself
            toServer.flush();

            // verifying bob's signed certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream fis = new FileInputStream("CA.crt");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            PublicKey CAKey = CAcert.getPublicKey();  //CA's public key

            fis = new FileInputStream(serverCertName);
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(fis);
            CAcert.checkValidity();
            ServerCert.verify(CAKey);

            PublicKey serverPublicKey = ServerCert.getPublicKey();  //server's public key
            System.out.println("I have the server's public key now...");

            // receive authentication message and decrypt
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);

            int totalBufferLength = 0;
            List<byte[]> totalBuffer = new ArrayList<>();

            int lengthOfBytes = 0;
            for (boolean finishedSending = false; !finishedSending;) {
                lengthOfBytes = fromServer.readInt();
                System.out.println("num bytes: " + lengthOfBytes);
                finishedSending = lengthOfBytes < 117;

                byte[] bobBuffer = new byte[lengthOfBytes];
                fromServer.readFully(bobBuffer, 0 , lengthOfBytes);
                //byte[] decryptedBobBuffer = dcipher.doFinal((bobBuffer)); // bad padding : decrypt error here
                totalBuffer.add(bobBuffer);
                totalBufferLength+= bobBuffer.length;

            } fromServer.skipBytes(117-lengthOfBytes);

            byte[] finalBuffer = new byte[totalBufferLength];
            int latestIndex = 0;

            for(int i=0; i< totalBuffer.size(); i++){
                byte[] from = totalBuffer.get(i);
                System.arraycopy(from, 0, finalBuffer, latestIndex, from.length);
                latestIndex += from.length;
            }

            // decrypt server message with server's public key
            byte[] deNonce = dcipher.doFinal(finalBuffer);

//          byte[] decryptedServerMessage = dcipher.doFinal(finalBuffer);
            String serverMessage = new String(deNonce);

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
                sum += numBytes;

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
        System.out.println("Total number of bytes: " + sum);
	}

}
