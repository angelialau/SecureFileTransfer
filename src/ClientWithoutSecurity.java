import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ClientWithoutSecurity {

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

			// do the security stuffz here
            InputStream fis = new FileInputStream("CA.crt");
            InputStream ServerCertInput = new FileInputStream("ServerCert.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(ServerCertInput);
            PublicKey CAKey = CAcert.getPublicKey();  //CA's public key
            PublicKey serverPublicKey = ServerCert.getPublicKey();  //CA's public key
            CAcert.checkValidity();
            ServerCert.verify(CAKey);

            // receive authentication message and decrypt
            Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
            int lengthOfBytes = fromServer.readInt();
            byte[] encryptedServerMessage = new byte[lengthOfBytes];
            int readBytes = fromServer.read( encryptedServerMessage );

            while(true){ // server still sending
                if(readBytes == lengthOfBytes){
                    break;
                }
            }

            // decrypt server message with server's public key
            byte[] decryptedServerMessage = dcipher.doFinal(encryptedServerMessage);
            String serverMessage = DatatypeConverter.printBase64Binary(decryptedServerMessage);

            System.out.println("Server said: " + serverMessage);



			System.out.println("Sending file...");

			// Send the filename
			toServer.writeInt(0);
			toServer.writeInt(filename.getBytes().length);
			toServer.write(filename.getBytes());
			toServer.flush();

			// Open the file
			fileInputStream = new FileInputStream(filename);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

	        byte [] fromFileBuffer = new byte[117];

	        // Send the file
	        for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < fromFileBuffer.length;

				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}

	        bufferedFileInputStream.close();
	        fileInputStream.close();


			System.out.println("Closing connection...");
	        toServer.writeInt(2);
	        toServer.flush();

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}
