import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class ServerCP1 {
	private static void sendBytes(DataOutputStream toClient, byte[] bytes) throws IOException {
		InputStream is = new ByteArrayInputStream(bytes);
		BufferedInputStream bis = new BufferedInputStream(is);
		byte [] byteBuffer = new byte[117];
		// Send bytes
		for (boolean byteEnded = false; !byteEnded;) {
			int numBytes = bis.read(byteBuffer);
			System.out.println(numBytes);
			byteEnded = numBytes < 117;

			toClient.writeInt(numBytes);
			toClient.write(byteBuffer);
			toClient.flush();
		}
	}


	public static void main(String[] args) {

		ServerSocket serverSocket = null;
		Socket clientSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			//initialising portnum and setting up connection
			int portNum = 4321; //socket address
			if (args.length > 0) portNum = Integer.parseInt(args[0]);

			System.out.println("Port number: " + portNum);
			serverSocket = new ServerSocket(portNum);
			System.out.println("Waiting for clients.");
			clientSocket = serverSocket.accept();
			System.out.println("Client connection is established.");

			fromClient = new DataInputStream(clientSocket.getInputStream());
			toClient = new DataOutputStream(clientSocket.getOutputStream());

            // initialising keys
			Path path = Paths.get("serverPrivateKey.der");

            byte[] privateKeyByte = Files.readAllBytes(path);
            PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyByte);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey myPrivateKey = keyFactory.generatePrivate(privateSpec);

            Cipher RSAEnCipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            RSAEnCipherPrivate.init(Cipher.ENCRYPT_MODE, myPrivateKey);

            Cipher RSADeCipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            RSADeCipherPrivate.init(Cipher.DECRYPT_MODE, myPrivateKey);

			while (!clientSocket.isClosed()) {
				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {
					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.readFully(filename, 0, numBytes);


					byte[] newFilename = RSADeCipherPrivate.doFinal(filename);

					fileOutputStream = new FileOutputStream("recv/" + new String(newFilename, 0, newFilename.length));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

					// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {
					int numBytes = fromClient.readInt();
					byte [] block = new byte[128];
					fromClient.readFully(block, 0, 128);


                    byte[] dbytes = RSADeCipherPrivate.doFinal(block);
					if (numBytes > 0){
						bufferedFileOutputStream.write(dbytes, 0, numBytes);}

					if (numBytes < 117){
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						clientSocket.close();
					}

				} else if (packetType == 2) { // for encrypting nonce
					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block,0, numBytes);

					byte[] encryptedBytes = RSAEnCipherPrivate.doFinal(block);

					InputStream inputStream = new ByteArrayInputStream(encryptedBytes);
					BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
					byte[] blockbyte = new byte[117];

					for (boolean byteFinished = false; !byteFinished;) {
						int numOfBytes = bufferedInputStream.read(blockbyte);
						byteFinished = numOfBytes < 117;

						toClient.writeInt(numOfBytes);
						toClient.write(blockbyte);
						toClient.flush();
					}
				}
				else if (packetType == 4){ //send certificate to client
					String certificate = "ServerCert.crt";
					System.out.println("Sending certificate " + certificate + " to client");

					FileInputStream fileInputStream = new FileInputStream(certificate);
					BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

					byte[] fromFileblock = new byte[117];

					for (boolean fileEnded = false; !fileEnded;){
						int numBytes = bufferedFileInputStream.read(fromFileblock);

						fileEnded = numBytes<117;
						toClient.writeInt(numBytes);
						toClient.write(fromFileblock);
						toClient.flush();
					}
					System.out.println("Sent certificate");
				}
			}
		} catch (Exception e) {e.printStackTrace();}
	}
}
