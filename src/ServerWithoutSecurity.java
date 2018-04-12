import javax.crypto.Cipher;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import java.util.concurrent.TimeUnit;

public class ServerWithoutSecurity {

	public static void main(String[] args) {

		ServerSocket serverSocket = null;
		Socket clientSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		String plaintext = "Hello I am Bob.";

		try {
			int portNum = 4321; //socket address
			serverSocket = new ServerSocket(portNum);
			System.out.println("Waiting for clients.");
			clientSocket = serverSocket.accept();
			System.out.println("Client connection is established.");

			fromClient = new DataInputStream(clientSocket.getInputStream());
			toClient = new DataOutputStream(clientSocket.getOutputStream());

			if (!clientSocket.isClosed()) {
                // get server's public key from CA's public key

                int lengthOfRandomBytes = fromClient.read();
                System.out.println("Byte length: " + lengthOfRandomBytes);
                byte[] clientMessage = new byte[lengthOfRandomBytes];
                int RandomBytes = fromClient.read(clientMessage);
                System.out.println(new String(clientMessage));

                if (RandomBytes != lengthOfRandomBytes){
                    TimeUnit.SECONDS.sleep(1);
                }

				String privateServerPath = "/Users/thamyeeting/Documents/SecureFileTransfer/serverPrivateKey.der";
				Path path = Paths.get(privateServerPath);

				byte[] privateKeyByte = Files.readAllBytes(path);

				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				PrivateKey myPrivateKey = keyFactory.generatePrivate(keySpec);

				// Encryption cipher
				Cipher RSAEnCipherPrivate = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				RSAEnCipherPrivate.init(Cipher.ENCRYPT_MODE, myPrivateKey);
				byte[] encryptedBytes = RSAEnCipherPrivate.doFinal(clientMessage);
                System.out.println("Encrypted Bytes: " + encryptedBytes);

				toClient.writeInt(encryptedBytes.length);
				toClient.write(encryptedBytes);

				/*
				Cipher RSADeCipherPrivate = Cipher.getInstance("RSA/ESC/PKCS1Padding");
				RSADeCipherPrivate.init(Cipher.DECRYPT_MODE, myPrivateKey);

				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					fromClient.read(filename);

					fileOutputStream = new FileOutputStream("recv/"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

				} else if (packetType == 2) {

					System.out.println("Closing connection...");

					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					clientSocket.close();
				}*/

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}
