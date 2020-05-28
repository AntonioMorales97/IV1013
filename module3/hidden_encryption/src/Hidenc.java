import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hides an encryption by creating an encrypted (AES) blob an storing it in a
 * random offset within a container file (holding random data) as such:
 * 
 * |Container|H(k)|Data|H(k)|H(Data)|Container|
 * 
 * where H(x) is the MD5 hash (the blob starts at the first H(k) and ends at
 * H(Data)).
 * 
 * Supports AES in ECB-and CTR-mode with a block size of 16.
 * 
 * @author Antonio
 *
 */
public class Hidenc {
	private byte[] key;
	private byte[] ctr;
	private byte[] templateBytes = null;
	private int size = -1;
	private int offset = -1;
	private boolean isCTRmode = false;
	private byte[] inputFileBytes;
	private String outputFileName;
	private Cipher cipher;

	private final int BLOCK_SIZE = 16;
	private final String HASH_ALGO = "MD5";
	private final String CRYPT_ALGO = "AES";
	private final String AES_ECB = "AES/ECB/NoPadding";
	private final String AES_CTR = "AES/CTR/NoPadding";

	/**
	 * Creates an instance of <code>Hidenc</code> which immediately set up the given
	 * configurations and starts the encryption. The given configurations are
	 * validated before any encryption can start.
	 * 
	 * @param args the given configurations (key, ctr, input, output, (optional)
	 *             offset, template or size)
	 */
	public Hidenc(String[] args) {
		setConfigurations(args);
		encrypt();
	}

	private void setConfigurations(String[] args) {
		for (String arg : args) {
			String[] parsedArg = parseInputArgument(arg);
			switch (parsedArg[0]) {
			case "--key":
				this.key = convertHexStringToByteArray(parsedArg[1], parsedArg[0]);
				break;
			case "--ctr":
				this.isCTRmode = true;
				this.ctr = convertHexStringToByteArray(parsedArg[1], parsedArg[0]);
				break;
			case "--input":
				this.inputFileBytes = readFileToBytes(parsedArg[1]);
				break;
			case "--output":
				this.outputFileName = parsedArg[1];
				break;
			case "--offset":
				this.offset = Integer.parseInt(parsedArg[1]);
				validateOffset();
				break;
			case "--template":
				this.templateBytes = readFileToBytes(parsedArg[1]);
				break;
			case "--size":
				this.size = Integer.parseInt(parsedArg[1]);
				break;
			default:
				System.out.println("Parameter " + parsedArg[0] + " is not supported.");
				System.out.println(
						"Currently supported parameters are: --key, --ctr, --input, --output, --offset, --template, --size");
				System.out.println("Exiting...");
				System.exit(0);
			}
		}
		validateInputArguments();

		if (this.templateBytes == null) {
			// no specified template, create one
			setUpRandomTemplate(this.size);
		}
	}

	private String[] parseInputArgument(String arg) {
		String[] parsed = arg.split("=");
		if (parsed.length != 2) {
			System.out.println("Expected the following format for parameters: <parameter>=<argument>");
			System.out.println("Received: " + arg);
			System.out.println("Exiting...");
			System.exit(0);
		}
		return parsed;
	}

	private byte[] convertHexStringToByteArray(String str, String param) {
		byte[] byteArray = new byte[str.length() / 2];
		for (int i = 0; i < byteArray.length; i++) {
			int pos = i * 2;
			try {
				int hexaInt = Integer.parseInt(str.substring(pos, pos + 2), 16);
				byteArray[i] = (byte) hexaInt;
			} catch (NumberFormatException exc) {
				System.out.println("Caught a non-hexadecimal string \"" + str.subSequence(pos, pos + 2)
				+ "\" in parameter: " + param);
				System.out.println("Exiting...");
				System.exit(0);
			}
		}
		return byteArray;
	}

	private byte[] readFileToBytes(String file) {
		Path pathToFile = Paths.get(file);
		byte[] bytes = null;
		try {
			bytes = Files.readAllBytes(pathToFile);
		} catch (IOException e) {
			System.out.println("Could not read the file: " + file);
			System.out.println("Check the name/path of/to the file and the permissions.");
			System.out.println("Exiting...");
			System.exit(0);
		}
		if (bytes == null || bytes.length == 0) {
			System.out.println("The file " + file + " was empty.");
			System.out.println("Exiting...");
			System.exit(0);
		}
		return bytes;
	}

	private void writeBytesToOutputFile() {
		Path pathToOutputFile = Paths.get(this.outputFileName);
		try {
			Files.write(pathToOutputFile, this.templateBytes);
		} catch (IOException e) {
			System.out.println("Could not write to " + this.outputFileName);
			System.out.println("Check the file name/path and permissions.");
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private void validateInputArguments() {
		if (this.key == null || this.outputFileName == null || this.inputFileBytes == null) {
			System.out.println(
					"Must have the following parameters: --key, --input, --output (and one of --template or --size)");
			System.out.println("Exiting...");
			System.exit(0);
		}

		// only one
		if (this.templateBytes != null && this.size != -1) {
			System.out.println("Choose either to use a template or specify a size (--template or --size)");
			System.out.println("Exiting...");
			System.exit(0);
		}

		// atleast one
		if (this.templateBytes == null && this.size == -1) {
			System.out.println("You must give a template or specify a size (--template or --size)");
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private void validateOffset() {
		if (this.offset < 0) {
			System.out.println("The offset cannot be a negative number.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		if (this.offset % BLOCK_SIZE != 0) {
			System.out.println("The offset must be a multiple of the block size " + BLOCK_SIZE);
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private void setUpRandomTemplate(int size) {
		this.templateBytes = new byte[size];
		Random rd = new Random();
		rd.nextBytes(this.templateBytes);
	}

	private void setUpRandomOffset(int blobSize) {
		if (this.templateBytes.length == blobSize)
			this.offset = 0;
		Random rd = new Random();
		while ((this.offset % BLOCK_SIZE) != 0) { // must be multiple of block size
			this.offset = rd.nextInt(this.templateBytes.length - blobSize);
		}

	}

	private void encrypt() {
		try {
			initCipher();
		} catch (InvalidKeyException e) {
			System.out.println("Invalid key when trying to initialize the cipher.");
			System.out.println("This could be due to invalid encoding, wronglength, uninitialized, etc.");
			System.out.println("Exiting...");
			System.exit(0);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Could not find cryptographic algorithm when trying to initialize the cipher.");
			System.out.println("Exiting...");
			System.exit(0);
		} catch (NoSuchPaddingException e) {
			System.out.println("Bad padding when trying to initialize the cipher. Got: " + e.getMessage());
			System.out.println("Exiting...");
			System.exit(0);
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("Got an invalid algorithm parameter when trying to initialize the cipher.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		byte[] blob = createBlob();

		if (this.offset == -1) {
			setUpRandomOffset(blob.length);
		} else if (this.offset + blob.length > this.templateBytes.length) {
			System.out.println("The given offset and the blob size cannot fit into the template.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		byte[] encBlob = encryptBlob(blob);
		insertEncryptedBlobIntoTemplate(encBlob);
		writeBytesToOutputFile();
	}

	private void insertEncryptedBlobIntoTemplate(byte[] encBlob) {
		int idx = 0;
		for (int i = this.offset; i < this.offset + encBlob.length; i++)
			this.templateBytes[i] = encBlob[idx++];
	}

	private byte[] encryptBlob(byte[] blob) {
		byte[] encBlob = null;
		try {
			encBlob = this.cipher.doFinal(blob);
		} catch (IllegalBlockSizeException e) {
			System.out.println("Received a bad block size when trying to encrypt the blob.");
			System.out.println("Exiting...");
			System.exit(0);
		} catch (BadPaddingException e) {
			System.out.println("Received bad padding when trying to encrypt the blob.");
			System.out.println("Exiting...");
			System.exit(0);
		}
		return encBlob;
	}

	private byte[] createBlob() {
		byte[] encKey = md5Hash(this.key); // H(k)
		byte[] hashData = md5Hash(this.inputFileBytes); // H(d)

		int blobSize = encKey.length + this.inputFileBytes.length + encKey.length + hashData.length;

		byte[] blob = new byte[blobSize];
		int idx = 0;
		for (int i = 0; i < encKey.length; i++)
			blob[idx++] = encKey[i];
		for (int i = 0; i < this.inputFileBytes.length; i++)
			blob[idx++] = this.inputFileBytes[i];
		for (int i = 0; i < encKey.length; i++)
			blob[idx++] = encKey[i];
		for (int i = 0; i < hashData.length; i++)
			blob[idx++] = hashData[i];
		return blob;
	}

	private void initCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
	InvalidAlgorithmParameterException {
		SecretKeySpec secKey = new SecretKeySpec(this.key, CRYPT_ALGO);
		if (this.isCTRmode) {
			this.cipher = Cipher.getInstance(AES_CTR);
			IvParameterSpec ivParamSpec = new IvParameterSpec(this.ctr); // init vector for AES in CTR-mode
			this.cipher.init(Cipher.ENCRYPT_MODE, secKey, ivParamSpec);
		} else {
			this.cipher = Cipher.getInstance(AES_ECB);
			this.cipher.init(Cipher.ENCRYPT_MODE, secKey);
		}
	}

	private byte[] md5Hash(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(HASH_ALGO);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("The hash algorithm \"" + HASH_ALGO + "\" could not be found.");
			System.out.println("Exiting...");
			System.exit(0);
		}
		md.update(data);
		return md.digest();
	}

	/**
	 * Creates a <code>Hidenc</code> with the given arguments from the command line.
	 * 
	 * @param args arguments from the command line.
	 */
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Hidenc he = new Hidenc(args);
	}
}
