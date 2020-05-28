import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Finds and decrypts a hidden encryption (AES) by finding the hidden blob in a
 * container file as such:
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
public class Hiddec {
	private byte[] key;
	private byte[] ctr;
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
	 * Creates an instance of <code>Hiddec</code> which immediately set up the given
	 * configurations and starts the decryption. The given configurations are
	 * validated before any decryption can start.
	 * 
	 * @param args the given configurations (key, ctr, input, output)
	 */
	public Hiddec(String[] args) {
		setConfigurations(args);
		decrypt();
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
			default:
				System.out.println("Parameter " + parsedArg[0] + " is not supported.");
				System.out.println("Currently supported parameters are: --key, --ctr, --input, --output");
				System.out.println("Exiting...");
				System.exit(0);
			}
		}
		validateInputArguments();
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

	private void writeBytesToOutputFile(byte[] data) {
		Path pathToOutputFile = Paths.get(this.outputFileName);
		try {
			Files.write(pathToOutputFile, data);
		} catch (IOException e) {
			System.out.println("Could not write to " + this.outputFileName);
			System.out.println("Check the file name/path or permissions.");
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private void validateInputArguments() {
		if (this.key == null || this.outputFileName == null || this.inputFileBytes == null) {
			System.out.println("Must have the three mandatory parameters: --key, --input, --output");
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private void decrypt() {
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
		byte[] encKey = md5Hash(this.key); // H(k)
		if (this.isCTRmode) {
			CTRMode(encKey);
		} else {
			ECBMode(encKey);
		}
	}

	private void initCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException {
		SecretKeySpec secKey = new SecretKeySpec(this.key, CRYPT_ALGO);
		if (this.isCTRmode) {
			this.cipher = Cipher.getInstance(AES_CTR);
			IvParameterSpec ivParamSpec = new IvParameterSpec(this.ctr); // init vector for AES in CTR-mode
			this.cipher.init(Cipher.DECRYPT_MODE, secKey, ivParamSpec);
		} else {
			this.cipher = Cipher.getInstance(AES_ECB);
			this.cipher.init(Cipher.DECRYPT_MODE, secKey);
		}
	}

	private void ECBMode(byte[] encKey) {
		int startOfFirstKey = findNextKey(encKey, 0);
		validateFoundKeyIndex(startOfFirstKey, "first");

		int startOfLastKey = findNextKey(encKey, startOfFirstKey + BLOCK_SIZE);
		validateFoundKeyIndex(startOfLastKey, "last");

		byte[] data = decrypt(Arrays.copyOfRange(this.inputFileBytes, startOfFirstKey + BLOCK_SIZE, startOfLastKey)); // decrypt data

		if (startOfLastKey + (2 * BLOCK_SIZE) > this.inputFileBytes.length) {
			System.out.println("Not enough data to verify the decrypted data.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		byte[] decryptedHashData = decrypt(Arrays.copyOfRange(this.inputFileBytes, startOfLastKey + BLOCK_SIZE,
				startOfLastKey + (2 * BLOCK_SIZE))); // H(d)
		byte[] hashData = md5Hash(data);

		if (!Arrays.equals(decryptedHashData, hashData)) {
			System.out.println(
					"The hash of the data is not the same as the decrypted hash of the data. The data is not the same.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		writeBytesToOutputFile(data);
	}

	private void CTRMode(byte[] encKey) {
		int startIdxOfFirstKey = findFirstKeyCTR(encKey);
		validateFoundKeyIndex(startIdxOfFirstKey, "first");

		int startIdxOfLastKey = findNextKey(encKey, startIdxOfFirstKey + BLOCK_SIZE);
		validateFoundKeyIndex(startIdxOfLastKey, "last");

		byte[] data = decryptDataCTR(startIdxOfFirstKey, startIdxOfLastKey);
		decrypt(Arrays.copyOfRange(this.inputFileBytes, startIdxOfLastKey, startIdxOfLastKey + BLOCK_SIZE)); /*Increment counter so we can get the last block next */

		byte[] decryptedHashData = decrypt(Arrays.copyOfRange(this.inputFileBytes, startIdxOfLastKey + BLOCK_SIZE,
				startIdxOfLastKey + (2 * BLOCK_SIZE)));
		byte[] hashData = md5Hash(data);

		if (!Arrays.equals(decryptedHashData, hashData)) {
			System.out.println(
					"The hash of the data is not the same as the decrypted hash of the data. The data is not the same.");
			System.out.println("Exiting...");
			System.exit(0);
		}

		writeBytesToOutputFile(data);
	}

	private void validateFoundKeyIndex(int idx, String keyPos) {
		if (idx == -1) {
			// not found
			System.out.println("Could not find the " + keyPos + " key.");
			System.out.println("Exiting...");
			System.exit(0);
		}
	}

	private int findFirstKeyCTR(byte[] encKey) {
		for (int i = 0; i < this.inputFileBytes.length; i += BLOCK_SIZE) {
			try {
				initCipher(); // reset cipher to decrypt a new block (we need to reset the counter value until we find the blob)
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
			if (this.inputFileBytes.length < i + BLOCK_SIZE) {
				System.out.println(
						"There is not enough data to read a complete block and therefore a blob cannot exist.");
				System.out.println("Exiting...");
				System.exit(0);
			}
			byte[] dec = decrypt(Arrays.copyOfRange(this.inputFileBytes, i, i + BLOCK_SIZE));
			if (Arrays.equals(dec, encKey))
				return i;
		}
		return -1;
	}

	private int findNextKey(byte[] encKey, int startIdx) {
		for (int i = startIdx; i < this.inputFileBytes.length; i += BLOCK_SIZE) {
			if (this.inputFileBytes.length < i + BLOCK_SIZE) {
				System.out.println(
						"There is not enough data to read a complete block and therefore a blob cannot exist.");
				System.out.println("Exiting...");
				System.exit(0);
			}
			byte[] dec = decrypt(Arrays.copyOfRange(this.inputFileBytes, i, i + BLOCK_SIZE));
			if (Arrays.equals(dec, encKey))
				return i;
		}
		return -1;
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

	private byte[] decrypt(byte[] input) {
		return this.cipher.update(input);
	}

	private byte[] decryptDataCTR(int start, int end) {
		try {
			initCipher(); // reset counter
			decrypt(Arrays.copyOfRange(this.inputFileBytes, start, start + BLOCK_SIZE)); // increment counter because this is the first block in blob
			return decrypt(Arrays.copyOfRange(this.inputFileBytes, start + BLOCK_SIZE, end)); // this is the data
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException e) {
			System.out.println("The following went wrong when trying to decrypt in CTR-mode: " + e.getMessage());
			System.out.println("Exiting...");
			System.exit(0);
		}
		return null;
	}

	/**
	 * Creates a <code>Hiddec</code> with the given arguments from the command line.
	 * 
	 * @param args arguments from the command line.
	 */
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Hiddec hd = new Hiddec(args);

	}
}
