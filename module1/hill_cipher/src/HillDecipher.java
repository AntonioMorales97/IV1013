
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.Rational;
import org.jscience.mathematics.vector.DenseMatrix;
import org.jscience.mathematics.vector.DenseVector;

/**
 * Class representing the hill decipher (decryption) and decrypts a file
 * consisting of space separated integers, produced by the hill cipher, with the
 * help the key that was used in the encryption. The <code>HillDecipher</code>
 * decrypts and writes block by block instead of reading the whole files into
 * memory.
 */
public class HillDecipher {
	private final int SPACE = 32;
	private final int radix;
	private final int blockSize;

	private FileOutputStream outputStream;

	private Scanner scan;

	private DenseMatrix<Rational> matrixKey;

	/**
	 * Creates an instance of <code>HillDecipher</code> with the given arguments.
	 * Initializes the input stream (<code>Scanner</code>) and the output stream
	 * (<code>FileOutputStream</code>).
	 * 
	 * @param radix          the radix (maximum 256)
	 * @param blockSize      the block size (maximum 8)
	 * @param keyFileName    the file name of the file where the key used in the
	 *                       encryption is stored
	 * @param plainFileName  the file name of the file where the integers to be
	 *                       decrypted will be written to
	 * @param cipherFileName the file name of the file where the encrypted integers
	 *                       will be read from
	 */
	public HillDecipher(int radix, int blockSize, String keyFileName, String plainFileName, String cipherFileName) {
		this.radix = radix;
		this.blockSize = blockSize;
		this.matrixKey = setUpMatrixKey(keyFileName);
		setUpScanner(cipherFileName);
		setUpFileOutputStream(plainFileName);
	}

	/**
	 * Starts the decryption by reading, decrypting (decoding), and writing block by
	 * block. Since the encrypted file has padding, the writing of the decrypted
	 * numbers must be done in 3 way: 1st way: The first way is when the first block
	 * is the first and only block, meaning that the the padding needs to be removed
	 * (padding specified in last number). 2nd way: The first block is not the only
	 * block and will write the numbers but skip the space after the last number.
	 * 3rd&4th way: If the block is not the first or the last block it will write
	 * first a space and then the number each iteration. Instead, if the block is
	 * not first but it is the last the padding needs to be removed (padding
	 * specified in the last number). This could mean that the whole last block is
	 * ignored (if it is the dummy padding block) or just some numbers.
	 */
	public void decrypt() {
		if (scan.hasNextInt()) {
			String[] nums = readInBlockNums();
			DenseVector<Rational> plainVec = getDenseVector(nums);
			DenseVector<Rational> decVec = decodeWithInverseKey(plainVec);
			if (scan.hasNextInt()) {
				/* This is indeed first block */
				writeFirstDecodedVectorToPlain(decVec); // no space after last num
			} else {
				/* This is first and last (first and only) block */
				writeFirstAndOnlyVectorToPlain(decVec);
			}
		}
		while (scan.hasNextInt()) {

			String[] nums = readInBlockNums();

			DenseVector<Rational> plainVec = getDenseVector(nums);

			DenseVector<Rational> decVec = decodeWithInverseKey(plainVec);

			if (scan.hasNextInt()) {
				/* Not last vector */
				writeDecodedVectorToPlain(decVec);
			} else {
				/* Last vector, remove padding */
				writeLastDecodedVectorToPlain(decVec);
			}
		}
	}

	private void writeFirstDecodedVectorToPlain(DenseVector<Rational> decVec) {
		int dimension = decVec.getDimension();
		int i = 0;
		for (; i < dimension - 1; i++) {
			try {
				outputStream.write(decVec.get(i).getDividend().toString().getBytes());
				outputStream.write(SPACE);
			} catch (IOException e) {
				System.out.println("Something went wrong when writing first vector to plain file!");
				systemExit();
			}
		}

		try {
			outputStream.write(decVec.get(i).getDividend().toString().getBytes());
		} catch (IOException e) {
			System.out.println("Something went wrong when writing the last number of the first vector to plain file!");
			systemExit();
		}
	}

	private void writeFirstAndOnlyVectorToPlain(DenseVector<Rational> decVec) {
		int dimension = decVec.getDimension();
		int padding = (int) decVec.get(dimension - 1).longValue();
		if (padding > blockSize) {
			System.out.println("Padding is bigger than the block size... Padding can only be {1,...,blockSize}");
			System.out.println("Probably encoded with other key!");
			systemExit();
		}

		int i = 0;
		for (; i < dimension - padding - 1; i++) {
			try {
				outputStream.write(decVec.get(i).getDividend().toString().getBytes());
				outputStream.write(SPACE);
			} catch (IOException e) {
				System.out.println("Something went wrong when writing the first and only vector to plain file!");
				systemExit();
			}
		}

		try {
			outputStream.write(decVec.get(i).getDividend().toString().getBytes());
		} catch (IOException e) {
			System.out.println(
					"Something went wrong when writing the last number of the first and only vector to plain file!");
			systemExit();
		}
	}

	private void writeLastDecodedVectorToPlain(DenseVector<Rational> decVec) {
		int dimension = decVec.getDimension();
		int padding = (int) decVec.get(dimension - 1).longValue();
		if (padding > blockSize) {
			System.out.println("Padding is bigger than the block size... Padding can only be {1,...,blockSize}");
			System.out.println("Probably encoded with other key!");
			systemExit();
		}

		for (int i = 0; i < dimension - padding; i++) {
			try {
				outputStream.write(SPACE);
				outputStream.write(decVec.get(i).getDividend().toString().getBytes());
			} catch (IOException e) {
				System.out.println("Something went wrong when writing the last vector to plain file!");
				systemExit();
			}
		}
	}

	private void writeDecodedVectorToPlain(DenseVector<Rational> decVec) {
		int dimension = decVec.getDimension();
		for (int i = 0; i < dimension; i++) {
			try {
				outputStream.write(SPACE);
				outputStream.write(decVec.get(i).getDividend().toString().getBytes());
			} catch (IOException e) {
				System.out.println("Something went wrong when writing to plain file!");
				systemExit();
			}
		}
	}

	private DenseVector<Rational> decodeWithInverseKey(DenseVector<Rational> block) {
		DenseVector<Rational> multVec = this.matrixKey.times(block);
		int dimension = multVec.getDimension();
		Rational[] modArray = new Rational[dimension];
		for (int i = 0; i < dimension; i++) {
			/* Out-commented does not work, returns 26 % 26 = 26... */
			// modArray[i] =
			// Rational.valueOf(multVec.get(i).getDividend().mod(LargeInteger.valueOf(radix)),
			// LargeInteger.ONE);

			long modNum = multVec.get(i).getDividend().mod(LargeInteger.valueOf(radix)).longValue() % radix;
			modArray[i] = Rational.valueOf(modNum, 1);
		}
		return DenseVector.valueOf(modArray);
	}

	private DenseVector<Rational> getDenseVector(String[] block) {
		Rational[] rationalArray = new Rational[blockSize];
		for (int i = 0; i < blockSize; i++) {
			Rational rational = Rational.valueOf(block[i]);
			if (rational.getDividend().longValue() >= radix) {
				System.out.println("The numbers must be smaller than the radix (" + radix + "). Received number: "
						+ rational.getDividend().longValue());
				systemExit();
			}

			rationalArray[i] = rational;
		}
		return DenseVector.valueOf(rationalArray);
	}

	private String[] readInBlockNums() {
		String[] nums = new String[blockSize];
		int count = 0;
		while (scan.hasNextInt() && count < blockSize) {
			int scannedNum = scan.nextInt();
			if (scannedNum < 0) {
				System.out.println("Negative numbers are not supported! Received: " + scannedNum);
				systemExit();
			}
			nums[count] = Integer.toString(scannedNum);
			count++;
		}

		/* Padding should not be needed since padding is already added in Hill Cipher */
		if (count < blockSize) {
			System.out.println("Not enough numbers in block. This does not come from corresponding Hill Cipher!");
			systemExit();
		}

		return nums;
	}

	private void setUpFileOutputStream(String plainFileName) {
		Path path = Paths.get(plainFileName);
		try {
			Files.deleteIfExists(path);
		} catch (SecurityException e) {
			System.out.println("Could not clean up the plain file due to file permissions!");
			systemExit();
		} catch (IOException e) {
			System.out.println("Something went wrong when trying to clean up plain file at start!");
			systemExit();
		}

		File file = new File(plainFileName);
		boolean append = true;
		try {
			this.outputStream = new FileOutputStream(file, append);
		} catch (FileNotFoundException e) {
			System.out.println("Could not open output stream to cipher file: " + plainFileName);
			systemExit();
		}

	}

	private void setUpScanner(String cipherFileName) {
		File plainFile = new File(cipherFileName);
		try {
			this.scan = new Scanner(plainFile);
		} catch (FileNotFoundException e) {
			System.out.println("Could not open the cipher text file: " + cipherFileName);
			systemExit();
		}
	}

	private DenseMatrix<Rational> setUpMatrixKey(String keyFileName) {
		String keyString = readKeyFileToString(keyFileName);
		DenseMatrix<Rational> matrixKey = buildMatrixKey(keyString);

		return inverseModuloMatrix(matrixKey);
	}

	private DenseMatrix<Rational> inverseModuloMatrix(DenseMatrix<Rational> matrix) {
		Rational det = matrix.determinant();
		if (det.longValue() == 0) {
			System.out.println("The determinant of the key matrix is 0. Cannot inverse!");
			systemExit();
		}
		/*
		 * D = (K^(-1)) mod radix, or [(d^(–1) mod radix) (d*K^(–1)] mod radix, where d
		 * is determinant of K
		 */
		LargeInteger largeIntegerDet = LargeInteger.valueOf(det.longValue());
		Rational invDet = null;
		try {
			invDet = Rational.valueOf(largeIntegerDet.modInverse(LargeInteger.valueOf(radix)), LargeInteger.ONE);
		} catch (ArithmeticException exc) {
			System.out.println("Failed to calculate modular inverse of key determinant for the given radix!");
			System.out.println("Check that the key was generated for the given radix. Determinant must be relatively "
					+ "prime to the radix!");
			systemExit();
		}
		return matrix.inverse().times(det).times(invDet);
	}

	private DenseMatrix<Rational> buildMatrixKey(String keyString) {
		String[] keyArray = keyString.split("\\s+");
		int size = squareSize(keyArray);
		if (size == -1) {
			System.out.println("The read key file does not represent a square matrix!");
			systemExit();
		}

		if (size == 1) {
			System.out.println("The matrix key must be bigger than 1!");
			systemExit();
		}

		if (size != blockSize) {
			System.out.println("The given block size does not correspond to the read in key matrix!");
			System.out.println("Block size is: " + blockSize + ", while the size of what was read in is: " + size);
			systemExit();
		}

		for (int i = 0; i < keyArray.length; i++) {
			int keyNum = Integer.parseInt(keyArray[i]);
			if (keyNum < 0) {
				System.out.println("The key cannot have any negative numbers in its matrix!");
				systemExit();
			}
		}

		Rational[][] matrixKey = new Rational[size][size];
		for (int i = 0; i < size; i++) {
			for (int j = 0; j < size; j++) {
				matrixKey[i][j] = Rational.valueOf(keyArray[i * size + j]);
			}
		}

		return DenseMatrix.valueOf(matrixKey);
	}

	private String readKeyFileToString(String keyFileName) {
		byte[] keyBytes = null;
		try {
			keyBytes = Files.readAllBytes(Paths.get(keyFileName));
		} catch (IOException e) {
			System.out.println("Something went wrong when trying to read the key file: " + keyFileName);
			System.out.println(
					"Check that the file exists and its file permissions. The file cannot be" + " larger than 2GB!");
			e.printStackTrace();
			systemExit();
		}

		return new String(keyBytes);
	}

	private int squareSize(String[] arr) {
		int sqrt = (int) Math.sqrt((double) arr.length);
		if (sqrt * sqrt != arr.length) {
			// Not square
			return -1;
		}
		return sqrt;
	}

	private void systemExit() {
		System.out.println("Exiting Hill Cipher...");
		System.exit(0);
	}

	/**
	 * Creates a <code>HillDecipher</code> and starts decryption accordingly to the
	 * given arguments.
	 * 
	 * @param args args[0] = radix, args[1] = block size, args[2] = key file name,
	 *             args[3] = plain file name, args[4] = cipher file name
	 */
	public static void main(String[] args) {
		if (args.length != 5) {
			System.out.println("Please enter: <radix> <blocksize> <keyfile> <plainfile> <cipherfile>");
			System.exit(0);
		}

		int radix = 0;
		int blockSize = 0;

		try {
			radix = Integer.parseInt(args[0]);
			blockSize = Integer.parseInt(args[1]);
		} catch (NumberFormatException exc) {
			System.out.println("The radix and block size must be numbers!");
			System.exit(0);
		}

		if (radix < 2 || radix > 256) {
			System.out.println("The radix r must be in {2, 3,..., 256}");
			System.exit(0);
		}

		if (blockSize < 3 || blockSize > 8) {
			System.out.println("The block size n must be in {3,...,8}");
			System.exit(0);
		}

		HillDecipher hdc = new HillDecipher(radix, blockSize, args[2], args[3], args[4]);
		hdc.decrypt();
		System.out.println("Hill Decipher Complete");
	}
}
