
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
 * Class representing the Hill Cipher (encryption) and can encrypt a file
 * consisting of space separated integers (representing other value i.e.
 * encoded) with a key and which will be written to a specified file. The
 * <code>HillCipher</code> reads block by block instead of reading whole files
 * and storing it in memory.
 */
public class HillCipher {
	private final int SPACE = 32;
	private final int radix;
	private final int blockSize;

	private FileOutputStream outputStream;
	private Scanner scan;
	private DenseMatrix<Rational> matrixKey;
	private boolean needDummyPaddColumn = false;

	/**
	 * Creates an instance of <code>HillCipher</code> with the given arguments.
	 * Initializes the input stream (<code>Scanner</code>) and the output stream
	 * (<code>FileOutputStream</code>).
	 * 
	 * @param radix          the radix (maximum 256)
	 * @param blockSize      the block size (maximum 8)
	 * @param keyFileName    the file name of the file where the key for the
	 *                       encryption will be read from
	 * @param plainFileName  the file name of the file where the integers to be
	 *                       encrypted will be read from
	 * @param cipherFileName the file name of the file where the encrypted integers
	 *                       will be written to
	 */
	public HillCipher(int radix, int blockSize, String keyFileName, String plainFileName, String cipherFileName) {
		this.radix = radix;
		this.blockSize = blockSize;
		this.matrixKey = setUpMatrixKey(keyFileName);

		setUpScanner(plainFileName);

		setUpFileOutputStream(cipherFileName);

		// encrypt();
	}

	/**
	 * Reads, encrypts, and writes block by block. Uses the <code>Scanner</code> to
	 * read in the blocks, the matrix key to encrypt, and the
	 * <code>FileOutputStream</code> to write. If no padding is needed, i.e. the
	 * number of blocks is a multiple of the block size, a dummy padding column
	 * (block) with the block size is written at the end for decryption which will
	 * remove the padding by reading its last value. For example, if the block size
	 * is 3 and the a dummy padding column is added it will consist of [3, 3, 3],
	 * meaning that the last 3 integers will be ignored in decryption (i.e the whole
	 * dummy). Instead, if padding smaller than the block size is needed, it will be
	 * included in the last block itself. For example, if the last block/vector only
	 * holds: [1, 2, X], where X is the needed padding of a block size 3, the final
	 * block that will be written will be: [1, 2, 1], meaning that the last 1
	 * integer will be ignore, i.e. the added padding.
	 */
	public void encrypt() {
		while (scan.hasNextInt()) {

			String[] nums = readInBlockNums();

			DenseVector<Rational> plainVec = getDenseVector(nums);

			DenseVector<Rational> encVec = encodeWithKey(plainVec);

			writeEncodedVectorToCipher(encVec);
		}

		if (this.needDummyPaddColumn) {
			writeDummyPaddColumn();
		}
	}

	private void writeDummyPaddColumn() {
		String padding = Integer.toString(blockSize);
		Rational[] dummyArr = new Rational[blockSize];
		for (int i = 0; i < blockSize; i++) {
			Rational rationalPadding = Rational.valueOf(padding);
			if (rationalPadding.getDividend().longValue() >= radix) {
				System.out.println("The padding must be smaller than the radix (" + radix + "). Received padding: "
						+ rationalPadding.getDividend().longValue());
				systemExit();
			}

			dummyArr[i] = rationalPadding;
		}

		try {
			outputStream.write(SPACE);
		} catch (IOException exc) {
			System.out.println("Something went wrong when writing space before dummy vector to cipher file!");
			systemExit();
		}

		DenseVector<Rational> dummyVec = DenseVector.valueOf(dummyArr);
		dummyVec = encodeWithKey(dummyVec);
		int i = 0;
		for (; i < blockSize - 1; i++) {
			try {
				outputStream.write(dummyVec.get(i).getDividend().toString().getBytes());
				outputStream.write(SPACE);
			} catch (IOException exc) {
				System.out.println("Something went wrong when writing the dummy vector to cipher file!");
				systemExit();
			}
		}

		try {
			outputStream.write(dummyVec.get(i).getDividend().toString().getBytes());
		} catch (IOException e) {
			System.out.println("Something went wrong when writing the last number of dummy vector to cipher file!");
			systemExit();
		}
	}

	private void writeEncodedVectorToCipher(DenseVector<Rational> encVec) {
		int dimension = encVec.getDimension();
		int i = 0;
		for (; i < dimension - 1; i++) {
			try {
				outputStream.write(encVec.get(i).getDividend().toString().getBytes());
				outputStream.write(SPACE);
			} catch (IOException e) {
				System.out.println("Something went wrong when writing to cipher file!");
				systemExit();
			}
		}

		try {
			outputStream.write(encVec.get(i).getDividend().toString().getBytes());
			if (scan.hasNextInt()) {
				outputStream.write(SPACE);
			}
		} catch (IOException e) {
			System.out.println("Something went wrong when writing the last number to cipher file!");
			systemExit();
		}

	}

	private DenseVector<Rational> encodeWithKey(DenseVector<Rational> block) {
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

		/*
		 * Check if this is last and if we need a dummy padding column at the end since
		 * no padding was needed
		 */
		if (!scan.hasNextInt() && count == blockSize) {
			this.needDummyPaddColumn = true;
		}

		/* Padding needed */
		if (count < blockSize) {
			int padding = blockSize - count;
			while (count < blockSize) {
				nums[count++] = Integer.toString(padding);
			}
		}

		return nums;
	}

	private void setUpFileOutputStream(String cipherFileName) {
		Path path = Paths.get(cipherFileName);
		try {
			Files.deleteIfExists(path);
		} catch (SecurityException e) {
			System.out.println("Could not clean up the cipher file due to file permissions!");
			systemExit();
		} catch (IOException e) {
			System.out.println("Something went wrong when trying to clean up cipher file at start!");
			systemExit();
		}

		File file = new File(cipherFileName);
		boolean append = true;
		try {
			this.outputStream = new FileOutputStream(file, append);
		} catch (FileNotFoundException e) {
			System.out.println("Could not open output stream to cipher file: " + cipherFileName);
			systemExit();
		}
	}

	private void setUpScanner(String plainFileName) {
		File plainFile = new File(plainFileName);
		try {
			this.scan = new Scanner(plainFile);
		} catch (FileNotFoundException e) {
			System.out.println("Could not open the plain text file: " + plainFileName);
			systemExit();
		}
	}

	private DenseMatrix<Rational> setUpMatrixKey(String keyFileName) {
		String keyString = readKeyFileToString(keyFileName);
		return buildMatrixKey(keyString);
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
	 * Creates the Hill Cipher and starts the encryption with the given arguments.
	 * 
	 * @param args args[0] = radix, args[1] = blocksize, args[2] = key file name,
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

		HillCipher hc = new HillCipher(radix, blockSize, args[2], args[3], args[4]);
		hc.encrypt();
		System.out.println("Hill Cipher Complete");
	}

}
