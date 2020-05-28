
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Random;

import org.jscience.mathematics.number.LargeInteger;
import org.jscience.mathematics.number.Rational;
import org.jscience.mathematics.vector.DenseMatrix;

/**
 * Class representing the hill cipher key generator. This class will generate a
 * random matrix key of a given size and make it work for a given radix, i.e.
 * the matrix key must be invertible and its determinant must be relatively
 * prime to the radix.
 *
 */
public class HillKeys {
	private final int NEW_LINE = 10;
	private final int SPACE = 32;
	private final int radix;
	private final int blockSize;

	private FileOutputStream outputStream;

	/**
	 * Initializes the <code>HillKeys</code> with the given radix and block size and
	 * sets up a <code>FileOutputStream</code> to the specified file name where the
	 * generated matrix key will be written to.
	 * 
	 * @param radix       the radix (maximum 256)
	 * @param blockSize   the block size (maximum 8)
	 * @param keyFileName the file name where the matrix key will be written to
	 */
	public HillKeys(int radix, int blockSize, String keyFileName) {
		this.radix = radix;
		this.blockSize = blockSize;

		setUpFileOutputStream(keyFileName);
	}

	/**
	 * Generates random matrix keys until a matrix key that satisfies the
	 * requirements is generated (invertible and its determinant is relatively prime
	 * to the radix) and is then written to the key file.
	 */
	public void generateKey() {
		Rational[][] keyArr = new Rational[blockSize][blockSize];
		DenseMatrix<Rational> matrixKey = null;

		/* Until valid matrix key is generated */
		while (true) {
			fillRandomNums(keyArr);

			matrixKey = DenseMatrix.valueOf(keyArr);

			Rational det = matrixKey.determinant();

			if (det.longValue() == 0) {
				continue;
			}

			/* Must work for decryption */
			LargeInteger detInt = LargeInteger.valueOf(det.longValue());
			try {
				detInt.modInverse(LargeInteger.valueOf(radix));
			} catch (ArithmeticException exc) {
				// System.out.println("bad: " + detInt);
				continue;
			}
			// System.out.println("good: " + detInt);
			break;
		}

		writeMatrixKeyToKeyFile(matrixKey);
	}

	private void writeMatrixKeyToKeyFile(DenseMatrix<Rational> matrixKey) {
		for (int i = 0; i < blockSize; i++) {
			for (int j = 0; j < blockSize; j++) {
				try {
					this.outputStream.write(matrixKey.get(i, j).getDividend().toString().getBytes());
					this.outputStream.write(SPACE);
				} catch (IOException e) {
					System.out.println("Something went wrong when writing to key file!");
					systemExit();
				}
			}
			try {
				this.outputStream.write(NEW_LINE);
			} catch (IOException e) {
				System.out.println("Something went wrong when writing to key file!");
				systemExit();
			}
		}
	}

	private void fillRandomNums(Rational[][] m) {
		Random rand = new Random();
		for (int i = 0; i < blockSize; i++) {
			for (int j = 0; j < blockSize; j++) {
				m[i][j] = Rational.valueOf(LargeInteger.valueOf(rand.nextInt(radix)), LargeInteger.ONE);
			}
		}
	}

	private void setUpFileOutputStream(String keyFileName) {
		Path path = Paths.get(keyFileName);
		try {
			Files.deleteIfExists(path);
		} catch (SecurityException e) {
			System.out.println("Could not clean up the cipher file due to file permissions!");
			systemExit();
		} catch (IOException e) {
			System.out.println("Something went wrong when trying to clean up cipher file at start!");
			systemExit();
		}

		File file = new File(keyFileName);
		boolean append = true;
		try {
			this.outputStream = new FileOutputStream(file, append);
		} catch (FileNotFoundException e) {
			System.out.println("Could not open output stream to cipher file: " + keyFileName);
			systemExit();
		}
	}

	private void systemExit() {
		System.out.println("Exiting Hill Cipher...");
		System.exit(0);
	}

	/**
	 * Generates a random matrix key for Hill Cipher and Hill Decipher by running
	 * the <code>HillKeys</code> with the given arguments.
	 * 
	 * @param args args[0] = radix, args[1] = blocksize, args[2] = key file name
	 */
	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println("Please enter: <radix> <blocksize> <keyfile>");
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

		HillKeys hk = new HillKeys(radix, blockSize, args[2]);
		hk.generateKey();
		System.out.println("Hill Keys Complete");
	}

}
