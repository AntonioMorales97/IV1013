
/**
 * Simple program to count the different bits on two strings (preferably of the
 * same length). Uses the XOR operator and counts the 1's after, i.e the number of different bits
 * since 0 XOR 0 = 0 and 1 XOR 1 = 0.
 */
public class BitComparison {

	private static int numberOfBitDifference(String s1, String s2) {
		if (s1 == null || s2 == null || s1.length() == 0 || s2.length() == 0)
			return 0;
		if (s2.length() < s1.length())
			return numberOfBitDifference(s2, s1);

		byte[] s1ByteArray = s1.getBytes();
		byte[] s2ByteArray = s2.getBytes();
		int numOfDiffBits = 0;
		for (int i = 0; i < s1ByteArray.length; i++) {
			numOfDiffBits += Integer.bitCount(s1ByteArray[i] ^ s2ByteArray[i]);
		}
		return numOfDiffBits;
	}

	/**
	 * Runs the program and prints out the number of different bits between the two
	 * given strings.
	 * 
	 * @param args args[0] String 1, args[1] String 2
	 */
	public static void main(String[] args) {
		if (args.length != 2) {
			System.out.println("Please enter: <String1> <String2>");
			System.exit(0);
		}

		System.out.println(numberOfBitDifference(args[0], args[1]));
	}
}
