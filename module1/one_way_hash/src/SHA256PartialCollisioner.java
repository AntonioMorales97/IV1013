import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple class that tries to find a partial collision (currently the first 24 bits) of a digested
 * message digested with a hard coded algorithm (currently SHA-256) using brute force.
 *
 */
public class SHA256PartialCollisioner {

	private MessageDigest messageDigest;
    private final String textEncoding = "UTF-8";
    private final String digestAlgorithm = "SHA-256";
    
    /**
     * Creates an instance of this class with the hard coded configurations.
     */
    public SHA256PartialCollisioner() {
        try {
            this.messageDigest = MessageDigest.getInstance(digestAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("The given algorithm: " + digestAlgorithm + ", could not be found!");
            System.exit(0);
        }
    }
    
    
    /**
     * Tries to find a partial collision for the first 24 bits of a digest (hash value) of a given
     * message using the digest algorithm of this instance (SHA-256). It tries to do so by
     * digesting (with the same algorithm) a counter that keeps increasing until such collision
     * is found.
     * 
     * @param msg the message to be digested and brute-force attacked (for the 24 first bits)
     */
    public void bruteForce24FirstBits(String msg) {
        byte[] msgDigest = generateDigest(msg);
        
        long counter = 0;
        System.out.println("The brute force attack is about to start. This might take a while!");
        System.out.println("Starting brute force attack!");
        while(true) {
            byte[] bruteDigest = generateDigest(Long.toString(counter));
            
            //compare first 24 bits (i.e. 3 first bytes)
            if(msgDigest[0] == bruteDigest[0] && msgDigest[1] == bruteDigest[1] && msgDigest[2] == bruteDigest[2]) {
                printResult(counter + 1, msg, msgDigest, bruteDigest);
                break;
            }
            counter++;
        }
    }
    
    private byte[] generateDigest(String msg) {
        byte[] msgBytes = null;
        try {
            msgBytes = msg.getBytes(this.textEncoding);
        } catch (UnsupportedEncodingException e) {
            System.out.println("The encoding: " + this.textEncoding + ", is not supported!");
            System.exit(0);
        }
        this.messageDigest.update(msgBytes);
        return this.messageDigest.digest();
    }
    
    private void printResult(long attempts, String inputText, byte[] inputDigest, byte[] bruteDigest) {
        System.out.println();
        System.out.println("Found a partial collision in the first 24 bits in the #" + attempts + " trial!");
        printDigest(inputText, inputDigest);
        System.out.println("The brute digest (by digesting the counter: " + (attempts - 1) + " using the same digest algorithm) is:");
        for(int i = 0; i < bruteDigest.length; i++) 
            System.out.format("%02x", bruteDigest[i] & 0xFF);
        System.out.println();
    }
    
    private void printDigest(String inputText, byte[] digest) {
        System.out.println("Digest for the message \"" + inputText +"\", using " + this.digestAlgorithm + " is:");
        for (int i = 0; i < digest.length; i++)
            System.out.format("%02x", digest[i] & 0xFF);
        System.out.println();
    }
    
    /**
     * Runs the partial collisioner to find a partial collision for the 24 first bits of a digest of
     * the given message. The digest algorithm is hard coded to SHA-256.
     * 
     * @param args args[0] the message to be digested.
     */
    public static void main(String[] args) {
        if(args.length != 1) {
            System.out.println("Please enter: <String>");
            System.out.println("The string must be surrounded by \"\", for example: \"No way\"");
            System.exit(0);
        }
        
        SHA256PartialCollisioner collisioner = new SHA256PartialCollisioner();
        collisioner.bruteForce24FirstBits(args[0]);    
    }

}
