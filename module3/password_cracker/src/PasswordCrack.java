import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Creates possible passwords from a given dictionary, jcrypts them with the users' salt, and tries to crack all the passwords.
 * Mangles up to 3 times (and mangles for append and prepend mangles) before going for a brute force attempt.
 *
 * @author Antonio
 *
 */
public class PasswordCrack {
    
    private class User {
        private String username;
        private String fullName;
        private String firstName;
        private String lastName;
        private String middleName;
        @SuppressWarnings("unused")
        private String password;
        private String salt;
        private String encryptedPasswordData;
        
        User (String userInfo){    
            String[] info = userInfo.split(":");
            if(info.length != 7) {
                System.out.println("Wrong format for user info!");
                System.out.println("Expected: account:encrypted password data:uid:gid:GCOS-field:homedir:shell");
                System.out.println("Received: " + userInfo);
                System.out.println("Exiting...");
                System.exit(0);
            }
            
            this.username = info[0];
            
            this.encryptedPasswordData = info[1];
            if(this.encryptedPasswordData.length() != 13) {
                System.out.println("Wrong format for encrypted password data!");
                System.out.println("Expected 13 characters (2 for salt and 11 for password encryption).");
                System.out.println("Received: " + encryptedPasswordData + " for: " + username);
                System.out.println("Exiting...");
                System.exit(0);
            }
            
            this.salt = this.encryptedPasswordData.substring(0, 2);
            this.password = this.encryptedPasswordData.substring(2);
            
            this.fullName = info[4];
            
            String[] names = this.fullName.split(" ");
            this.firstName = names.length > 0 ? names[0] : null;
            if(this.firstName != null)
                if(this.firstName.charAt(this.firstName.length() - 1) == '.')
                    this.firstName = this.firstName.substring(0, this.firstName.length() - 1);
            this.middleName = names.length == 3 ? names[1] : null;
            if(this.middleName != null)
                if(this.middleName.charAt(this.middleName.length() - 1) == '.')
                    this.middleName = this.middleName.substring(0, this.middleName.length() - 1);
            if(names.length > 1)
                this.lastName = names.length == 3 ? names[2] : names[1];
            
        }
    }
    
    private List<User> users;
    private List<String> dict;
    
    /**
     * Creates the password cracker and tries to crack the passwords by trying to mangling words in the dictionary. If the 
     * mangling of words in the dictionary fails (i.e. uncracked passwords are left), the password cracker will try with brute force.
     * @param dictionaryFile
     * @param userInfoFile
     */
    public PasswordCrack(String dictionaryFile, String userInfoFile) {
        this.users = new CopyOnWriteArrayList<>();
        readInUsers(userInfoFile);
        if(this.users.isEmpty()) {
            //System.out.println("No users added. Nothing to crack.");
            //System.out.println("Exiting...");
            System.exit(0);
        }
        
        this.dict = new ArrayList<>();
        addUserInfoNamesToDict();
        addCommonPasswordsToDict();
        getDictionary(dictionaryFile);
        
        passwordCrack();
        if(!this.users.isEmpty()) {
            //should always come here if passwordCrack failed
            startBrute();
        }
        //Will not come here until trying ALL possibilities for 8 chars long password
        //Brute failed for 8 characters (alphanumerical chars)
    }
    
    private void addCommonPasswordsToDict() {
        String[] commonPasswords = {
        		"111111", "222222", "333333", "444444", "555555", "666666", "777777",
        		"888888", "999999", "123123", "123456", "1234567890", "qwerty", "starwars",
        		"asdfg", "zxcvbnm", "1q2w3e", "iloveyou", "12345", "12345678", "1234567", "password"
        };
        for(String pw : commonPasswords)
        	this.dict.add(pw);
    }
    
    private void addUserInfoNamesToDict() {
        for(User user : this.users) {
            this.dict.add(user.username);
            
            if(user.firstName != null) {
                this.dict.add(user.firstName);
                this.dict.add(user.firstName + user.firstName);
                this.dict.add(user.username + user.firstName);
                this.dict.add(user.firstName + user.username);
            }
                
            if(user.middleName != null) {
                this.dict.add(user.middleName);
                this.dict.add(user.middleName + user.middleName);
                this.dict.add(user.username + user.middleName);
                this.dict.add(user.middleName + user.username);
            }
                
            if(user.lastName != null) {
                this.dict.add(user.lastName);
                this.dict.add(user.lastName + user.lastName);
                this.dict.add(user.username + user.lastName);
                this.dict.add(user.lastName + user.username);
            }
            
            if(user.firstName != null && user.middleName != null && user.lastName != null) {
                this.dict.add(user.firstName + user.middleName + user.lastName);
                this.dict.add(user.firstName + user.lastName + user.middleName);
                this.dict.add(user.lastName + user.firstName + user.middleName);
                this.dict.add(user.lastName + user.middleName + user.firstName);
                this.dict.add(user.middleName + user.firstName + user.lastName);
                this.dict.add(user.middleName + user.lastName + user.firstName);
            }
            
            if(user.firstName != null && user.lastName != null) {
                this.dict.add(user.firstName + user.lastName);
                this.dict.add(user.lastName + user.firstName);
            }
            
            if(user.firstName != null && user.middleName != null) {
                this.dict.add(user.firstName + user.middleName);
                this.dict.add(user.middleName + user.firstName);
            }
            
            if(user.middleName != null && user.lastName != null) {
                this.dict.add(user.middleName + user.lastName);
                this.dict.add(user.lastName + user.middleName);
            }    
        }
    }
    
    private void readInUsers(String userFileName) {
        List<String> userInfoLines = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(userFileName));
            String userInfoLine = null;
            try {
                while((userInfoLine = reader.readLine()) != null) {
                    userInfoLines.add(userInfoLine);
                }
            } catch (IOException e) {
                System.out.println("Got an IO exception. Could not read line in file: " + userFileName);
                System.out.println("Check file permissions!");
                System.exit(0);
            }
            try {
                reader.close();
            } catch (IOException e) {
                System.out.println("Got an IO exception when trying to close file: " + userFileName);
                System.out.println("Exiting..."); //or continue?
                System.exit(0);
            }
        } catch (FileNotFoundException e) {
            System.out.println("The file: " + userFileName + ", was not found or could not be found!");
            System.out.println("Check the path and file permissions.");
            System.out.println("Exiting...");
            System.exit(0);
        }
        
        for(String userInfoLine : userInfoLines)
            this.users.add(new User(userInfoLine));
        
    }
    
    private void getDictionary(String dictionaryFileName) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(dictionaryFileName));
            String passwordLine = null;
            try {
                while((passwordLine = reader.readLine()) != null) {
                    this.dict.add(passwordLine);
                }
            } catch (IOException e) {
                System.out.println("Got an IO exception. Could not read line in file: " + dictionaryFileName);
                System.out.println("Check file permissions!");
                System.exit(0);
            }
            try {
                reader.close();
            } catch (IOException e) {
                System.out.println("Got an IO exception when trying to close file: " + dictionaryFileName);
                System.out.println("Exiting..."); //or continue?
                System.exit(0);
            }
        } catch (FileNotFoundException e) {
            System.out.println("The file: " + dictionaryFileName + ", was not found or could not be found!");
            System.out.println("Check the path and file permissions.");
            System.out.println("Exiting...");
            System.exit(0);
        }
    }
    
    private void passwordCrack() {
        //No mangle
        CompletableFuture<Void> noMangle = CompletableFuture.runAsync(() -> {
            for(String str : this.dict)
                compareWordToPass(str);
        });
        
        CompletableFuture<Void> oneMangle = CompletableFuture.runAsync(() -> {
          //One mangle
            for(String str : this.dict) {
                for(int i = 1; i <= 12; i++) {
                    compareWordToPass(simpleMangleString(i, str));
                }
            }
        });
        
        //Two mangle
        CompletableFuture<Void> twoMangle = CompletableFuture.runAsync(() -> {  
            for(String str : this.dict) {
                for(int i = 1; i <= 12; i++) {
                    String firstMangle = simpleMangleString(i, str);
                    for(int j = 1; j <= 12; j++) {
                        compareWordToPass(simpleMangleString(j, firstMangle));
                    }
                }
                 
            }
        });
        
      //Three mangle
        CompletableFuture<Void> threeMangle = CompletableFuture.runAsync(() -> { 
            for(String str : this.dict) {
                for(int i = 1; i <= 12; i++) {
                    String firstMangle = simpleMangleString(i, str);
                    for(int j = 1; j <= 12; j++) {
                        String secondMangle = simpleMangleString(j, firstMangle);
                        for(int k = 1; k <= 12; k++) {
                            compareWordToPass(simpleMangleString(k, secondMangle));
                        }
                    }
                }     
            }
        });
        
        //Prepend and append (+ two mangle)
        CompletableFuture<Void> prependAppend = CompletableFuture.runAsync(() -> {
            for(String str : this.dict) {
                for(String prepended : prependOne(str))
                    compareWordToPass(prepended);
                for(String appended : appendOne(str))
                    compareWordToPass(appended);
            }
            for(String s : this.dict) {     
                for(String str : prependOne(s)) {
                    for(int i = 1; i <= 12; i++) {
                        compareWordToPass(simpleMangleString(1, str));
                    }
                }
                
                for(String str : appendOne(s)) {
                    for(int i = 1; i <= 12; i++) {
                        compareWordToPass(simpleMangleString(1, str));
                    }
                }      
            }
        });
        
        //three mangle append and prepend with reverse string (ultra slow)
        CompletableFuture<Void> threeMangleAppendPrepend = CompletableFuture.runAsync(() -> { 
            for(String s : this.dict) {
                for(String str : prependOne(reverseString(s))) {
                    compareWordToPass(str);
                    for(int i = 1; i <= 12; i++) {
                        compareWordToPass(simpleMangleString(i, str));
                    }  
                }
                
                for(String str : appendOne(reverseString(s))) {
                    compareWordToPass(str);
                    for(int i = 1; i <= 12; i++) {
                        compareWordToPass(simpleMangleString(i, str));
                    }
                }
            }
        });
        
        CompletableFuture.allOf(noMangle, oneMangle, twoMangle, threeMangle, prependAppend, threeMangleAppendPrepend).join();
    }
    
    //currently support 12 different "simple" mangles
    private String simpleMangleString(int mangleIdx, String word) {
        switch (mangleIdx) {
        case 1:
            return deleteFirstChar(word);
        case 2:
            return deleteLastChar(word);
        case 3:
            return reverseString(word);
        case 4:
            return duplicateString(word);
        case 5:
            return reflectString(word);
        case 6:
            return reflectStringFirstReverse(word);
        case 7:
            return upperCase(word);
        case 8:
            return lowerCase(word);
        case 9:
            return capitalize(word);
        case 10:
            return nCapitalize(word);
        case 11:
            return toggleStartWithFirst(word);
        case 12:
            return toggleStartWithSecond(word);
        default:
            return "";
        }
    }
    
    private void compareWordToPass(String word) {
        List<User> remove = new ArrayList<>();
        for(User user : this.users) {
            if(user.encryptedPasswordData.compareTo(jcrypt.crypt(user.salt, word)) == 0) {
                System.out.println(word);
                remove.add(user); 
            }
        }
        for(User user : remove)
            this.users.remove(user);
        
        if(this.users.isEmpty())
            System.exit(0);
    }
    
    private List<String> prependOne(String word){
        List<String> prepended = new ArrayList<>();
        StringBuilder tempSb = new StringBuilder();
        for(int i = 48; i <= 57; i++) {
            tempSb.setLength(0);
            tempSb.append((char) i).append(word);
            prepended.add(tempSb.toString());
        }
        for(int i = 65; i <= 90; i++) {
            tempSb.setLength(0);
            tempSb.append((char) i).append(word);
            prepended.add(tempSb.toString());
        }
        
        for(int i = 97; i <= 122; i++) {
            tempSb.setLength(0);
            tempSb.append((char) i).append(word);
            prepended.add(tempSb.toString());
        }
        return prepended;
    }
    
    private List<String> appendOne(String word){
        List<String> appended = new ArrayList<>();
        if(word.length() >= 8)
            return appended;
        StringBuilder tempSb = new StringBuilder();
        tempSb.append(word);
        int originalLength = tempSb.length();
        for(int i = 48; i <= 57; i++) {
            tempSb.append((char) i);
            appended.add(tempSb.toString());
            tempSb.setLength(originalLength);
        }
        for(int i = 65; i <= 90; i++) {
            tempSb.append((char) i);
            appended.add(tempSb.toString());
            tempSb.setLength(originalLength);
        }
        
        for(int i = 97; i <= 122; i++) {
            tempSb.append((char) i);
            appended.add(tempSb.toString());
            tempSb.setLength(originalLength);
        }   
        return appended;
    }
    
    private String deleteFirstChar(String word) {
        if(word.length() == 0)
            return word;
        return word.substring(1);
    }
    
    private String deleteLastChar(String word) {
        if(word.length() > 8)
            return word;
        if(word.length() == 0)
            return word;
        return word.substring(0, word.length() - 1);
    }
    
    private String reverseString(String word) {
        return new StringBuilder(word).reverse().toString();
    }
    
    private String duplicateString(String word) {
        if(word.length() >= 8)
            return word;
        return new StringBuilder(word).append(word).toString();
    }
    
    private String reflectString(String word) {
        if(word.length() >= 8)
            return word;
        StringBuilder sb = new StringBuilder(word);
        StringBuilder rev = new StringBuilder(word).reverse();
        sb.append(rev);
        return sb.toString();
    }
    
    private String reflectStringFirstReverse(String word) {
        if(word.length() >= 8)
            return new StringBuilder(word).reverse().toString();
        StringBuilder sb = new StringBuilder(word);
        StringBuilder rev = new StringBuilder(word).reverse();
        rev.append(sb);
        return rev.toString();
    }
    
    private String upperCase(String word) {
        return word.toUpperCase();
    }
    
    private String lowerCase(String word) {
        return word.toLowerCase();
    }
    
    private String capitalize(String word) {
        if(word.length() == 0)
            return word;
        int charIdx = (int) word.charAt(0);
        if(charIdx < 97)
            return word;
        StringBuilder sb = new StringBuilder(word);
        sb.deleteCharAt(0);
        sb.insert(0, (char)(charIdx - 32));
        return sb.toString();
    }
    
    private String nCapitalize(String word) {
        if(word.length() == 0)
            return word;
        int charIdx = (int) word.charAt(0);
        if(charIdx >= 65 && charIdx <= 90)
            charIdx += 32;
        StringBuilder sb = new StringBuilder();
        sb.insert(0, (char) charIdx);
        sb.append(upperCase(word.substring(1, word.length())));
        return sb.toString();
    }
    
    private String toggleStartWithFirst(String word) {
        StringBuilder sb = new StringBuilder();
        sb.setLength(0);
        String upperCase = upperCase(word);
        String lowerCase = lowerCase(word);
        for(int i = 0; i < word.length(); i++) {
            if (i % 2 == 0) {
                sb.append(upperCase.charAt(i));
            } else {
                sb.append(lowerCase.charAt(i));
            }
        }
        return sb.toString();
    }
    
    private String toggleStartWithSecond(String word) {
        StringBuilder sb = new StringBuilder();
        sb.setLength(0);
        String upperCase = upperCase(word);
        String lowerCase = lowerCase(word);
        for(int i = 0; i < word.length(); i++) {
            if (i % 2 == 1) {
                sb.append(upperCase.charAt(i));
            } else {
                sb.append(lowerCase.charAt(i));
            }
        }
        return sb.toString();
    }
    
    /****************************************BRUTE FORCE**********************************************************/
    private void startBrute(){    
        int cores = Runtime.getRuntime().availableProcessors();
        int passwordLength = 8;
        if(cores <= 1) {
            brute(1); //recursive call for single core
            return; //just in case
        }
        
        ExecutorService executorService = Executors.newFixedThreadPool(cores);
        List<Callable<Object>> todo = new ArrayList<>();
        int currPasswordLength = 1;
        for(int i = 0; i < cores && currPasswordLength <= passwordLength; i++) {
            char[] attempt = new char[currPasswordLength];
            todo.add(Executors.callable(new BruteForce(currPasswordLength, attempt)));
            currPasswordLength++;
        }
        
        try {
            executorService.invokeAll(todo);
        } catch (InterruptedException e) {
            System.out.println("1. Got interrupted when trying to wait for all threads to finish...");
            System.out.println("Exiting...");
            System.exit(0);
        }
        
        if(currPasswordLength > 8) {
            System.exit(0);
        }
        
        todo = new ArrayList<>();
        for(int i = 0; i < cores && currPasswordLength <= 8; i++) {
            char[] attempt = new char[currPasswordLength];
            todo.add(Executors.callable(new BruteForce(currPasswordLength, attempt)));
            currPasswordLength++;
        }
        
        try {
            executorService.invokeAll(todo);
        } catch (InterruptedException e) {
            System.out.println("2. Got interrupted when trying to wait for all threads to finish...");
            System.out.println("Exiting...");
            System.exit(0);
        }
        
        if(currPasswordLength > 8) {
            System.exit(0);
        }
        
        todo = new ArrayList<>();
        for(int i = 0; i < cores && currPasswordLength <= 8; i++) {
            char[] attempt = new char[currPasswordLength];
            todo.add(Executors.callable(new BruteForce(currPasswordLength, attempt)));
            currPasswordLength++;
        }
        
        try {
            executorService.invokeAll(todo);
        } catch (InterruptedException e) {
            System.out.println("3. Got interrupted when trying to wait for all threads to finish...");
            System.out.println("Exiting...");
            System.exit(0);
        }
        
        if(currPasswordLength > 8) {
            System.exit(0);
        }
        
        todo = new ArrayList<>();
        for(int i = 0; i < cores && currPasswordLength <= 8; i++) {
            char[] attempt = new char[currPasswordLength];
            todo.add(Executors.callable(new BruteForce(currPasswordLength, attempt)));
            currPasswordLength++;
        }
        
        if(currPasswordLength > 8) {
            System.exit(0);
        }
        
        try {
            executorService.invokeAll(todo);
        } catch (InterruptedException e) {
            System.out.println("4. Got interrupted when trying to wait for all threads to finish...");
            System.out.println("Exiting...");
            System.exit(0);
        }
        
        executorService.shutdown();
        System.exit(0);
    }
    
    private void bruteCurrString(int idx, int ch, char[] attempt) {
        if (ch <= 9) {
            attempt[idx] = (char) (ch+48);
        } else if (ch <= 35) {
            attempt[idx] = (char) (ch+55);
        } else {
            attempt[idx] = (char) (ch+61);
        }
        compareWordToPass(new String(attempt));
    }
    
    private void brute(int i, char[] attempt){
        if(i <= 0)
            return;
        for(int p = 0; p < 62; p++){
            bruteCurrString(i - 1, p, attempt);
            brute(i - 1, attempt);
        }
    }
    
    private void brute(int i){
        if(i <= 0) return;
        if(i > 8) return;
        
        char[] attempt = new char[i];
        brute(i, attempt);
        brute(i + 1);
    }
    
    private class BruteForce implements Runnable {
        private char[] attempt;
        private int n;
        
        BruteForce(int n, char[] attempt){
            this.attempt = attempt;
            this.n = n;
        }

        @Override
        public void run() {
            brute(this.n, this.attempt);
        }
        
    }
    /*******************************************************************************************/
    /*
    private void printList(List<User> list) {
        for(User user : list) {
            System.out.println(user.middleName);
        }
    }
    
    private void printAlreadyFound() {
        List<String> pass = new ArrayList<>();
        pass.add("geoffrey");
        pass.add("Harry");
        pass.add("balding");
        pass.add("manes");
        pass.add("monkey");
        pass.add("spiky");
        pass.add("aRABELLA");
        pass.add("roadness");
        pass.add("saynub");
        pass.add("hOWLER");
        pass.add("RENDERS");
        pass.add("sPiEs");
        pass.add("noissimbus");
        pass.add("yearyear");
        pass.add("wchimlas");
        pass.add("CITARCOTSIRAITNA");
        pass.add("666666")
        
        for(String str : pass)
            for(User user : this.users) {
                if(user.encryptedPasswordData.compareTo(jcrypt.crypt(user.salt, str)) == 0)
                    System.out.println(user.username);
            }
    }
    */
    
    /**
     * Creates the <code>PasswordCrack</code> with the given dictionary file and the password file. Starts
     * cracking the password immediately.
     * @param args args[0]: the path to the dictionary file. args[1]: the path to the password file.
     */
    public static void main(String[] args) {
        if(args.length != 2) {
            System.out.println("Expects two arguments in the form: <path to dictionary file> <path to password file)>");
            System.out.println("If there is no dictionary file it is possible for it to be empty, as long as the file exists."
                    + " Then brute force will run much sooner.");
            System.out.println("The password file holds the user information (e.g. encrypted password). If the file is empty, i.e. nothing"
                    + " to crack, the program will exit after reading the empty file.");
            System.out.println("Please try again!");
            System.exit(0);
        }
        @SuppressWarnings("unused")
        PasswordCrack pc = new PasswordCrack(args[0], args[1]);
    }

}
