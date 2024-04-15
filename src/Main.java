public class Main {
   public static void main(String [] args_cmd) throws java.lang.Exception {
      Arguments args = Arguments.parse(args_cmd);

      // We use buffered file streams so massive files don't have to be loaded
      // into memory all at once, which also avoids reading over the whole file
      // twice, once for the memory copy and another to run the algorithm.
      java.io.BufferedInputStream input = new java.io.BufferedInputStream(new java.io.FileInputStream(args.input));
      java.io.BufferedOutputStream output = new java.io.BufferedOutputStream(new java.io.FileOutputStream(args.output));

      String password = readPassword(args);

      byte [] secrets = deriveSecrets(password);

      Cryptor cryptor = chooseCryptor(args.algorithm);

      // TODO: File hashing.  When encrypting, calculate the file hash and
      // store it along with the hash length at the start of the encrypted data.
      // When decrypting, attempt to read the file hash and compare against the
      // final decrypted data.  This provides protection in the case of file
      // corruption, or more likely, different encryption algorithms being used
      // to encrypt and decrypt or an invalid password.  Otherwise, the file
      // decrypted file data will be nonsense.

      switch (args.mode) {
      case Encrypt:
         cryptor.encrypt(input, output, secrets);
         break;

      case Decrypt:
         cryptor.decrypt(input, output, secrets);
         break;
      }

      return;
   }

   // Attempts to read plaintext password from the source specified in arguments.
   private static String readPassword(Arguments args) throws java.lang.Exception {
      String file_path = args.secrets;
      if (file_path == null) {
         return readPasswordPrompt();
      }

      return readPasswordFile(file_path);
   }

   // Reads password from the user using a terminal prompt.
   private static String readPasswordPrompt() throws ConsoleUnavailableException {
      java.io.Console console = System.console();
      if (console == null) {
         throw new ConsoleUnavailableException("console unavailable");
      }

      char [] data = console.readPassword("Please enter the password: ");

      return new String(data);
   }

   // Reads password from a user-specified file path.
   private static String readPasswordFile(String path) throws java.lang.Exception {
      byte [] bytes = readFileBytes(path);

      return new String(bytes);
   }

   // This is only available in Java 11...
   private static byte [] readFileBytes(String path) throws java.lang.Exception {
      final int BUFFER_SIZE = 1024;

      java.io.FileInputStream stream_input = new java.io.FileInputStream(new java.io.File(path));

      java.io.ByteArrayOutputStream stream_output = new java.io.ByteArrayOutputStream();

      int bytes_read_count;
      byte [] bytes_read_buffer = new byte[BUFFER_SIZE];

      while ((bytes_read_count = stream_input.read(bytes_read_buffer, 0, BUFFER_SIZE)) != -1) {
         stream_output.write(bytes_read_buffer, 0, bytes_read_count);
      }

      byte [] bytes = stream_output.toByteArray();

      return bytes;
   }

   private static final java.util.HashMap<Cryptor.Algorithm, Cryptor> MAP_CRYPTOR = new java.util.HashMap<Cryptor.Algorithm, Cryptor>() {{
      put(Cryptor.Algorithm.Plaintext,       new Cryptor.Plaintext());
      put(Cryptor.Algorithm.ConstantOffset,  new Cryptor.ConstantOffset());
      put(Cryptor.Algorithm.AES256,          new Cryptor.AES256());
   }};

   private static Cryptor chooseCryptor(Cryptor.Algorithm algorithm) {
      return MAP_CRYPTOR.get(algorithm);
   }

   private static byte [] deriveSecrets(String password) {
      // This will use standard salting + hashing, which works in the following
      // way:
      //
      // 1. We append some constant string value to the password, which is
      // called 'salting'.  This protects the password from 'rainbow tables',
      // which are essentially pre-computer brute-force attacks.
      //
      // 2. We run a hashing algorithm to convert the password into a list of
      // bytes which protects encrypted data from sharing similar keys with
      // similar passwords, if that makes sense.
      //
      // The output byte data will be used as the key, or as we call it, secrets
      // used to encrypt/decrypt data.
      //
      // Also worth noting that this function must have the same output for
      // each unique input across versions.  Basically, once implemented, the
      // output can never change, otherwise it will invalidate encryption keys
      // for older files, thus making them impossible to decrypt.

      final String PASSWORD_SALT = "### ENCRYPT 2024 ###";

      String password_salted = password + PASSWORD_SALT;

      byte [] password_salted_bytes = password_salted.getBytes();

      return Sha512.hash(password_salted_bytes);
   }
}

class ConsoleUnavailableException extends java.lang.Exception {
   public ConsoleUnavailableException(String err) {
      super(err);
   }
}

