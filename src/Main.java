public class Main {
   public static void main(String [] args_cmd) throws java.lang.Exception {
      Arguments args = Arguments.parse(args_cmd);

      // We use buffered file streams so massive files don't have to be loaded
      // into memory all at once, which also avoids reading over the whole file
      // twice, once for the memory copy and another to run the algorithm.
      java.io.BufferedInputStream input = new java.io.BufferedInputStream(new java.io.FileInputStream(args.input));
      java.io.BufferedOutputStream output = new java.io.BufferedOutputStream(new java.io.FileOutputStream(args.output));

      String password = readPassword(args);

      byte [] secrets      = deriveSecrets(password);
      byte [] secrets_hash = deriveSecretsHash(secrets);

      Cryptor cryptor;
      switch (args.mode) {
      case Encrypt:
         writeHeader(output, args.algorithm, secrets_hash);
         cryptor = chooseCryptor(args.algorithm);

         cryptor.encrypt(input, output, secrets);
         break;

      case Decrypt:
         Cryptor.Algorithm algorithm = readAndVerifyHeader(input, secrets_hash);
         cryptor = chooseCryptor(algorithm);

         cryptor.decrypt(input, output, secrets);
         break;
      }

      input.close();
      output.close();

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

      Hasher hasher = new Hasher.Sha512();

      byte [] hash = hasher.digest(password_salted_bytes);

      return hash;
   }

   // Runs another round of salting+hashing to hash the encryption secrets
   // for use with the file header (used for checking passwords).
   private static byte [] deriveSecretsHash(byte [] secrets) {
      final byte [] SECRETS_SALT = "### ENCRYPT 2024 ###".getBytes();

      byte [] secrets_salted = new byte [secrets.length + SECRETS_SALT.length];
      System.arraycopy(secrets, 0, secrets_salted, 0, secrets.length);
      System.arraycopy(SECRETS_SALT, 0, secrets_salted, secrets.length, SECRETS_SALT.length);

      Hasher hasher = new Hasher.Sha512();
      
      byte [] hash512 = hasher.digest(secrets_salted);
      
      // Compress the 64-byte hash to 4 bytes by XORing every 4th byte with
      // the previous.  This should help verify passwords without leaking
      // secrets combined with the 2nd round of salting + hashing.
      byte [] hash = new byte[Header.HASH_LENGTH];
      System.arraycopy(hash512, 0, hash, 0, Header.HASH_LENGTH);
      for (int block_offset = Header.HASH_LENGTH; block_offset < 64; block_offset += Header.HASH_LENGTH) {
         for (int i = 0; i < Header.HASH_LENGTH; ++i) {
            hash[i] ^= hash512[block_offset + i];
         }
      }

      return hash;
   }

   // Attempts to write the header to the destination.  'secrets' should be the
   // 4-byte hash of the real secrets.
   private static void writeHeader(java.io.OutputStream output, Cryptor.Algorithm algorithm, byte [] secrets) throws java.lang.Exception {
      Header header = new Header(algorithm, secrets);
      header.serialize(output);
      return;
   }

   // Attempts to read the header from the given file and verifies the algorithm
   // and password are correct.  'secrets' should be the 4-byte hash of the
   // real secrets.  Returns the parsed algorithm for the file.
   private static Cryptor.Algorithm readAndVerifyHeader(java.io.InputStream input, byte [] secrets) throws java.lang.Exception {
      Header header_read = Header.deserialize(input);

      for (int i = 0; i < Header.HASH_LENGTH; ++i) {
         if (header_read.hash[i] != secrets[i]) {
            throw new MalformedHeaderException("password is incorrect");
         }
      }

      return header_read.algorithm;
   }
}

class ConsoleUnavailableException extends java.lang.Exception {
   public ConsoleUnavailableException(String err) {
      super(err);
   }
}

class MalformedHeaderException extends java.lang.Exception {
   public MalformedHeaderException(String err) {
      super(err);
   }
}

