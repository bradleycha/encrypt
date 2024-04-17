public class Header {
   public Cryptor.Algorithm algorithm; // algorithm used to encrypt
   public byte [] hash;                // hash of the secrets key

   // The length of the secrets hash.
   public static final int HASH_LENGTH = 4;

   // Constructs the header using the given algorithm and a 4-byte hash of the
   // secrets key, which is used to check the password.
   public Header(Cryptor.Algorithm algorithm, byte [] hash) {
      this.algorithm = algorithm;
      this.hash = new byte [HASH_LENGTH];
      System.arraycopy(hash, 0, this.hash, 0, HASH_LENGTH);
      return;
   }

   private static final byte MAGIC_HEADER_UPPER = 'E';   // EnCrypt
   private static final byte MAGIC_HEADER_LOWER = 'H';   // Header
   private static final byte MAGIC_FOOTER_UPPER = 'E';   // EnCrypt
   private static final byte MAGIC_FOOTER_LOWER = 'F';   // Footer

   private static final byte [] MAGIC_HEADER = {MAGIC_HEADER_UPPER, MAGIC_HEADER_LOWER};
   private static final byte [] MAGIC_FOOTER = {MAGIC_FOOTER_UPPER, MAGIC_FOOTER_LOWER};

   private static final java.util.HashMap<Cryptor.Algorithm, Byte> MAP_ALGORITHM = new java.util.HashMap<Cryptor.Algorithm, Byte>() {{
      put(Cryptor.Algorithm.Plaintext,       (byte)0);
      put(Cryptor.Algorithm.ConstantOffset,  (byte)1);
      put(Cryptor.Algorithm.AES256,          (byte)2);
   }};

   private static final Cryptor.Algorithm [] MAP_BYTE_ALGORITHM = {
      Cryptor.Algorithm.Plaintext,
      Cryptor.Algorithm.ConstantOffset,
      Cryptor.Algorithm.AES256,
   };

   private static final int HEADER_BYTE_LENGTH = MAGIC_HEADER.length + HASH_LENGTH + 1 + MAGIC_FOOTER.length;

   public void serialize(java.io.OutputStream output) throws java.io.IOException {
      // Serialized data will be formatted as such:
      //
      // byte     magic_header_upper
      // byte     magic_header_lower
      // byte[4]  hash
      // byte     algorithm
      // byte     magic_footer_upper
      // byte     magic_footer_lower
      //
      // We have the 4 bytes worth of magic numbers to protect against
      // accidental false positives of random date being interpreted as valid.
   
      byte algorithm_byte = MAP_ALGORITHM.get(this.algorithm);

      byte [] header = new byte [HEADER_BYTE_LENGTH];
      // header
      System.arraycopy(MAGIC_HEADER, 0, header, 0, MAGIC_HEADER.length);

      // hash
      System.arraycopy(this.hash, 0, header, MAGIC_HEADER.length, HASH_LENGTH);

      // algorithm
      header[MAGIC_HEADER.length + HASH_LENGTH] = algorithm_byte;

      // footer
      System.arraycopy(MAGIC_FOOTER, 0, header, MAGIC_HEADER.length + HASH_LENGTH + 1, MAGIC_FOOTER.length);

      output.write(header);
      return;
   }

   public static Header deserialize(java.io.InputStream input) throws java.lang.Exception {
      byte [] header_bytes = new byte [HEADER_BYTE_LENGTH];
      if (input.read(header_bytes) < HEADER_BYTE_LENGTH) {
         throw new DeserializeException("header is missing or damaged, file may be corrupt");
      }

      // header
      for (int i = 0; i < MAGIC_HEADER.length; ++i) {
         if (header_bytes[i] != MAGIC_HEADER[i]) {
            throw new DeserializeException("header is missing or damaged, file may be corrupt");
         }
      }

      // footer
      for (int i = 0; i < MAGIC_FOOTER.length; ++i) {
         if (header_bytes[MAGIC_HEADER.length + HASH_LENGTH + 1 + i] != MAGIC_FOOTER[i]) {
            throw new DeserializeException("header is missing or damaged, file may be corrupt");
         }
      }

      // hash
      byte [] hash = new byte[HASH_LENGTH];
      System.arraycopy(header_bytes, MAGIC_HEADER.length, hash, 0, HASH_LENGTH);

      // algorithm
      byte algorithm_byte = header_bytes[MAGIC_HEADER.length + HASH_LENGTH];
      if (algorithm_byte >= MAP_BYTE_ALGORITHM.length) {
         throw new DeserializeException("algorithm byte is invalid");
      }

      Cryptor.Algorithm algorithm = MAP_BYTE_ALGORITHM[algorithm_byte];
   
      return new Header(algorithm, hash);
   }

   public static class DeserializeException extends java.lang.Exception {
      public DeserializeException(String msg) {
         super(msg);
      }
   }
}

