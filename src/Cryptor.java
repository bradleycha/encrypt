public interface Cryptor {
   // Encrypts the data read from 'input', writing to 'output', deriving the
   // encryption key from 'secrets'.
   public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception;

   // Decrypts the data read from 'input', writing to 'output', deriving the
   // encryption key from 'secrets'.
   public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception;

   // A specific algorithm to use for crypto.
   public static enum Algorithm {
      Plaintext,
      ConstantOffset,
   }

   public static class Plaintext implements Cryptor {
      public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         // TODO: Implement
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         // TODO: Implement
         return;
      }
   }

   public static class ConstantOffset implements Cryptor {
      public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         // TODO: Implement
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         // TODO: Implement
         return;
      }
   }
}

