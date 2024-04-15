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
      AES256,
   }

   public static class Plaintext implements Cryptor {
      public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         int content = input.read();
         while(content!=-1){
            output.write(content);
            content = input.read();
         }
         input.close();
         output.close();
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         int content = input.read();
         while(content!=-1){
            output.write(content);
            content = input.read();
         }
         input.close();
         output.close();
         return;
      }
   }

   public static class ConstantOffset implements Cryptor {
      public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         byte offset = deriveOffset(secrets);
         int content = input.read();
         while(content!=-1){
            output.write(content+offset);
            content = input.read();
         }
         input.close();
         output.close();
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         byte offset = deriveOffset(secrets);
         int content = input.read();
         while(content!=-1){
            output.write(content-offset);
            content = input.read();
         }
         input.close();
         output.close();
         return;
      }

      private static byte deriveOffset(byte [] secrets) {
         final byte START_OFFSET = 0x42;

         byte offset = START_OFFSET;
         for (byte b : secrets) {
            // This intentionally overflows.
            offset += b;
         }

         return offset;
      }
   }
   public static class AES256 implements Cryptor {
      public void encrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception{
         
         return;
      }
      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception{
         
         return;
      }
   }
}

