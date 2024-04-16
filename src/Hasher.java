public interface Hasher {
   // Hashes the given byte data into an arbitrarily long byte array, known as
   // the 'digest'.
   public byte [] digest(byte [] data);

   public static class Sha512 implements Hasher {
      public byte [] digest(byte [] data) {
         // TODO: Implement
         return data;
      }
   }
}

