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
         byte[] initial_key = new byte[32];
         byte[][] rcon = new byte[7][4];
         for(int i = 0; i<32; i++){
            initial_key[i] = secrets[i];
         }
         System.out.print("Initial Key: "+initial_key.toString()+"\n");
         byte[][] matrix = new byte[4][4];
         byte[][] expanded_key = new byte[60][4];
         for(int i=0; i<8; i++){
            if(i==0){
               rcon[i][0] = 1;
            }
            else if(i>0 && rcon[i-1][0]<128){
               rcon[i][0] = (byte)(rcon[i-1][0] * 2);
            }
            else if(i>0 && rcon[i-1][0]>=128){
               rcon[i][0] = (byte)((rcon[i-1][0] * 2) ^ (283));
            }
            rcon[i][1] = 0;
            rcon[i][2] = 0;
            rcon[i][3] = 0;
         }

         for(int i = 0; i<60; i++){
            //W_i calculation
            if(i<8){
               expanded_key[i][0] = initial_key[i];
               expanded_key[i][1] = initial_key[i+1];
               expanded_key[i][2] = initial_key[i+2];
               expanded_key[i][3] = initial_key[i+3];
            }
            else if(i>=8 && (i%8)==0){
               for(int j = 0; j<4; j++){
                  expanded_key[i][j] = (byte)(expanded_key[i-8][j] ^ SubWord(RotateWord(expanded_key[i-1]))[j] ^ rcon[i/8][0]);
               }
            }
            else if(i>=8 && (i%8)==4){
               for(int j = 0; j<4; j++){
                  expanded_key[i][j] = (byte)(expanded_key[i-8][j] ^ SubWord(expanded_key[i-1])[j]);
               }
            }
            else{
               for(int j = 0; j<4; j++){
                  expanded_key[i][j] = (byte)(expanded_key[i-8][j] ^ expanded_key[i-1][j]);
               }
            }
         }

         for(int i = 0; i<4; i++){
            int bytesRead = input.read(matrix[i]);
            if(bytesRead<4){
               matrix[i][3] = 0;
            }
            if(bytesRead<3){
               matrix[i][2] = 0;
            }
            if(bytesRead<2){
               matrix[i][1] = 0;
            }
            if(bytesRead<1){
               matrix[i][0] = 0;
            }
         }
         for(byte[] column: matrix){
            for(byte value: column){
               System.out.print(value+",");
            }
            System.out.println("");
         }
         for(int i = 0; i<4; i++){
            input.read(matrix[i]);
         }
         //Initial AddRoundKey
         for(int i = 0; i<4; i++){
            for(int j = 0; j<4; j++){
               matrix[i][j] ^= expanded_key[i][j];
            }
         }
         //13 rounds
         for(int i = 0; i<13;i++){
            //SubBytes
            for(int j = 0; j<4;j++){
               for(int k = 0; k<4; k++){
                  matrix[j][k] = (byte)(matrix[j][k] ^ matrix[j][(k+4)%8] ^ matrix[j][(k+5)%8] ^ matrix[j][(k+6)%8] ^ matrix[j][(k+7)%8] ^ 01100011);
               }
            }
            //ShiftRows
            
            //MixColumns

            //AddRoundKey
            for(int j = 0; j<4; j++){
               for(int k = 0; k<4; k++){
                matrix[j][k] ^= expanded_key[j][k];
               }
            }
         }
         ///final round(14)
         //SubBytes
         for(int j = 0; j<4;j++){
            for(int k = 0; k<4; k++){
               matrix[j][k] = (byte)(matrix[j][k] ^ matrix[j][(k+4)%8] ^ matrix[j][(k+5)%8] ^ matrix[j][(k+6)%8] ^ matrix[j][(k+7)%8] ^ 01100011);
            }
         }
         //ShiftRows

         //AddRoundKey
         for(int i = 0; i<4; i++){
            for(int j = 0; j<4; j++){
               matrix[i][j] ^= expanded_key[i][j];
            }
         }
         return;
      }
      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception{
         //TODO: Implement
         return;
      }
      private static byte[] RotateWord(byte[] word){
         byte[] new_word = new byte[4];
         new_word[3]=word[0];
         new_word[2]=word[3];
         new_word[1]=word[2];
         new_word[0]=word[1];
         return new_word;
      }
      private static byte[] SubWord(byte[] word){
         byte[] new_word = new byte[4];
         for(int i = 0; i<4; i++){
            new_word[i] = (byte)(word[i] ^ word[(i+4)%8] ^ word[(i+5)%8] ^ word[(i+6)%8] ^ word[(i+7)%8] ^ 01100011);
         }
         return new_word;
      }
   }
}

