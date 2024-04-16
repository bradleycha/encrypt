import java.util.Base64;
import java.io.ByteArrayOutputStream;
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
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         int content = input.read();
         while(content!=-1){
            output.write(content);
            content = input.read();
         }
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
         return;
      }

      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception {
         byte offset = deriveOffset(secrets);
         int content = input.read();
         while(content!=-1){
            output.write(content-offset);
            content = input.read();
         }
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
         //TODO:
         /*
          * better block handling
          better byte manipulation
          better bit manipulation
          functionize everything
          */
         int bytesRead = 0;
         byte[][] stateMatrix = new byte[4][4]; //I'm imagining it as columns x rows
         //byte[] initialKey = new byte[32]; //32 byte (256 bit) key
         
         int N = 8; //length of the key in 32-bit (4-byte) words
         byte[][] K = new byte[N][4]; //32-bit word index x byte index (32 words with 4 bytes each)
         for(int i = 0; i<N; i++){
            for(int j = 0; j<4;j++){
               K[i][j] = secrets[4*i+j];
            }
         }
         
         //The Key Schedule (Generating expandedKeys)
         int R = 15; //number of rounds needed, 15 for 256
         byte[][] W = new byte[4*R][4]; //W: rounds x keys, each key is a 4x4x8 bit block (128bit)
         byte[][] rcon = new byte[8][4];
         byte[] rc = new byte[8];
         //Round Constant Generation(rcon[1] to rcon[7] for 256)
         for(int i = 1; i<8;i++){
            if(i==1){
               rc[i] = 1;
            }
            else if(i>1 && rc[i-1]<128){
               rc[i] = (byte)(rc[i-1] << 1);
            }
            else if(i>1 && rc[i-1]>=128){
               rc[i] = (byte)((rc[i-1] << 1) ^ 283);
            }
            rcon[i][0] = rc[i];
            for(int j = 1; j<=3; j++){
               rcon[i][j] = 0;
            }
         }
         //Expanded Key Word Generation
         for(int i = 0; i<4*R; i++){
            if(i<N){
               W[i] = K[i];
            }
            else if(i>=N && i%N==0){
               W[i] = wordXOR(wordXOR(W[i-N], SubWord(RotateWord(W[i-1]))), rcon[i/N]);
            }
            else if(i>=N && i%N==4){
               W[i] = wordXOR(W[i-N], SubWord(W[i-1]));
            }
            else{
               W[i] = wordXOR(W[i-N], W[i-1]);
            }
         }
         //read & encrypt
         ByteArrayOutputStream out = new ByteArrayOutputStream();
         while(bytesRead != -1){
            //Read 1 block to the state matrix (read 4 words columnwise)
            for(int c = 0; c<4; c++){
               bytesRead = input.read(stateMatrix[c]);
            }
            //Now we have a full 4x4x8 bit block, 128 bits total

            //Traverse 14 rounds, r
            for(int r = 0; r<=14; r++){
               if(r>0){
                  //SubBytes
                  for(int c = 0; c<4; c++){
                     for(int i = 0; i<4; i++){
                        stateMatrix[c][i] = sBox(stateMatrix[c][i]);
                     }
                  }
                  //ShiftRows left circular byte shift each row incrementally
                  for(int i=1; i<4; i++){
                     for(int j=0; j<i; j++){
                        byte tempByte = stateMatrix[0][i];
                        stateMatrix[0][i] = stateMatrix[1][i];
                        stateMatrix[1][i] = stateMatrix[2][i];
                        stateMatrix[2][i] = stateMatrix[3][i];
                        stateMatrix[3][i] = tempByte;
                     }
                  }
               }
               if(r>0 && r<14){
                  //MixColumns
                  byte[][] matrix_constant = {{2,1,1,3}, {3,2,1,1}, {1,3,2,1}, {1,1,3,2}};
                  byte[][] new_matrix = new byte[4][4];
                  for(int j = 0; j<4; j++){
                     for(int k = 0; k<4; k++){
                        for(int l = 0; l<4; l++){
                           new_matrix[j][k] ^= (byte)(matrix_constant[k][l] * stateMatrix[j][k]);
                        }
                     }
                  }
               }
               //AddRoundKey
               for(int c = 0; c<4; c++){
                  for(int i = 0; i<4; i++){
                     stateMatrix[c][i] = (byte)(stateMatrix[c][i] ^ W[4*r+c][i]);
                  }
               }
            }
            for(byte[] column: stateMatrix){
               out.write(column);
            }
         }
         output.write(Base64.getEncoder().encode(out.toByteArray()));

         
         return;
      }
      public void decrypt(java.io.InputStream input, java.io.OutputStream output, byte [] secrets) throws java.lang.Exception{
         //TODO
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
         byte[] newWord = new byte[4];
         for(int i = 0; i<4; i++){
            byte b = word[i];
            newWord[i] = sBox(b);
         }
         return newWord;
      }
      private static byte sBox(byte b){
         byte s = (byte)(b ^ leftCircularShift(b, 1) ^ leftCircularShift(b, 2) ^ leftCircularShift(b, 3) ^ leftCircularShift(b, 4) ^ 99);
         return s;
      }
      private static byte leftCircularShift(byte b, int d){
         byte newByte = (byte)((b << d) | (b >> Integer.SIZE-d));
         return newByte;
      }
      private static byte[] wordXOR(byte[] w1, byte[] w2){
         byte[] newWord = new byte[w1.length];
         for(int i = 0; i<w1.length; i++){
            newWord[i] = (byte)(w1[i] ^ w2[i]);
         }
         return newWord;
      }
   }
}