public class Main {
   public static void main(String [] args_cmd) throws java.lang.Exception {
      Arguments args = Arguments.parse(args_cmd);

      String secrets = readSecrets(args);

      return;
   }

   // Attempts to read secrets (password) from the source specified in arguments.
   private static String readSecrets(Arguments args) throws java.lang.Exception {
      String file_path = args.secrets;
      if (file_path == null) {
         return readSecretsPrompt();
      }

      return readSecretsFile(file_path);
   }

   // Reads secrets from the user using a password prompt.
   private static String readSecretsPrompt() throws ConsoleUnavailableException {
      java.io.Console console = System.console();
      if (console == null) {
         throw new ConsoleUnavailableException("console unavailable");
      }

      char [] data = console.readPassword("Please enter the password: ");

      return new String(data);
   }

   // Reads secrets from a user-specified file path.
   private static String readSecretsFile(String path) throws java.lang.Exception {
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
}

class ConsoleUnavailableException extends java.lang.Exception {
   public ConsoleUnavailableException(String err) {
      super(err);
   }
}

