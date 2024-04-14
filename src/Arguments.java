public class Arguments {
   String      input;      // input file path
   String      output;     // output file path
   Mode        mode;       // encryption mode (encrypt or decrypt)
   Algorithm   algorithm;  // which algorithm to use for encryption
   
   public static enum Mode {
      Encrypt,
      Decrypt,
   }

   public static enum Algorithm {
      Plaintext,
   }

   // Collection of various different argument parsing exceptions.
   // These are all grouped under a single class as a thin wrapper to bundle
   // them all together as a generic parsing error.
   public static class ParseException extends java.lang.Exception {
      public ParseException(String error_message) {
         super(error_message);
      }

      // An argument not in the form "--[identifier] or -[identifier]"
      public static class InvalidArgument extends ParseException {
         public InvalidArgument(String argument) {
            super(String.format("\'%s\' is not an argument, try --help for more information", argument));
         }
      }

      // An argument with an unknown identifier.
      public static class UnknownIdentifier extends ParseException {
         public UnknownIdentifier(String identifier) {
            super(String.format("unknown identifier \'%s\'", identifier));
         }
      }

      // A required argument is missing
      public static class MissingRequiredArgument extends ParseException {
         public MissingRequiredArgument(String argument) {
            super(String.format("missing required argument \'%s\'", argument));
         }
      }

      // An argument which did not expect a parameter but one was provided.
      public static class UnexpectedParameter extends ParseException {
         public UnexpectedParameter(String argument, String parameter) {
            super(String.format("argument \'%s\' did not expect parameter \'%s\'", argument, parameter));
         }
      }

      // An argument which expects a parameter but one was not provided.
      public static class ExpectedParameter extends ParseException {
         public ExpectedParameter(String argument) {
            super(String.format("argument \'%s\' expects a parameter", argument));
         }
      }

      // An argument was provided an invalid parameter.
      public static class InvalidParameter extends ParseException {
         public InvalidParameter(String argument, String parameter) {
            super(String.format("argument \'%s\' has an invalid parameter \'%s\'", argument, parameter));
         }
      }
   }

   // Attempts to parse command-line arguments into a serialized argument list.
   public static Arguments parse(String [] args) throws ParseException {
      // This implementation works as follows:
      //
      // 1. Store a temporary version of the struct with all required members
      // set to 'null'.
      //
      // 2. Tokenize each argument into its 'identifier' and 'parameter'.
      //
      // 3. Serialize the identifier into enum representation.
      //
      // 4. Based on the argument, choose how to parse the parameter and store
      // it in the arguments list.
      //
      // 5. At the end, check for any missing arguments.
      //
      // 6. Return the freshly parsed arguments!

      ArgumentConsumer consumer = new ArgumentConsumer();

      // Tokenize and parse each given argument.
      for (String arg : args) {
         parseArgument(consumer, arg);
      }

      return consumer.finalState();
   }

   // Internal constructor which sets every argument to its default value, or
   // 'null' if required.
   private Arguments() {
      return;
   }

   // --- The following is what should be modified when adding new arguments ---

   // Internal representation of the Arguments struct pre-finialization which
   // is used when parsing individual arguments.
   private static class ArgumentConsumer {
      public boolean    help;
      public boolean    version;
      public String     input;
      public String     output;
      public Mode       mode;
      public Algorithm  algorithm;

      public ArgumentConsumer() {
         this.help      = false;
         this.version   = false;
         this.input     = null;
         this.output    = null;
         this.mode      = Mode.Encrypt;
         this.algorithm = null;
         return;
      }

      // Takes the current state and finalizes it into a complete Arguments
      // class, throwing an exception if any required arguments are missing.
      public Arguments finalState() throws ParseException.MissingRequiredArgument {
         Arguments args = new Arguments();

         // Special cases for 'help' and 'version' since they display text
         // then exit instead.  This will allow missing arguments, which is
         // what we want.
         if (this.help) {
            displayHelpMenu();
            System.exit(0);
         }
         if (this.version) {
            displayVersionText();
            System.exit(0);
         }

         // This sucks...there's probably some meta-programming thing you can
         // do, but for now we do it manually.  Note that not every field is
         // required, thus not every field is checked.
         if (this.input == null) {
            throw new ParseException.MissingRequiredArgument("input");
         }
         if (this.output == null) {
            throw new ParseException.MissingRequiredArgument("output");
         }
         if (this.algorithm == null) {
            throw new ParseException.MissingRequiredArgument("algorithm");
         }

         args.input     = this.input;
         args.output    = this.output;
         args.mode      = this.mode;
         args.algorithm = this.algorithm;
         return args;
      }

      private static void displayHelpMenu() {
         // TODO: Implement
         System.out.println("Help menu!");
         return;
      }

      private static void displayVersionText() {
         // TODO: Implement
         System.out.println("Version text!");
         return;
      }
   }

   // Internal enum representation of an argument identifier.
   private static enum Identifier {
      Help,
      Version,
      Input,
      Output,
      Mode,
      Algorithm,
   }

   // Short-form identifier map for parsing.  Edit this if you are adding a new
   // argument and it should have a short-form identifier.
   private static final java.util.HashMap<Character, Identifier> MAP_IDENTIFIER_SHORT = new java.util.HashMap<Character, Identifier>() {{
      put('h', Identifier.Help);
      put('v', Identifier.Version);
      put('i', Identifier.Input);
      put('o', Identifier.Output);
      put('m', Identifier.Mode);
      put('a', Identifier.Algorithm);
   }};

   // Long-form identifier map for parsing. Edit this if you are adding a new
   // argument and it should have a long-form identifier.
   private static final java.util.HashMap<String, Identifier> MAP_IDENTIFIER_LONG = new java.util.HashMap<String, Identifier>() {{
      put("help",       Identifier.Help);
      put("version",    Identifier.Version);
      put("input",      Identifier.Input);
      put("output",     Identifier.Output);
      put("mode",       Identifier.Mode);
      put("algorithm",  Identifier.Algorithm);
   }};

   // Instead of simply mapping function pointers, we have to use polymorphism
   // because Java doesn't do function pointers...
   private static interface Parser {
      // Parses the argument, storing the results in 'arguments' with optimal
      // argument parameter 'parameter', which is 'null' if there is no
      // parameter.  'identifier' is the identifier string used to invoke the
      // argument.  This argument does not need any checks and is only present
      // for formatting of errors.
      public abstract void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException;

      // Implement your own classes implementing Parser to define parse
      // functions for each argument.  Make sure to add this to the map!

      public static class Help implements Parser {
         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter != null) {
               throw new ParseException.UnexpectedParameter(identifier, parameter);
            }

            consumer.help = true;
            return;
         }
      }

      public static class Version implements Parser {
         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter != null) {
               throw new ParseException.UnexpectedParameter(identifier, parameter);
            }

            consumer.version = true;
            return;
         }
      }

      public static class Input implements Parser {
         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter == null) {
               throw new ParseException.ExpectedParameter(identifier);
            }

            consumer.input = parameter;
            return;
         }
      }

      public static class Output implements Parser {
         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter == null) {
               throw new ParseException.ExpectedParameter(identifier);
            }

            consumer.output = parameter;
            return;
         }
      }

      public static class Mode implements Parser {
         private static final java.util.HashMap<String, Arguments.Mode> MAP_MODE = new java.util.HashMap<String, Arguments.Mode>() {{
            put("encrypt", Arguments.Mode.Encrypt);
            put("decrypt", Arguments.Mode.Decrypt);
         }};

         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter == null) {
               throw new ParseException.ExpectedParameter(identifier);
            }

            Arguments.Mode mode = MAP_MODE.get(parameter);
            if (mode == null) {
               throw new ParseException.InvalidParameter(identifier, parameter);
            }

            consumer.mode = mode;
            return;
         }
      }

      public static class Algorithm implements Parser {
         private static final java.util.HashMap<String, Arguments.Algorithm> MAP_ALGORITHM = new java.util.HashMap<String, Arguments.Algorithm>() {{
            put("plaintext", Arguments.Algorithm.Plaintext);
         }};

         public void parse(ArgumentConsumer consumer, String identifier, String parameter) throws ParseException {
            if (parameter == null) {
               throw new ParseException.ExpectedParameter(identifier);
            }

            Arguments.Algorithm algorithm = MAP_ALGORITHM.get(parameter);
            if (algorithm == null) {
               throw new ParseException.InvalidParameter(identifier, parameter);
            }

            consumer.algorithm = algorithm;
            return;
         }
      }
   }

   // Finally...we can define our map for parsers.  Every single argument should
   // have a parser defined.
   private static final java.util.HashMap<Identifier, Parser> MAP_PARSER = new java.util.HashMap<Identifier, Parser>() {{
      put(Identifier.Help,       new Parser.Help());
      put(Identifier.Version,    new Parser.Version());
      put(Identifier.Input,      new Parser.Input());
      put(Identifier.Output,     new Parser.Output());
      put(Identifier.Mode,       new Parser.Mode());
      put(Identifier.Algorithm,  new Parser.Algorithm());
   }};

   // --------------------------------------------------------------------------

   // Takes a single string argument and tokenizes, serializes, and parses.
   private static void parseArgument(ArgumentConsumer consumer, String argument) throws ParseException {
      final char TOKEN_ARGUMENT_PREFIX    = '-';
      final char TOKEN_PARAMETER_PREFIX   = '=';

      // Sanity check - does this argument have the correct prefix?
      if (argument.length() < 2 || argument.charAt(0) != TOKEN_ARGUMENT_PREFIX) {
         throw new ParseException.InvalidArgument(argument);
      }

      boolean is_short_form = argument.charAt(1) != TOKEN_ARGUMENT_PREFIX;

      String identifier;
      String parameter;

      // Start offset for the argument identifier
      int argument_prefix_index;
      if (is_short_form) {
         argument_prefix_index = 1;
      } else {
         argument_prefix_index = 2;
      }

      // Splits the identifier and parameter into two strings.
      int parameter_sep_index = argument.indexOf(TOKEN_PARAMETER_PREFIX);
      if (parameter_sep_index != -1) {
         identifier  = argument.substring(argument_prefix_index, parameter_sep_index);
         parameter   = argument.substring(parameter_sep_index + 1);
      } else {
         identifier  = argument.substring(argument_prefix_index);
         parameter   = null;
      }

      // Serialize the identifier into its enum representation.
      Identifier identifier_parsed;
      if (is_short_form) {
         // Also check the identifier is a single character for better error
         // reporting.
         if (identifier.length() != 1) {
            throw new ParseException.InvalidArgument(argument);
         }

         identifier_parsed = serializeIdentifierShort(identifier.charAt(0));
      } else {
         // Check for zero-length identifiers.
         if (identifier.length() == 0) {
            throw new ParseException.InvalidArgument(argument);
         }

         identifier_parsed = serializeIdentifierLong(identifier);
      }

      // Run the parser on the argument
      MAP_PARSER.get(identifier_parsed).parse(consumer, identifier, parameter);

      return;
   }

   // Serializes a short-form identifier to its enum representation.
   private static Identifier serializeIdentifierShort(char identifier) throws ParseException.UnknownIdentifier {
      Identifier identifier_found = MAP_IDENTIFIER_SHORT.get(identifier);
      if (identifier_found == null) {
         throw new ParseException.UnknownIdentifier(Character.toString(identifier));
      }

      return identifier_found;
   }

   // Serializes a long-form identififer to its enum representation.
   private static Identifier serializeIdentifierLong(String identifier) throws ParseException.UnknownIdentifier {
      Identifier identifier_found = MAP_IDENTIFIER_LONG.get(identifier);
      if (identifier_found == null) {
         throw new ParseException.UnknownIdentifier(identifier);
      }

      return identifier_found;
   }
}

