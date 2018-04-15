import java.nio.ByteBuffer;
import java.util.Scanner;
import java.util.TreeMap;
import java.util.Vector;

// import org.apache.commons.cli.*;
// import java.util.Collection;
// javac -cp ".;commons-cli-1.4.jar" -d . Main.java
// java -cp ".;commons-cli-1.4.jar" Main

public class Main
{   
    public static void main(String [] args) throws Exception
    {
        if(args.length > 0)
        {
            // parse signatures
            SignatureParser signatures = new SignatureParser(args[0]);

            signatures.parseSignatures();

            
            TreeMap<String,Vector<Signature>> signatureMapping = signatures.GetSignatures();
            // pass signatures to sherlock ids
            SherlockIDS sherlock = new SherlockIDS(signatureMapping);
            sherlock.Investigate();
            
        }else {
            System.out.println("not enough arguments ");
        }
        
        
        //OptionHandler optHandler = new OptionHandler();
        //
        //if(optHandler.parseOptions(args) == 1)
        //{
        //    optHandler.runOptions();
        //    
        //} else{
        //    System.out.println("Error in parsing of options, exiting");
        //}
    }
    
}