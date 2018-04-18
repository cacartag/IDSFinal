import java.util.Scanner;
import java.util.Arrays;
import java.util.Vector;
import java.util.TreeMap;
import java.io.BufferedReader;
import java.io.FileReader;
import javax.xml.bind.DatatypeConverter;
import java.lang.*;


public class SignatureParser{
    private String signatureFile;
    private TreeMap<String,Vector<Signature>> signatures;
    BufferedReader reader;
    private String[] rules;
    private String[] acceptedProtocols = {"ip","arp","tcp","udp","icmp"};
    
    SignatureParser()
    {
        signatures = new TreeMap<String,Vector<Signature>>();
        signatureFile = new String();
        reader = null;
        
        // initialize all possible signature protocol types
        for(String protocol: acceptedProtocols)
        {
            signatures.put(new String(protocol), new Vector<Signature>());
        }
    }
    
    SignatureParser(String s)
    {
        signatures = new TreeMap<String,Vector<Signature>>();
        signatureFile = s;
        reader = null;
        
        // initialize all possible signature protocol types
        for(String protocol: acceptedProtocols)
        {
            signatures.put(new String(protocol), new Vector<Signature>());
        }
        
    }
    
    public void parseSignatures()
    {
        System.out.println("Signature parser received: \n" + signatureFile);
     
        try{
            
            reader = new BufferedReader(new FileReader(signatureFile));
            String text = new String();
            
            // count number of elements to initialize array
            int count = 0;

            while((text = reader.readLine()) != null)
            {
                count++;
            }
            
            rules = new String[count];
            
            count = 0;
            reader = new BufferedReader(new FileReader(signatureFile));
            while((text = reader.readLine()) != null)
            {
                rules[count] = text;
                count++;
            }
            
        } catch(Exception e)
        {
            System.out.println(e);
            return;
        }
        
        Signature temp = new Signature(acceptedProtocols);
        //temp.parse(rules[0]);
        Vector<Signature> ipVector = new Vector<Signature>();
        Vector<Signature> arpVector = new Vector<Signature>();
        Vector<Signature> tcpVector = new Vector<Signature>();
        Vector<Signature> udpVector = new Vector<Signature>();
        Vector<Signature> icmpVector = new Vector<Signature>();
        
        for(int x = 0; x < rules.length; x++)
        {
            temp.parse(rules[x]);
            //temp.printRule();
            
            
            if(temp.GetProtocol().equals("ip"))
            {
                ipVector.add(temp);
            } else if(temp.GetProtocol().equals("arp")){
                arpVector.add(temp);
            } else if(temp.GetProtocol().equals("tcp")){
                tcpVector.add(temp);
            } else if(temp.GetProtocol().equals("udp")){
                udpVector.add(temp);
            } else if(temp.GetProtocol().equals("icmp")){
                icmpVector.add(temp);
            }
            temp = new Signature(acceptedProtocols);
        }

        signatures.put("ip",ipVector);
        signatures.put("arp",arpVector);
        signatures.put("tcp",tcpVector);
        signatures.put("udp",udpVector);
        signatures.put("icmp",icmpVector);
        
    }
    
    public TreeMap<String,Vector<Signature>> GetSignatures()
    {
        return signatures;
    }
    
}