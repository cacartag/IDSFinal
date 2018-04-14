import java.util.Scanner;
import java.util.Arrays;
import java.util.Vector;
import java.util.TreeMap;
import java.util.Map;
import java.io.BufferedReader;
import java.io.FileReader;
import java.lang.*;


public class SignatureParser{
    private String signatureFile;
    private Map<String,Vector<Signature>> signatures;
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
            
            //for(int x = 0; x < rules.length; x++)
            //{
            //    System.out.println(rules[x]);
            //}
            
        } catch(Exception e)
        {
            System.out.println(e);
            return;
        }
        
        Signature temp = new Signature(acceptedProtocols);
        //temp.parse(rules[0]);
        
        for(int x = 0; x < rules.length; x++)
        {
            temp.parse(rules[x]);
        }


    }
    
}

class Signature{
    private String action;
    private String protocol;
    private String ipSource;
    private String maskSource;
    private boolean ipAnySource;
    private String port1Source;
    private String port2Source;
    private boolean portAnySource;
    private boolean bidirectional;
    private String ipTarget;
    private String maskTarget;
    private boolean ipAnyTarget;
    private String port1Target;
    private String port2Target;
    private boolean portAnyTarget;
    private String rule;
    private String[] acceptedProtocols;
    
    Signature()
    {
        action = new String();
        protocol = new String();
        ipSource = new String();
        maskSource = new String();
        ipAnySource = false;
        port1Source = new String();
        port2Source = new String();
        portAnySource = false;
        bidirectional = false;
        ipTarget = new String();
        maskTarget = new String();
        ipAnyTarget = false;
        port1Target = new String();
        port2Target = new String();
        portAnyTarget = false;
        rule = new String();
    }
    
    Signature(String[] ap)
    {
        action = new String();
        protocol = new String();
        ipSource = new String();
        maskSource = new String();
        ipAnySource = false;
        port1Source = new String();
        port2Source = new String();
        portAnySource = false;
        bidirectional = false;
        ipTarget = new String();
        maskTarget = new String();
        ipAnyTarget = false;
        port1Target = new String();
        port2Target = new String();
        portAnyTarget = false;
        rule = new String();
        acceptedProtocols = ap;
    }
    
    public void parse(String r)
    {
        rule = r;
        
        // only need the first seven for initial parsing
        String[] splitRule = rule.split(" ");
        
        if(splitRule.length >= 7)
        {
            // parse and check action
            if(splitRule[0].equals("alert") || splitRule.equals("pass"))
            {
                action = splitRule[0];
                System.out.println("Action: " + action);
            } else {
                System.out.println("Did not recognize the action type");
            }
            
            // parse and check protocol
            if(Arrays.asList(acceptedProtocols).contains(splitRule[1]))
            {
                protocol = splitRule[1];
                System.out.println("Protocol: " + protocol);
            } else {
                System.out.println("Did not recognize the protocol type");
            }
            
            // parse and check ipsource and mask
            String[] splitIpMask = splitRule[2].split("/");
            
            if(splitIpMask.length == 2 || splitIpMask.length == 1)
            {
                if(splitIpMask.length == 2)
                {
                    String[] ipSplit = splitIpMask[0].split("\\.");
                    
                    if(ipSplit.length == 4)
                    {
                        ipSource = splitIpMask[0];
                    }
                    
                    maskSource = splitIpMask[1];
                } else if(splitIpMask[0].equals("any")) {
                    ipAnySource = true;
                    ipSource = splitIpMask[0];
                    maskSource = splitIpMask[0];
                } else {
                    System.out.println("Did not recognize ip source, and mask format");
                }
                
                System.out.println("Ip Source: " + ipSource);
                System.out.println("Mask Source: " + maskSource);
                
                
            }
            else {
                System.out.println("Did not recognize ip source, and mask format");
            }
            
            // parse and check the port source/sources
            String[] ports = splitRule[3].split(":");
            if(ports.length == 1 || ports.length == 2)
            {
                port1Source = ports[0];

                System.out.println("Port 1 source: " + port1Source);
                
                if(ports.length == 2)
                {
                    port2Source = ports[1];
                    System.out.println("Port 2 source: " + port2Source);
                }
            
                if(port1Source.equals("any"))
                {
                    portAnySource = true;
                    System.out.println("Source port any is set");
                }
            
            } else {
                System.out.println("Did not recognize the port format");
            }
            
            // parse and check the direction
            if(splitRule[4].equals("->") || splitRule[4].equals("<>"))
            {
                if(splitRule[4].equals("->"))
                {
                    bidirectional = false;
                }
                else{
                    bidirectional = true;
                }
                
                if(bidirectional)
                {
                    System.out.println("Direction: bidirectional");
                } else{
                    System.out.println("Direction: inbound");
                }
                    
            } else {
                System.out.println("Did not recognize the direction");
            }
            
            // parse and check iptarget and mask
            splitIpMask = splitRule[5].split("/");
            
            if(splitIpMask.length == 2)
            {
                if(splitIpMask.length == 2)
                {
                    String[] ipSplit = splitIpMask[0].split("\\.");
                    
                    if(ipSplit.length == 4)
                    {
                        ipTarget = splitIpMask[0];
                    }
                    
                    maskTarget = splitIpMask[1];
                } else if(splitIpMask[0].equals("any")) {
                    ipAnyTarget = true;
                    ipTarget = splitIpMask[0];
                    maskTarget = splitIpMask[0];
                } else {
                    System.out.println("Did not recognize ip source, and mask format");
                }
                
                System.out.println("Ip Target: " + ipTarget);
                System.out.println("Mask Target: " + maskTarget);
            }
            else {
                System.out.println("Did not recognize ip source, and mask format");
            }
            
            // parse and check the port target/targets
            ports = splitRule[6].split(":");
            if(ports.length == 1 || ports.length == 2)
            {
                port1Target = ports[0];

                System.out.println("Port 1 target: " + port1Target);
                
                if(ports.length == 2)
                {
                    port2Target = ports[1];
                    System.out.println("Port 2 target: " + port2Target);
                }
                
                if(port1Target.equals("any"))
                {
                    portAnySource = true;
                    System.out.println("Target port any is set");
                }
            
            } else {
                System.out.println("Did not recognize the port format");
            }
            
            if(splitRule.length > 7)
            {
                System.out.println("Options detected");
            }
        } else {
            System.out.println("Rule is missing arguments, recheck format");
        }
        
        System.out.println();
        System.out.println();

        
        //for(int x = 0; x < 7; x++)
        //{
        //    System.out.println(splitRule[x]);
        //}
        
    }
    
    
}

class signatureOptions{
    private String msg;
    private String logto;
    private String ttl;
    private String tos;
    private String id;
    private String fragoffset;
    private String fragbits;
    private String dsize;
    private String flags;
    private String seq;
    private String ack;
    private String itype;
    private String icode;
    private String content;
    private String sameip;
    private String sid;

    signatureOptions()
    {
        msg = new String();
        logto = new String();
        ttl = new String();
        tos = new String();
        id = new String();
        fragoffset = new String();
        fragbits = new String();
        dsize = new String();
        flags = new String();
        seq = new String();
        ack = new String();
        itype = new String();
        icode = new String();
        content = new String();
        sameip = new String();
        sid = new String();
    }
    
    public void parse()
    {
        
    }
}