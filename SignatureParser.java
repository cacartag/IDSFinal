import java.util.Scanner;
import java.util.Arrays;
import java.util.Vector;
import java.util.TreeMap;
import java.util.Map;
import java.io.BufferedReader;
import java.io.FileReader;
import javax.xml.bind.DatatypeConverter;
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
    private SignatureOptions options;
    
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
        options = new SignatureOptions();
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
        options = new SignatureOptions();
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
                //System.out.println("Action: " + action);
            } else {
                System.out.println("Did not recognize the action type");
            }
            
            // parse and check protocol
            if(Arrays.asList(acceptedProtocols).contains(splitRule[1]))
            {
                protocol = splitRule[1];
                //System.out.println("Protocol: " + protocol);
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
                
                //System.out.println("Ip Source: " + ipSource);
                //System.out.println("Mask Source: " + maskSource);
                
                
            }
            else {
                System.out.println("Did not recognize ip source, and mask format");
            }
            
            // parse and check the port source/sources
            String[] ports = splitRule[3].split(":");
            if(ports.length == 1 || ports.length == 2)
            {
                port1Source = ports[0];

                //System.out.println("Port 1 source: " + port1Source);
                
                if(ports.length == 2)
                {
                    if(!((Integer.parseInt(ports[0]) > Integer.parseInt(ports[1])) || (Integer.parseInt(ports[0]) < 0) || (Integer.parseInt(ports[1]) < 0)))
                    {
                        port2Source = ports[1];
                        //System.out.println("Port 2 source: " + port2Source);
                    }
                    else{
                        //System.out.println("Port range is not valid, replacing with any");
                        portAnySource = true;
                        port1Target = "any";
                    }
                }
            
                if(port1Source.equals("any"))
                {
                    portAnySource = true;
                    //System.out.println("Source port any is set");
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
                    //System.out.println("Direction: bidirectional");
                } else{
                    //System.out.println("Direction: inbound");
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
                
                //System.out.println("Ip Target: " + ipTarget);
                //System.out.println("Mask Target: " + maskTarget);
            }
            else {
                System.out.println("Did not recognize ip source, and mask format");
            }
            
            // parse and check the port target/targets
            ports = splitRule[6].split(":");
            if(ports.length == 1 || ports.length == 2)
            {
                port1Target = ports[0];

                //System.out.println("Port 1 target: " + port1Target);
                
                if(ports.length == 2)
                {
                    if(!((Integer.parseInt(ports[0]) > Integer.parseInt(ports[1])) || (Integer.parseInt(ports[0]) < 0) || (Integer.parseInt(ports[1]) < 0)))
                    {
                        port2Target = ports[1];
                        //System.out.println("Port 2 target: " + port2Target);
                    }
                    else{
                        System.out.println("Port range is not valid, replacing with any");
                        portAnyTarget = true;
                        port1Target = "any";
                    }
                }
                
                if(port1Target.equals("any"))
                {
                    portAnyTarget = true;
                    //System.out.println("Target port any is set");
                }
                
            } else {
                System.out.println("Did not recognize the port format");
            }
            
            if(splitRule.length > 7)
            {
                //System.out.println("Options detected");
                
                //int optionStartingIndex = rule.indexOf("(");
                //
                //System.out.println("Option starts at: " + optionStartingIndex);
                
                // parse rule string for options
                String optionSubstring = rule.substring(rule.indexOf("(") + 1,rule.length() - 1);
             
                options.parse(optionSubstring);
                //System.out.println("Options are: " + options);
                //options.CheckMatchingIP(new IPPacketParser());
                
                //byte [] testPayload = new byte[]{0x00,0x01,(byte)0x86,(byte)0xa5,(byte)0x56,(byte)0x15,(byte)0x25,(byte)0x15,0x00,0x01,(byte)0x86,(byte)0xb5,(byte)0x76,(byte)0xa5,0x00,(byte)0x01,(byte)0x96,(byte)0xa5};
                //boolean contentMatch = options.ContentMatching(testPayload);
                //
                //if(contentMatch)
                //{
                //    System.out.println("content matches");
                //} else {
                //    System.out.println("content does not match");
                //}
            }
            
            
        } else {
            System.out.println("Rule is missing arguments, recheck format");
        }
        
        System.out.println();
        System.out.println();
    }
    
    // compare ip, and port numbers
    public boolean SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort)
    {
        
        boolean matching1 = CheckOneWaySignature(ipSource,ipTarget,port1Source,port2Source,port1Target,port2Target,ip,sourcePort,destinationPort);
        boolean matching2 = false;
        
        if(bidirectional)
        {
            matching2 = CheckOneWaySignature(ipTarget,ipSource,port1Target,port2Target,port1Source,port2Source,ip,sourcePort,destinationPort);
        }
        
        return (matching1 | matching2);
    }
    
    private boolean CheckOneWaySignature(String sourceIPUni,String targetIPUni,String port1SourceUni,String port2SourceUni,String port1TargetUni,String port2TargetUni,IPPacketParser ip, int sourcePort, int destinationPort)
    {
        boolean matching = true;
        
        // if any is set for source ip, then don't need to check
        if(!sourceIPUni.equals("any"))
        {
            if(!sourceIPUni.equals(ip.getSourceAddressString()))
            {
                matching = false;
            }
        }

        // if any is set for target ip, then don't need to check
        if(!targetIPUni.equals("any"))
        {
            if(!targetIPUni.equals(ip.getDestinationAddressString()))
            {
                matching = false;
            }
        }
        
        // if any is set for port 1 source, then don't need to check
        if(!port1SourceUni.equals("any"))
        {
            // if port 2 of source is empty then a range is not defined
            if(port2SourceUni.isEmpty())
            {
                if(Integer.parseInt(port1SourceUni) != sourcePort)
                {
                    matching = false;
                }
            } else 
            {
                if(!(sourcePort > Integer.parseInt(port1SourceUni)  && sourcePort < Integer.parseInt(port2SourceUni)))
                {
                    matching = false;
                }
            }
        }

        // if any is set for port 1 target, then don't need to check
        if(!port1TargetUni.equals("any"))
        {
            // if port 2 of target is empty then a range was not defined
            if(port2TargetUni.isEmpty())
            {
                if(Integer.parseInt(port1TargetUni) != destinationPort)
                {
                    matching = false;
                }
            } else 
            {
                if(!(destinationPort > Integer.parseInt(port1TargetUni) && destinationPort < Integer.parseInt(port2TargetUni)))
                {
                    matching = false;
                }
            }
        }
        
        return matching;
    }
    
    public String GetProtocol()
    {
        return protocol;
    }
    
    public void printRule()
    {
        if(!action.isEmpty())
        {
            System.out.println("Action: " + action);
        }
        
        if(!protocol.isEmpty())
        {
            System.out.println("Protocol: " + protocol);
        }
        
        if(!ipSource.isEmpty())
        {
            System.out.println("IP Source: " + ipSource);
        }
        
        if(!maskSource.isEmpty())
        {
            System.out.println("Mask Source: " + maskSource);
        }
        
        if(!port1Source.isEmpty())
        {
            System.out.println("Port 1 Source: " + port1Source);
        }
        
        if(!port2Source.isEmpty())
        {
            System.out.println("Port 2 Source: " + port2Source);
        }    

        if(bidirectional)
        {
            System.out.println("<>");
        } else {
            System.out.println("->");
        }
        
        if(!ipTarget.isEmpty())
        {
            System.out.println("IP Target: " + ipTarget);
        }
        
        if(!maskTarget.isEmpty())
        {
            System.out.println("Mask Target: " + maskTarget);
        }
        
        if(!port1Target.isEmpty())
        {
            System.out.println("Port 1 Target: " + port1Target);
        }
        
        if(!port2Target.isEmpty())
        {
            System.out.println("Port 2 Target: " + port2Target);
        }

    }
}

class SignatureOptions{
    private String msg;
    private String logto;
    private String ttl;
    private String tos;
    private String id;
    private String fragoffset;
    private String fragbits;
    private int fragbitsMask;
    private String fragbitsOperation;
    private String dsize;
    private String flags;
    private int flagsMask;
    private String flagsOperation;
    private String seq;
    private String ack;
    private String itype;
    private String icode;
    private String content;
    private boolean sameip;
    private String sid;
    private String option;
    
    
    SignatureOptions()
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
        sameip = false;
        sid = new String();
        fragbitsMask = 0;
        fragbitsOperation = new String();
        flagsMask = 0;
        flagsOperation = new String();
    }
    
    public void parse(String o)
    {
        option = o;
        
        //System.out.println("Received options:\n" + option);
        
        String[] splitOption = option.split(";");
        //System.out.println("Parsed options");
        
        for(int x = 0; x < splitOption.length; x++)
        {
            splitOption[x] = splitOption[x].trim();
            //System.out.println(splitOption[x]);
        }
        
        for(String option: splitOption)
        {
            String[] singleOptionParsed = option.split(":");
            String op = "";
            String argument = "";
            
            if(singleOptionParsed.length == 2)
            {
                op = singleOptionParsed[0].trim();
                argument = singleOptionParsed[1].trim();
                //System.out.println(op);
                //System.out.println(argument);
                
                if(op.equals("msg"))
                {
                    msg = argument;
                    //System.out.println("Matched msg: " + msg);
                } else if(op.equals("logto"))
                {
                    logto = argument;
                    //System.out.println("Matched logto: " + logto);
                } else if(op.equals("ttl"))
                {
                    ttl = argument;
                    //System.out.println("Matched ttl: " + ttl);
                } else if(op.equals("tos")){
                    tos = argument;
                    //System.out.println("Matched tos: " + tos);
                } else if(op.equals("id"))
                {
                    id = argument;
                    //System.out.println("Matched id: " + id);
                } else if(op.equals("fragoffset"))
                {
                    fragoffset = argument;
                    //System.out.println("Matched fragoffset: " + fragoffset);
                } else if(op.equals("fragbits"))
                {
                    fragbits = argument.toUpperCase();
                    //System.out.println("Matched fragbits: " + fragbits);
                    
                    // Generate fragbit mask
                    //[0] Reserved flag
                    //[1] Don't Fragment
                    //[2] More Fragments
                    // bit direction used
                    // <--
                    // MDR 
                    // 210
                    
                    //
                    if(fragbits.indexOf('M') > -1)
                    {
                        //System.out.println("M: " + fragbits.indexOf('M'));
                        fragbitsMask = fragbitsMask | 0x04;
                    }
                    
                    if(fragbits.indexOf('D') > -1)
                    {
                        //System.out.println("D: " + fragbits.indexOf('D'));
                        fragbitsMask = fragbitsMask | 0x02;
                    }
                    
                    if(fragbits.indexOf('R') > -1)
                    {
                        //System.out.println("R: " + fragbits.indexOf('R'));
                        fragbitsMask = fragbitsMask | 0x01;
                    }
                    
                    if(fragbits.indexOf('+') > 0)
                    {
                        fragbitsOperation = "and";
                    }
                    
                    if(fragbits.indexOf('*') > 0)
                    {
                        fragbitsOperation = "or";
                    }
                    
                    if(fragbits.indexOf('!') > 0)
                    {
                        fragbitsOperation = "not";
                    }
                    
                    if(!fragbits.isEmpty())
                    {
                        fragbits = "and";
                    }
                    
                    //System.out.printf("fragbits mask: 0x%02X\n", fragbitsMask);
                    //System.out.println("fragbits operation: " + fragbitsOperation);
                    
                } else if(op.equals("dsize"))
                {
                    dsize = argument;
                    //System.out.println("Matched dsize: " + dsize);
                } else if(op.equals("flags"))
                {
                    flags = argument;
                    //System.out.println("Matched flags: " + flags);
                    
                    // Generate tcp flags mask
                    // bit direction used
                    // <-------
                    // CEUAPRSF 
                    // 76543210
                    
                    if(flags.indexOf('C') > -1)
                    {
                        flagsMask = flagsMask | 0x80;
                    }
                    
                    if(flags.indexOf('E') > -1)
                    {
                        flagsMask = flagsMask | 0x40;
                    }
                    
                    if(flags.indexOf('U') > -1)
                    {
                        flagsMask = flagsMask | 0x20;
                    }
                    
                    if(flags.indexOf('A') > -1)
                    {
                        flagsMask = flagsMask | 0x10;
                    }
                    
                    if(flags.indexOf('P') > -1)
                    {
                        flagsMask = flagsMask | 0x08;
                    }
                    
                    if(flags.indexOf('R') > -1)
                    {
                        flagsMask = flagsMask | 0x04;
                    }
                    
                    if(flags.indexOf('S') > -1)
                    {
                        flagsMask = flagsMask | 0x02;
                    }
                    
                    if(flags.indexOf('F') > -1)
                    {
                        flagsMask = flagsMask | 0x01;
                    }
                    
                    if(flags.indexOf('+') > 0)
                    {
                        flagsOperation = "and";
                    }
                    
                    if(flags.indexOf('*') > 0)
                    {
                        flagsOperation = "or";
                    }
                    
                    if(flags.indexOf('!') > 0)
                    {
                        flagsOperation = "not";
                    }
                    
                    if(flagsOperation.isEmpty())
                    {
                        flagsOperation = "and";
                    }
                    
                    //System.out.printf("flags mask: 0x%02X\n", flagsMask);
                    //System.out.println("flags operation: " + flagsOperation);
                    
                } else if(op.equals("seq"))
                {
                    seq = argument;
                    //System.out.println("Matched seq: " + seq);
                } else if(op.equals("ack"))
                {
                    ack = argument;
                   // System.out.println("Matched ack: " + ack);
                } else if(op.equals("itype"))
                {
                    itype = argument;
                    //System.out.println("Matched itype: " + itype);
                } else if(op.equals("icode"))
                {
                    icode = argument;
                    //System.out.println("Matched icode: " + icode);
                } else if(op.equals("content"))
                {
                    content = argument.substring(2,argument.length() - 2);
                    //System.out.println("Matched content: " + content);
                } else if(op.equals("sameip"))
                {
                    //sameip = argument;
                    sameip = true;
                    //System.out.println("Matched sameip ");
                } else if(op.equals("sid"))
                {
                    sid = argument;
                   // System.out.println("Matched sid: " + sid);
                }
                
            } else {
                System.out.println("Option format is not recognized");
            }
        }
    }
    
    public boolean CheckMatchingICMP(ICMPParser icmp)
    {
        boolean matching = false;
        
        if(!itype.isEmpty())
        {
            int typeT = Integer.parseInt(itype);
            if(typeT == Integer.parseInt(icmp.getTypeString()))
            {
                matching = true;
            }
        }
        
        if(!icode.isEmpty())
        {
            int codeT = Integer.parseInt(icode);
            if(codeT == Integer.parseInt(icmp.getCodeString()))
            {
                matching = true;
            }
        }
        
        return matching;
    }
    
    public boolean CheckMatchingTCP(TCPParser tcp)
    {
        boolean matching = false;
        
        if(!seq.isEmpty())
        {
            int seqT = Integer.parseInt(seq);
            if(seqT == Integer.parseInt(tcp.getSequenceNumberString()))
            {
                matching = true;
            }
        }
        
        if(!flags.isEmpty())
        {
            // Generate tcp flags mask
            // bit direction used
            // <-------
            // CEUAPRSF 
            // 76543210

            int currentTCPFlags = 0;
            
            if(flagsOperation.equals("and"))
            {
                if((flagsMask & currentTCPFlags) == flagsMask)
                {
                    //System.out.println("matched and operation");
                    matching = true;
                }
            } else if(flagsOperation.equals("or")) {
                if((int)((0xFF)&(flagsMask & currentTCPFlags)) > 0)
                {
                    //System.out.println("matched or operation");
                    matching = true;
                }
            } else if(flagsOperation.equals("not")) {
                if((flagsMask & currentTCPFlags) == 0)
                {
                    //System.out.println("matched not operation");
                    matching = true;
                }
            }

        }

        if(!ack.isEmpty())
        {
            int ackT = Integer.parseInt(ack);
            if(ackT == Integer.parseInt(tcp.getSequenceNumberString()))
            {
                matching = true;
            }
        }
        
        return matching;
    }
    
    public boolean CheckMatchingIP(IPPacketParser ip)
    {
        boolean matching = false;
        
        if(!ttl.isEmpty())
        {
            int ttlT = Integer.parseInt(ttl);
            if(ttlT == Integer.parseInt(ip.getTTLString()))
            {
                matching = true;
            }
        }
        
        if(!tos.isEmpty())
        {
            int tosT = Integer.parseInt(tos);
            if(tosT == Integer.parseInt(ip.getDSCPString()))
            {
                matching = true;
            }
        }
        
        if(!id.isEmpty())
        {
            int idT = Integer.parseInt(id);
            if(idT == Integer.parseInt(ip.getIdentification()))
            {
                matching = true;
            }
        }
        
        if(!fragoffset.isEmpty())
        {
            int fragoffsetT = Integer.parseInt(fragoffset);
            if(fragoffsetT == Integer.parseInt(ip.getFragmentOffsetString()))
            {
                matching = true;
            }
        }
        
        if(sameip)
        {
            if(ip.getSourceAddressString().equals(ip.getDestinationAddressString()))
            {
                matching = true;
            }
        }
        
        if(!fragbits.isEmpty())
        {
            //[0] Reserved flag
            //[1] Don't Fragment
            //[2] More Fragments
            // bit direction used
            // <--
            // MDR 
            // 210
            
            byte[] ipFlags = ip.getFlags();
            int currentFlags = 0;
            
            // M Flag
            if((int)(ipFlags[2]) == 1)
            {
                currentFlags = currentFlags | 0x04;
            }

            // D Flag
            if((int)(ipFlags[1]) == 1)
            {
                currentFlags = currentFlags | 0x02;
            }
            
            // R Flag
            if((int)(ipFlags[0]) == 1)
            {
                currentFlags = currentFlags | 0x01;
            }
            
            if(fragbitsOperation.equals("and"))
            {
                if((fragbitsMask & currentFlags) == fragbitsMask)
                {
                    //System.out.println("matched and operation");
                    matching = true;
                }
            } else if(fragbitsOperation.equals("or")) {
                if((int)((0xFF)&(fragbitsMask & currentFlags)) > 0)
                {
                    //System.out.println("matched or operation");
                    matching = true;
                }
            } else if(fragbitsOperation.equals("not")) {
                if((fragbitsMask & currentFlags) == 0)
                {
                    //System.out.println("matched not operation");
                    matching = true;
                }
            }
            
        }
        
        return matching;
    }
    
    public String getSID()
    {
        return sid;
    }
    
    public boolean SIDSet()
    {
        if(!fragoffset.isEmpty())
        {
            return true;
        }
        
        return false;
    }
    
    public boolean ContentMatching(byte[] payload)
    {
        boolean matching = false;
        //String contentParsed = content
        if(!content.isEmpty())
        {
            String [] contentArray = content.split(" ");
            byte [] contentByteArray = new byte[contentArray.length];
            
            for(int x = 0; x < contentArray.length; x++)
            {
                contentByteArray[x] = DatatypeConverter.parseHexBinary(contentArray[x])[0];
    
                //System.out.printf("Before: %s, After0x%02X\n",contentArray[x],contentByteArray[x]);
    
            }
            
            int countContent = 0;
            System.out.println("ContentByteArray length: " + contentByteArray.length);
            for(int x = 0; x < payload.length; x++)
            {
                if((payload[x] == contentByteArray[countContent]) && (countContent < contentByteArray.length))
                {
                    System.out.println("CountContent: "+ countContent);
                    if(countContent == (contentByteArray.length -1))
                    {
                        matching = true;
                        break;
                    }
                    countContent++;
                } else if((payload[x] == contentByteArray[0])){
                    countContent = 1;
                }
                else{
                    countContent = 0;
                }
            }
        }
        
        return matching;
    }
    
    public boolean PayloadSizeMatching(int payloadSize)
    {
        boolean matching = false;
        
        if(!dsize.isEmpty())
        {
            int sizeToCompareTo = Integer.parseInt(dsize);
            
            if(sizeToCompareTo == payloadSize)
            {
                matching = true;
            }
        }
        
        return matching;
    }
    
    public String messageToPrint()
    {
        return msg;
    }
    
    public String fileToPrintTo()
    {
        return logto;
    }
    
    public void printOptions()
    {
        if(!msg.isEmpty())
        {
            System.out.println("msg: " + msg);
        }
        
        if(!logto.isEmpty())
        {
            System.out.println("log to: " + logto);
        }
        
        if(!ttl.isEmpty())
        {
            System.out.println("ttl: " + ttl);
        }
        
        if(!tos.isEmpty())
        {
            System.out.println("tos: " + tos);
        }
        
        if(!id.isEmpty())
        {
            System.out.println("id: " + id);
        }
        
        if(!fragoffset.isEmpty())
        {
            System.out.println("fragoffset: " + fragoffset);
        }
        
        if(!fragbits.isEmpty())
        {
            System.out.println("fragbits: " + fragbits);
        }
        
        if(!dsize.isEmpty())
        {
            System.out.println("dsize: " + dsize);
        }
        
        if(!flags.isEmpty())
        {
            System.out.println("flags: " + flags);
        }
        
        if(!seq.isEmpty())
        {
            System.out.println("seq: " + seq);
        }
        
        if(!ack.isEmpty())
        {
            System.out.println("ack: " + ack);
        }
        
        if(!itype.isEmpty())
        {
            System.out.println("itype: " + itype);
        }
        
        if(!icode.isEmpty())
        {
            System.out.println("icode: " + icode);
        }
        if(!content.isEmpty())
        {
            System.out.println("content: " + content);
        }
        
        if(sameip)
        {
            System.out.println("sameip is being checked");
        }
        
        if(!sid.isEmpty())
        {
            System.out.println("sid: " + sid);
        }
    }
}