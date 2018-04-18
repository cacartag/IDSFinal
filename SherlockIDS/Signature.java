import java.util.Scanner;
import java.util.Arrays;
import java.util.Vector;
import java.util.TreeMap;
import java.io.BufferedReader;
import java.io.FileReader;
import javax.xml.bind.DatatypeConverter;
import java.lang.*;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;

public class Signature{
    private String action;
    private String protocol;
    private String ipSource;
    private String maskSource;
    private String ipMaskSource;
    private boolean ipAnySource;
    private String port1Source;
    private String port2Source;
    private boolean portAnySource;
    private boolean bidirectional;
    private String ipTarget;
    private String maskTarget;
    private String ipMaskTarget;
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
                    ipMaskSource = splitRule[2];
                    
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
            
            if(splitIpMask.length == 2 || splitIpMask.length == 1)
            {
                if(splitIpMask.length == 2)
                {
                    String[] ipSplit = splitIpMask[0].split("\\.");
                    
                    if(ipSplit.length == 4)
                    {
                        ipTarget = splitIpMask[0];
                    }
                    
                    maskTarget = splitIpMask[1];
                    ipMaskTarget = splitRule[5];
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
             
                options.parse(optionSubstring, rule);
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
    public boolean SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
    {
        
        boolean matching1 = CheckOneWaySignature(ipSource,ipMaskSource,ipTarget,ipMaskTarget,port1Source,port2Source,port1Target,port2Target,ip,sourcePort,destinationPort, portAvailable);
        boolean matching2 = false;
        
        if(bidirectional)
        {
            matching2 = CheckOneWaySignature(ipTarget,ipMaskTarget,ipSource,ipMaskSource,port1Target,port2Target,port1Source,port2Source,ip,sourcePort,destinationPort, portAvailable);
        }
        
        return (matching1 | matching2);
    }
    
    private boolean CheckOneWaySignature(String sourceIPUni, String sourceMaskUni,String targetIPUni,String targetMaskUni,String port1SourceUni,String port2SourceUni,String port1TargetUni,String port2TargetUni,IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
    {
        boolean matching = true;
        
        // if any is set for source ip, then don't need to check
        //System.out.println("sourceIPUni: " + sourceIPUni);
        if(!sourceIPUni.equals("any"))
        {
            if(!InSameSubnet(sourceMaskUni,ip.getSourceAddressString()))
            {
                matching = false;
            }
        }

        // if any is set for target ip, then don't need to check
        //System.out.println("targetIPUni: " + targetIPUni);
        if(!targetIPUni.equals("any"))
        {
            if(!InSameSubnet(targetMaskUni, ip.getDestinationAddressString()))
            {
                matching = false;
            }
        }
        
        // this will be unset for icmp, arp, and ip packets
        if(portAvailable)
        {
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
        }
        
        return matching;
    }
    
    public boolean InSameSubnet(String subnetIPMask, String ipMatching)
    {
        //System.out.println("checking subnet: "+ subnetIPMask);
        //System.out.println("IP to check: " + ipMatching);
        SubnetUtils utilSubnet = new SubnetUtils(subnetIPMask); 
        SubnetInfo subnet = utilSubnet.getInfo();
        boolean matching = subnet.isInRange(ipMatching);

        return matching;
    }
    
    public String GetProtocol()
    {
        return protocol;
    }
    
    public SignatureOptions GetSignatureOptions()
    {
        return options;
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
            System.out.println("Direction: <>");
        } else {
            System.out.println("Direction: ->");
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
        
        options.printOptions();

    }
}