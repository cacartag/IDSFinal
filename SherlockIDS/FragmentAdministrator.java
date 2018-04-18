import java.lang.Thread;  
import java.util.concurrent.ConcurrentLinkedQueue;
import java.sql.Timestamp;
import java.util.Map;
import java.util.HashMap;
import java.util.TreeMap;
import java.util.Vector;
import java.util.Arrays;
import java.lang.*;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.format.DateTimeFormatter;  
import java.time.LocalDateTime;    
import java.util.ArrayList;
import java.util.Collection;

public class FragmentAdministrator extends Thread
{
    ConcurrentLinkedQueue<FragmentModel> reassembledPacketQueue;
    ConcurrentLinkedQueue<IPFragmentAssembler> threadQueue; 
    ConcurrentLinkedQueue<Map<String,IPPacketParser>> packetQueue;
    boolean threadsStillAlive;
    AtomicInteger mainDone; 
    IPFragmentAssembler threadsArray[];
    Vector<String> doneID;
    ICMPParser icmp;
    TCPParser tcp;
    UDPParser udp;
    Vector<Signature> arpRules;
    Vector<Signature> ipRules;
    Vector<Signature> icmpRules;
    Vector<Signature> tcpRules;
    Vector<Signature> udpRules;
  
    FragmentAdministrator(ConcurrentLinkedQueue<FragmentModel> r, AtomicInteger m,ConcurrentLinkedQueue<Map<String,IPPacketParser>> p, TreeMap<String,Vector<Signature>> signatures)
    {
        reassembledPacketQueue = r;
        packetQueue = p;
        threadsStillAlive = true;
        mainDone = m;
        doneID = new Vector<String>();
        icmp = new ICMPParser();
        tcp = new TCPParser();
        udp = new UDPParser();
        
        arpRules = signatures.get("arp");
        ipRules = signatures.get("ip");
        icmpRules = signatures.get("icmp");
        tcpRules = signatures.get("tcp");
        udpRules = signatures.get("udp");
        
    }

    public void run()
    {
        boolean lastIteration = true;
        BufferedWriter out = null;       
        FileWriter fstream;
        
        System.out.println("started fragment administrator");
        
        try{
            fstream = new FileWriter("Fragment.txt", true); //true tells to append data.
            out = new BufferedWriter(fstream);        
            while((mainDone.get() == 0))
            {
                FragmentModel s = reassembledPacketQueue.peek();
                
                while(s != null)
                {
                    s = reassembledPacketQueue.poll();
    
                    try  
                    {

                        out.write("Reassembled Packet ID"+(s.getReassembledPacket()).getIdentification()+"\n");
                        if(s.getSid() == 2)
                        {
                            out.write("Overlap Detected\n");
                            
                            String parsedPacket = (s.getReassembledPacket()).printAllReturn();
                            out.write(parsedPacket);
                            
                            doneID.addElement((s.getReassembledPacket()).getIdentification());
                            
                            CheckRules(s.getReassembledPacket(),out,s.getSid());
                            
                        } else if(s.getSid() == 3)
                        {
                            out.write("Packet larger than 64K has been detected\n");
                            
                            CheckRules(((s.getFragments()).get((s.getFragments()).firstKey())),out,s.getSid());
                        }
                        else if(s.getSid() == 4)
                        {
                            out.write("Timeout Detected, incomplete fragments are: \n");

    
                            printIncompletePackets((s.getFragments()).values(), out);
                            
                            // ((s.getFragments()).get((s.getFragments()).firstKey())).printAll();
                            
                            CheckRules(((s.getFragments()).get((s.getFragments()).firstKey())),out,s.getSid());
                        } else {
                        
                            String parsedPacket = (s.getReassembledPacket()).printAllReturn();
                            out.write(parsedPacket);
                            
                            doneID.addElement((s.getReassembledPacket()).getIdentification());
                            
                            CheckRules(s.getReassembledPacket(),out,1);
                        }
                    }
                    catch (Exception e)
                    {
                        System.err.println("Error out: \n");
                        e.printStackTrace();
                        
                    }
                    
                    s = reassembledPacketQueue.peek();
                }
                
                // see if any of the finished id packets are holding up queue
                boolean needToFlush = true;
                Map<String,IPPacketParser> queueFlush = packetQueue.peek();
                Object doneArray[] = doneID.toArray();                 
                
                while(needToFlush && (queueFlush != null))
                {
                    needToFlush = false;
                    //check if the packets id matches finished packet
                
                    for(int x = 0; x < doneArray.length; x++)
                    {
                        if(queueFlush.containsKey((String)doneArray[x]))
                        {
                            packetQueue.poll();
                            queueFlush = packetQueue.peek();
                            needToFlush = true;
                        }
                    }
                }
                
                
            }
            
            out.close();
        } catch (Exception exce)
        {
            System.err.println("Error: " + exce);
        }
        
        
        
        System.out.println("main Done, and no more threads");
    }
    
    public void CheckRules(IPPacketParser ip, BufferedWriter fragmentOut, int currentSID) throws Exception
    {
        icmp = new ICMPParser();
        tcp = new TCPParser();
        udp = new UDPParser();
        
        if((Integer.parseInt(ip.getProtocolString()) == 1) && (currentSID != 4))
        {
            //System.out.println("inside icmp admin");
            //icmp.parsePacket(ip.getPacket());
            fragmentOut.write("ICMP Traffic detected:\n");
            fragmentOut.write(icmp.printAllReturn());
            
            //checking ip rules
            CheckIPRules(ipRules,ip,currentSID);
            
            // checking icmp rules
            for(int x = 0; x < icmpRules.size(); x++)
            {
                Signature icmpRule = icmpRules.get(x);
                SignatureOptions icmpOptions = icmpRule.GetSignatureOptions();
                
                //icmpRule.CheckMatchingICMP(icmp);
                
                boolean matchedSignature = icmpRule.SignatureMatching(ip, 0, 0, false);
                boolean matchedOptions = icmpOptions.CheckMatchingICMP(icmp);
                boolean sizeAndContentMatching = CheckSizeAndContent(icmpOptions,icmp.getPayloadBytes(), icmp.getPayloadSize());
                boolean checkSID = sidComparison(icmpOptions,currentSID);
                
                if(matchedSignature && matchedOptions && sizeAndContentMatching && checkSID)
                {
                    String message = icmpOptions.messageToPrint();
                    String sid = icmpOptions.getSID();
                    String logto = icmpOptions.fileToPrintTo();
                    
                    BufferedWriter out = null;
                    FileWriter fstream;
                    
                    if(!logto.isEmpty())
                    {
                        fstream = new FileWriter(logto,true);
                        out = new BufferedWriter(fstream);
                        String write = new String();
                        


                        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
                        LocalDateTime now = LocalDateTime.now();  
                        write += dtf.format(now) + " ";   
                        
                        
                        if(!message.isEmpty())
                        {
                            write += message + " from fragment administrator" ;
                        }
                        
                        write += "\n\n";
                        
                        out.write(write);
                        
                        out.close();

                    } else {
                        if(!message.isEmpty())
                        {
                            System.out.println(message);
                        }
                        
                        if(!sid.isEmpty())
                        {
                            System.out.println(sid);
                        }
                    }
                    

                }
            }
            
        }else if((Integer.parseInt(ip.getProtocolString()) == 6) && (currentSID != 4))// check that the protocol is TCP
        {
            tcp.parsePacket(ip.getPacket());
            fragmentOut.write("TCP Traffic detected\n");
            fragmentOut.write(tcp.printAllReturn());
            
            //System.out.println("inside tcp admin");
            //SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
           
            //checking ip rules
            CheckIPRules(ipRules,ip,currentSID);
            // checking tcp rules
            for(int x = 0; x < tcpRules.size(); x++)
            {
                Signature tcpRule = tcpRules.get(x);
                SignatureOptions tcpOptions = tcpRule.GetSignatureOptions();
                
                boolean matchedSignature = tcpRule.SignatureMatching(ip, Integer.parseInt(tcp.getSourcePortString()), Integer.parseInt(tcp.getDestinationPortString()), true);
                boolean matchedOptions = tcpOptions.CheckMatchingTCP(tcp);
                boolean sizeAndContentMatching = CheckSizeAndContent(tcpOptions,tcp.getPayloadBytes(), tcp.getPayloadSize());
                boolean checkSID = sidComparison(tcpOptions,currentSID);
                
                //if(sizeAndContentMatching)
                //    System.out.println("matches content");
                        
                //tcpOptions.printOptions();
                if(matchedSignature && matchedOptions && sizeAndContentMatching && checkSID)
                {
                    String message = tcpOptions.messageToPrint();
                    String sid = tcpOptions.getSID();
                    String logto = tcpOptions.fileToPrintTo();
                    
                    BufferedWriter out = null;
                    FileWriter fstream;
                    
                    if(!logto.isEmpty())
                    {
                        fstream = new FileWriter(logto,true);
                        out = new BufferedWriter(fstream);
                        String write = new String();
                        


                        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
                        LocalDateTime now = LocalDateTime.now();  
                        write += dtf.format(now) + " ";   
                        
                        
                        if(!message.isEmpty())
                        {
                            write += message + " from fragment administrator" ;
                        }
                        
                        write += "\n\n";
                        
                        out.write(write);
                        
                        out.close();

                    } else {
                        if(!message.isEmpty())
                        {
                            System.out.println(message);
                        }
                        
                        if(!sid.isEmpty())
                        {
                            System.out.println(sid);
                        }
                    }
                }
                    
            }
           
           
        } else if((Integer.parseInt(ip.getProtocolString()) == 17) && (currentSID != 4))
        {
            udp.parsePacket(ip.getPacket());
            fragmentOut.write("UDP Traffic detected\n");
            fragmentOut.write(udp.printAllReturn());
            
            //System.out.println("inside udp admin");
            //checking ip rules
            CheckIPRules(ipRules,ip,currentSID);
           
            for(int x = 0; x < udpRules.size(); x++)
            {
                Signature udpRule = udpRules.get(x);
                SignatureOptions udpOptions = udpRule.GetSignatureOptions();
                
                boolean matchedSignature = udpRule.SignatureMatching(ip, Integer.parseInt(udp.getSourcePortString()), Integer.parseInt(udp.getDestinationPortString()), true);
            
                boolean sizeAndContentMatching = CheckSizeAndContent(udpOptions,udp.getPayloadBytes(), udp.getPayloadSize());
                boolean checkSID = sidComparison(udpOptions,currentSID);
                
                //tcpOptions.printOptions();
                if(matchedSignature && sizeAndContentMatching && checkSID)
                {
                    String message = udpOptions.messageToPrint();
                    String sid = udpOptions.getSID();
                    String logto = udpOptions.fileToPrintTo();
                    
                    BufferedWriter out = null;
                    FileWriter fstream;
                    
                    if(!logto.isEmpty())
                    {
                        fstream = new FileWriter(logto,true);
                        out = new BufferedWriter(fstream);
                        String write = new String();
                        


                        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
                        LocalDateTime now = LocalDateTime.now();  
                        write += dtf.format(now) + " ";   
                        
                        
                        if(!message.isEmpty())
                        {
                            write += message + " from fragment administrator" ;
                        }
                        
                        write += "\n\n";
                        
                        out.write(write);
                        
                        out.close();

                    } else {
                        if(!message.isEmpty())
                        {
                            System.out.println(message);
                        }
                    }
                }   
            }
            
        } else {
            //SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
            //System.out.println("inside ip only admin");
           CheckIPRules(ipRules,ip, currentSID);

        }
        
    }
    
    public void CheckIPRules(Vector<Signature> ipRules,IPPacketParser ip,int currentSID) throws Exception
    {
        // checking ip rules
        for(int x = 0; x < ipRules.size(); x++)
        {
            Signature ipRule = ipRules.get(x);
            SignatureOptions ipOptions = ipRule.GetSignatureOptions();
            
            boolean matchedSignature = ipRule.SignatureMatching(ip,0, 0, false);
            boolean matchedOptions = ipOptions.CheckMatchingIP(ip);
            boolean sizeAndContentMatching = CheckSizeAndContent(ipOptions,ip.getPayloadBytes(), ip.getPayloadSize());
            boolean checkSID = sidComparison(ipOptions,currentSID);
            
            if(matchedSignature && matchedOptions && sizeAndContentMatching && checkSID)
            {
                String message = ipOptions.messageToPrint();
                String sid = ipOptions.getSID();
                String logto = ipOptions.fileToPrintTo();
                
                BufferedWriter out = null;
                FileWriter fstream;
                
                if(!logto.isEmpty())
                {
                    fstream = new FileWriter(logto,true);
                    out = new BufferedWriter(fstream);
                    String write = new String();

                    DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");  
                    LocalDateTime now = LocalDateTime.now();  
                    write += dtf.format(now) + " ";   
                    
                    
                    if(!message.isEmpty())
                    {
                        write += message + " from fragment administrator" ;
                    }
                    
                    write += "\n\n";
                    
                    out.write(write);
                    
                    out.close();

                } else {
                    if(!message.isEmpty())
                    {
                        System.out.println(message);
                    }
                }
            }
        }
    }   
    
    public boolean CheckSizeAndContent(SignatureOptions option, byte[] payload, int payloadSize)
    {
        // check for payload size only if set
        boolean payloadSizeMatching = true;
        if(option.PayloadSizeMatchingSet())
        {
            payloadSizeMatching = option.PayloadSizeMatching(payloadSize);
        }
        
        // check for payload content if set
        boolean payloadContentMatching = true;
        if(option.ContentMatchingSet())
        {
            payloadContentMatching = option.ContentMatching(payload);
        }
        
        return payloadSizeMatching & payloadContentMatching;
    }
    
    public void printIncompletePackets(Collection<IPPacketParser> incompleteFrags, BufferedWriter fragmentOut) throws Exception
    {                    
        icmp = new ICMPParser();
        tcp = new TCPParser();
        udp = new UDPParser();
    
        ArrayList<IPPacketParser> incompleteFragments = new ArrayList<IPPacketParser>(incompleteFrags);
        
        for(int x = 0; x < incompleteFragments.size(); x++)
        {
            fragmentOut.write((incompleteFragments.get(x)).printAllReturn());
        }
    }
    
    public boolean sidComparison(SignatureOptions option,int currentSID)
    {
        boolean matching = true;

        if(option.SIDSet())
        {
            int ruleSID = Integer.parseInt(option.getSID());
            if(ruleSID == currentSID)
            {
                matching = true;
            } else {
                matching = false;
            }
        }
            
        return matching;
        
    }
}