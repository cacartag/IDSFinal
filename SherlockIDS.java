import java.nio.ByteBuffer;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Collection;
import java.util.Vector;
import java.lang.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.BufferedReader;
import java.io.PrintStream;
import java.io.InputStreamReader;
import javax.xml.bind.DatatypeConverter;
import java.lang.Thread;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.TreeMap;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.BufferedWriter;
import java.time.format.DateTimeFormatter;  
import java.time.LocalDateTime;    
import java.io.FileWriter;

public class SherlockIDS{
    private TreeMap<String,Vector<Signature>> signatures;
    private SimplePacketDriver driver;
    private String[] adapters;
    private EthernetParser eth;
    private IPPacketParser ip;
    private TCPParser tcp;
    private ARPParser arp;
    private UDPParser udp;
    private ICMPParser icmp;
    private boolean doneReading;
    private BufferedReader readStream;
    private String inputFile;
    
    SherlockIDS()
    {
        signatures = new TreeMap<String,Vector<Signature>>();
        driver = new SimplePacketDriver();
        adapters = driver.getAdapterNames();
        eth = new EthernetParser();
        ip = new IPPacketParser();
        tcp = new TCPParser();
        arp = new ARPParser();
        udp = new UDPParser();
        icmp = new ICMPParser();
        doneReading = false;
        inputFile = new String();
    }
    
    SherlockIDS(TreeMap<String,Vector<Signature>> s)
    {
        signatures = s;
        driver = new SimplePacketDriver();
        adapters = driver.getAdapterNames();
        eth = new EthernetParser();
        ip = new IPPacketParser();
        tcp = new TCPParser();
        arp = new ARPParser();
        udp = new UDPParser();
        icmp = new ICMPParser();
        doneReading = false;
        inputFile = new String();
    }
    
    SherlockIDS(TreeMap<String,Vector<Signature>> s, String inFile)
    {
        signatures = s;
        driver = new SimplePacketDriver();
        adapters = driver.getAdapterNames();
        eth = new EthernetParser();
        ip = new IPPacketParser();
        tcp = new TCPParser();
        arp = new ARPParser();
        udp = new UDPParser();
        icmp = new ICMPParser();
        doneReading = false;
        inputFile = inFile;
    }
    
    public void SetupInvestigation()
    {
        //System.out.println("Signatures Received by Sherlock");
        //System.out.println("IP: ");
        //PrintReceivedRules("ip");
        //System.out.println("\n\nARP: ");
        //PrintReceivedRules("arp");        
        //System.out.println("\n\nTCP: ");
        //PrintReceivedRules("tcp");
        //System.out.println("\n\nUDP: ");
        //PrintReceivedRules("udp");
        //System.out.println("\n\nICMP: ");
        //PrintReceivedRules("icmp");
        
        if(inputFile.isEmpty())
        {
            chooseInterface();
        } else {
            System.out.println("File to read from is: " + inputFile);
        }
    }
    
    public void Investigate() throws Exception
    {

        if(!inputFile.isEmpty())
        {
            try
            {
                FileInputStream in = new FileInputStream(inputFile);        
                readStream = new BufferedReader(new InputStreamReader(in,"UTF-8"));
                
            } catch (Exception e)
            {
                System.out.println("Error: Could not open input file" + inputFile + "\n Looking for adapter");
                chooseInterface();
            }
        }
        
        // new variables created for ip fragment reassembly
        AtomicInteger mainDone = new AtomicInteger(0);
        Vector<String> fragmentIDs = new Vector<String>();
        ConcurrentLinkedQueue<Map<String,IPPacketParser>> packetQueue = new ConcurrentLinkedQueue<Map<String,IPPacketParser>>();
        ConcurrentLinkedQueue<FragmentModel> reassembledPacketQueue = new ConcurrentLinkedQueue<FragmentModel>();
        Vector<IPFragmentAssembler> threadVector = new Vector<IPFragmentAssembler>();
        FragmentAdministrator adminThread = new FragmentAdministrator(reassembledPacketQueue,mainDone,packetQueue, signatures);
        Object threads[];
        boolean threadsStillAlive = true;
        
        Vector<Signature> arpRules = signatures.get("arp");
        Vector<Signature> ipRules = signatures.get("ip");
        Vector<Signature> icmpRules = signatures.get("icmp");
        Vector<Signature> tcpRules = signatures.get("tcp");
        Vector<Signature> udpRules = signatures.get("udp");
        
        // parsing ethernet frames
        boolean continueLoopEth = true;

        // admin thread for fragments
        adminThread.start();
        
        while(continueLoopEth)
        {
            
            byte [] packet = getPacket();
            eth = new EthernetParser();
            ip = new IPPacketParser();
            tcp = new TCPParser();
            udp = new UDPParser();
            icmp = new ICMPParser();

            System.out.printf("\n");
            
            if(packet.length > 14)
            {
                eth.parsePacket(packet);

                if(eth.getTypeString().equals("0800"))
                {   
                    
                    ip.parsePacket(packet);
                        
                    if(ip.getIfFragment() == true)
                    {
                        //System.out.println("Detected Fragment");
                        if(!fragmentIDs.contains(ip.getIdentification()))
                        {
                            
                            // new id received
                            
                            IPFragmentAssembler ipf = new IPFragmentAssembler(packetQueue,ip.getIdentification(),reassembledPacketQueue);
                            ipf.start();
                            Map<String,IPPacketParser> toThread = new HashMap<String,IPPacketParser>();
                            toThread.put(ip.getIdentification(),ip);
                            packetQueue.add(toThread);
                            threadVector.addElement(ipf);
                            fragmentIDs.addElement(ip.getIdentification());
                            CheckIPRules(ipRules);
                            //System.out.println("Create Thread: "+ ip.getIdentification());
                        }else{
                            
                            // already received this packets ID
                            Map<String,IPPacketParser> toThread = new HashMap<String,IPPacketParser>();
                            toThread.put(ip.getIdentification(),ip);
                            packetQueue.add(toThread);
                            CheckIPRules(ipRules);
                        }
                    } else {
                        //ip.printHeaderOnly();
                        //ip.printAll();    
                        
                        // check that the protocol is icmp
                        if(Integer.parseInt(ip.getProtocolString()) == 1)
                        {
                            icmp.parsePacket(packet);
                            //icmp.printAll();
                            
                            //checking ip rules
                            CheckIPRules(ipRules);
                            
                            // checking icmp rules
                            for(int x = 0; x < icmpRules.size(); x++)
                            {
                                Signature icmpRule = icmpRules.get(x);
                                SignatureOptions icmpOptions = icmpRule.GetSignatureOptions();
                                
                                //icmpRule.CheckMatchingICMP(icmp);
                                
                                boolean matchedSignature = icmpRule.SignatureMatching(ip, 0, 0, false);
                                boolean matchedOptions = icmpOptions.CheckMatchingICMP(icmp);
                                boolean sizeAndContentMatching = CheckSizeAndContent(icmpOptions,icmp.getPayloadBytes(), icmp.getPayloadSize());
                                
                                if(matchedSignature && matchedOptions && sizeAndContentMatching)
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
                                            write += message + " ";
                                        }
                                        
                                        if(!sid.isEmpty())
                                        {
                                            write += sid;
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
                            
                        }else if(Integer.parseInt(ip.getProtocolString()) == 6)// check that the protocol is TCP
                        {
                            tcp.parsePacket(packet);
                            tcp.printAll();
                            
                            //SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
                           
                            //checking ip rules
                            CheckIPRules(ipRules);
                            // checking tcp rules
                            for(int x = 0; x < tcpRules.size(); x++)
                            {
                                Signature tcpRule = tcpRules.get(x);
                                SignatureOptions tcpOptions = tcpRule.GetSignatureOptions();
                                
                                boolean matchedSignature = tcpRule.SignatureMatching(ip, Integer.parseInt(tcp.getSourcePortString()), Integer.parseInt(tcp.getDestinationPortString()), true);
                                boolean matchedOptions = tcpOptions.CheckMatchingTCP(tcp);
                                boolean sizeAndContentMatching = CheckSizeAndContent(tcpOptions,tcp.getPayloadBytes(), tcp.getPayloadSize());
                                
                                //if(sizeAndContentMatching)
                                //    System.out.println("matches content");
                                        
                                //tcpOptions.printOptions();
                                if(matchedSignature && matchedOptions && sizeAndContentMatching)
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
                                            write += message + " ";
                                        }
                                        
                                        if(!sid.isEmpty())
                                        {
                                            write += sid;
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
                           
                           
                        } else if(Integer.parseInt(ip.getProtocolString()) == 17)
                        {
                            udp.parsePacket(packet);
                            //udp.printAll();
                            
                            //checking ip rules
                            CheckIPRules(ipRules);
                           
                            for(int x = 0; x < udpRules.size(); x++)
                            {
                                Signature udpRule = udpRules.get(x);
                                SignatureOptions udpOptions = udpRule.GetSignatureOptions();
                                
                                boolean matchedSignature = udpRule.SignatureMatching(ip, Integer.parseInt(udp.getSourcePortString()), Integer.parseInt(udp.getDestinationPortString()), true);
                            
                                boolean sizeAndContentMatching = CheckSizeAndContent(udpOptions,udp.getPayloadBytes(), udp.getPayloadSize());
                                
                                //tcpOptions.printOptions();
                                if(matchedSignature && sizeAndContentMatching)
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
                                            write += message + " ";
                                        }
                                        
                                        if(!sid.isEmpty())
                                        {
                                            write += sid;
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
                            
                        } else {
                            //SignatureMatching(IPPacketParser ip, int sourcePort, int destinationPort, boolean portAvailable)
                           CheckIPRules(ipRules);

                        }
                    }
                } else if(eth.getTypeString().equals("0806"))
                {
                    // goint to need to check this
                    // eth.printHeaderOnly();
                    arp.parsePacket(packet);
                    
                    arp.printAll();
                }
            }

            if(doneReading)
            {
                continueLoopEth = false;
            }
        }
        threads = threadVector.toArray();
        
        while(threadsStillAlive)
        {
            threadsStillAlive = false;
            if(threads != null)
            {
                for(int x = 0; x < threads.length; x++)
                {
                    if(((IPFragmentAssembler)threads[x]).isAlive())
                    {
                        threadsStillAlive = true;
                    }
                }
            }
        }
        mainDone.set(1);       

    }

    public void PrintReceivedRules(String protocol)
    {
        Vector<Signature> protocolSignatures = signatures.get(protocol);
        
        for(int x = 0; x < protocolSignatures.size(); x++)
        {
            Signature temp = protocolSignatures.get(x);
            temp.printRule();
            System.out.println("\n\n");
        }
    }
    
    // scans interfaces and prompts the user to choose one
    public void chooseInterface()
    {
        Scanner sc = new Scanner(System.in);
        
        System.out.println("Adapter found are:");
        for (int index = 0; index < adapters.length; index++)
        {
            System.out.println("("+index+"): "+adapters[index]);
        }
        
        System.out.println("Which interfaces do you want to monitor?");
        
        int adapterIndex = sc.nextInt();
        
        if(driver.openAdapter(adapters[adapterIndex]))
        {
            System.out.println("adapter "+ adapters[adapterIndex] + " open");
        }
    }
    
    // get packet from either a file or the chosen network interface card
    public byte[] getPacket() throws Exception
    {
        byte [] packet; // temporary initialization
        boolean endOfFile = false;
        
        if(inputFile.isEmpty())
        {
            // read from NIC
            packet = driver.readPacket();
            
        } else {
            try{
                // using Byte vector since we don't know the size of the packet
                Vector<Byte> byteAccumulator = new Vector<Byte>();
                String temp = new String();
                Byte [] finalPacket;
                
                do
                {
                    // string needs to be converted into Byte class array
                    // needs to go through byte primitive step
                    String [] byteString = new String[0];
                    
                    if((temp = readStream.readLine()) != null)
                    {
                        byteString = temp.split(" ");
                    }
                    else{
                        endOfFile = true;
                        temp = new String();
                        //byteString = temp.split(" ");
                        //break;
                    }

                    if(byteString.length > 0)
                    {
                        Byte [] byteTemp = new Byte[byteString.length];
                        
                        if(!temp.isEmpty() || endOfFile)
                        {
                            for(int counter = 0; counter < byteString.length; counter++)
                            {
                                byteTemp[counter] = new Byte(DatatypeConverter.parseHexBinary(byteString[counter])[0]);
                            }                        
                            
                            byteAccumulator.addAll(Arrays.asList(byteTemp));
                        }
                    }
                    
                } while (!temp.isEmpty());

                finalPacket = new Byte[byteAccumulator.size()];
                packet = new byte[byteAccumulator.size()];
                byteAccumulator.toArray(finalPacket);
                
                for(int counter = 0; counter < finalPacket.length; counter++)
                {
                    packet[counter] = finalPacket[counter];
                }
                
                // check that end of file hasn't been reached yet
                if(endOfFile)
                {
                    doneReading = true;
                }
                
            } catch (Exception e){
                packet = new byte[50];
                e.printStackTrace();
                System.out.println("Error: Could not read from input file");
                doneReading = true;
            }   
        }   
        return packet;
    }
    
    public void CheckIPRules(Vector<Signature> ipRules) throws Exception
    {
        // checking ip rules
        for(int x = 0; x < ipRules.size(); x++)
        {
            Signature ipRule = ipRules.get(x);
            SignatureOptions ipOptions = ipRule.GetSignatureOptions();
            
            boolean matchedSignature = ipRule.SignatureMatching(ip,0, 0, false);
            boolean matchedOptions = ipOptions.CheckMatchingIP(ip);
            boolean sizeAndContentMatching = CheckSizeAndContent(ipOptions,ip.getPayloadBytes(), ip.getPayloadSize());
            
            if(matchedSignature && matchedOptions && sizeAndContentMatching)
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
                        write += message + " ";
                    }
                    
                    if(!sid.isEmpty())
                    {
                        write += sid;
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

}