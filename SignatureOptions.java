import java.util.Scanner;
import java.util.Arrays;
import java.util.Vector;
import java.util.TreeMap;
import java.io.BufferedReader;
import java.io.FileReader;
import javax.xml.bind.DatatypeConverter;
import java.lang.*;

public class SignatureOptions{
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
        
        System.out.println("starting to check for matching tcp");
        
        if(!seq.isEmpty())
        {
            System.out.println("checking sequence number");
            int seqT = Integer.parseInt(seq);
            if(seqT == Integer.parseInt(tcp.getSequenceNumberString()))
            {
                matching = true;
            }
        }
        
        if(!flags.isEmpty())
        {
            int currentTCPFlags = tcp.getTCPFlags();
            
            System.out.println("checking flags ");
            System.out.println("flags mask: " + flagsMask);            
            System.out.println("current flags: " + currentTCPFlags);
            // Generate tcp flags mask
            // bit direction used
            // <-------
            // CEUAPRSF 
            // 76543210

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
            System.out.println("checking acknowledgement");
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