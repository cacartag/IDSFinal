import java.util.Vector;
import java.util.TreeMap;

public class SherlockIDS{
    TreeMap<String,Vector<Signature>> signatures;

    SherlockIDS()
    {
        signatures = new TreeMap<String,Vector<Signature>>();
    }
    
    SherlockIDS(TreeMap<String,Vector<Signature>> s)
    {
        signatures = s;
    }
    
    public void Investigate()
    {
        System.out.println("Signatures Received by Sherlock");
        System.out.println("IP: ");
        PrintReceivedRules("ip");
        System.out.println("\n\nARP: ");
        PrintReceivedRules("arp");        
        System.out.println("\n\nTCP: ");
        PrintReceivedRules("tcp");
        System.out.println("\n\nUDP: ");
        PrintReceivedRules("udp");
        System.out.println("\n\nICMP: ");
        PrintReceivedRules("icmp");
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

}