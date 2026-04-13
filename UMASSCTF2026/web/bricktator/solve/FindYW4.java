import java.io.*; import java.util.*;

public class FindYW4 {
    static int idSize=8;
    static Map<Long,String> utf8=new HashMap<>(),clsNames=new HashMap<>(),baContent=new HashMap<>();
    static Map<Long,Long> clsSuper=new HashMap<>(),str2ba=new HashMap<>(),instClass=new HashMap<>();
    static Map<Long,byte[]> msData=new HashMap<>(),allInst=new HashMap<>();
    static Map<Long,List<long[]>> clsFields=new HashMap<>();
    // OBJ_ARRAY: arrayObjId -> list of element object IDs
    static Map<Long,List<Long>> objArrays=new HashMap<>();
    static long strCls=0,msCls=0;
    
    public static void main(String[] args)throws Exception{
        var in=new DataInputStream(new BufferedInputStream(new FileInputStream("heapdump.hprof"),4*1024*1024));
        while(in.read()!=0);idSize=in.readInt();in.readLong();
        System.err.println("Parsing...");
        while(in.available()>0){int t=in.readUnsignedByte();in.readInt();int l=in.readInt();
            if(t==1){long id=ri(in);byte[] d=new byte[l-idSize];in.readFully(d);utf8.put(id,new String(d,"UTF-8"));}
            else if(t==2){in.readInt();long c=ri(in);in.readInt();long n=ri(in);String nm=utf8.getOrDefault(n,"");clsNames.put(c,nm);if(nm.equals("java/lang/String"))strCls=c;if(nm.contains("MapSession"))msCls=c;}
            else if(t==0xC||t==0x1C)parseH(in,l);else in.skipBytes(l);}
        in.close();
        
        Map<Long,String> strContent=new HashMap<>();
        for(var e:str2ba.entrySet()){String c=baContent.get(e.getValue());if(c!=null)strContent.put(e.getKey(),c);}
        
        Long ywStr=null;
        for(var e:strContent.entrySet())if("YANKEE_WHITE".equals(e.getValue())){ywStr=e.getKey();break;}
        System.err.println("YANKEE_WHITE String: "+Long.toHexString(ywStr));
        
        // Nodes referencing YANKEE_WHITE
        byte[] ywRef=lb(ywStr);
        Set<Long> ywNodes=new HashSet<>();
        for(var e:allInst.entrySet())if(cb(e.getValue(),ywRef))ywNodes.add(e.getKey());
        System.err.println("Nodes with YW ref: "+ywNodes.size());
        
        // Find which OBJ_ARRAY contains these nodes
        Map<Long,Long> node2array=new HashMap<>(); // nodeId -> arrayId
        for(var e:objArrays.entrySet()){
            for(long elemId:e.getValue()){
                if(ywNodes.contains(elemId)){
                    node2array.put(elemId,e.getKey());
                }
            }
        }
        System.err.println("Nodes found in arrays: "+node2array.size());
        
        // Find which instances reference these arrays (= ConcurrentHashMap with table field)
        Set<Long> ywArrayIds=new HashSet<>(node2array.values());
        Map<Long,Long> array2map=new HashMap<>(); // arrayId -> mapInstanceId
        for(long arrId:ywArrayIds){
            byte[] arrRef=lb(arrId);
            for(var e:allInst.entrySet()){
                if(cb(e.getValue(),arrRef)){
                    array2map.put(arrId,e.getKey());
                    break; // usually only one map per array
                }
            }
        }
        System.err.println("Arrays -> Maps: "+array2map.size());
        
        // Match to MapSession attrs
        Map<String,Long> sessAttrs=new HashMap<>();
        for(var e:msData.entrySet()){
            byte[] d=e.getValue();
            if(d.length>=3*idSize){
                long idRef=rib(d,0);
                String sid=strContent.get(idRef);
                long attrsRef=rib(d,2*idSize);
                if(sid!=null&&sid.matches("\\d{5}-[0-9a-f]{8}"))
                    sessAttrs.put(sid,attrsRef);
            }
        }
        
        Set<Long> ywMapIds=new HashSet<>(array2map.values());
        System.err.println("YW Map IDs: "+ywMapIds.size());
        
        System.out.println("=== YANKEE_WHITE Sessions ===");
        for(var e:sessAttrs.entrySet()){
            if(ywMapIds.contains(e.getValue())){
                System.out.println(e.getKey());
            }
        }
    }
    
    static void parseH(DataInputStream in,int rem)throws Exception{while(rem>0){int st=in.readUnsignedByte();rem--;switch(st){
        case 0xFF:ri(in);rem-=idSize;break;case 1:ri(in);ri(in);rem-=2*idSize;break;
        case 2:case 3:ri(in);in.readInt();in.readInt();rem-=idSize+8;break;
        case 4:ri(in);in.readInt();rem-=idSize+4;break;case 5:case 7:ri(in);rem-=idSize;break;
        case 6:ri(in);in.readInt();rem-=idSize+4;break;case 8:ri(in);in.readInt();in.readInt();rem-=idSize+8;break;
        case 0x20:{long c=ri(in);in.readInt();long s=ri(in);clsSuper.put(c,s);for(int i=0;i<5;i++)ri(in);in.readInt();rem-=7*idSize+8;int cp=in.readUnsignedShort();rem-=2;for(int i=0;i<cp;i++){in.readUnsignedShort();rem-=2;int t=in.readUnsignedByte();rem--;rem-=sv(in,t);}int sc=in.readUnsignedShort();rem-=2;for(int i=0;i<sc;i++){ri(in);rem-=idSize;int t=in.readUnsignedByte();rem--;rem-=sv(in,t);}int fc=in.readUnsignedShort();rem-=2;List<long[]> fl=new ArrayList<>();for(int i=0;i<fc;i++){long n=ri(in);rem-=idSize;int t=in.readUnsignedByte();rem--;fl.add(new long[]{n,t});}clsFields.put(c,fl);break;}
        case 0x21:{long o=ri(in);in.readInt();long c=ri(in);int ds=in.readInt();byte[] d=new byte[ds];in.readFully(d);rem-=2*idSize+8+ds;if(c==strCls&&d.length>=idSize)str2ba.put(o,rib(d,0));if(clsNames.getOrDefault(c,"").contains("MapSession"))msData.put(o,d);allInst.put(o,d);instClass.put(o,c);break;}
        case 0x22:{long a=ri(in);in.readInt();int n=in.readInt();ri(in);rem-=2*idSize+8;List<Long> elems=new ArrayList<>();for(int i=0;i<n;i++){elems.add(ri(in));rem-=idSize;}objArrays.put(a,elems);break;}
        case 0x23:{long a=ri(in);in.readInt();int n=in.readInt();int et=in.readUnsignedByte();rem-=idSize+9;int es=ps(et);int ab=n*es;if(et==8&&n>=5&&n<=100){byte[] ar=new byte[n];in.readFully(ar);String c=new String(ar,"UTF-8");if(c.matches("\\d{5}-[0-9a-f]{8}")||c.equals("YANKEE_WHITE")||c.equals("Q_CLEARANCE"))baContent.put(a,c);}else in.skipBytes(ab);rem-=ab;break;}
        default:return;}}}
    
    static long ri(DataInputStream in)throws IOException{return idSize==8?in.readLong():in.readInt()&0xFFFFFFFFL;}
    static long rib(byte[] d,int o){long v=0;for(int i=0;i<idSize;i++)v=(v<<8)|(d[o+i]&0xFF);return v;}
    static int sv(DataInputStream in,int t)throws IOException{int s=t==2?idSize:ps(t);in.skipBytes(s);return s;}
    static int ps(int t){return switch(t){case 2->8;case 4,8->1;case 5,9->2;case 6,10->4;case 7,11->8;default->throw new RuntimeException("t:"+t);};}
    static byte[] lb(long v){byte[] b=new byte[8];for(int i=7;i>=0;i--){b[i]=(byte)(v&0xFF);v>>=8;}return b;}
    static boolean cb(byte[] h,byte[] n){for(int i=0;i<=h.length-n.length;i++){boolean m=true;for(int j=0;j<n.length;j++)if(h[i+j]!=n[j]){m=false;break;}if(m)return true;}return false;}
}
