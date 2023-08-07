package scanner.detection;


import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;
import org.apache.dubbo.rpc.service.GenericService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scanner.utils.Configuration;
import scanner.utils.Socket;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DubboFinder extends AbstractFinder {
    private Logger logger = LoggerFactory.getLogger(getClass());
    //\xda\xbb\xc2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x052.0.2\x01$\x050.0.0\x01$\x00H\x04path\x01$\x12remote.application\x011\tinterface\x01$\x07version\x050.0.0\x07timeout\xcb\xe8Z
    private final byte[] handshake = new byte[]{
            -38, -69, -62, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 5, 50, 46, 48, 46, 50, 1, 36, 5, 48, 46, 48, 46, 48, 1, 36, 0, 72, 4, 112, 97, 116, 104, 1, 36, 18, 114, 101, 109, 111, 116, 101, 46, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 1, 49, 9, 105, 110, 116, 101, 114, 102, 97, 99, 101, 1, 36, 7, 118, 101, 114, 115, 105, 111, 110, 5, 48, 46, 48, 46, 48, 7, 116, 105, 109, 101, 111, 117, 116, -53, -24, 90
    };

    private int mainVersion;

    public DubboFinder() {
        this.name = "dubbo";

    }

    @Override
    public boolean isTarget(String ip, int port) {
        super.init(ip, port);

        String finger = new String(Socket.sendOne(ip, port, handshake));
        if (finger.contains("org.apache.dubbo.remoting.RemotingException")) {
            this.mainVersion = 2;
            Configuration.add("DubboFinded" + ip, true);
            return true;
        } else if (finger.contains("Service $ with version 0.0.0 not found")) {
            this.mainVersion = 3;
            Configuration.add("DubboFinded" + ip, true);
            return true;
        } else if (finger.equals("")) {
            finger = new String(Socket.sendOne(ip, port, "help\n".getBytes()));
            if (finger.contains("dubbo>")) {
                finger = new String(Socket.sendOne(ip, port, "version\n".getBytes()));
                if (finger.contains("Unsupported command: version")) {
                    return true;
                }
            }
        }
        return false;
    }

    public String getErrorInfoFor3() {
        try {
            String base = String.format("dubbo://%s:%d/org.apache.dubbo.metadata.MetadataService:1.0.0", this.ip, this.port);
            ReferenceConfig<GenericService> referenceConfig = new ReferenceConfig<>();
            referenceConfig.setRetries(0);
            referenceConfig.setApplication(new ApplicationConfig("test"));
            referenceConfig.setInterface("org.apache.dubbo.metadata.MetadataService");
            referenceConfig.setUrl(base);
            referenceConfig.setGeneric("raw.return");
            referenceConfig.setVersion("1.0.0");
            GenericService genericService = referenceConfig.get();
            Object[] args = new Object[]{};
            genericService.$invoke("getMetadataInfo", new String[]{"java.lang.String"}, args);
        } catch (org.apache.dubbo.rpc.RpcException e) {
            return e.toString();
        }
        return "";
    }

    private DubboInfo getInfoByError() {
        String info = "";
        DubboInfo dubboInfo = new DubboInfo();
        if (mainVersion == 2) {
            info = new String(Socket.sendOne(ip, port, handshake));
        } else if (mainVersion == 3) {
            info = getErrorInfoFor3();
        }
        String regex = "Not found exported service: .*?\\[(.*?)\\], may be version";
        Pattern pattern = Pattern.compile(regex);
        Matcher m = pattern.matcher(info);
        if (m.find()) {
            String[] Services = m.group(1).split(",");
            for (String func : Services) {
                String[] ServiceAndVersionAndPort = func.split(":");
                DubboInfo.Service service = new DubboInfo.Service();
                String className = ServiceAndVersionAndPort[0];
                service.setClassName(className);
                if (className.contains("org.apache.dubbo.metadata.MetadataService")) {
                    dubboInfo.setApplicationName(className.split("/")[0]);
                }
                if (ServiceAndVersionAndPort.length == 3) {
                    service.setVersion(ServiceAndVersionAndPort[1]);
                    service.setPort(Integer.parseInt(ServiceAndVersionAndPort[2]));
                } else if (ServiceAndVersionAndPort.length == 2) {
                    service.setPort(Integer.parseInt(ServiceAndVersionAndPort[1]));
                }
                dubboInfo.addService(service);
            }
            return dubboInfo;
        }
        return null;
    }

    private DubboInfo getInfoByTelnet() {
        // 如果目标为Dubbo3.x，并且存在MetaService，则不需要再telnet获取信息
        String finger = new String(Socket.sendOne(ip, port, "help\n".getBytes()));
        if (finger.contains(">dubbo") && finger.contains("help disabled for security reasons, please enable support by listing the commands through 'telnet'")) {
            //dubbo 3.x
            logger.debug("target Dubbo close telnet information");
            return null;
        } else if (finger.contains("Please input \"help [command]\" show detail.")) {
            String Services = new String(Socket.sendOne(ip, port, "ls\n".getBytes()));
            String regex = "(?s)PROVIDER:\r\n(.*)\r\n\r\n";
            Pattern pattern = Pattern.compile(regex);
            Matcher m = pattern.matcher(Services);
            if (m.find()) {
                DubboInfo dubboInfo = new DubboInfo();
                for (String className : m.group(1).split("\r\n")) {
                    if (!className.isEmpty()) {
                        DubboInfo.Service Service = new DubboInfo.Service();
                        Service.setClassName(className);
                        String detail = new String(Socket.sendOne(ip, port, String.format("ls %s\n", className).getBytes()));
                        m = Pattern.compile(String.format("(?s)%s \\(as provider\\):\r\n\t(.*)\r\n\r\ndubbo>", className)).matcher(detail);
                        if (m.find()) {
                            String[] methods = m.group(1).split("\r\n\t");
                            JSONArray jsonArray = new JSONArray();
                            for (String method : methods) {
                                JSONObject jsonObject = new JSONObject();
                                jsonObject.put("name", method);
                                jsonArray.add(jsonObject);
                            }

                            Service.setMethods(jsonArray);
                            dubboInfo.put(className, Service);
                        }
                    }
                }

                return dubboInfo;
            }
        }
        return new DubboInfo();
    }

    public DubboInfo getInfo() {
        DubboInfo ret = new DubboInfo();
        ret.update(getInfoByError());
        ret.update(getInfoByTelnet());
        if (ret.getVersion().isEmpty() && mainVersion != 0) {
            ret.setVersion(String.format("%d.x", mainVersion));
        }
        return ret;
    }

    public static void main(String[] args) throws Exception {
        DubboFinder d = new DubboFinder();
        d.isTarget("127.0.0.1", 8088);
        d.getInfo();

    }
}
