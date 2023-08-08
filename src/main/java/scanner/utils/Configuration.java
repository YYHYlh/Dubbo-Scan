package scanner.utils;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Properties;

public class Configuration {
    private static Map properties;
    public static int timeout;
    public static ArrayList<Integer> usuallyPorts;
    public static boolean methodGuess;
    public static int methodParametersGuessMaxLength;
    public static ArrayList<String> methodParametersGuessList;
    public static String zookeeperName;
    public static String zookeeperPass;
    public static String zookeeperScheme;
    public static String reverseIp;
    public static int reversePort;
    public static String fileIp;
    public static int filePort;

    public static void add(String key, Object value) {
        properties.put(key, value);
    }

    public static Object get(String key) {
        return properties.get(key);
    }

    static {
        try {
            Yaml yaml = new Yaml();
            String jarPath = Configuration.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            String filePath = new File(jarPath).getParent() + File.separator;
            properties = yaml.loadAs(new FileInputStream(filePath + "config.yaml"), Map.class);
            timeout = (int) properties.get("timeout") * 1000;
            usuallyPorts = (ArrayList<Integer>) properties.get("usuallyPorts");
            methodGuess = (boolean) properties.get("methodParametersGuess");
            if (methodGuess) {
                methodParametersGuessList = (ArrayList<String>) properties.get("methodParametersGuessList");
                methodParametersGuessMaxLength = (int) properties.get("methodParametersGuessMaxLength");
            }
            if (properties.get("zookeeper") != null) {
                Map<String, String> m = (Map) properties.get("zookeeper");
                zookeeperName = m.get("username");
                zookeeperPass = m.get("password");
                zookeeperScheme = m.get("scheme");
            }
            if (properties.get("reverse") != null) {
                Map m = (Map) properties.get("reverse");
                reverseIp = (String) m.get("shellIp");
                reversePort = (int) m.get("shellPort");
                fileIp = (String) m.get("fileIp");
                filePort = (int) m.get("filePort");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
