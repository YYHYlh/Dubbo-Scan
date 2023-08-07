package scanner;

import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scanner.detection.Detector;
import scanner.detection.AbstractFinder;
import scanner.detection.DubboInfo;
import scanner.scan.Scanner;
import scanner.utils.Configuration;

import java.io.*;
import java.net.URISyntaxException;
import java.util.*;

public class Main {
    //存储信息获取后的服务信息{ip:{service:port}}
    public static JSONObject AttackMap = new JSONObject();
    //存储信息获取后的Dubbo信息 {ip:DubboInfo}
    public static HashMap<String, DubboInfo> DubboInfoMap = new HashMap<>();

    private static Logger logger = LoggerFactory.getLogger(Main.class);

    public static Map<String, List<Integer>> readTargetFile(String filePath) {
        cn.hutool.core.io.file.FileReader fileReader = new cn.hutool.core.io.file.FileReader(filePath);
        Map<String, List<Integer>> ipPortMap = new HashMap<>();
        for (String line : fileReader.readLines()) {
            String[] parts = line.split(":");
            String ip = parts[0];
            if (ip.length() == 0) {
                continue;
            }
            ipPortMap.putIfAbsent(ip, new ArrayList<>());
            if (parts.length == 2) {
                int port = Integer.parseInt(parts[1]);
                ipPortMap.get(ip).add(port);
            } else if (parts.length == 1) {
                ipPortMap.get(ip).addAll(Configuration.usuallyPorts);
            }
        }

        return ipPortMap;
    }

    private void run(String ip, List port) {
        //服务探测
        Detector detector = new Detector();
        List<AbstractFinder> finders = detector.findService(ip, (ArrayList<Integer>) port);

        //信息收集
        JSONObject jsonObject = new JSONObject();
        for (AbstractFinder finder : finders) {
            try {
                jsonObject.put(finder.name, finder.getPort());
                String tmpIp = ip;
                if (finder.getInfo().getIp().length() > 0) {
                    tmpIp = finder.getInfo().getIp();
                }
                if (DubboInfoMap.get(tmpIp) != null) {
                    DubboInfoMap.get(tmpIp).update(finder.getInfo());
                } else {
                    DubboInfoMap.put(tmpIp, finder.getInfo());
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (AttackMap.get(ip) != null) {
            ((JSONObject) AttackMap.get(ip)).putAll(jsonObject);
        } else {
            AttackMap.put(ip, jsonObject);
        }

    }

    private void updateInfo() {
        for (String target : DubboInfoMap.keySet()) {
            DubboInfo dubboInfo = DubboInfoMap.get(target);
            Optional<Integer> portNotMinusOne = dubboInfo.values().stream()
                    .map(DubboInfo.Service::getPort)
                    .filter(portS -> portS != -1)
                    .findFirst();
            int portS = portNotMinusOne.get();
            if (!AttackMap.containsKey(target) && portS > 0) {
                JSONObject j = new JSONObject();
                j.put("dubbo", portS);
                AttackMap.put(target, j);
            } else if (!((JSONObject) AttackMap.get(target)).containsKey("dubbo")) {
                ((JSONObject) AttackMap.get(target)).put("dubbo", portS);
            }
            logger.info("\n【DubboInfo】\nIP: " + target + "\n" + DubboInfoMap.get(target));

        }

    }

    private void scan() {
        for (String targetIp : AttackMap.keySet()) {
            Scanner scanner;
            JSONObject map = (JSONObject) AttackMap.get(targetIp);
            for (String service : map.keySet()) {
                logger.info(String.format("Check IP: %s PORT: %s Service: %s", targetIp, map.get(service), service));
                scanner = new Scanner(targetIp, (int) map.get(service), service);
                scanner.run();
            }
        }

    }

    public static void main(String[] args) {
        try {
            String jarPath = Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            String filePath = new File(jarPath).getParent() + File.separator;
            Map<String, List<Integer>> ipPortMap = readTargetFile(filePath + "target.txt");
            Main m = new Main();
            logger.info("==================start detect==================");
            for (String ip : ipPortMap.keySet()) {
                m.run(ip, ipPortMap.get(ip));
            }
            m.updateInfo();
            logger.info("==================start scan==================");
            m.scan();

        } catch (Exception e) {
            e.printStackTrace();
        }


    }

}