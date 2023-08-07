package scanner.detection;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.ExponentialBackoffRetry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import scanner.utils.Configuration;
import scanner.utils.Socket;

import java.net.URI;
import java.net.URLDecoder;
import java.util.List;

import static scanner.Main.AttackMap;

public class ZookeeperFinder extends AbstractFinder {
    private CuratorFramework client;
    private Logger logger = LoggerFactory.getLogger(getClass());

    public ZookeeperFinder() {
        this.name = "zookeeper";
    }

    @Override
    public boolean isTarget(String ip, int port) {
        byte[] finger = Socket.sendOne(ip, port, "conf\n".getBytes());
        if (new String(finger).contains("conf is not executed because it is not in the whitelist.") || new String(finger).contains("clientPort")) {
            init(ip, port);
            return true;
        }
        return false;
    }

    private void findDubboFromZookeeper(String className, DubboInfo.Service service) {
        try {
            String serviceUrl = client.getChildren().forPath("/dubbo/" + className + "/providers").get(0);
            String urlBase = serviceUrl.split(className)[0];
            URI url = new URI(URLDecoder.decode(urlBase, "UTF-8"));
            String ip = url.getHost();
            int port = url.getPort();
            service.setPort(port);
            if (AttackMap.get(ip) != null) {
                ((JSONObject) AttackMap.get(ip)).put("dubbo", port);
            } else {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("dubbo", port);
                AttackMap.put(ip, jsonObject);
            }
        } catch (IndexOutOfBoundsException e) {
            logger.debug("[-][Zookeeper]Can't find service:" + className);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public DubboInfo getInfo() {
        DubboInfo dubboInfo = new DubboInfo();
        try {
            CuratorFrameworkFactory.Builder builder = CuratorFrameworkFactory.builder()
                    .connectString(String.format("%s:%d", ip, port))
                    .retryPolicy(new ExponentialBackoffRetry(1000, 3))
                    .connectionTimeoutMs(Configuration.timeout)
                    .sessionTimeoutMs(Configuration.timeout);
            if (Configuration.zookeeperName != null) {
                builder.authorization(Configuration.zookeeperScheme, (Configuration.zookeeperName + ":" + Configuration.zookeeperPass).getBytes());
            }
            client = builder.build();
            client.start();
            List<String> data = client.getChildren().forPath("/dubbo");
            if (data.contains("metadata")) {
                List<String> Services = client.getChildren().forPath("/dubbo/metadata");
                for (String fuc : Services) {
                    DubboInfo.Service service = new DubboInfo.Service();
                    List<String> configFileName = client.getChildren().forPath("/dubbo/metadata/" + fuc + "/provider");
                    if (configFileName.size() > 0) {
                        String dIp = new String(client.getData().forPath("/dubbo/metadata/" + fuc + "/provider"));
                        if (!dIp.equals(ip)) {
                            dubboInfo.setIp(dIp);
                        }
                        dubboInfo.setApplicationName(configFileName.get(0));
                        byte[] config = client.getData().forPath("/dubbo/metadata/" + fuc + "/provider/" + configFileName.get(0));
                        JSONObject map = ((JSONObject) JSON.parse(config));
                        service.setClassName((String) map.get("canonicalName"));
                        findDubboFromZookeeper((String) map.get("canonicalName"), service);
                        service.setMethods((JSONArray) map.get("methods"));
                        String port = (String) ((JSONObject) map.get("parameters")).get("bind.port");
                        if (port != null && service.getPort() == -1) {
                            service.setPort(Integer.parseInt(port));
                        }
                        dubboInfo.put(service.getClassName(), service);
                        dubboInfo.setVersion((String) ((JSONObject) map.get("parameters")).get("release"));
                    }
                }
            }
        } catch (Exception e) {
        } finally {
            if (client != null) {
                client.close();
            }

        }
        return dubboInfo;
    }

    public static void main(String[] args) throws Exception {
        ZookeeperFinder d = new ZookeeperFinder();
        d.isTarget("127.0.0.1", 2181);
        System.out.println(d.getInfo());
    }
}
