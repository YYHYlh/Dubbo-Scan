package scanner.scan;

import org.apache.curator.framework.AuthInfo;
import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.framework.CuratorFrameworkFactory;
import org.apache.curator.retry.RetryNTimes;
import scanner.exploit.DubboExploiter;
import scanner.exploit.ZookeeperExploiter;
import scanner.utils.Configuration;
import scanner.utils.Socket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ZookeeperScanner extends AbstractScanner {
    public CuratorFramework client;
    public List<String> applicationNameList = new ArrayList<String>();

    public ZookeeperScanner(String ip, int port) {
        exploiter = new ZookeeperExploiter();
        this.ip = ip;
        this.port = port;
    }

    // 查看/dubbo/config/MIGRATION，如果存在说明有consumer,利用CVE-2021-36162尝试攻击
    @Override
    public boolean scan() {
        // 如果没有配置回连，则不检测该漏洞
        if (Configuration.reverseIp == null || Configuration.reversePort <= 0) {
            return false;
        }
        try {
            CuratorFrameworkFactory.Builder builder = CuratorFrameworkFactory.builder()
                    .connectString(String.format("%s:%d", ip, port))
                    .retryPolicy(new RetryNTimes(1, 1000))
                    .connectionTimeoutMs(Configuration.timeout)
                    .sessionTimeoutMs(Configuration.timeout);
            if (Configuration.zookeeperName != null) {
                builder.authorization(Configuration.zookeeperScheme, (Configuration.zookeeperName + ":" + Configuration.zookeeperPass).getBytes());
            }
            client = builder.build();
            client.start();
            try {
                List<String> data = client.getChildren().forPath("/dubbo");
                if (data.contains("metadata")) {
                    List<String> Services = client.getChildren().forPath("/dubbo/metadata");
                    for (String fuc : Services) {
                        if (client.checkExists().forPath("/dubbo/metadata/" + fuc + "/consumer") != null) {
                            List<String> configFileName = client.getChildren().forPath("/dubbo/metadata/" + fuc + "/consumer");
                            for (String conf : configFileName) {
                                if (!applicationNameList.contains(conf)) {
                                    applicationNameList.add(conf);
                                }
                            }
                        }

                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (applicationNameList.size() > 0) {
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        AbstractScanner scanner = new ZookeeperScanner("127.0.0.1", 2181);
        if (scanner.scan()) {
            scanner.exploit();
        }

    }
}
