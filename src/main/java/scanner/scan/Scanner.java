package scanner.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class Scanner {
    private List<AbstractScanner> initScanners = new ArrayList<AbstractScanner>();
    private String ip;
    private int port;
    private Logger logger = LoggerFactory.getLogger(getClass());

    private void initScaners() {
        initScanners.add(new DubboScaner(ip, port));
        initScanners.add(new ZookeeperScanner(ip, port));
    }

    public Scanner(String ip, int port, String scanner) {
        this.ip = ip;
        this.port = port;
        if (scanner.equals("dubbo")) {
            initScanners.add(new DubboScaner(ip, port));
        } else if (scanner.equals("zookeeper")) {
            initScanners.add(new ZookeeperScanner(ip, port));
        }

    }

    public void run() {
        for (AbstractScanner scanner : initScanners) {
            if (scanner.scan()) {
                scanner.exploit();
            } else {
                logger.info(String.format("%s:%d 无法被利用", scanner.getIp(), scanner.getPort()));
            }
        }
    }

}
