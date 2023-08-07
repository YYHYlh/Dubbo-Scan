package scanner.detection;

import scanner.utils.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Detector {
    private final List<AbstractFinder> abstractFinders = new ArrayList<AbstractFinder>();
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public static enum DetectMode {
        NORMAL,
        ALL
    }

    private void initFinder() {
        abstractFinders.add(new DubboFinder());
        abstractFinders.add(new ZookeeperFinder());
        abstractFinders.add(new TelnetQOSFinder());
    }

    public List<AbstractFinder> findService(String ip, ArrayList<Integer> portList) {
        List<AbstractFinder> abstractFinderList = new ArrayList<>();
        try {
            for (int port : portList) {
                for (AbstractFinder abstractFinder : abstractFinders) {
                    executor.submit(new FinderWorker(abstractFinder, ip, port, abstractFinderList));
                }
            }
            executor.shutdown();
            boolean terminated = executor.awaitTermination((long) portList.size() * Configuration.timeout * 2 + 10, TimeUnit.SECONDS);
            if (terminated) {
                return abstractFinderList;
            } else {
                System.out.println("等待超时，仍有任务未完成");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public List findService(String ip, DetectMode mode) {
        if (mode.equals(DetectMode.ALL)) {
            ArrayList<Integer> portList = new ArrayList<Integer>();
            for (int i = 1; i <= 65535; i++) {
                portList.add(i);
            }
            return findService(ip, portList);
        } else if (mode.equals(DetectMode.NORMAL)) {
            return findService(ip, Configuration.usuallyPorts);
        }
        return new ArrayList<>();
    }

    public Detector() {
        initFinder();
    }

    public static void main(String[] args) throws Exception {
        Detector detector = new Detector();
    }
}
