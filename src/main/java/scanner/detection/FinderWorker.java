package scanner.detection;

import java.util.List;

public class FinderWorker extends Thread {
    private final String ip;
    private final int port;
    private final AbstractFinder worker;
    private final List<AbstractFinder> finderList;

    public FinderWorker(AbstractFinder finder, String ip, int port, List<AbstractFinder> finderList) {
        this.worker = finder;
        this.ip = ip;
        this.port = port;
        this.finderList = finderList;
    }

    public synchronized void add() {
        worker.init(ip, port);
        finderList.add(worker);
    }

    @Override
    public void run() {
        if (worker.isTarget(ip, port)) {
            add();
        }
    }
}
