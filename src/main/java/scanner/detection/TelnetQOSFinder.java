package scanner.detection;

import cn.hutool.core.util.ReUtil;
import scanner.utils.Configuration;
import scanner.utils.Socket;

public class TelnetQOSFinder extends AbstractFinder {
    public TelnetQOSFinder() {
        this.name = "telnetQOS";
    }

    @Override
    public boolean isTarget(String ip, int port) {
        String finger = new String(Socket.sendOne(ip, port, "version\n".getBytes()));
        if (finger.contains("dubbo version")) {
            init(ip, port);
            return true;
        }
        return false;
    }

    @Override
    public DubboInfo getInfo() {
        String version = new String(Socket.sendOne(ip, port, "version\n".getBytes()));
        version = ReUtil.findAll("dubbo version \"(.*)\"", version, 1).get(0);
        DubboInfo dubboInfo = new DubboInfo();
        dubboInfo.setVersion(version);
        if (Configuration.get("DubboFinded" + ip) == null) {
            String dubboPort = new String(Socket.sendOne(ip, port, "ps\n".getBytes()));
            if (!dubboPort.contains("no such command")) {
                DubboFinder dubboFinder = new DubboFinder();
                if (dubboFinder.isTarget(ip, Integer.parseInt(dubboPort.replace("\r\ndubbo>", "")))) {
                    System.out.println("find dubbo by dubbo telnet QOS");
                    dubboInfo.update(dubboFinder.getInfo());
                }
            }
        }

        return dubboInfo;
    }

    public static void main(String[] args) throws Exception {
        TelnetQOSFinder d = new TelnetQOSFinder();
        d.isTarget("127.0.0.1", 22222);
        System.out.println(d.getInfo());

    }
}
