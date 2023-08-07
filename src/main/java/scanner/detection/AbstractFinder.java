package scanner.detection;

public abstract class AbstractFinder {
    public String name;
    protected String ip;
    protected int port;

    protected void init(String ip, int port) {
        this.ip = ip;
        this.port = port;

    }

    public abstract boolean isTarget(String ip, int port);

    public abstract DubboInfo getInfo();


    public String getIp() {
        return ip;
    }

    public int getPort() {
        return port;
    }

}
