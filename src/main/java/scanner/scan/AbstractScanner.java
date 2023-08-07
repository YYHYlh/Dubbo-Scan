package scanner.scan;

import scanner.exploit.AbstractExploiter;

public abstract class AbstractScanner {
    protected String ip;
    protected Integer port;

    public abstract boolean scan();

    protected AbstractExploiter exploiter;

    public String getIp() {
        return ip;
    }

    public Integer getPort() {
        return port;
    }


    public void exploit() {
        try {
            exploiter.exploit(this);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
