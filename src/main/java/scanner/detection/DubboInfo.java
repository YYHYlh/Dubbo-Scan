package scanner.detection;


import com.alibaba.fastjson.JSONArray;

import java.util.HashMap;
import java.util.Objects;

public class DubboInfo extends HashMap<String, DubboInfo.Service> {


    private String ip;
    private String applicationName;
    private String version;

    public DubboInfo() {
        setIp("");
        setApplicationName("");
        setVersion("");

    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public void addService(Service Service) {
        this.put(Service.getClassName(), Service);
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName.trim();
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        for (Service func : this.values()) {
            s.append(func.toString());
            s.append("\n\n");
        }
        String ret = "";
        if (!Objects.equals(applicationName, "")) {
            ret += String.format("Group Name:%s\n", applicationName);
        }
        if (!Objects.equals(version, "")) {
            ret += String.format("version:%s\n", version);
        }
        if (s.length() > 0) {
            ret += String.format("services:\n%s", s);
        }
        return ret;
    }

    public void update(DubboInfo dubboInfo) {
        if (dubboInfo == null) {
            return;
        }
        if (!dubboInfo.getApplicationName().isEmpty()) {
            this.setApplicationName(dubboInfo.getApplicationName());
        }
        if (this.getVersion().isEmpty() || (this.getVersion().contains(".x") && !dubboInfo.getVersion().isEmpty())) {
            this.setVersion(dubboInfo.getVersion());
        }
        if (dubboInfo.size() != 0 && this.size() == 0) {
            this.putAll(dubboInfo);
        } else {
            for (String key : dubboInfo.keySet()) {
                Service Service = dubboInfo.get(key);
                if (this.containsKey(key)) {
                    Service tmp = this.get(key);
                    if (Service.getMethods().size() != 0 && tmp.getMethods().size() == 0) {
                        tmp.setMethods(Service.getMethods());
                    }
                    if (Service.getPort() > 0 && tmp.getPort() == -1) {
                        tmp.setPort(Service.getPort());
                    }
                    if (!Service.getVersion().isEmpty() && tmp.getVersion().isEmpty()) {
                        tmp.setVersion(Service.getVersion());
                    }
                    if (!Service.getReturnType().isEmpty() && tmp.getReturnType().isEmpty()) {
                        tmp.setReturnType(Service.getReturnType());
                    }
                    this.put(Service.getClassName(), tmp);
                } else {
                    this.put(key, Service);
                }
            }
        }
    }

    public static class Service {

        private String className = "";
        private JSONArray methods = new JSONArray();
        private String version = "";
        private int port = -1;
        private String returnType = "";

        @Override
        public String toString() {
            String ret = "";
            if (!Objects.equals(className, "")) {
                ret += String.format("\tinterface:%s\n", className);
            }
            if (!Objects.equals(version, "")) {
                ret += String.format("\tversion:%s\n", version);
            }
            if (methods.stream().toArray().length > 0) {
                ret += String.format("\tmethods:%s\n", methods);
            }
            if (port > 0) {
                ret += String.format("\tport:%d", port);
            }
            return ret;
        }

        public String getClassName() {
            return className;
        }

        public void setClassName(String className) {
            if (className != null) {
                this.className = className.replaceAll("\n|\r|\t| ", "");
            }
        }

        public JSONArray getMethods() {
            return methods;
        }

        public void setMethods(JSONArray methods) {
            this.methods = methods;
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            if (version != null) {
                this.version = version;
            }
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            if (port != -1) {
                this.port = port;
            }
        }

        public String getReturnType() {
            return returnType;
        }

        public void setReturnType(String returnType) {
            this.returnType = returnType;
        }

    }
}
