package scanner.utils;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;

public class Socket {
    public static byte[] sendOne(String ip, int port, byte[] handshake) {
        java.net.Socket socket = new java.net.Socket();
        InputStream inputStream = null;
        try {
            socket.connect(new InetSocketAddress(ip, port), Configuration.timeout);
            socket.setSoTimeout(Configuration.timeout);
            Utils.sendByte(socket, handshake);
            return Utils.readBytes(socket);
        } catch (Exception e) {

        } finally {
            try {
                socket.close();
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {

            }

        }
        return new byte[0];
    }
}
