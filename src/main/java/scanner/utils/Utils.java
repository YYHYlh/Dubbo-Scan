package scanner.utils;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.io.*;

public class Utils {
    public static void sendByte(Socket socket, byte[] data) throws IOException {
        OutputStream outputStream = socket.getOutputStream();
        outputStream.write(data);
        outputStream.flush();
    }

    public static byte[] readBytes(Socket socket) throws IOException {
        InputStream inputStream = socket.getInputStream();
        byte[] buffer = new byte[1024]; // 缓冲区大小，根据实际情况调整

        int bytesRead;
        bytesRead = inputStream.read(buffer);
        byte[] receivedBytes = new byte[bytesRead];
        System.arraycopy(buffer, 0, receivedBytes, 0, bytesRead);

        return receivedBytes;
    }

}
