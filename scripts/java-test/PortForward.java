import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Test-only TCP forwarder for `npm run test:java`, run inside the Maven container as a Java 21
 * single-file program: `java PortForward.java <target host> <port>...`. It listens on
 * 127.0.0.1:<port> in the container and forwards every connection to <target host>:<port>, the
 * Docker host. Portvakt and the mock IdP then have the same URL (http://localhost:<port>) on the
 * host and in the container, so issuers, redirects and SAML endpoints match on both sides. Prints
 * "ready" once every port listens.
 */
public final class PortForward {
  public static void main(String[] args) throws Exception {
    if (args.length < 2) throw new IllegalArgumentException("usage: PortForward <target host> <port>...");
    String target = args[0];
    for (int index = 1; index < args.length; index++) {
      int port = Integer.parseInt(args[index]);
      ServerSocket server = new ServerSocket();
      server.setReuseAddress(true);
      server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
      Thread.ofPlatform().daemon(false).name("accept-" + port).start(() -> accept(server, target, port));
    }
    System.out.println("ready");
    System.out.flush();
  }

  private static void accept(ServerSocket server, String target, int port) {
    while (true) {
      try {
        Socket client = server.accept();
        Thread.ofVirtual().start(() -> connect(client, target, port));
      } catch (IOException exception) {
        System.err.println("accept failed on " + port + ": " + exception.getMessage());
      }
    }
  }

  private static void connect(Socket client, String target, int port) {
    try (client; Socket upstream = new Socket(target, port)) {
      client.setTcpNoDelay(true);
      upstream.setTcpNoDelay(true);
      Thread toUpstream = Thread.ofVirtual().start(() -> pipe(client, upstream));
      pipe(upstream, client);
      toUpstream.join();
    } catch (IOException | InterruptedException exception) {
      // The connection ended; the HTTP client sees a closed connection.
    }
  }

  private static void pipe(Socket from, Socket to) {
    try {
      InputStream in = from.getInputStream();
      OutputStream out = to.getOutputStream();
      byte[] buffer = new byte[16 * 1024];
      int read;
      while ((read = in.read(buffer)) >= 0) {
        out.write(buffer, 0, read);
        out.flush();
      }
      to.shutdownOutput();
    } catch (IOException exception) {
      try {
        to.close();
        from.close();
      } catch (IOException ignored) {
        // Already closed.
      }
    }
  }
}
