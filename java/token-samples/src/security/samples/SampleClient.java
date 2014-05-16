package security.samples;

import java.io.IOException;

public abstract class SampleClient {
    protected Transport.Connection conn;

    protected void usage(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java <options> SampleClient "
                    + "<server-host> <server-port>");
            System.exit(-1);
        }
    }

    public SampleClient(String[] args) throws Exception {
        usage(args);

        String hostName = args[1];
        short port = (short) Integer.parseInt(args[2]);

        this.conn = Transport.Connector.connect(hostName, port);
    }

    public void run() throws IOException {
        System.out.println("Connected to server");

        try {
            onConnection(conn);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            conn.close();
        }
    }

    protected abstract void onConnection(Transport.Connection conn) throws Exception;
}
