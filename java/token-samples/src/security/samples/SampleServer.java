package security.samples;

import java.io.IOException;

public abstract class SampleServer {
    protected Transport.Acceptor acceptor;

    protected void usage(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java <options> SampleServer <ListenPort>");
            System.exit(-1);
        }
    }

    public SampleServer(String[] args) throws IOException {
        usage(args);

        short listenPort = (short) Integer.parseInt(args[0]);
        this.acceptor = new Transport.Acceptor(listenPort);
    }

    public void run() throws IOException {
        try {
            while (true) {
                System.out.println("Waiting for incoming connection...");

                Transport.Connection conn = acceptor.accept();
                System.out.println("Got connection from client");

                try {
                    onConnection(conn);
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    conn.close();
                }
            }
        } finally {
            acceptor.close();
        }
    }

    protected abstract void onConnection(Transport.Connection conn) throws Exception;
}
