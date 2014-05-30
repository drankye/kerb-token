package security.samples;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Transport {

    public static class Acceptor {
        ServerSocket serverSocket;

        public Acceptor(short listenPort) throws IOException {
            this.serverSocket = new ServerSocket(listenPort);
        }

        public Connection accept() throws IOException {
            Socket socket = serverSocket.accept();
            return new Connection(socket);
        }

        public void close() throws IOException {
            serverSocket.close();
        }
    }

    public static class Connector {
        public static Connection connect(String host, short port) throws IOException {
            Socket socket = new Socket(host, port);
            return new Connection(socket);
        }
    }

    public static class Connection {
        private Socket socket;
        private DataInputStream instream;
        private DataOutputStream outstream;

        public Connection(Socket socket) throws IOException {
            this.socket = socket;
            instream = new DataInputStream(socket.getInputStream());
            outstream = new DataOutputStream(socket.getOutputStream());
        }

        public void close() throws IOException {
            socket.close();
        }

        public void sendToken(byte[] token) throws IOException {
            if (token != null) {
                outstream.writeInt(token.length);
                outstream.write(token);
            } else {
                outstream.writeInt(0);
            }
            outstream.flush();
        }

        public void sendMessage(Message msg) throws IOException {
            if (msg != null) {
                sendToken(msg.header);
                sendToken(msg.body);
            }
        }

        public void sendMessage(byte[] header, byte[] body) throws IOException {
            sendMessage(new Transport.Message(header, body));
        }

        public void sendMessage(String header, byte[] body) throws IOException {
            sendMessage(new Transport.Message(header, body));
        }

        public byte[] recvToken() throws IOException {
            int len = instream.readInt();
            if (len > 0) {
                byte[] token = new byte[len];
                instream.readFully(token);
                return token;
            }
            return null;
        }

        public Message recvMessage() throws IOException {
            byte[] header = recvToken();
            byte[] body = recvToken();
            Message msg = new Message(header, body);
            return msg;
        }
    }

    public static class Message {
        public byte[] header;
        public byte[] body;


        Message(byte[] header, byte[] body) {
            this.header = header;
            this.body = body;
        }

        public Message(String header, byte[] body) {
            this.header = header.getBytes();
            this.body = body;
        }
    }
}
