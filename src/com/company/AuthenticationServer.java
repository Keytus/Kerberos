package com.company;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Objects;

public class AuthenticationServer {
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[Constants.defaultSize];
    private HashMap<String, String> clientsMap = new HashMap<>();
    private String K_C_TGS;//ключ, выдаваемый C для доступа к серверу выдачи разрешений TGS ;
    private String TGT;//Ticket Granting Ticket - билет на доступ к серверу выдачи разрешений
    private Integer p1 = 30;//период действия билета
    public AuthenticationServer() {
        try {
            socket = new DatagramSocket(Constants.authenticationServerPort);
        } catch (SocketException e) {
            e.printStackTrace();
        }
        clientsMap.put("Fred","47+M/ZurUX8=");
        clientsMap.put("Kred","aPQmH0Ppurw=");
        clientsMap.put("Vred","eiW/7Fj9tRo=");
    }
    public void run() {
        running = true;
        System.out.println("AS running");

        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
                System.out.println("C->AS");
            } catch (IOException e) {
                e.printStackTrace();
            }
            InetAddress address = packet.getAddress();
            int port = packet.getPort();
            String c= new String(packet.getData(), 0, packet.getLength());
            if (!clientsMap.containsKey(c)) {
                System.out.println("Запрос отклонён");
                System.exit(-1);
            }

            System.out.println("AS get c from C:" + c);

            DesEncrypter encrypterK_AS_TGS = new DesEncrypter(Constants.K_AS_TGS);
            byte[] decodedKey = Base64.getDecoder().decode(clientsMap.get(c));
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
            DesEncrypter encrypterK_C = new DesEncrypter(originalKey);

            System.out.println("K_S: "+clientsMap.get(c));

            K_C_TGS = Base64.getEncoder().encodeToString(Objects.requireNonNull(DesEncrypter.generateSK()).getEncoded());

            System.out.println("K_C_TGS: "+K_C_TGS);

            TGT = c + "\n";
            TGT += Constants.authenticationServerPort + "\n";
            TGT += LocalDateTime.now().format(Constants.formatter) + "\n";
            TGT += p1 + "\n";
            TGT += K_C_TGS;

            System.out.println("TGT: "+TGT);

            System.out.println("AS->C");

            buf = encrypterK_C.encrypt(encrypterK_AS_TGS.encrypt(TGT));
            packet = new DatagramPacket(buf, buf.length, address, port);
            try {
                socket.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.println("TGT encrypted by K_AS_TGS and K_C: "+new String(buf,0,buf.length));

            buf = encrypterK_C.encrypt(K_C_TGS);
            packet = new DatagramPacket(buf, buf.length, address, port);
            try {
                socket.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("K_C_TGS encrypted by K_C: "+new String(buf,0,buf.length));

        }
        socket.close();
    }
}
