package com.company;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Objects;

public class TicketGrantingServer {
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[256];
    private byte[] encryptedTGT;
    private byte[] encryptedAut1;
    private String[] TGT;
    private String[] Aut1;
    private String TGS;//Ticket Granting Service - билет для доступа к SS {TGS} ={с,ss,t3,p2, KC_SS }.
    private String K_C_SS;//ключ для взаимодействия C и SS
    private int p2 = 20;

    public TicketGrantingServer()
    {
        try {
            socket = new DatagramSocket(Constants.ticketGrantingServerPort);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }
    public void run() {
        running = true;
        System.out.println("TGS running");

        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }
            InetAddress address = packet.getAddress();
            int port = packet.getPort();

            String received= new String(packet.getData(), 0, packet.getLength());
            encryptedTGT = received.split("\n")[0].getBytes();
            encryptedAut1 = received.split("\n")[1].getBytes();

            System.out.println("TGS get encrypted TGT,encrypted Aut1, ID from C");

            DesEncrypter encrypterAS_TGS = new DesEncrypter(Constants.K_AS_TGS);
            TGT = encrypterAS_TGS.decryptToStr(encryptedTGT).split("\n");
            System.out.println("TGS decrypt TGT:"+TGT);

            try {
                DesEncrypter encrypterK_C_TGS = new DesEncrypter(DesEncrypter.getSK(TGT[TGTComponents.K_C_TGS.ordinal()]));
                Aut1 = encrypterK_C_TGS.decryptToStr(encryptedAut1).split("\n");
            }
            catch (Exception ex)
            {
                System.out.println("C used wrong K_C");
                System.exit(-1);
            }
            System.out.println("TGS decrypt Aut1:"+Aut1);

            LocalDateTime t1 = LocalDateTime.parse(TGT[TGTComponents.t1.ordinal()], Constants.formatter);
            int p1 = Integer.parseInt(TGT[TGTComponents.p1.ordinal()]);
            LocalDateTime t2 = LocalDateTime.parse(Aut1[1], Constants.formatter);

            if(t2.isAfter(t1.plusMinutes(p1)))
            {
                System.out.println("TGT time limit is over");
                System.exit(-1);
            }
            System.out.println("TGS check TGT time limit");

            System.out.println("TGS->C");
            K_C_SS = Base64.getEncoder().encodeToString(Objects.requireNonNull(DesEncrypter.generateSK()).getEncoded());
            System.out.println("K_C_SS:"+ K_C_SS);

            TGS = TGT[TGTComponents.c.ordinal()] + "\n";
            TGS += Constants.serviceServerPort + "\n";
            TGS += LocalDateTime.now().format(Constants.formatter) + "\n";
            TGS += p2 + "\n";
            TGS += K_C_SS;
            System.out.println("TGS:"+ TGS);

            DesEncrypter encrypterK_TGS_SS = new DesEncrypter(Constants.K_TGS_SS);
            DesEncrypter encrypterK_C_TGS = new DesEncrypter(DesEncrypter.getSK(TGT[TGTComponents.K_C_TGS.ordinal()]));

            buf = encrypterK_C_TGS.encrypt(encrypterK_TGS_SS.encrypt(TGS));
            packet = new DatagramPacket(buf, buf.length, address, port);
            try {
                socket.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }

            System.out.println("TGS encrypted by K_TGS_SS and K_C_TGS: "+new String(buf,0,buf.length));

            buf = encrypterK_C_TGS.encrypt(K_C_SS);
            packet = new DatagramPacket(buf, buf.length, address, port);
            try {
                socket.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("K_C_SS encrypted by K_C_TGS: "+new String(buf,0,buf.length));

        }
        socket.close();
    }
}
