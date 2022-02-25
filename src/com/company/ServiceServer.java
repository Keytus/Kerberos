package com.company;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.time.LocalDateTime;

public class ServiceServer
{
    private DatagramSocket socket;
    private boolean running;
    private byte[] buf = new byte[256];
    private byte[] encryptedTGS;
    private byte[] encryptedAut2;
    private String[] TGS;
    private String[] Aut2;

    public ServiceServer()
    {
        try {
            socket = new DatagramSocket(Constants.serviceServerPort);
        } catch (SocketException e) {
            e.printStackTrace();
        }
    }
    public void run() {
        running = true;
        System.out.println("SS running");

        while (running) {
            DesEncrypter encrypterK_C_SS = null;
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
                System.out.println("C->SS");
            } catch (IOException e) {
                e.printStackTrace();
            }
            InetAddress address = packet.getAddress();
            int port = packet.getPort();
            packet = new DatagramPacket(buf, buf.length, address, port);
            String received= new String(packet.getData(), 0, packet.getLength());
            encryptedTGS = received.split("\n")[0].getBytes();
            encryptedAut2 = received.split("\n")[1].getBytes();

            System.out.println("SS get encrypted TGS,encrypted Aut2 from C");
            DesEncrypter encrypterK_TGS_SS = new DesEncrypter(Constants.K_TGS_SS);
            TGS = encrypterK_TGS_SS.decryptToStr(encryptedTGS).split("\n");
            System.out.println("SS decrypt TGS:"+TGS);

            try {
                encrypterK_C_SS = new DesEncrypter(DesEncrypter.getSK(TGS[TGSComponents.K_C_SS.ordinal()]));
                Aut2 = encrypterK_C_SS.decryptToStr(encryptedAut2).split("\n");
            }
            catch (Exception ex)
            {
                System.out.println("C used wrong K_C_SS");
                System.exit(-1);
            }
            System.out.println("SS decrypt Aut2:"+Aut2);

            LocalDateTime t3 = LocalDateTime.parse(TGS[TGSComponents.t3.ordinal()], Constants.formatter);
            int p2 = Integer.parseInt(TGS[TGSComponents.p2.ordinal()]);
            LocalDateTime t4 = LocalDateTime.parse(Aut2[1], Constants.formatter);

            if(t4.isAfter(t3.plusMinutes(p2)))
            {
                System.out.println("TGS time limit is over");
                System.exit(-1);
            }
            System.out.println("SS check TGS time limit");

            System.out.println("SS->C");

            String t4SS = t4.plusMinutes(1).format(Constants.formatter);

            buf = encrypterK_C_SS.encrypt(t4SS);
            packet = new DatagramPacket(buf, buf.length, address, port);
            try {
                socket.send(packet);
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println("SS send encrypted t4+1 to C");

        }
        socket.close();
    }
}
