package com.company;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.time.LocalDateTime;

public class Client
{
    private DatagramSocket socket;
    private InetAddress address;
    private byte[] encryptedTGT = new byte[Constants.defaultSize];
    private byte[] encryptedTGS = new byte[Constants.defaultSize];
    private String c;//идентификатор
    private String K_C;//основной ключ C
    private String K_C_TGS;//ключ, выдаваемый C для доступа к серверу выдачи разрешений TGS
    private String K_C_SS;
    private String Aut1;//аутентификационный блок - Aut1 = {с,t2}, t2 - метка времени
    private String Aut2;//где Aut2={c,t4}.
    private String t4SS;//t4+1

    public Client()
    {
        try {
            socket = new DatagramSocket();
        } catch (SocketException e) {
            e.printStackTrace();
        }
        try {
            address = InetAddress.getByName("localhost");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public void authorization() {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        try {
            c = reader.readLine();
            K_C = reader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        DatagramPacket packet;
        DesEncrypter encrypterK_C = new DesEncrypter(DesEncrypter.getSK(K_C));

        SendPacket(c, Constants.authenticationServerPort);

        packet = ReceivePacket();
        System.out.println("C get encrypted TGT from AS:"+ (new String(packet.getData(), 0, packet.getLength())));
        encryptedTGT = encrypterK_C.decrypt((new String(packet.getData(), 0, packet.getLength()).getBytes()));

        packet = ReceivePacket();
        System.out.println("C get encrypted K_C_TGS from AS:"+ (new String(packet.getData(), 0, packet.getLength())));
        K_C_TGS = encrypterK_C.decryptToStr((new String(packet.getData(), 0, packet.getLength()).getBytes()));
        System.out.println("C->TGS");
        System.out.println("C decrypt K_C_TGS:"+ K_C_TGS);
        DesEncrypter encrypterK_C_TGS = new DesEncrypter(DesEncrypter.getSK(K_C_TGS));

        Aut1 = c + "\n" + LocalDateTime.now().format(Constants.formatter);
        System.out.println("Aut1:"+ Aut1);

        String msg = new String(encryptedTGT, 0, encryptedTGT.length) + "\n";
        byte[] encryptedAut1 = encrypterK_C_TGS.encrypt(Aut1);
        msg += new String(encryptedAut1, 0, encryptedAut1.length) + "\n";
        msg += Constants.serviceServerPort;
        SendPacket(msg, Constants.ticketGrantingServerPort);
        System.out.println("C send encrypted TGT, encrypted Aut1, ID to TGS");

        ////
        packet = ReceivePacket();
        System.out.println("C get encrypted TGS from TGS:"+ (new String(packet.getData(), 0, packet.getLength())));
        encryptedTGS = encrypterK_C_TGS.decrypt((new String(packet.getData(), 0, packet.getLength()).getBytes()));

        packet = ReceivePacket();
        System.out.println("C get encrypted KC_SS from TGS:"+ (new String(packet.getData(), 0, packet.getLength())));
        K_C_SS = encrypterK_C_TGS.decryptToStr((new String(packet.getData(), 0, packet.getLength()).getBytes()));
        System.out.println("C->SS");
        System.out.println("C decrypt K_C_SS:"+ K_C_SS);
        DesEncrypter encrypterK_C_SS = new DesEncrypter(DesEncrypter.getSK(K_C_SS));

        Aut2 = c + "\n" + LocalDateTime.now().format(Constants.formatter);
        System.out.println("Aut2:"+ Aut2);

        msg = new String(encryptedTGS, 0, encryptedTGT.length) + "\n";
        byte[] encryptedAut2 = encrypterK_C_SS.encrypt(Aut2);
        msg += new String(encryptedAut2, 0, encryptedAut2.length) + "\n";
        SendPacket(msg, Constants.serviceServerPort);
        System.out.println("C send encrypted TGS, encrypted Aut1, ID to SS");

        packet = ReceivePacket();
        System.out.println("C get encrypted t4+1 from SS:"+ (new String(packet.getData(), 0, packet.getLength())));
        try {
            t4SS = encrypterK_C_SS.decryptToStr((new String(packet.getData(), 0, packet.getLength()).getBytes()));
            System.out.println("C decrypt t4+1:" + t4SS);
            System.out.println("End");
        }
        catch (Exception e)
        {
            System.out.println("C can't decrypt t4+1 from SS");
            System.exit(-1);
        }

    }
    private DatagramPacket ReceivePacket()
    {
        byte[] buf =  new byte[Constants.defaultSize];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        try {
            socket.receive(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return packet;
    }
    private void SendPacket(String msg, int receiver)
    {
        byte[] buf = msg.getBytes();
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, receiver);
        try {
            socket.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private void SendPacket(byte[] buf, int receiver)
    {
        DatagramPacket packet = new DatagramPacket(buf, buf.length, address, receiver);
        try {
            socket.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void close() {
        socket.close();
    }
}
