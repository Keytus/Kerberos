package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;

public class Main {

    public static void main(String[] args) {

        Thread serviceServerThread = new Thread(() -> {
            while (true)
            {
                ServiceServer serviceServer = new ServiceServer();
                serviceServer.run();
            }
        });
        serviceServerThread.start();

        Thread authenticationThread = new Thread(() -> {
            while (true)
            {
                AuthenticationServer authenticationServer = new AuthenticationServer();
                authenticationServer.run();
            }
        });
        authenticationThread.start();

        Thread ticketGrantingThread = new Thread(() -> {
            while (true)
            {
                TicketGrantingServer ticketGrantingServer = new TicketGrantingServer();
                ticketGrantingServer.run();
            }
        });
        ticketGrantingThread.start();

        Client client = new Client();
        client.authorization();
    }
}
