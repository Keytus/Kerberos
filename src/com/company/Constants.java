package com.company;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.time.format.DateTimeFormatter;

public class Constants {
    public final static int defaultSize = 256;
    public final static int serviceServerPort = 4445;
    public final static int ticketGrantingServerPort = 4446;
    public final static int authenticationServerPort = 4447;
    public final static DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    public static SecretKey K_AS_TGS;
    public static SecretKey K_TGS_SS;

    static {
        try {
            K_AS_TGS = KeyGenerator.getInstance("DES").generateKey();
            K_TGS_SS = KeyGenerator.getInstance("DES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
enum TGTComponents{
    c,
    tgs,
    t1,
    p1,
    K_C_TGS
}
enum TGSComponents{
    c,
    ss,
    t3,
    p2,
    K_C_SS
}
