package com.company;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

class DesEncrypter {
    Cipher ecipher;
    Cipher dcipher;

    public DesEncrypter(SecretKey key) {

        try {
            ecipher = Cipher.getInstance("DES");
            dcipher = Cipher.getInstance("DES");
            ecipher.init(Cipher.ENCRYPT_MODE, key);
            dcipher.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException  | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(String str){
        byte[] utf8;
        byte[] enc = new byte[0];
        try {
            utf8 = str.getBytes("UTF8");
            enc = ecipher.doFinal(utf8);
        } catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return Base64.getEncoder().encode(enc);
    }

    public byte[] encrypt(byte[] utf8){
        byte[] enc = new byte[0];
        try {
            enc = ecipher.doFinal(utf8);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return Base64.getEncoder().encode(enc);
    }

    public String decryptToStr(byte[] str) {
        byte[] dec = Base64.getDecoder().decode(str);
        byte[] utf8;
        try {
            utf8 = dcipher.doFinal(dec);
            return new String(utf8, "UTF8");
        } catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e) {
            e.printStackTrace();
            System.out.println(e);
            return null;
        }
    }
    public byte[] decrypt(byte[] str) {
        byte[] dec = Base64.getDecoder().decode(str);
        byte[] utf8;
        try {
            utf8 = dcipher.doFinal(dec);
            return utf8;
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static SecretKey getSK(String str)
    {
        byte[] decodedKey = Base64.getDecoder().decode(str);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    }
    public static SecretKey generateSK()
    {
        try {
            return KeyGenerator.getInstance("DES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
}