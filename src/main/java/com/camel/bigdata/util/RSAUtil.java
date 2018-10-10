package com.camel.bigdata.util;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;

/**
 * @author biao.xu
 * @date 2018/10/10 16:14
 * RSA安全组件：非对称加密，公钥加密，私钥解密；私钥加密，公钥解密
 */
public class RSAUtil {

    public RSAUtil() {
    }

    /**
     * 生成密钥对
     * @return
     */
    public static Map<String, Object> genKeyPair() {
        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("生成keyPairGen: " + e.getMessage());
        }

        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap(2);
        keyMap.put("RSAPublicKey", publicKey);
        keyMap.put("RSAPrivateKey", privateKey);
        return keyMap;
    }

    /**
     * RSA签名：（MD5 + 加密）
     * 1.将字符串根据MD5生成数字摘要，2.再用私钥将数字摘要加密
     * @param text：明文字符串(key=value)
     * @param privateKey：私钥
     * @param charset：字符集
     * @return：返回签名字符串
     */
    public static String sign(String text, String privateKey, String charset) {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        byte[] result;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(privateK);
            signature.update(getContentBytes(text, charset));
            result = signature.sign();
        } catch (Exception exception) {
            throw new RuntimeException("RSA签名异常", exception);
        }

        return Base64.encodeBase64String(result);
    }

    /**
     * RSA验签：（MD5 + 解密）
     * 1.将字符串根据MD5生成数字摘要，2.根据公钥解密签名字符串得到数字摘要，3.比较1和2是否相等
     * @param text：明文字符串（key=value）
     * @param sign：签名字符串
     * @param publicKey：公钥
     * @param charset:字符集
     * @return ：公钥解密签名后，拿到数字摘要，再与生成的数字摘要比较
     */
    public static boolean verify(String text, String sign, String publicKey, String charset) {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicK = keyFactory.generatePublic(keySpec);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(publicK);
            signature.update(getContentBytes(text, charset));
            boolean b = signature.verify(Base64.decodeBase64(sign));
            return b;
        } catch (Exception exception) {
            throw new RuntimeException("RSA验证签名异常：", exception);
        }
    }

    /**
     * 私钥解密
     * @param encryptedData
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(2, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        for (int i = 0; inputLen - offSet > 0; offSet = i * 128) {
            byte[] cache;
            if (inputLen - offSet > 128) {
                cache = cipher.doFinal(encryptedData, offSet, 128);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 公钥解密
     * @param encryptedData
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(2, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        for (int i = 0; inputLen - offSet > 0; offSet = i * 128) {
            byte[] cache;
            if (inputLen - offSet > 128) {
                cache = cipher.doFinal(encryptedData, offSet, 128);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }

        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 公钥加密
     * @param data
     * @param publicKey
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(1, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        for (int i = 0; inputLen - offSet > 0; offSet = i * 117) {
            byte[] cache;
            if (inputLen - offSet > 117) {
                cache = cipher.doFinal(data, offSet, 117);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * 私钥解密
     * @param data
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(1, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        for (int i = 0; inputLen - offSet > 0; offSet = i * 117) {
            byte[] cache;
            if (inputLen - offSet > 117) {
                cache = cipher.doFinal(data, offSet, 117);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    private static byte[] getContentBytes(String content, String charset) {
        if (charset != null && !"".equals(charset)) {
            try {
                return content.getBytes(charset);
            } catch (UnsupportedEncodingException var3) {
                throw new RuntimeException("签名过程错误,编码集不对,编码集:" + charset);
            }
        } else {
            return content.getBytes();
        }
    }

    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get("RSAPrivateKey");
        return Base64.encodeBase64String(key.getEncoded());
    }

    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get("RSAPublicKey");
        return Base64.encodeBase64String(key.getEncoded());
    }

    public static void rsaKeyGenerate(String appId) throws Exception {
        Map map = genKeyPair();
        System.out.println(appId + ".public.key=" + getPublicKey(map));
        System.out.println(appId + ".private.key=" + getPrivateKey(map));
    }

    public static void main(String[] args) throws Exception {
        // rsaKeyGenerate("camel");
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCA2AjclP2tHMrXpCIZc+AGHnpj7DcCu4Z2/fjAMYVzD5GbtWDhVqwerlKhVUZAuSvvW65XTiDHcduMcFJeWict63XEwOwJ1KmTdc65rS5vOzRHkHgmePI/0aYj4SBMROMaiu6kfO3uWxfGR+Y1GpCD52r2veyBHQ7dWJ/YX3SdMwIDAQAB";
        String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIDYCNyU/a0cytekIhlz4AYeemPsNwK7hnb9+MAxhXMPkZu1YOFWrB6uUqFVRkC5K+9brldOIMdx24xwUl5aJy3rdcTA7AnUqZN1zrmtLm87NEeQeCZ48j/RpiPhIExE4xqK7qR87e5bF8ZH5jUakIPnava97IEdDt1Yn9hfdJ0zAgMBAAECgYBPGtROAdfB6lSLkwUwlVksyJeiM8wOjG3hLssDzSO+4gcnD3Q8xYcFi0fGL+HjKQ1VdveSOLCdY0VFc0zPCxDUHBdP+ia/yQVKO82i7oFUFbtyrVRVWXlZpfIHuBiKUkE3AAtTZb43/OALNYi1PmkfQ6tuHOlcM6N+1phqinhT4QJBAMK/otAEdhKQE2zGEsOe7kdmWdV7Aq7xdWgVvtzF0kC5c2iWdoU4ZhKu9R4Gw/VQBwD+sKzkHqla/kjhsOoySSMCQQCpXgVGocu8NsjBfZLgZa44Qmg2aTzEybR/qzHbX0cK9EjETrqOFAbpQtCBK6arusX/d4etxX2X81ny5P0fvoSxAkAkwu3l3GG5YU75Ym5aVN7fxXdBsAWypkumSSyNGh51L0yUuopG3X2PG02TzG0jGmcoDeulxy3uhAmqEkhF/RYHAkBD5bZVv40ukgPfVdko7npugWjHz16WQYqD1/yvxj1zzcTSNgGh7bNrleaCsh4qIEE6DhAtgMu9u8gmkNhM/pKxAkAj4WgyvU9M74f3QqsOghA/xQNExxci7FmUdQXkj6EsDMQh7OrbapW+K/IFYG9hqoa2Ql+pKiO/z38AUdAnkTch";
        String text = "user=xiaoming";
        String sing = sign(text,privateKey,"UTF-8");
        System.out.println("签名：" + sing);
        System.out.println("验证签名结果：" + verify(text,sing,publicKey,"UTF-8"));

        System.out.println("-----------------公钥加密，私钥解密--------------------");
        System.out.println("加密之前的字符串：" + text);
        byte[] data = getContentBytes(text,"UTF-8");
        byte[] dataEncode = encryptByPublicKey(data,publicKey);
        System.out.println("公钥加密后：" +  Base64.encodeBase64String(dataEncode));
        byte[] dataDecode = decryptByPrivateKey(dataEncode,privateKey);
        System.out.println("私钥解密后的字符串：" + new String(dataDecode));

        System.out.println("-----------------私钥加密，公钥解密--------------------");
        System.out.println("加密之前的字符串：" + text);
        byte[] data2 = getContentBytes(text,"UTF-8");
        byte[] dataEncode2 = encryptByPrivateKey(data2,privateKey);
        System.out.println("私钥加密后：" +  Base64.encodeBase64String(dataEncode2));
        byte[] dataDecode2 = decryptByPublicKey(dataEncode2,publicKey);
        System.out.println("公钥解密后的字符串：" + new String(dataDecode2));

    }
}
