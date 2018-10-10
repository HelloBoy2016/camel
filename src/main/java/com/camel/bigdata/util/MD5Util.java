package com.camel.bigdata.util;

/**
 * @author biao.xu
 * @date 2018/10/10 16:14
 * MD5加解密组件
 */

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.digest.DigestUtils;

public class MD5Util {
    public MD5Util() {
    }

    /**
     * 签名
     * @param text：字符串（key=value）
     * @param key：加盐减少HASH碰撞
     * @param charset：字符集
     * @return：签名
     */
    public static String sign(String text, String key, String charset) {
        text = text + key;
        return DigestUtils.md5Hex(getContentBytes(text, charset));
    }

    /**
     * 验签
     * @param text：字符串（key=value）
     * @param sign：签名后的字符串
     * @param key：加盐减少HASH碰撞
     * @param charset：字符集
     * @return: 两次签名结果是否一致
     */
    public static boolean verify(String text, String sign, String key, String charset) {
        text = text + key;
        String mySign = DigestUtils.md5Hex(getContentBytes(text, charset));
        return mySign.equals(sign);
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

    public static void main(String[] args) {
        String key = "2018#";
        String text = "user=xiaoming";
        String sign = sign(text,key,"UTF-8");
        System.out.println("签名：" + sign);
        System.out.println("验证签名结果：" + verify(text,sign,key,"UTF-8"));
    }
}
