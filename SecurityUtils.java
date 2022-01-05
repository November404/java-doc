package com.november.utilsonline.utils;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 加密类
 *
 * @author November
 * @since 2022 -01-05
 */
@Slf4j
public class SecurityUtils {
    /**
     * 双向加密 DES.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class DES {
        // 8位元密钥
        private static final byte[] KEY_BYTES = {0x11, 0x22, 0x4F, 0x58, (byte) 0x88, 0x20, 0x50, 0x38};

        static {
            Security.addProvider(new com.sun.crypto.provider.SunJCE());
        }

        /**
         * 获取加密KEY.
         *
         * @return byte [ ]
         */
        public synchronized static byte[] getKey() {
            return KEY_BYTES;
        }

        /**
         * 利用密钥加密 使用默认的秘钥.
         *
         * @param src the src
         * @return string string
         */
        public synchronized static String encrypt(String src) {
            return encrypt(getKey(), src);
        }

        /**
         * 利用密钥解密.
         *
         * @param src the src
         * @return string string
         */
        public synchronized static String decrypt(String src) {
            return decrypt(getKey(), src);
        }

        /**
         * 利用密钥加密.
         *
         * @param keyByte 秘钥
         * @param src     明文
         * @return string string
         */
        public synchronized static String encrypt(byte[] keyByte, String src) {
            // 加密，结果保存进cipherByte
            byte[] cipherByte = null;
            try {
                SecretKey deskey = new SecretKeySpec(keyByte, "DES");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("DES");
                // 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式
                c.init(Cipher.ENCRYPT_MODE, deskey);
                byte[] bytes = src.getBytes();
                cipherByte = c.doFinal(bytes);
            } catch (Exception e) {
                log.error("Des encrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = SecurityUtils.byte2str(cipherByte);
            return str;
        }

        /**
         * 利用密钥解密.
         *
         * @param keyByte 秘钥
         * @param src     明文
         * @return string string
         */
        public synchronized static String decrypt(byte[] keyByte, String src) {

            byte[] cipherByte = null;
            try {
                SecretKey deskey = new SecretKeySpec(keyByte, "DES");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("DES");

                // 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示加密模式
                c.init(Cipher.DECRYPT_MODE, deskey);
                cipherByte = c.doFinal(str2bytes(src));

            } catch (Exception e) {
                log.error("Des decrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = new String(cipherByte);
            return str;

        }
    }

    /**
     * 双向加密 DES3.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class DES3 {
        // 24位元密钥
        private static final byte[] KEY_BYTES = {0x11, 0x22, 0x4F, 0x58,
                (byte) 0x88, 0x20, 0x50, 0x38, 0x28, 0x25, 0x79, 0x51, (byte) 0xCB,
                (byte) 0xDD, 0x55, 0x66, 0x77, 0x29, 0x74, (byte) 0x98, 0x30, 0x40,
                0x36, (byte) 0xE2};

        static {
            Security.addProvider(new com.sun.crypto.provider.SunJCE());
        }

        /**
         * 获取加密KEY.
         *
         * @return byte [ ]
         */
        public synchronized static byte[] getKey() {
            return KEY_BYTES;
        }

        /**
         * 利用密钥加密 使用默认的秘钥.
         *
         * @param src the src
         * @return string string
         */
        public synchronized static String encrypt(String src) {
            return encrypt(getKey(), src);
        }

        /**
         * 利用密钥解密.
         *
         * @param src 明文
         * @return string string
         */
        public synchronized static String decrypt(String src) {
            return decrypt(getKey(), src);
        }

        /**
         * 利用密钥加密.
         *
         * @param keyByte 秘钥
         * @param src     明文
         * @return string string
         */
        public synchronized final static String encrypt(byte[] keyByte, String src) {
            // 加密，结果保存进cipherByte
            byte[] cipherByte = null;
            try {
                SecretKey deskey = new SecretKeySpec(keyByte, "DESede");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("DESede");
                // 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式
                c.init(Cipher.ENCRYPT_MODE, deskey);
                byte[] bytes = src.getBytes();
                cipherByte = c.doFinal(bytes);
            } catch (Exception e) {
                log.error("Des3 encrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = SecurityUtils.byte2str(cipherByte);
            return str;
        }

        /**
         * 利用密钥解密.
         *
         * @param keyByte 秘钥
         * @param src     明文
         * @return string string
         */
        public synchronized final static String decrypt(byte[] keyByte, String src) {
            byte[] cipherByte = null;
            try {
                SecretKey deskey = new SecretKeySpec(keyByte, "DESede");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("DESede");

                // 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示加密模式
                c.init(Cipher.DECRYPT_MODE, deskey);
                cipherByte = c.doFinal(str2bytes(src));
            } catch (Exception e) {
                log.error("Des3 decrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = new String(cipherByte);
            return str;

        }
    }

    /**
     * 双向加密 AES 16字节 128位密钥.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class AES {
        // 16位加密KEY
        private static final byte[] KEY_BYTES = {0x11, 0x22, 0x4F, 0x58,
                (byte) 0x88, 0x20, 0x50, 0x38, 0x28, 0x25, 0x79, 0x51, (byte) 0xCB,
                (byte) 0xDD, 0x55, 0x66};

        static {
            Security.addProvider(new com.sun.crypto.provider.SunJCE());
        }

        /**
         * 获取加密KEY.
         *
         * @return byte [ ]
         */
        public synchronized static byte[] getKey() {
            return KEY_BYTES;
        }

        /**
         * 使用默认密钥加密.
         *
         * @param src the src
         * @return string string
         */
        public synchronized static String encrypt(String src) {
            return encrypt(getKey(), src);
        }

        /**
         * 使用默认密钥解密.
         *
         * @param src the src
         * @return string string
         */
        public synchronized static String decrypt(String src) {
            return decrypt(getKey(), src);
        }

        /**
         * 利用密钥加密.
         *
         * @param keyByte 16字节 128位密钥
         * @param src     明文
         * @return string string
         */
        public synchronized static String encrypt(byte[] keyByte, String src) {
            // 加密，结果保存进cipherByte
            byte[] cipherByte;
            try {
                SecretKey deskey = new SecretKeySpec(keyByte, "AES");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("AES");
                // 根据密钥，对Cipher对象进行初始化，ENCRYPT_MODE表示加密模式
                c.init(Cipher.ENCRYPT_MODE, deskey);
                byte[] bytes = src.getBytes();
                cipherByte = c.doFinal(bytes);
            } catch (Exception e) {
                log.error("AES encrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = SecurityUtils.byte2str(cipherByte);
            return str;
        }

        /**
         * 利用密钥解密.
         *
         * @param keyByte 16字节 128位秘钥
         * @param src     the src
         * @return string string
         */
        public synchronized static String decrypt(byte[] keyByte, String src) {
            byte[] cipherByte = null;
            try {
                SecretKey desKey = new SecretKeySpec(keyByte, "AES");
                // 生成Cipher对象,指定其支持的DES算法
                Cipher c = Cipher.getInstance("AES");

                // 根据密钥，对Cipher对象进行初始化，DECRYPT_MODE表示加密模式
                c.init(Cipher.DECRYPT_MODE, desKey);
                cipherByte = c.doFinal(str2bytes(src));

            } catch (Exception e) {
                log.error("AES decrypt failed. case: {}", e.getMessage());
                return null;
            }

            String str = new String(cipherByte);
            return str;

        }
    }

    /**
     * 非对称加密 RSA.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class RSA {
        /**
         * 公钥加密.
         *
         * @param publicKey 公钥
         * @param src       明文
         * @return string string
         */
        public static String encrypt(String publicKey, String src) {
            byte[] bytes = encrypt(publicKey, src.getBytes());
            String str = byte2str(bytes);
            return str;
        }

        /**
         * 私钥解密.
         *
         * @param privateKey 私钥
         * @param src        明文
         * @return string string
         */
        public static String decrypt(String privateKey, String src) {
            byte[] srcBytes = str2bytes(src);
            byte[] bytes = decrypt(privateKey, srcBytes);
            String str = new String(bytes);
            return str;
        }


        /**
         * 加密
         *
         * @param publicKey 公钥
         * @param srcBytes  明文数组
         * @return byte [ ]
         */
        public synchronized static byte[] encrypt(String publicKey, byte[] srcBytes) {
            if (publicKey != null) {
                try {
                    // 对公钥解密
                    byte[] keyBytes = Base64.getDecoder().decode(publicKey);
                    // 取得公钥
                    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    Key pubKey = keyFactory.generatePublic(x509KeySpec);
                    // 对数据加密
                    Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
                    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                    return cipher.doFinal(srcBytes);
                } catch (Exception e) {
                    log.error("RSA encrypt failed. case: {}", e.getMessage());
                    return null;
                }
            }
            return null;
        }

        /**
         * 解密
         *
         * @param privateKey 私钥
         * @param srcBytes   明文数组
         * @return byte[ ]
         */
        public synchronized static byte[] decrypt(String privateKey, byte[] srcBytes) {
            if (privateKey != null) {
                try {
                    // 对密钥解密
                    byte[] keyBytes = Base64.getDecoder().decode(privateKey.getBytes());
                    // 取得私钥
                    PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

                    // 对数据解密
                    Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
                    cipher.init(Cipher.DECRYPT_MODE, priKey);
                    return cipher.doFinal(srcBytes);
                } catch (Exception e) {
                    log.error("RSA decrypt failed. case: {}", e.getMessage());
                    return null;
                }
            }
            return null;
        }
    }

    /**
     * 单向加密 MD5算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class MD5 {
        /**
         * 加密.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            byte[] bytes = eccrypt(src);
            String str = byte2str(bytes).toUpperCase();
            return str;
        }

        private synchronized static byte[] eccrypt(String info) {
            try {
                // 根据MD5算法生成MessageDigest对象
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                byte[] srcBytes = info.getBytes(StandardCharsets.UTF_8);
                // 使用srcBytes更新摘要
                md5.update(srcBytes);
                // 完成哈希计算，得到result
                byte[] resultBytes = md5.digest();
                return resultBytes;
            } catch (Exception e) {
                log.error("MD5 eccrypt failed. case: {}", e.getMessage());
                return null;
            }
        }

    }

    /**
     * 单向加密 SHA算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class SHA {
        /**
         * 加密 默认SHA-1.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            return SHA256.encrypt(src);
        }
    }

    /**
     * 单向加密 SHA1(SHA-1)算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class SHA1 {
        /**
         * 加密.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            byte[] bytes = eccrypt(src);
            String str = byte2str(bytes);
            return str;
        }

        private synchronized static byte[] eccrypt(String info) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("SHA");
                byte[] srcBytes = info.getBytes();
                // 使用srcBytes更新摘要
                md5.update(srcBytes);
                // 完成哈希计算，得到result
                byte[] resultBytes = md5.digest();
                return resultBytes;
            } catch (Exception e) {
                log.error("SHA1 eccrypt failed. case: {}", e.getMessage());
                return null;
            }
        }

    }

    /**
     * 单向加密 SHA256(SHA-256)算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class SHA256 {
        /**
         * 加密.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            byte[] bytes = eccrypt(src);
            String str = byte2str(bytes);
            return str;
        }

        private synchronized static byte[] eccrypt(String info) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("SHA-256");
                byte[] srcBytes = info.getBytes();
                // 使用srcBytes更新摘要
                md5.update(srcBytes);
                // 完成哈希计算，得到result
                byte[] resultBytes = md5.digest();
                return resultBytes;
            } catch (Exception e) {
                log.error("SHA256 eccrypt failed. case: {}", e.getMessage());
                return null;
            }
        }

    }

    /**
     * 单向加密 SHA384(SHA-384)算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class SHA384 {
        /**
         * 加密.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            byte[] bytes = eccrypt(src);
            String str = byte2str(bytes);
            return str;
        }

        private synchronized static byte[] eccrypt(String info) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("SHA-384");
                byte[] srcBytes = info.getBytes();
                // 使用srcBytes更新摘要
                md5.update(srcBytes);
                // 完成哈希计算，得到result
                byte[] resultBytes = md5.digest();
                return resultBytes;
            } catch (Exception e) {
                log.error("SHA384 eccrypt failed. case: {}", e.getMessage());
                return null;
            }
        }

    }

    /**
     * 单向加密 SHA512(SHA-512)算法.
     *
     * @author November
     * @since 2022 -01-05
     */
    public static class SHA512 {
        /**
         * 加密.
         *
         * @param src 明文
         * @return string string
         */
        public static String encrypt(String src) {
            byte[] bytes = eccrypt(src);
            String str = byte2str(bytes);
            return str;
        }

        private synchronized static byte[] eccrypt(String info) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("SHA-512");
                byte[] srcBytes = info.getBytes();
                // 使用srcBytes更新摘要
                md5.update(srcBytes);
                // 完成哈希计算，得到result
                byte[] resultBytes = md5.digest();
                return resultBytes;
            } catch (Exception e) {
                log.error("SHA512 eccrypt failed. case: {}", e.getMessage());
                return null;
            }
        }

    }

    /**
     * 字节数组转换16进制字符串.
     *
     * @param bytes 字节数组
     * @return string string
     */
    public static String byte2str(byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        char hexDigits[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
        int j = bytes.length;
        char str[] = new char[j * 2];
        int k = 0;
        for (int i = 0; i < j; i++) {
            byte byte0 = bytes[i];
            str[k++] = hexDigits[byte0 >>> 4 & 0xf];
            str[k++] = hexDigits[byte0 & 0xf];
        }
        return new String(str);
    }

    /**
     * 16进制的字符串转换为字节数组.
     *
     * @param str 16进制的字符串
     * @return byte[] bytes
     */
    public static byte[] str2bytes(String str) {
        if (str == null) {
            return null;
        }
        String tmpStr = str.replaceAll(" ", "");
        byte[] bRet = new byte[tmpStr.length() / 2];
        for (int i = 0; i < tmpStr.length() / 2; i++) {
            Integer itg = new Integer(16 * getChrInt(tmpStr.charAt(2 * i)) + getChrInt(tmpStr.charAt(2 * i + 1)));
            bRet[i] = itg.byteValue();
        }
        return bRet;
    }

    /**
     * 16进制字符转换10进制数�?
     *
     * @param chr 16进制字符
     * @return int
     */
    private static int getChrInt(char chr) {
        int iRet = 0;

        if (chr == "0".charAt(0)) {
            iRet = 0;
        } else if (chr == "1".charAt(0)) {
            iRet = 1;
        } else if (chr == "2".charAt(0)) {
            iRet = 2;
        } else if (chr == "3".charAt(0)) {
            iRet = 3;
        } else if (chr == "4".charAt(0)) {
            iRet = 4;
        } else if (chr == "5".charAt(0)) {
            iRet = 5;
        } else if (chr == "6".charAt(0)) {
            iRet = 6;
        } else if (chr == "7".charAt(0)) {
            iRet = 7;
        } else if (chr == "8".charAt(0)) {
            iRet = 8;
        } else if (chr == "9".charAt(0)) {
            iRet = 9;
        } else if (chr == "A".charAt(0) || chr == "a".charAt(0)) {
            iRet = 10;
        } else if (chr == "B".charAt(0) || chr == "b".charAt(0)) {
            iRet = 11;
        } else if (chr == "C".charAt(0) || chr == "c".charAt(0)) {
            iRet = 12;
        } else if (chr == "D".charAt(0) || chr == "d".charAt(0)) {
            iRet = 13;
        } else if (chr == "E".charAt(0) || chr == "e".charAt(0)) {
            iRet = 14;
        } else if (chr == "F".charAt(0) || chr == "f".charAt(0)) {
            iRet = 15;
        }

        return iRet;
    }
}
