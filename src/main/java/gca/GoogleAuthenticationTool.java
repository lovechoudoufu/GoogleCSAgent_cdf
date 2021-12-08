package gca;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import de.taimos.totp.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;


import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.Base64;


public class GoogleAuthenticationTool {

    public static String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);

    }

    /**
     * 根据32位随机码获得正确的6位数字
     *
     * @param secretKey
     * @return
     */
    public static String getTOTPCode(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return TOTP.getOTP(hexKey);
    }


    /**
     * 生成绑定二维码（字符串）
     *
     * @param account   账户信息（展示在Google Authenticator App中的）
     * @param secretKey 密钥
     * @param title     标题 （展示在Google Authenticator App中的）
     * @return
     */
    public static String spawnScanQRString(String account, String secretKey, String title) {
        try {
            return "otpauth://totp/"
                    + URLEncoder.encode(title + ":" + account, "UTF-8").replace("+", "%20")
                    + "?secret=" + URLEncoder.encode(secretKey, "UTF-8").replace("+", "%20")
                    + "&issuer=" + URLEncoder.encode(title, "UTF-8").replace("+", "%20");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * 生成二维码（文件）【返回图片的base64，若指定输出路径则同步输出到文件中】
     *
     * @param barCodeData 二维码字符串信息
     * @param outPath     输出地址
     * @param height
     * @param width
     * @throws WriterException
     * @throws IOException
     */
    public static String createQRCode(String barCodeData, String outPath, int height, int width)
            throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE,
                width, height);
        BufferedImage bufferedImage = MatrixToImageWriter.toBufferedImage(matrix);

        ByteArrayOutputStream bof = new ByteArrayOutputStream();
        ImageIO.write(bufferedImage, "png", bof);
        String base64 = imageToBase64(bof.toByteArray());
        if(outPath!=null&&!outPath.equals("")) {
            try (FileOutputStream out = new FileOutputStream(outPath)) {
                MatrixToImageWriter.writeToStream(matrix, "png", out);
            }
        }
        return base64;
    }

    /**
     * 将图片文件转换成base64字符串，参数为该图片的路径
     *
     * @param dataBytes
     * @return java.lang.String
     */
    private static String imageToBase64(byte[] dataBytes) {
        // 对字节数组Base64编码
        String encoded = Base64.getEncoder().encodeToString(dataBytes);
        //Base32 base32 = new Base32();
        //String encoded = base32.encodeToString(dataBytes);
        if (dataBytes != null) {
            return "data:image/jpeg;base64," + encoded;// 返回Base64编码过的字节数组字符串
        }
        return null;
    }

}
