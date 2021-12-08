package gca;

import com.google.zxing.WriterException;
import javassist.*;

import javax.swing.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.Scanner;

public class GoogleCSAgent {
    public static void premain(String agentArgs, Instrumentation inst) throws Exception {
        if (agentArgs == null){
            System.out.println("GoogleCSAgent need args");
            return;
        }
        //Have class resources and TOTP secret
        ClassPool classPool = ClassPool.getDefault();
        String className = "server.ManageUser";
        //Find ClassFile to byte[] and give it to classfileBuffer
        CtClass cl = classPool.getCtClass(className);
        byte[] classfileBuffer = cl.toBytecode();
        //defrost server.ManageUser class
        cl.stopPruning(true);
        cl.defrost();
        byte[] classfileBuffer2 = addCsTransformer(className,classfileBuffer,agentArgs);
        cl = classPool.makeClass(new ByteArrayInputStream(classfileBuffer2));
        cl.toClass();

        inst.addTransformer(new DefineTransformer(),false);
//        inst.addTransformer(new DefineTransformer(agentArgs),false);

    }
    static class DefineTransformer implements ClassFileTransformer {
//        String QRString;
        private final ClassPool classPool = ClassPool.getDefault();
//        public DefineTransformer(String args){
//            this.QRString = args;
//        }

        @Override
        public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined, ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {
            try {
                if (className==null){
                    return classfileBuffer;
                }else if (className.equals("beacon/BeaconData")) {
                    // 暗桩修复，修改zip包后，30分钟所有命令都会变成exit，非侵入式修改下其实不需要
                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                    CtMethod mtd = cls.getDeclaredMethod("shouldPad");
                    mtd.setBody("{$0.shouldPad = false;}");
                    return cls.toBytecode();
                }else if (className.equals("common/Authorization")) {
                    // 设置破解key
                    CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                    String func = "public static byte[] hex2bytes(String s) {" +
                            "   int len = s.length();" +
                            "   byte[] data = new byte[len / 2];" +
                            "   for (int i = 0; i < len; i += 2) {" +
                            "       data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));" +
                            "   }" +
                            "   return data;" +
                            "}";
                    CtMethod hex2bytes = CtNewMethod.make(func, cls);
                    cls.addMethod(hex2bytes);

                    CtConstructor mtd = cls.getDeclaredConstructor(new CtClass[]{});
                    mtd.setBody("{$0.watermark = 999999;" +
                            "$0.validto = \"forever\";" +
                            "$0.valid = true;" +
                            "common.MudgeSanity.systemDetail(\"valid to\", \"perpetual\");" +
                            "common.MudgeSanity.systemDetail(\"id\", String.valueOf($0.watermark));" +
                            "common.SleevedResource.Setup(hex2bytes(\"5e98194a01c6b48fa582a6a9fcbb92d6\"));" +
                            "}");
                    return cls.toBytecode();
                }
//                
            } catch (Exception exception) {
                System.out.printf("Error: %s\n",exception);
            }
            return classfileBuffer;
        }

    }
    public static byte[] addCsTransformer(String className,byte[] classfileBuffer,String totpSecretKey) throws Exception{
        ClassPool classPool = ClassPool.getDefault();
        try {
            if (className == null) {
                return classfileBuffer;
            } else if (className.equals("server.ManageUser")) { // 只修改 ManageUser 类
                CtClass cls = classPool.makeClass(new ByteArrayInputStream(classfileBuffer));
                CtMethod ctmethod = cls.getDeclaredMethod("process",
                        new CtClass[]{classPool.get("common.Request")});
                String func = "{"
                        + "if (!$0.authenticated && \"aggressor.authenticate\".equals($1.getCall()) && $1.size() == 3) {"
                        + "   java.lang.String mnickname = $1.arg(0)+\"\";"
                        + "   java.lang.String mpassword = $1.arg(1)+\"\";"
                        + "   java.lang.String mver = $1.arg(2)+\"\";"
                        + "   if(mnickname.length() < 6){ $0.client.writeObject($1.reply(\"Dynamic Code Error.\"));return; };" // 用户名如果低于 6 位就直接 return

                        + "   java.lang.String lastcode = gca.GoogleAuthenticationTool.getTOTPCode(\""+totpSecretKey+"\");"// 生成 TOTP 6位数字
                        + "   if(!mnickname.substring(mnickname.length()-6, mnickname.length()).equals(lastcode)) {" // 比对动态口令，如果口令没对上，就 return
                        + "       $0.client.writeObject($1.reply(\"GFhub Internal version requires AuthCode!\"));return;"
                        + "   }"
                        + "}"
                        + "}";
                ctmethod.insertBefore(func); // 把上面的代码插入到 process 函数最前面，如果口令正确，就继续走 cs 常规的流程
                byte[] result = cls.toBytecode();
                //if not detach ,will frost class
                cls.detach();
                return result;

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.printf("[CSTOTPAgent] PreMain transform Error: %s\n", ex);
        }
        return new byte[]{};
    }
    public static void Generator(){
        // 该部分借鉴：https://github.com/HKirito/GoogleAuth
        String title = "GoogleCSAgent";
        String name = "GFhub";

        System.out.println("Generate TOTP key");
        String secret = GoogleAuthenticationTool.generateSecretKey();
        System.out.println("SecretKey: "+secret);

        //Get User input
        Scanner scanner = new Scanner(System.in);
        System.out.println("Please input your name and title(eg：name,title): ");
        String line = scanner.nextLine();
        String[] split = line.split(",");
        if (split[0]==" "){
            name = split[0];
            title = split[1];
        }
        String QRString = GoogleAuthenticationTool.spawnScanQRString(name,secret,title);
        String codestring = null;
        try {
            codestring = GoogleAuthenticationTool.createQRCode(QRString,"",400,400);
        } catch (WriterException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(codestring);
        System.out.println("\nSecret： "+secret);
        String totpSecretKey = GoogleAuthenticationTool.getTOTPCode(secret);
    }

    public static void main(String[] args) {
        GoogleCSAgent.Generator();
    }
}
