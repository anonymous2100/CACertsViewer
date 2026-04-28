package com.ctgu.util;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Date;

/**
 * Bouncy Castle 与 Nimbus JOSE+JWT 常见用法示例
 */
public class CryptoJwtUtil
{
  private static final String KEYSTORE_FILE_PATH = "C:/0_WorkFiles/CertFiles/enc-keystore.jks";
  private static final String STORE_PASSWORD = "password";

  static
  {
    // 1. 全局注册 Bouncy Castle 提供者 (bcprov的核心作用)
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * 程序入口：演示完整的 KeyStore 操作流程。
   * <ol>
   *   <li>加载（或初始化）磁盘上的 JKS KeyStore</li>
   *   <li>生成一张自签名 Root CA 证书并打印信息</li>
   *   <li>将 CA 证书及新生成的服务器证书写入 KeyStore</li>
   *   <li>将 KeyStore 持久化到磁盘</li>
   * </ol>
   *
   * @param args 命令行参数（暂未使用）
   * @throws Exception 任意执行异常
   */
  public static void main(String[] args) throws Exception
  {
    KeyStore keyStore = loadKeyStore(KEYSTORE_FILE_PATH, STORE_PASSWORD);

    // generateRootCert() 现在同时返回密钥对和证书
    KeyPair rootKeyPair = generateSecureKeyPair(2048);
    X509Certificate rootCert = generateRootCert(rootKeyPair);
    printCertificate(rootCert);

    saveCertsToKeyStore(keyStore, rootKeyPair, rootCert);
  }

  /**
   * 将证书条目保存到 KeyStore 内存对象中，完成后持久化写盘。
   * <ul>
   *   <li>{@code "root-ca"}：以 {@code PrivateKeyEntry} 存储 Root CA 的私钥 + 证书，
   *       <b>可导出私钥</b>（适合自建 CA 场景）</li>
   *   <li>{@code "server-tls"}：另生成一对新的 RSA 密钥，签发自签名证书，以 {@code PrivateKeyEntry} 存储</li>
   * </ul>
   * <p>
   * 注意：如果只需将 Root CA 作为<b>信任锚</b>（只存公钥，不存私钥），
   * 应改用 {@code keyStore.setCertificateEntry("trusted-root-ca", certificate)}，
   * 该方式创建的是 {@code TrustedCertificateEntry}，<b>不含也不能导出私钥</b>，
   * 对标浏览器/JDK 的 cacerts 用途。
   * </p>
   *
   * @param keyStore    目标 KeyStore 内存对象
   * @param rootKeyPair Root CA 的密钥对（私钥将一同存入）
   * @param certificate Root CA 的 X.509 证书
   * @throws Exception KeyStore 操作异常或证书生成异常
   */
  public static void saveCertsToKeyStore(KeyStore keyStore, KeyPair rootKeyPair, X509Certificate certificate) throws Exception
  {
    // ── Root CA 条目：使用 PrivateKeyEntry，私钥可导出 ──────────────────────────
    KeyStore.PrivateKeyEntry rootEntry = new KeyStore.PrivateKeyEntry(rootKeyPair.getPrivate(), new X509Certificate[] { certificate });
    KeyStore.PasswordProtection pp = new KeyStore.PasswordProtection(STORE_PASSWORD.toCharArray());
    keyStore.setEntry("root-ca", rootEntry, pp);

    // ── Server TLS 条目：新密钥对 + 以 Root CA 证书补全链 ──────────────────────
    KeyPair serverKeyPair = generateSecureKeyPair(2048);
    X509Certificate serverCert = generateSelfSignedCert(serverKeyPair);
    X509Certificate[] serverChain = { serverCert, certificate };
    keyStore.setEntry("server-tls", new KeyStore.PrivateKeyEntry(serverKeyPair.getPrivate(), serverChain), pp);

    // 持久化到磁盘
    saveKeyStore(keyStore, KEYSTORE_FILE_PATH, STORE_PASSWORD);
  }

  /**
   * 根据给定的 RSA 密钥对生成一张自签名 X.509 v3 CA 证书（使用 Bouncy Castle）。
   * <p>证书属性：</p>
   * <ul>
   *   <li>DN：{@code CN=My Trusted Root CA, O=Example Security, C=CN}</li>
   *   <li>有效期：昨天 ~ 一年后</li>
   *   <li>扩展：BasicConstraints(CA=true)、KeyUsage(digitalSignature | keyCertSign | cRLSign)</li>
   *   <li>签名算法：SHA256WithRSAEncryption</li>
   * </ul>
   *
   * @param keyPair 用于签名和嵌入公钥的 RSA 密钥对
   * @return 生成的自签名 X.509 证书
   * @throws Exception 证书构建或签名异常
   */
  public static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception
  {
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    // 自签名证书，颁发者与主题相同
    X500Name issuerAndSubject = new X500Name("CN=My Trusted Root CA, O=Example Security, C=CN");
    BigInteger serialNumber = new BigInteger(128, new SecureRandom());
    Date notBefore = new Date(System.currentTimeMillis() - 86400000L);  // 昨天
    Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 一年后

    // 构建证书
    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(issuerAndSubject, serialNumber, notBefore, notAfter, issuerAndSubject, publicKey);

    // 添加基本约束扩展（标识为 CA 证书）
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    // 添加密钥用途扩展
    certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

    // 使用 BC 提供者，以私钥签名
    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);

    X509CertificateHolder certHolder = certBuilder.build(signer);
    return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
  }

  /**
   * 从磁盘加载 JKS 格式的 KeyStore。
   * <p>若文件不存在或大小为 0（如上次异常中断遗留的空文件），则初始化一个新的空 KeyStore，
   * 不会立即写盘，由调用方在适当时机调用 {@link #saveKeyStore} 持久化。</p>
   *
   * @param filePath      KeyStore 文件的绝对路径
   * @param storePassword KeyStore 的访问密码
   * @return 已加载（或新初始化）的 KeyStore 对象
   * @throws RuntimeException 包装底层 KeyStoreException / IOException 等异常
   */
  public static KeyStore loadKeyStore(String filePath, String storePassword)
  {
    String type = "JKS";
    char[] storePasswordArray = storePassword.toCharArray();
    File file = new File(filePath);
    KeyStore keyStore;
    try
    {
      keyStore = KeyStore.getInstance(type);
      if(!file.exists() || file.length() == 0)
      {
        // 文件不存在或为空：初始化一个空的 KeyStore
        keyStore.load(null, storePasswordArray);
        System.out.println("Keystore file not found or empty, initialized a new empty KeyStore.");
      }
      else
      {
        // 文件存在且有内容：从文件加载
        try (InputStream in = new BufferedInputStream(new FileInputStream(file)))
        {
          keyStore.load(in, storePasswordArray);
          System.out.println("Keystore loaded from: " + filePath);
        }
      }
    }
    catch(KeyStoreException e)
    {
      System.err.println("Keystore has not been initialized properly.");
      throw new RuntimeException(e);
    }
    catch(NoSuchAlgorithmException e)
    {
      System.err.println("Required algorithm unavailable.");
      throw new RuntimeException(e);
    }
    catch(CertificateException e)
    {
      System.err.println("Error encoding certificates.");
      throw new RuntimeException(e);
    }
    catch(IOException e)
    {
      System.err.println("I/O error while loading keystore: " + e.getMessage());
      throw new RuntimeException(e);
    }
    return keyStore;
  }

  /**
   * 将内存中的 KeyStore 持久化写入磁盘文件。
   * <p>若目标文件的父目录不存在，会自动递归创建。</p>
   *
   * @param keyStore      要保存的 KeyStore 对象
   * @param filePath      目标文件的绝对路径
   * @param storePassword KeyStore 的访问密码
   * @throws RuntimeException 包装底层 KeyStoreException / IOException 等异常
   */
  public static void saveKeyStore(KeyStore keyStore, String filePath, String storePassword)
  {
    char[] storePasswordArray = storePassword.toCharArray();
    File file = new File(filePath);
    // 确保父目录存在
    if(file.getParentFile() != null)
    {
      file.getParentFile().mkdirs();
    }
    try (OutputStream out = new BufferedOutputStream(new FileOutputStream(file)))
    {
      keyStore.store(out, storePasswordArray);
      System.out.println("Keystore saved successfully to: " + filePath);
    }
    catch(KeyStoreException e)
    {
      System.err.println("Keystore has not been initialized properly.");
      throw new RuntimeException(e);
    }
    catch(NoSuchAlgorithmException e)
    {
      System.err.println("Required algorithm unavailable.");
      throw new RuntimeException(e);
    }
    catch(CertificateException e)
    {
      System.err.println("Error encoding certificates.");
      throw new RuntimeException(e);
    }
    catch(IOException e)
    {
      System.err.println("I/O error while saving keystore: " + e.getMessage());
      throw new RuntimeException(e);
    }
  }

  /**
   * 根据给定的 RSA 密钥对生成 Root CA 自签名证书（使用 Bouncy Castle）。
   * 可用于导入 KeyStore 或分发给客户端作为信任锚。
   * <p>证书属性：</p>
   * <ul>
   *   <li>DN：{@code CN=My Root CA, O=Example Inc, C=US}</li>
   *   <li>有效期：当前时间起约 10 年</li>
   *   <li>扩展：BasicConstraints(CA=true)、KeyUsage(digitalSignature | keyCertSign)</li>
   *   <li>签名算法：SHA256WithRSAEncryption</li>
   * </ul>
   * <p>
   * 调用方负责保管 {@code keyPair} 中的私钥；
   * 若需将私钥存入 KeyStore，使用 {@code PrivateKeyEntry}；
   * 若仅作为信任锚存入，使用 {@code setCertificateEntry}（不含私钥）。
   * </p>
   *
   * @param keyPair 用于签名和嵌入公钥的 RSA 密钥对（私钥由调用方决定是否持久化）
   * @return 生成的 Root CA X.509 证书
   * @throws RuntimeException 包装底层证书构建异常
   */
  public static X509Certificate generateRootCert(KeyPair keyPair)
  {
    X500Name subject = new X500Name("CN=My Root CA, O=Example Inc, C=US");
    // 自签名证书，颁发者和主题相同
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    Date notAfter = new Date(notBefore.getTime() + 24L * 60 * 60 * 1000 * 356 * 10);
    try
    {
      //构建签名者
      ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
      //构建证书内容
      X509v3CertificateBuilder certificateBuilder =
          new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
      // 标记为CA证书
      certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      // 可选：添加密钥用途
      certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));
      //生成证书
      return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(signer));
    }
    catch(OperatorCreationException | CertIOException | CertificateException e)
    {
      throw new RuntimeException(e);
    }
  }

  /**
   * 打印 X.509 证书的基本信息到标准输出，包括版本、序列号、颁发者、主体、有效期及公钥算法。
   *
   * @param certificate 要打印的 X.509 证书
   */
  public static void printCertificate(X509Certificate certificate)
  {
    System.out.println("Version: " + certificate.getVersion());
    System.out.println("Certificate Serial Number: " + certificate.getSerialNumber());
    System.out.println("Certificate Issuer: " + certificate.getIssuerX500Principal());
    System.out.println("Certificate Subject: " + certificate.getSubjectX500Principal());
    System.out.println("Certificate Valid From: " + certificate.getNotBefore());
    System.out.println("Certificate Valid To: " + certificate.getNotAfter());
    System.out.println("public Key Algorithm: " + certificate.getPublicKey().getAlgorithm());
  }

  /**
   * 使用 {@code SunRsaSign} 提供者生成指定长度的 RSA 密钥对。
   * <p>密钥长度上限为 4096 位，超出部分自动截断为 4096。</p>
   *
   * @param keySize 期望的密钥位数（推荐 2048 或 4096）
   * @return 生成的 RSA 密钥对
   * @throws RuntimeException 包装 NoSuchAlgorithmException / NoSuchProviderException
   */
  public static KeyPair generateSecureKeyPair(int keySize)
  {
    int usedKeySize = Math.min(keySize, 4096);
    try
    {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
      SecureRandom random = new SecureRandom();
      generator.initialize(usedKeySize, random);
      return generator.generateKeyPair();
    }
    catch(NoSuchAlgorithmException | NoSuchProviderException e)
    {
      throw new RuntimeException(e);
    }
  }

  /**
   * 演示 RSA 非对称签名与验签的基本流程（使用 JDK 默认提供者）：
   * <ol>
   *   <li>生成 2048 位 RSA 密钥对</li>
   *   <li>用私钥对数据进行 SHA256withRSA 签名</li>
   *   <li>用公钥验证签名结果</li>
   *   <li>打印 Base64 编码的原始数据</li>
   * </ol>
   *
   * @throws NoSuchAlgorithmException 算法不存在
   * @throws InvalidKeyException      密钥无效
   * @throws SignatureException       签名/验签失败
   */
  public static void demo1() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
  {
    //1、生成生成密钥对
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    SecureRandom random = new SecureRandom();
    generator.initialize(2048, random);
    KeyPair keyPair = generator.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();
    PublicKey publicKey = keyPair.getPublic();

    //2、要签名的数据
    byte[] data = "Hello, PKI".getBytes();

    //3、使用私钥签名
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(data);
    byte[] signatureData = signature.sign();

    //4、使用公钥验证
    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(publicKey);
    verifier.update(data);
    boolean verify = verifier.verify(signatureData);
    System.out.println("Signature verified: " + verify);
    System.out.println("Base64 encoded data: " + Base64.getEncoder().encodeToString(data));
  }












  // ====================================================================================
  // 1. bcprov-jdk18on 常见用法 (作为底层安全提供者)
  // ====================================================================================

  /**
   * 示例 1.1：显式指定 Bouncy Castle（BC）提供者，分别生成 RSA 和 EC（P-256）密钥对，
   * 并打印其公钥算法名称。
   * <p>BC 提供者支持更多曲线与算法，在需要 FIPS 或跨平台兼容性时优先使用。</p>
   *
   * @throws NoSuchAlgorithmException 算法不存在
   * @throws NoSuchProviderException  BC 提供者未注册
   */
  public static void demoBcProvKeyPairGeneration() throws NoSuchAlgorithmException, NoSuchProviderException
  {
    // 显式指定使用 BC 提供者生成 RSA 密钥
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
    rsaGen.initialize(2048);
    KeyPair rsaPair = rsaGen.generateKeyPair();
    System.out.println("1.1 生成 RSA 公钥算法: " + rsaPair.getPublic().getAlgorithm());
    // 显式指定使用 BC 提供者生成 EC 密钥 (Nimbus ECDSA 常用)
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
    ecGen.initialize(256); // P-256 曲线
    KeyPair ecPair = ecGen.generateKeyPair();
    System.out.println("1.1 生成 EC 公钥算法: " + ecPair.getPublic().getAlgorithm());
  }

  /**
   * 示例 1.2：使用 BC 提供者进行 AES-256/GCM/NoPadding 对称加解密。
   * <p>GCM 模式提供认证加密（AEAD），兼顾机密性与完整性，是现代推荐的 AES 使用方式。</p>
   * <p>注意：解密时需使用加密时生成的 IV（通过 {@code cipher.getIV()} 获取）。</p>
   *
   * @throws Exception 加解密过程中的任意异常
   */
  public static void demoBcProvAesEncryption() throws Exception
  {
    // 生成 AES 密钥
    KeyGenerator aesGen = KeyGenerator.getInstance("AES", "BC");
    aesGen.init(256);
    SecretKey aesKey = aesGen.generateKey();
    // 使用 AES/GCM/NoPadding (现代推荐的AES加密模式)
    javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "BC");
    String plainText = "Hello Bouncy Castle AES!";
    // 加密
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey);
    byte[] cipherText = cipher.doFinal(plainText.getBytes());
    // 解密 (GCM模式需要用到加密时生成的IV和Tag，这里用getIV()模拟保存)
    byte[] iv = cipher.getIV();
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
    String decryptedText = new String(cipher.doFinal(cipherText));
    System.out.println("1.2 AES/GCM 加解密成功: " + decryptedText);
  }
  // ====================================================================================
  // 2. bcpkix-jdk18on 常见用法 (处理PEM格式和X.509证书)
  // ====================================================================================

  /**
   * 示例 2.1：使用 {@link JcaPEMWriter} 将 RSA 私钥对象序列化为 PEM 格式字符串（PKCS#8）。
   * <p>PEM 格式广泛用于 OpenSSL、Nginx、Spring Boot 等场景下的密钥/证书文件交换。</p>
   *
   * @throws IOException              写入 PEM 时发生 I/O 错误
   * @throws NoSuchAlgorithmException 算法不存在
   * @throws NoSuchProviderException  BC 提供者未注册
   */
  public static void demoBcPkixPemConversion() throws IOException, NoSuchAlgorithmException, NoSuchProviderException
  {
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
    rsaGen.initialize(2048);
    KeyPair keyPair = rsaGen.generateKeyPair();
    // 使用 JcaPEMWriter 将私钥写为 PEM 格式
    StringWriter stringWriter = new StringWriter();
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter))
    {
      pemWriter.writeObject(keyPair.getPrivate());
    }
    String pemString = stringWriter.toString();
    System.out.println("2.1 转换私钥为 PEM 格式成功，首行: " + pemString.split("\n")[0]);
  }

  /**
   * 示例 2.2：使用 Bouncy Castle 生成一张 RSA 自签名 X.509 v3 证书（颁发者与主体不同），
   * 并转换为 JDK 原生的 {@link X509Certificate} 对象。
   * <p>适用于构建内部测试 CA、本地 HTTPS 服务等场景。</p>
   *
   * @throws Exception 证书构建或签名异常
   */
  public static void demoBcPkixSelfSignedCertificate() throws Exception
  {
    // 1. 准备密钥对
    KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA", "BC");
    rsaGen.initialize(2048);
    KeyPair keyPair = rsaGen.generateKeyPair();
    // 2. 构建证书颁发者与主题信息
    X500Name issuerName = new X500Name("CN=MyTestCA, O=MyOrg, C=CN");
    X500Name subjectName = new X500Name("CN=localhost, O=MyOrg, C=CN");
    BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date();
    Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000); // 1年有效期
    // 3. 构建证书构造器
    JcaX509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(issuerName, serialNumber, notBefore, notAfter, subjectName, keyPair.getPublic());
    // 4. 创建签名器 (使用 SHA256WithRSA)
    ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider("BC").build(keyPair.getPrivate());
    // 5. 生成证书 (BC格式的证书持有者)
    X509CertificateHolder certHolder = certBuilder.build(signer);
    // 6. 转换为 Java 原生的 X509Certificate 对象
    X509Certificate x509Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    System.out.println("2.2 生成自签名证书成功，SubjectDN: " + x509Cert.getSubjectX500Principal());
  }
  // ====================================================================================
  // 3. nimbus-jose-jwt 常见用法 (JWT 签发、验证与 JWKS)
  // ====================================================================================

  /**
   * 示例 3.1：使用 HMAC-SHA256（HS256）对称算法签发并验证 JWT。
   * <p>适用于单体应用内部 Token 场景，签发方与验证方共享同一密钥。
   * 密钥需至少 256 位（32 字节）。</p>
   *
   * @throws Exception JWT 签发或验证异常
   */
  public static void demoNimbusHmacJwt() throws Exception
  {
    // 1. 生成一个共享密钥 (至少 256 bits for HS256)
    byte[] sharedSecret = new byte[32];
    new SecureRandom().nextBytes(sharedSecret);
    // 2. 构建 JWT Payload
    JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user-hmac-001").issuer("my-monolith-app")
        .expirationTime(new Date(System.currentTimeMillis() + 60000)).build();
    // 3. 签发 JWT
    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
    signedJWT.sign(new MACSigner(sharedSecret));
    String jwtString = signedJWT.serialize();
    System.out.println("3.1 HMAC 签名生成的 JWT: " + jwtString.substring(0, 30) + "...");
    // 4. 验证 JWT
    SignedJWT parsedJWT = SignedJWT.parse(jwtString);
    boolean isValid = parsedJWT.verify(new MACVerifier(sharedSecret));
    System.out.println("3.1 HMAC 验证结果: " + isValid);
  }

  /**
   * 示例 3.2：使用 ECDSA P-256（ES256）非对称算法签发 JWT，并生成 JWKS 公钥集合，
   * 最后模拟微服务从 JWKS 端点获取公钥并完成 JWT 验证。
   * <p>适用于微服务/分布式架构：Auth Server 持有私钥签发，Resource Server 仅需公钥验证。</p>
   * <p><b>注意：</b>生产环境暴露的 JWKS 中严禁包含私钥，应使用 {@code ecKey.toPublicJWK()}。</p>
   *
   * @throws Exception JWT 签发、JWKS 解析或验证异常
   */
  public static void demoNimbusEcdsaJwtAndJwks() throws Exception
  {
    // 1. 生成 EC 密钥对 (P-256 曲线)
    KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "BC");
    ecGen.initialize(256);
    KeyPair ecPair = ecGen.generateKeyPair();
    ECPrivateKey privateKey = (ECPrivateKey)ecPair.getPrivate();
    ECPublicKey publicKey = (ECPublicKey)ecPair.getPublic();
    String kid = "ec-key-2023"; // 密钥ID，用于JWKS匹配
    // =================== 签发 JWT (使用私钥) ===================
    JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("user-ecdsa-002").issuer("my-auth-server")
        .expirationTime(new Date(System.currentTimeMillis() + 60000)).build();
    SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build(), claims);
    signedJWT.sign(new ECDSASigner(privateKey)); // Nimbus 使用 ECDSA 签名器
    String jwtString = signedJWT.serialize();
    System.out.println("3.2 ECDSA 签名生成的 JWT: " + jwtString.substring(0, 30) + "...");
    // =================== 生成 JWKS (暴露公钥) ===================
    ECKey ecKey = new ECKey.Builder(Curve.P_256, publicKey).privateKey(privateKey) // 注意：如果是给外部服务验证，JWKS中千万不要放私钥！这里仅为演示
        .keyID(kid).algorithm(JWSAlgorithm.ES256).build();
    // 构建只包含公钥的 JWKS (生产环境应使用 ecKey.toPublicJWK() 剥离私钥)
    JWKSet jwkSet = new JWKSet(ecKey.toPublicJWK());
    String jwksJson = jwkSet.toString();
    System.out.println("3.2 生成的 JWKS (仅含公钥): " + jwksJson);
    // =================== 验证 JWT (使用 JWKS 中的公钥) ===================
    // 模拟微服务从 JWKS Endpoint 获取公钥并验证
    JWKSet parsedJwkSet = JWKSet.parse(jwksJson);
    ECKey publicKeyFromJwks = (ECKey)parsedJwkSet.getKeyByKeyId(kid);
    SignedJWT parsedJWT = SignedJWT.parse(jwtString);
    // 使用从 JWKS 转换出的公钥进行验证
    boolean isValid = parsedJWT.verify(new ECDSAVerifier(publicKeyFromJwks));
    System.out.println("3.2 使用 JWKS 公钥验证 ECDSA JWT 结果: " + isValid);
  }
}