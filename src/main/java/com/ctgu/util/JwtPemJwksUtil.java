package com.ctgu.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

/**
 * JWT 和 JWKS 工具类 (依赖 Nimbus + Bouncy Castle)
 */
public class JwtPemJwksUtil
{
  static
  {
    // 必须显式注册 Bouncy Castle 作为安全提供者
    java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  // =================== 1. PEM 密钥解析 ===================

  /**
   * 从 PEM 格式的字符串中解析出 RSA 私钥
   * 支持 PKCS#1 (BEGIN RSA PRIVATE KEY) 和 PKCS#8 (BEGIN PRIVATE KEY)
   */
  public static RSAPrivateKey readRsaPrivateKeyFromPem(String pemStr) throws IOException
  {
    PEMParser pemParser = new PEMParser(new StringReader(pemStr));
    Object object = pemParser.readObject();
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    PrivateKey privateKey;
    if(object instanceof PrivateKeyInfo)
    {
      // PKCS#8 格式
      privateKey = converter.getPrivateKey((PrivateKeyInfo)object);
    }
    else if(object instanceof PEMKeyPair)
    {
      // PKCS#1 格式
      privateKey = converter.getKeyPair((PEMKeyPair)object).getPrivate();
    }
    else
    {
      throw new IllegalArgumentException("不支持的私钥格式: " + (object == null ? "null" : object.getClass()));
    }
    return (RSAPrivateKey)privateKey;
  }

  /**
   * 从 PEM 格式的字符串中解析出 RSA 公钥
   * 支持公钥块 (BEGIN PUBLIC KEY) 和 证书 (BEGIN CERTIFICATE)
   */
  public static RSAPublicKey readRsaPublicKeyFromPem(String pemStr) throws IOException, CertificateException
  {
    PEMParser pemParser = new PEMParser(new StringReader(pemStr));
    Object object = pemParser.readObject();
    if(object == null)
    {
      throw new IllegalArgumentException("PEM 内容解析失败，请检查格式");
    }
    PublicKey publicKey;
    if(object instanceof SubjectPublicKeyInfo)
    {
      // 标准公钥格式 (BEGIN PUBLIC KEY)
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      publicKey = converter.getPublicKey((SubjectPublicKeyInfo)object);
    }
    else if(object instanceof X509CertificateHolder)
    {
      // 从证书中提取公钥 (BEGIN CERTIFICATE)
      // 【修复点】：使用 JcaX509CertificateConverter 而不是 JcaPEMKeyConverter
      JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter().setProvider("BC");
      publicKey = certConverter.getCertificate((X509CertificateHolder)object).getPublicKey();
    }
    else
    {
      throw new IllegalArgumentException("不支持的公钥/证书格式: " + object.getClass());
    }
    return (RSAPublicKey)publicKey;
  }
  // =================== 2. JWT 签发与验证 ===================

  /**
   * 使用 RSA 私钥签发 JWT
   */
  public static String generateJwt(RSAPrivateKey privateKey, String issuer, String subject, Date expiresAt) throws JOSEException
  {
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(subject).issuer(issuer).expirationTime(expiresAt).issueTime(new Date())
        .jwtID(UUID.randomUUID().toString()).build();
    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("my-rsa-key-1") // 对应 JWKS 中的 kid
        .build();
    SignedJWT signedJWT = new SignedJWT(header, claimsSet);
    signedJWT.sign(new RSASSASigner(privateKey));
    return signedJWT.serialize();
  }

  /**
   * 使用 RSA 公钥验证 JWT
   */
  public static JWTClaimsSet verifyAndParseJwt(String jwtToken, RSAPublicKey publicKey) throws JOSEException, java.text.ParseException
  {
    SignedJWT signedJWT = SignedJWT.parse(jwtToken);
    boolean isValid = signedJWT.verify(new RSASSAVerifier(publicKey));
    if(!isValid)
    {
      throw new JOSEException("JWT 签名验证失败!");
    }
    JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
    Date expirationTime = claims.getExpirationTime();
    if(expirationTime != null && expirationTime.before(new Date()))
    {
      throw new JOSEException("JWT 已过期!");
    }
    return claims;
  }
  // =================== 3. JWKS 生成 ===================

  /**
   * 将 RSA 公钥转换为 JWKS 格式
   */
  public static String generateRsaJwks(RSAPublicKey publicKey, String kid) throws JOSEException
  {
    RSAKey rsaKey = new RSAKey.Builder(publicKey).keyID(kid).algorithm(JWSAlgorithm.RS256).build();
    com.nimbusds.jose.jwk.JWKSet jwkSet = new com.nimbusds.jose.jwk.JWKSet(rsaKey);
    return jwkSet.toJSONObject().toString();
  }

  // =================== 4. 测试 Main 方法 ===================
  public static void main(String[] args)
  {
    try
    {
      System.out.println("--- 动态生成 RSA 密钥对进行演示 ---");
      java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
      gen.initialize(2048);
      java.security.KeyPair keyPair = gen.generateKeyPair();
      RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
      RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
      // 1. 生成 JWKS
      String jwksJson = generateRsaJwks(publicKey, "my-key-id-001");
      System.out.println("\n1. 生成的 JWKS (暴露给外部服务):");
      System.out.println(jwksJson);
      // 2. 使用私钥签发 JWT
      Date expiresAt = new Date(System.currentTimeMillis() + 3600 * 1000);
      String jwtToken = generateJwt(privateKey, "my-auth-server", "user-12345", expiresAt);
      System.out.println("\n2. 签发的 JWT Token:");
      System.out.println(jwtToken);
      // 3. 使用公钥验证 JWT
      System.out.println("\n3. 验证 JWT Token...");
      JWTClaimsSet claims = verifyAndParseJwt(jwtToken, publicKey);
      System.out.println("验证成功! 解析出的 Subject: " + claims.getSubject());
      System.out.println("解析出的 Issuer: " + claims.getIssuer());
    }
    catch(Exception e)
    {
      e.printStackTrace();
    }
  }
}