package com.ctgu.util;

import com.ctgu.model.ChainAnalysisResult;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 证书格式化工具类
 * @date 2026-04-10 14:04
 */
public final class CertificateFormatter
{
  public static final DateTimeFormatter DATE_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z", Locale.ROOT).withZone(ZoneId.systemDefault());

  private CertificateFormatter()
  {
  }

  public static String shortDn(String dn)
  {
    String[] parts = dn.split(",");
    return parts.length == 0 ? dn : parts[0].trim();
  }

  public static String formatCertificateDetails(X509Certificate certificate, ChainAnalysisResult analysis) throws GeneralSecurityException
  {
    return formatCertificateDetails(certificate, null, analysis);
  }

  public static String formatCertificateDetails(X509Certificate certificate, PrivateKey privateKey, ChainAnalysisResult analysis)
      throws GeneralSecurityException
  {
    StringBuilder builder = new StringBuilder();
    builder.append("Subject: ").append(certificate.getSubjectX500Principal().getName()).append('\n');
    builder.append("Issuer: ").append(certificate.getIssuerX500Principal().getName()).append('\n');
    builder.append("Serial Number: ").append(certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT)).append('\n');
    builder.append("Valid From: ").append(DATE_FORMAT.format(certificate.getNotBefore().toInstant())).append('\n');
    builder.append("Valid To: ").append(DATE_FORMAT.format(certificate.getNotAfter().toInstant())).append('\n');
    builder.append("Signature Algorithm: ").append(certificate.getSigAlgName()).append('\n');
    builder.append("Public Key: ").append(describePublicKey(certificate.getPublicKey())).append('\n');
    builder.append("CA Certificate: ").append(certificate.getBasicConstraints() >= 0 ? "Yes" : "No").append('\n');
    builder.append("Basic Constraints: ").append(certificate.getBasicConstraints()).append('\n');
    builder.append("Key Usage: ").append(formatKeyUsage(certificate.getKeyUsage())).append('\n');
    builder.append("Extended Key Usage: ").append(formatExtendedKeyUsage(certificate)).append('\n');
    builder.append("Subject Alternative Names: ").append(formatSan(certificate)).append('\n');
    builder.append("SHA-1: ").append(FingerprintUtils.fingerprintSha1(certificate)).append('\n');
    builder.append("SHA-256: ").append(FingerprintUtils.fingerprintSha256(certificate)).append('\n');
    if(privateKey != null)
    {
      builder.append('\n').append(formatPrivateKeyInfo(privateKey));
    }
    if(analysis != null)
    {
      builder.append('\n').append(formatChainAnalysis(analysis));
    }
    builder.append('\n').append(toPem(certificate));
    builder.append('\n').append(publicKeyToPem(certificate.getPublicKey()));
    return builder.toString();
  }

  public static String formatPrivateKeyInfo(PrivateKey privateKey)
  {
    StringBuilder builder = new StringBuilder();
    builder.append("=== 私钥信息 ===\n");
    builder.append("算法: ").append(privateKey.getAlgorithm()).append('\n');
    builder.append("格式: ").append(privateKey.getFormat()).append('\n');
    byte[] encoded = privateKey.getEncoded();
    int bits = encoded != null ? encoded.length * 8 : -1;
    builder.append("编码长度: ").append(bits > 0 ? bits + " bits (" + encoded.length + " bytes)" : "未知").append('\n');
    builder.append("（私钥内容已隐藏，请使用\"导出私钥\"按钮导出）\n");
    return builder.toString();
  }

  public static String formatChainAnalysis(ChainAnalysisResult analysis)
  {
    StringBuilder builder = new StringBuilder();
    builder.append("Chain Analysis").append('\n');
    builder.append("Stored Directly: ").append(analysis.trustedDirectly() ? "Yes" : "No").append('\n');
    builder.append("Self-Signed: ").append(analysis.selfSigned() ? "Yes" : "No").append('\n');
    builder.append("CA Certificate: ").append(analysis.certificateAuthority() ? "Yes" : "No").append('\n');
    builder.append("Chain Built To Trust Anchor: ").append(analysis.chainBuildComplete() ? "Yes" : "No").append('\n');
    builder.append("Missing Issuer In Truststore: ").append(analysis.missingIssuer() ? "Yes" : "No").append('\n');
    builder.append("Trust Anchor Alias: ").append(analysis.trustAnchorAlias() == null ? "None" : analysis.trustAnchorAlias()).append('\n');
    builder.append("Chain Path: ")
        .append(analysis.chainSubjects().isEmpty() ? "Unavailable" : String.join(" -> ", analysis.chainSubjects())).append('\n');
    if(!analysis.diagnostics().isEmpty())
    {
      builder.append("Diagnostics:").append('\n');
      for(String line : analysis.diagnostics())
      {
        builder.append("- ").append(line).append('\n');
      }
    }
    return builder.toString();
  }

  public static String toPem(X509Certificate certificate) throws CertificateEncodingException
  {
    String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(certificate.getEncoded());
    return "-----BEGIN CERTIFICATE-----\n" + encoded + "\n-----END CERTIFICATE-----\n";
  }

  public static String publicKeyToPem(PublicKey publicKey)
  {
    String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(publicKey.getEncoded());
    return "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n";
  }

  public static String privateKeyToPkcs8Pem(PrivateKey privateKey)
  {
    String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(privateKey.getEncoded());
    return "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n";
  }

  public static String formatSan(X509Certificate certificate)
  {
    try
    {
      Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
      if(sans == null || sans.isEmpty())
      {
        return "None";
      }
      StringJoiner joiner = new StringJoiner(", ");
      for(List<?> san : sans)
      {
        if(san.size() > 1)
        {
          joiner.add(String.valueOf(san.get(1)));
        }
      }
      return joiner.length() == 0 ? "Present" : joiner.toString();
    }
    catch(Exception ex)
    {
      return "Unavailable";
    }
  }

  public static String formatKeyUsage(boolean[] keyUsage)
  {
    if(keyUsage == null)
    {
      return "None";
    }
    String[] labels =
        { "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
            "encipherOnly", "decipherOnly" };
    StringJoiner joiner = new StringJoiner(", ");
    for(int i = 0; i < Math.min(keyUsage.length, labels.length); i++)
    {
      if(keyUsage[i])
      {
        joiner.add(labels[i]);
      }
    }
    return joiner.length() == 0 ? "None" : joiner.toString();
  }

  private static String formatExtendedKeyUsage(X509Certificate certificate)
  {
    try
    {
      List<String> usage = certificate.getExtendedKeyUsage();
      return usage == null || usage.isEmpty() ? "None" : String.join(", ", usage);
    }
    catch(Exception ex)
    {
      return "Unavailable";
    }
  }

  private static String describePublicKey(PublicKey publicKey)
  {
    return publicKey.getAlgorithm() + " (" + publicKey.getFormat() + ", " + inferKeySize(publicKey) + " bits)";
  }

  private static int inferKeySize(PublicKey publicKey)
  {
    byte[] encoded = publicKey.getEncoded();
    return encoded == null ? -1 : encoded.length * 8;
  }
}