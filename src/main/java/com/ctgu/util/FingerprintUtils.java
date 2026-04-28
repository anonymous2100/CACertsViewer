package com.ctgu.util;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 证书指纹工具类，提供计算证书指纹的功能
 * @date 2026-04-10 14:03
 */
public final class FingerprintUtils
{
  private FingerprintUtils()
  {
  }

  public static String fingerprintSha1(X509Certificate certificate) throws GeneralSecurityException
  {
    return fingerprint(certificate, "SHA-1");
  }

  public static String fingerprintSha256(X509Certificate certificate) throws GeneralSecurityException
  {
    return fingerprint(certificate, "SHA-256");
  }

  private static String fingerprint(X509Certificate certificate, String algorithm) throws GeneralSecurityException
  {
    byte[] digest = MessageDigest.getInstance(algorithm).digest(certificate.getEncoded());
    StringBuilder builder = new StringBuilder();
    for(int i = 0; i < digest.length; i++)
    {
      if(i > 0)
      {
        builder.append(':');
      }
      builder.append(String.format("%02X", digest[i]));
    }
    return builder.toString();
  }
}
