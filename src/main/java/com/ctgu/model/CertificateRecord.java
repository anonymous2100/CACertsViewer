package com.ctgu.model;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 证书记录实体
 * @date 2026-04-10 14:00
 */
public record CertificateRecord(String alias, String entryType, String subject, String issuer, String serialNumber, Instant validFrom,
                                Instant validTo, String signatureAlgorithm, String sha1, String sha256, X509Certificate certificate,
                                boolean expired, boolean notYetValid, int chainLength, Path sourcePath, PrivateKey privateKey)
{
  /**
   * Convenience: true when this entry carries a private key
   */
  public boolean hasPrivateKey()
  {
    return privateKey != null;
  }
}
