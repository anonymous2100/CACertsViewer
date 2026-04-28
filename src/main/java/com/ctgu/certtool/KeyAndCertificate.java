package com.ctgu.certtool;

import lombok.Data;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 证书及密钥对生成结果实体
 * @date 2026-04-10 13:59
 */
@Data
public class KeyAndCertificate
{
  /**
   * 私钥
   */
  private PrivateKey privateKey;
  /**
   * 公钥
   */
  private PublicKey publicKey;
  /**
   * 证书
   */
  private X509Certificate certificate;

  public KeyAndCertificate(PrivateKey privateKey, PublicKey publicKey, X509Certificate certificate)
  {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.certificate = certificate;
  }
}