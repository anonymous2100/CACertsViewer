package com.ctgu.service;

import com.ctgu.model.CertificateRecord;
import com.ctgu.model.PasswordAwareLoadResult;
import com.ctgu.model.TrustStoreDocument;
import com.ctgu.util.CertificateFormatter;
import com.ctgu.util.FingerprintUtils;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 信任库服务，负责处理信任库的加载、刷新、创建、保存、证书导入导出等核心业务逻辑
 * @date 2026-04-10 14:02
 */
public class TrustStoreService
{
  public PasswordAwareLoadResult load(Path path, char[] password) throws IOException, GeneralSecurityException
  {
    Objects.requireNonNull(path, "path");
    char[] effectivePassword = password == null ? new char[0] : password.clone();

    List<String> candidates = detectCandidateTypes(path);
    Exception last = null;
    for(String type : candidates)
    {
      try
      {
        KeyStore store = KeyStore.getInstance(type);
        try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(path)))
        {
          store.load(inputStream, effectivePassword);
        }

        TrustStoreDocument document = new TrustStoreDocument();
        document.setPath(path);
        document.setStoreType(type);
        document.setPassword(effectivePassword);
        document.setKeyStore(store);
        refresh(document);
        document.setDirty(false);
        return new PasswordAwareLoadResult(document, type);
      }
      catch(IOException | GeneralSecurityException ex)
      {
        last = ex;
      }
    }

    if(last instanceof IOException ioException)
    {
      throw ioException;
    }
    if(last instanceof GeneralSecurityException securityException)
    {
      throw securityException;
    }
    throw new KeyStoreException("Could not open truststore.");
  }

  public void refresh(TrustStoreDocument document) throws GeneralSecurityException
  {
    List<CertificateRecord> records = new ArrayList<>();
    Enumeration<String> aliases = document.getKeyStore().aliases();
    while(aliases.hasMoreElements())
    {
      String alias = aliases.nextElement();
      Certificate certificate = document.getKeyStore().getCertificate(alias);
      if(!(certificate instanceof X509Certificate x509Certificate))
      {
        continue;
      }

      String entryType = describeEntryType(document.getKeyStore(), alias);
      boolean expired = x509Certificate.getNotAfter().toInstant().isBefore(Instant.now());
      boolean notYetValid = x509Certificate.getNotBefore().toInstant().isAfter(Instant.now());
      int chainLength = 0;
      Certificate[] chain = document.getKeyStore().getCertificateChain(alias);
      if(chain != null)
      {
        chainLength = chain.length;
      }

      // Try to load the private key for Key Entry items (key password = store password)
      PrivateKey privateKey = null;
      if(document.getKeyStore().isKeyEntry(alias))
      {
        try
        {
          Key key = document.getKeyStore().getKey(alias, document.getPassword());
          if(key instanceof PrivateKey pk)
          {
            privateKey = pk;
          }
        }
        catch(Exception ignored)
        {
          // Key password may differ from store password; leave privateKey null
        }
      }

      records.add(new CertificateRecord(alias, entryType, CertificateFormatter.shortDn(x509Certificate.getSubjectX500Principal().getName()),
          CertificateFormatter.shortDn(x509Certificate.getIssuerX500Principal().getName()),
          x509Certificate.getSerialNumber().toString(16).toUpperCase(Locale.ROOT), x509Certificate.getNotBefore().toInstant(),
          x509Certificate.getNotAfter().toInstant(), x509Certificate.getSigAlgName(), FingerprintUtils.fingerprintSha1(x509Certificate),
          FingerprintUtils.fingerprintSha256(x509Certificate), x509Certificate, expired, notYetValid, chainLength, document.getPath(),
          privateKey));
    }
    records.sort(Comparator.comparing(CertificateRecord::alias, String.CASE_INSENSITIVE_ORDER));
    document.setCertificates(records);
  }

  public TrustStoreDocument createEmpty(String storeType, char[] password) throws GeneralSecurityException, IOException
  {
    KeyStore store = KeyStore.getInstance(storeType);
    char[] effectivePassword = password == null ? new char[0] : password.clone();
    store.load(null, effectivePassword);
    TrustStoreDocument document = new TrustStoreDocument();
    document.setStoreType(storeType);
    document.setPassword(effectivePassword);
    document.setKeyStore(store);
    refresh(document);
    return document;
  }

  public List<X509Certificate> parseCertificates(Path certificatePath) throws IOException, GeneralSecurityException
  {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(certificatePath)))
    {
      Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(inputStream);
      List<X509Certificate> result = new ArrayList<>();
      for(Certificate certificate : certificates)
      {
        if(certificate instanceof X509Certificate x509Certificate)
        {
          result.add(x509Certificate);
        }
      }
      if(result.isEmpty())
      {
        throw new GeneralSecurityException("No X.509 certificate was found in the file.");
      }
      return result;
    }
  }

  public boolean aliasExists(TrustStoreDocument document, String alias) throws KeyStoreException
  {
    return document.getKeyStore().containsAlias(alias);
  }

  public void importCertificate(TrustStoreDocument document, String alias, X509Certificate certificate, boolean replaceExisting)
      throws GeneralSecurityException
  {
    if(!replaceExisting && document.getKeyStore().containsAlias(alias))
    {
      throw new KeyStoreException("Alias already exists.");
    }
    if(replaceExisting && document.getKeyStore().containsAlias(alias))
    {
      document.getKeyStore().deleteEntry(alias);
    }
    document.getKeyStore().setCertificateEntry(alias, certificate);
    refresh(document);
    document.setDirty(true);
  }

  public void deleteAlias(TrustStoreDocument document, String alias) throws GeneralSecurityException
  {
    if(!document.getKeyStore().containsAlias(alias))
    {
      throw new KeyStoreException("Alias not found.");
    }
    document.getKeyStore().deleteEntry(alias);
    refresh(document);
    document.setDirty(true);
  }

  public void save(TrustStoreDocument document, Path targetPath, char[] password) throws IOException, GeneralSecurityException
  {
    char[] effectivePassword = password == null ? new char[0] : password.clone();
    try (OutputStream outputStream = Files.newOutputStream(targetPath))
    {
      document.getKeyStore().store(outputStream, effectivePassword);
    }
    document.setPath(targetPath);
    document.setPassword(effectivePassword);
    document.setDirty(false);
  }

  public void exportCertificate(X509Certificate certificate, Path outputPath, boolean pemFormat)
      throws IOException, GeneralSecurityException
  {
    if(pemFormat)
    {
      Files.writeString(outputPath, CertificateFormatter.toPem(certificate));
      return;
    }
    Files.write(outputPath, certificate.getEncoded());
  }

  /**
   * Attempt to load the private key for a given alias using the supplied key password.
   * Useful when the key password differs from the store password.
   */
  public PrivateKey loadPrivateKey(TrustStoreDocument document, String alias, char[] keyPassword) throws GeneralSecurityException
  {
    Key key = document.getKeyStore().getKey(alias, keyPassword);
    if(key instanceof PrivateKey pk)
    {
      return pk;
    }
    throw new GeneralSecurityException("别名 \"" + alias + "\" 没有对应的私钥，或密码不正确。");
  }

  public void exportPublicKey(X509Certificate certificate, Path outputPath, boolean pemFormat) throws IOException
  {
    if(pemFormat)
    {
      Files.writeString(outputPath, CertificateFormatter.publicKeyToPem(certificate.getPublicKey()));
    }
    else
    {
      Files.write(outputPath, certificate.getPublicKey().getEncoded());
    }
  }

  public void exportPrivateKey(PrivateKey privateKey, Path outputPath, boolean pemFormat) throws IOException
  {
    if(pemFormat)
    {
      Files.writeString(outputPath, CertificateFormatter.privateKeyToPkcs8Pem(privateKey));
    }
    else
    {
      Files.write(outputPath, privateKey.getEncoded());
    }
  }

  private List<String> detectCandidateTypes(Path path)
  {
    String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
    if(name.endsWith(".p12") || name.endsWith(".pfx") || name.endsWith(".pkcs12"))
    {
      return List.of("PKCS12", "JKS");
    }
    if(name.endsWith(".jks") || name.endsWith(".cacerts") || name.equals("cacerts"))
    {
      return List.of("JKS", "PKCS12");
    }
    return List.of("JKS", "PKCS12");
  }

  private String describeEntryType(KeyStore keyStore, String alias) throws KeyStoreException
  {
    if(keyStore.isCertificateEntry(alias))
    {
      return "Trusted Certificate";
    }
    if(keyStore.isKeyEntry(alias))
    {
      return "Key Entry";
    }
    return "Unknown";
  }
}