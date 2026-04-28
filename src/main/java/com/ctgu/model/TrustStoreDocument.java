package com.ctgu.model;

import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeSupport;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 信任库文档实体
 * @date 2026-04-10 14:01
 */
public class TrustStoreDocument
{
  private final PropertyChangeSupport pcs = new PropertyChangeSupport(this);
  private final List<CertificateRecord> certificates = new ArrayList<>();
  private boolean dirty;

  private KeyStore keyStore;
  private Path path;
  private String storeType;
  private char[] password;

  public List<CertificateRecord> getCertificates()
  {
    return Collections.unmodifiableList(certificates);
  }

  public void setCertificates(List<CertificateRecord> records)
  {
    List<CertificateRecord> old = new ArrayList<>(certificates);
    certificates.clear();
    certificates.addAll(records);
    pcs.firePropertyChange("certificates", old, new ArrayList<>(certificates));
  }

  public KeyStore getKeyStore()
  {
    return keyStore;
  }

  public void setKeyStore(KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }

  public Path getPath()
  {
    return path;
  }

  public void setPath(Path path)
  {
    this.path = path;
  }

  public String getStoreType()
  {
    return storeType;
  }

  public void setStoreType(String storeType)
  {
    this.storeType = storeType;
  }

  public char[] getPassword()
  {
    return password;
  }

  public void setPassword(char[] password)
  {
    this.password = password == null ? null : password.clone();
  }

  public boolean isDirty()
  {
    return dirty;
  }

  public void setDirty(boolean value)
  {
    boolean old = this.dirty;
    this.dirty = value;
    pcs.firePropertyChange("dirty", old, value);
  }

  public String getDisplayName()
  {
    return path == null ? "Untitled Truststore" : path.getFileName().toString();
  }

  public void addPropertyChangeListener(PropertyChangeListener listener)
  {
    pcs.addPropertyChangeListener(listener);
  }

  public void removePropertyChangeListener(PropertyChangeListener listener)
  {
    pcs.removePropertyChangeListener(listener);
  }

  public void addPropertyChangeListener(String propertyName, PropertyChangeListener listener)
  {
    pcs.addPropertyChangeListener(propertyName, listener);
  }

  public void removePropertyChangeListener(String propertyName, PropertyChangeListener listener)
  {
    pcs.removePropertyChangeListener(propertyName, listener);
  }
}
