package com.ctgu.certtool;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 证书 Subject 构造者
 * @date 2026-04-10 13:58
 */
public class SubjectBuilder
{
  /**
   * 常用名称（Common Name）
   */
  private String cn;
  /**
   * 企业名称（Organization）
   */
  private String o;
  /**
   * 部门（Organizational Unit）
   */
  private String ou;
  /**
   * 国家（Country）
   */
  private String c;
  /**
   * 省份（State）
   */
  private String st;
  /**
   * 城市（Locality）
   */
  private String l;

  public SubjectBuilder setCn(String cn)
  {
    this.cn = cn;
    return this;
  }

  public SubjectBuilder setO(String o)
  {
    this.o = o;
    return this;
  }

  public SubjectBuilder setOu(String ou)
  {
    this.ou = ou;
    return this;
  }

  public SubjectBuilder setC(String c)
  {
    this.c = c;
    return this;
  }

  public SubjectBuilder setSt(String st)
  {
    this.st = st;
    return this;
  }

  public SubjectBuilder setL(String l)
  {
    this.l = l;
    return this;
  }

  public X500Name build()
  {
    X500NameBuilder x500NameBuilder = new X500NameBuilder();
    if(StringUtils.isNotBlank(cn))
    {
      x500NameBuilder.addRDN(BCStyle.CN, cn);
    }
    if(StringUtils.isNotBlank(o))
    {
      x500NameBuilder.addRDN(BCStyle.O, o);
    }
    if(StringUtils.isNotBlank(ou))
    {
      x500NameBuilder.addRDN(BCStyle.OU, ou);
    }
    if(StringUtils.isNotBlank(c))
    {
      x500NameBuilder.addRDN(BCStyle.C, c);
    }
    if(StringUtils.isNotBlank(st))
    {
      x500NameBuilder.addRDN(BCStyle.ST, st);
    }
    if(StringUtils.isNotBlank(l))
    {
      x500NameBuilder.addRDN(BCStyle.L, l);
    }
    return x500NameBuilder.build();
  }
}