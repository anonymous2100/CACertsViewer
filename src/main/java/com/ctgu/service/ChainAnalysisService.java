package com.ctgu.service;

import com.ctgu.model.CertificateRecord;
import com.ctgu.model.ChainAnalysisNode;
import com.ctgu.model.ChainAnalysisResult;
import com.ctgu.model.TrustStoreDocument;
import com.ctgu.util.CertificateFormatter;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author lihuahui
 * @version 1.0
 * @description: 链分析服务，提供对选定证书的链构建和分析功能
 * @date 2026-04-10 14:01
 */
public class ChainAnalysisService
{
  public ChainAnalysisResult analyze(TrustStoreDocument document, CertificateRecord record)
  {
    X509Certificate certificate = record.certificate();
    boolean trustedDirectly = true;
    boolean selfSigned = isLikelySelfSigned(certificate);
    boolean certificateAuthority = certificate.getBasicConstraints() >= 0;
    List<String> chainSubjects = new ArrayList<>();
    List<String> diagnostics = new ArrayList<>();
    List<ChainAnalysisNode> nodes = new ArrayList<>();
    Set<String> visitedSubjects = new HashSet<>();

    X509Certificate current = certificate;
    chainSubjects.add(formatSubject(current));
    nodes.add(new ChainAnalysisNode(record.alias(), formatSubject(current), "Selected Certificate",
        selectedBadges(record, certificateAuthority, selfSigned)));

    boolean chainBuildComplete = false;
    boolean missingIssuer = false;
    String trustAnchorAlias = selfSigned ? record.alias() : null;

    diagnostics.add("This certificate is stored directly in the open truststore under alias '" + record.alias() + "'.");
    if(certificateAuthority)
    {
      diagnostics.add("The selected certificate has CA basic constraints and can act as a trust anchor.");
    }
    else
    {
      diagnostics.add("The selected certificate is not marked as a CA certificate.");
    }

    if(selfSigned)
    {
      chainBuildComplete = true;
      diagnostics.add("The certificate appears to be self-signed.");
      nodes.set(0, new ChainAnalysisNode(record.alias(), formatSubject(current), "Trust Anchor",
          selectedBadges(record, certificateAuthority, true)));
    }
    else
    {
      while(true)
      {
        String currentSubject = current.getSubjectX500Principal().getName(X500Principal.RFC2253);
        if(!visitedSubjects.add(currentSubject))
        {
          diagnostics.add("Chain building stopped because a certificate loop was detected.");
          break;
        }

        Optional<IssuerMatch> issuerRecord = findIssuer(document, current, record.alias());
        if(issuerRecord.isEmpty())
        {
          missingIssuer = true;
          diagnostics.add("No issuer certificate in this truststore could be matched to the selected certificate.");
          nodes.add(new ChainAnalysisNode(null, CertificateFormatter.shortDn(current.getIssuerX500Principal().getName()), "Missing Issuer",
              List.of("Missing issuer")));
          break;
        }

        IssuerMatch issuer = issuerRecord.get();
        current = issuer.record().certificate();
        chainSubjects.add(formatSubject(current));
        if(issuer.signatureVerified())
        {
          diagnostics.add("Found issuer match in truststore alias '" + issuer.record().alias() + "' and verified the signature.");
        }
        else
        {
          diagnostics.add("Found likely issuer match in truststore alias '" + issuer.record().alias()
              + "' based on issuer/subject names, but signature verification did not complete.");
        }

        boolean issuerSelfSigned = isLikelySelfSigned(current);
        nodes.add(new ChainAnalysisNode(issuer.record().alias(), formatSubject(current), issuerSelfSigned ? "Trust Anchor" : "Issuer",
            issuerBadges(issuer, issuerSelfSigned)));

        if(issuerSelfSigned)
        {
          trustAnchorAlias = issuer.record().alias();
          chainBuildComplete = true;
          diagnostics.add("Chain terminates at a likely self-signed trust anchor alias '" + issuer.record().alias() + "'.");
          break;
        }
      }
    }

    return new ChainAnalysisResult(trustedDirectly, selfSigned, certificateAuthority, chainBuildComplete, missingIssuer, trustAnchorAlias,
        List.copyOf(chainSubjects), List.copyOf(diagnostics), List.copyOf(nodes));
  }

  private Optional<IssuerMatch> findIssuer(TrustStoreDocument document, X509Certificate certificate, String currentAlias)
  {
    String issuerDn = certificate.getIssuerX500Principal().getName(X500Principal.RFC2253);
    List<CertificateRecord> candidates = document.getCertificates().stream().filter(candidate -> !candidate.alias().equals(currentAlias))
        .filter(candidate -> candidate.certificate().getSubjectX500Principal().getName(X500Principal.RFC2253).equals(issuerDn)).toList();

    for(CertificateRecord candidate : candidates)
    {
      if(verifiesAgainst(certificate, candidate.certificate().getPublicKey()))
      {
        return Optional.of(new IssuerMatch(candidate, true));
      }
    }
    if(!candidates.isEmpty())
    {
      return Optional.of(new IssuerMatch(candidates.get(0), false));
    }
    return Optional.empty();
  }

  private List<String> selectedBadges(CertificateRecord record, boolean certificateAuthority, boolean selfSigned)
  {
    List<String> badges = new ArrayList<>();
    badges.add("Trusted");
    badges.add(certificateAuthority ? "CA" : "End-entity");
    if(selfSigned)
    {
      badges.add("Self-signed");
      badges.add("Root in store");
    }
    if(record.expired())
    {
      badges.add("Expired");
    }
    if(record.notYetValid())
    {
      badges.add("Not yet valid");
    }
    return List.copyOf(badges);
  }

  private List<String> issuerBadges(IssuerMatch issuer, boolean selfSigned)
  {
    List<String> badges = new ArrayList<>();
    badges.add(issuer.signatureVerified() ? "Verified" : "Likely match");
    badges.add("Trusted");
    if(issuer.record().certificate().getBasicConstraints() >= 0)
    {
      badges.add("CA");
    }
    if(selfSigned)
    {
      badges.add("Self-signed");
      badges.add("Root in store");
    }
    if(issuer.record().expired())
    {
      badges.add("Expired");
    }
    return List.copyOf(badges);
  }

  private boolean verifiesAgainst(X509Certificate certificate, PublicKey publicKey)
  {
    try
    {
      certificate.verify(publicKey);
      return true;
    }
    catch(Exception ex)
    {
      return false;
    }
  }

  private boolean isLikelySelfSigned(X509Certificate certificate)
  {
    boolean sameSubjectAndIssuer = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
    if(!sameSubjectAndIssuer)
    {
      return false;
    }
    return verifiesAgainst(certificate, certificate.getPublicKey()) || certificate.getBasicConstraints() >= 0;
  }

  private String formatSubject(X509Certificate certificate)
  {
    return CertificateFormatter.shortDn(certificate.getSubjectX500Principal().getName());
  }

  private record IssuerMatch(CertificateRecord record, boolean signatureVerified)
  {
  }
}