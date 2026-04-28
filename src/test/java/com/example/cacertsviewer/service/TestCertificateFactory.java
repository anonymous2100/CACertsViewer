package com.example.cacertsviewer.service;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

final class TestCertificateFactory {
    private static final String SELF_SIGNED_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIICujCCAaKgAwIBAgIIIj4p0ugEW0YwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMS
            Y2FjZXJ0c3ZpZXdlci10ZXN0MB4XDTI2MDMxNTEwMzI0MloXDTI3MDMxNjEwMzI0Mlow
            HTEbMBkGA1UEAxMSY2FjZXJ0c3ZpZXdlci10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAo0FWhq4b9Ysd1qbStTvqAXMIYn/TBDWcOvcSEeAP/G1O1Fm9+GAt
            XPZeIhE1mOy0ky1S+6B+nwCc7Dm1JLbMNhbSmAZUdhdo9aaMVqNISQJwLutLKa0gGdNt
            oeX5itSv14AcPr3gfO3leFYKB39T47ypryKt6BvdBsfxS6ff96dmjFV7DwGZeJf1aFyN
            NVWrSt7fYEhbgqZnmH3LxhJoxcju9uSCexf2Zd+DqBHB/ghUjrwfiWlfR1cU1MJL9CRY
            dnvuzhxMHP1MkPkYAUMZTaumcbQUT1AEzji5MYsPyCmBPgtxKMpGPlmmKGseVPH/evLa
            AXhKAoiT4Wcpzl0JdQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQA+ML5YsM5nyHZ3ZW5J
            NahJtJnqsXwxLsqhxIP2dJWpG1l8rkOlSN+FVDc92EEIesN2p8+ChFF9Sey05DLiDRcq
            a2GSDF94sH3TqyZqE1uCwQHYxpmLL0FkoYru2RCNcAjpeFJJCPP/99uumz2kBC/G7Rdm
            ct1UnWArCw+E+tg+9NmvoqxiL9yF15q1HpsRe2zZ9zTvzPj8TwrOqtkNimCQ+E+CO5Hs
            btehiG8b1O3n2S0PiP8s2+gAzxdeSjk7Ca7QvA6CNIiKEiDYgEdHfx3L4DM5MbIuerOz
            eR2Zc3tgtqNN+CpsrKjLkyYtTHPTTD+zErIqAOk6NcB/jL4WY0nC
            -----END CERTIFICATE-----
            """;
    private static final String ROOT_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIC7jCCAdagAwIBAgIILLKvRB4D224wDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAxMS
            Y2FjZXJ0c3ZpZXdlci1yb290MB4XDTI2MDMxNTEzMjY1M1oXDTMxMDMxNjEzMjY1M1ow
            HTEbMBkGA1UEAxMSY2FjZXJ0c3ZpZXdlci1yb290MIIBIjANBgkqhkiG9w0BAQEFAAOC
            AQ8AMIIBCgKCAQEAqNCxkXXb6g9emOaXJNELBfzYdS1SJJGrDVHeUg4kbT0Ne7jZdUDh
            UqUMsb9MsEUaeKi0R8xKFV1w8y7johyPfMpjPotafEpYLnfFYnJ520Brx6ZpA6DO226S
            IhiCYVl9DLx6dB9wL7/D4/mj/FJlGnb/IMvgbCK0jerlIcB6KuSd/xk264De+Ql0c4xA
            TmF5o0DQT3YnLkBAu8b33+Jlk3p937Pc59zEaZATtwCfsn/djM5b0GZXoekJzIO11qgO
            5Ed5Kk7vQo21OQMJLrvhxbc/UHHzDKcu5oqwRmGax1l3cqXrf3vHwNYak45ktmgh3fbf
            D30pVGaAw+GZfjQhCQIDAQABozIwMDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTN
            eoB/FjxpRFLJ5YXKW4wvRmeADTANBgkqhkiG9w0BAQsFAAOCAQEAeGBriV8u1vGgub/p
            T3hrnwfMkCsz877TxxgK2XM6cDOrXvMnml/zoQK0XZOTzBb8AHDQjuZ0zjrGhcdiWcI5
            Q+gSPgSrd69Lw/9WskFcsVlWd8IvchpDnIO7y+oKK/Yd3SDWjBmWuomFulRuGgq92ExO
            Ptys0MKzZiY28xWO0bnIafQL7lBU7MC0bpHS05LhiajKaeBUywdqS7NxSQ2RhqiCekBt
            0IxXseq0mGWOFBLCLz9e9FXuLxpWsgMOUjOljTfzjv0mr3+NCHpTTvcz5Tc1/tOxiBYO
            99mqpW3xH1p2cuFx7GLHnmwuhU6fbScu3sEnCYBICwIzosAZ6g99hQ==
            -----END CERTIFICATE-----
            """;
    private static final String LEAF_CERTIFICATE_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIC8TCCAdmgAwIBAgIBADANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDExJjYWNlcnRz
            dmlld2VyLXJvb3QwHhcNMjYwMzE1MTMyNjUzWhcNMjgwMzE2MTMyNjUzWjAaMRgwFgYD
            VQQDEw9zZXJ2aWNlLmV4YW1wbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
            AQCum4RCKp583Oanb5ZuQEcf9w4kcUDAISi57/dSKXseosBk0SBslUfJ3u+E3na42g+q
            a2Ssie6L9In9rLng03w9o7LarThFn0LSiU8uQINjJR+bjHEyPqsukGIuSH+N6S6eRpbm
            XROKVso1GLpfW5hYdERxuAoQST93uW8sRa+gS9MVOLmBfyhW5Q6JS8pkwrf98MlHfY8o
            UbTp0qzhHAgles2ALcy8G6eRjCyyR0gSxvxSQR2V0y2wnZDWVaDegjz3Uy3AkUl6Th0j
            gA3tBurIImR2tvVz924AWavNKWGFp9ZT/RecPwVa+6E2SQlFKG12ImirwL74UvZxqNAc
            3UdlAgMBAAGjPzA9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdDgQW
            BBQD5NZEfOBiFISc+HxoXQ4n7hZfczANBgkqhkiG9w0BAQsFAAOCAQEAWYJHKi0zIcIE
            v54uA2Wkm4YND4X7SBM83Ckqz+H4MHRbrc6yBn0RqpKim+UATWQUtvFiFrZkk+XDPotT
            uc/lqUVQSQHn+UE+7hLc4zawvQ+zzoEdQWcrt7jrqTuJDhpeAMWIY1dgqxGsPu7NCnrH
            Or+NjdW4GH/BgriXo9xH3dmj7eDNqUsQ1TVsjGpyz7oawkjI+Qwu/1G6MejAfxeKO4SR
            ctbgpWHnUeDR7L/eGWOFSk4hHyMve9r26eJw0LuEDYOo9Uy89Bpt7fSrq/NR3hyfhkOZ
            1uRzihzqydiIWsYmz+3HLhWnjI5RZdkcOHcAPEhIeTv7SWIfSojE+wN1Wg==
            -----END CERTIFICATE-----
            """;

    private TestCertificateFactory() {
    }

    static X509Certificate createSelfSigned(String commonName) throws Exception {
        return readCertificate(SELF_SIGNED_CERTIFICATE_PEM);
    }

    static X509Certificate createRootCertificate() throws Exception {
        return readCertificate(ROOT_CERTIFICATE_PEM);
    }

    static X509Certificate createLeafCertificate() throws Exception {
        return readCertificate(LEAF_CERTIFICATE_PEM);
    }

    private static X509Certificate readCertificate(String pem) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII))) {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        }
    }
}