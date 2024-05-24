#include "digitalcertificateprivate.h"

#include <openssl/x509v3.h>

#include <QDateTime>
#include <QDebug>

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetVersion(X509 *x509)
{
    if(!x509)
        return QString();

    int ver = X509_get_version(x509);
    switch(ver)
    {
    case 0:		//V1
        return QString("V1");
    case 1:		//V2
        return QString("V2");
    case 2:		//V3
        return QString("V3");
    default:    //Error!
        return QString();;
    }

    return QString();
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetSerialNumber(X509 *x509)
{
    if(!x509)
        return QString();

    ASN1_INTEGER *asn1_i = nullptr;
    BIGNUM *bignum = nullptr;
    char *serial = nullptr;

    asn1_i = X509_get_serialNumber(x509);
    bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);

    if(!bignum)
        return QString();

    serial = BN_bn2hex(bignum);
    if (!serial)
        return QString();

    return QString(serial);
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetKeyType(X509 *x509)
{
    if(!x509)
        return QString();

    EVP_PKEY *pubKey = X509_get_pubkey(x509);
    int id = EVP_PKEY_base_id(pubKey);

    switch (id) {
    case EVP_PKEY_RSA:
        return QString("RSA");
    case EVP_PKEY_DSA:
        return QString("DSA");
    case EVP_PKEY_DH:
        return QString("DH");
    case EVP_PKEY_EC:
        return QString("SM2");
    default:
        break;
    }

    return QString();
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetSignType(X509 *x509)
{
    if(!x509)
        return QString();

    QString sigAlg;
    const X509_ALGOR *alg = X509_get0_tbs_sigalg(x509);
    if(alg->parameter) {
        int sig_nid = OBJ_obj2nid(alg->algorithm);
        if(sig_nid != NID_undef) {
            sigAlg = QString(OBJ_nid2ln(sig_nid));
        }
    }
    else {//SM2
        char test[32] = {0};
        int len = OBJ_obj2txt(test, 32, alg->algorithm, 0);
        std::string oid(test, len);
        if(oid == "1.2.156.10197.1.501") {
            sigAlg = "SM3";
        }
        else if(oid == "1.2.840.113549.1.1.5") {
            sigAlg = "sha1";
        }
        else if(oid == "1.2.840.113549.1.1.11") {
            sigAlg = "sha256";
        }
    }

    return sigAlg;
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetNotBefore(X509 *x509)
{
    if(!x509)
        return QString();

    ASN1_TIME *not_before = X509_get_notBefore(x509);
    unsigned char* not_before_str = not_before->data;
    QDateTime dateTime = QDateTime::fromString(QString((char *)not_before_str), "yyyyMMddHHmmssZ");

    return dateTime.toString("yyyy-MM-dd hh:mm:ss");
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetNotAfter(X509 *x509)
{
    if(!x509)
        return QString();

    ASN1_TIME *not_after = X509_get_notBefore(x509);
    unsigned char* not_after_str = not_after->data;
    QDateTime dateTime = QDateTime::fromString(QString((char *)not_after_str), "yyyyMMddHHmmssZ");

    return dateTime.toString("yyyy-MM-dd hh:mm:ss");
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetIssuer(X509 *x509)
{
    if(!x509)
        return QString();

    int nNameLen = 512;
    char csCommonName[512] = {0};
    nNameLen = X509_NAME_get_text_by_NID(X509_get_issuer_name(x509), NID_commonName, csCommonName, nNameLen);

    if(-1 == nNameLen)
        return QString();

    return QString(csCommonName).mid(0, nNameLen);
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetSubject(X509 *x509)
{
    if(!x509)
        return QString();

    int nNameLen = 512;
    char csSubName[512] = {0};
    nNameLen = X509_NAME_get_text_by_NID(X509_get_subject_name(x509), NID_countryName, csSubName, nNameLen);

    if(-1 == nNameLen)
        return QString();

    return QString(csSubName).mid(0, nNameLen);
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetPublicKey(X509 *x509)
{
    if(!x509)
        return QString();

    EVP_PKEY *pubKey = X509_get_pubkey(x509);
    if(!pubKey)
        return QString();

    // 获取公钥的 DER 编码
    unsigned char *pubKeyDER = nullptr;
    int pubKeyDERLen = i2d_PublicKey(pubKey, &pubKeyDER);
    if (pubKeyDERLen <= 0) {
        EVP_PKEY_free(pubKey);
        return QString();
    }
    EVP_PKEY_free(pubKey);

    QString resStr;
    for (int i = 0; i < pubKeyDERLen; i++) {
        resStr.append(QString::number(static_cast<unsigned char>(pubKeyDER[i]), 16).toUpper());
    }

    return resStr;

}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetPublicKeyType(X509 *x509)
{
    if(!x509)
        return QString();

    EVP_PKEY *pubKey = X509_get_pubkey(x509);
    if(!pubKey)
        return QString();

    QString publicKeyType;
    if (EVP_PKEY_id(pubKey) == EVP_PKEY_EC) {
        EC_KEY *ecKey = EVP_PKEY_get0_EC_KEY(pubKey);
        if (ecKey) {
            const EC_GROUP *group = EC_KEY_get0_group(ecKey);
            if (group) {
                int nid = EC_GROUP_get_curve_name(group);
                if (nid != NID_undef) {
                    const ASN1_OBJECT *obj = OBJ_nid2obj(nid);
                    if (obj) {
                        char oidBuffer[128];
                        int len = OBJ_obj2txt(oidBuffer, sizeof(oidBuffer), obj, 1);
                        if (len > 0) {
                            oidBuffer[len] = '\0'; // 确保字符串以 null 结尾
                            publicKeyType = QString(oidBuffer);
                        } else {
                            qDebug() << "Failed to convert OID to string";
                        }
                    } else {
                        qDebug() << "Failed to get ASN1_OBJECT for NID";
                    }
                } else {
                    qDebug() << "Unknown curve or not a named curve";
                }
            }
        }
    } else {
        qDebug() << "Not an EC public key";
    }
    EVP_PKEY_free(pubKey);

    return QString(publicKeyType);
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetExtBasicConstraints(X509 *x509)
{
    if (!x509)
        return QString();

    int crit = 0;
    char value[512] = {0};
    BASIC_CONSTRAINTS *bcons = NULL;

    bcons = (BASIC_CONSTRAINTS*)X509_get_ext_d2i(x509, NID_basic_constraints, &crit, NULL);
    if (!bcons)
        return QString();

    if (!bcons->ca)
    {
        strcat_s(value, 512, "Subject Type=End Entity; ");
        strcat_s(value, 512, "Path Length Constraint=None");
    }
    else
    {
        char temp[128] = {0};
        sprintf_s(temp, 128, "Path Length Constraint=%d", bcons->pathlen);
        strcat_s(value, 512, "Subject Type=CA; ");
        strcat_s(value, 512, temp);
    }
    BASIC_CONSTRAINTS_free(bcons);

    return QString(value);

}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetAuthorizationKeyIdentifier(X509 *x509)
{
    X509_EXTENSION *ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_authority_key_identifier, -1));
    if (ext != NULL) {
        ASN1_OCTET_STRING *octetStr = X509_EXTENSION_get_data(ext);
        const unsigned char *ptr = octetStr->data;
        QString akidStr;

        // 解析授权密钥标识符
        AUTHORITY_KEYID *akid = d2i_AUTHORITY_KEYID(NULL, &ptr, octetStr->length);
        if (akid) {
            if (akid->keyid) {
                QByteArray keyIdBytes((const char*)akid->keyid->data, akid->keyid->length);
                akidStr = keyIdBytes.toHex();
            }
            AUTHORITY_KEYID_free(akid);
        }

        if(!akidStr.isEmpty())
            akidStr = QString("KeyID=%1").arg(akidStr.toUpper());
        return akidStr;
    }
    return QString();
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetCRL(X509 *x509)
{
    QString crlStr;
    // 获取证书的扩展属性
    X509_EXTENSION *ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_crl_distribution_points, -1));

    if (ext != NULL) {
        // 获取扩展属性的数据
        ASN1_OCTET_STRING *octetStr = X509_EXTENSION_get_data(ext);

        // 将数据解析为 CRL 分发点的结构
        STACK_OF(DIST_POINT) *distPoints = NULL;
        DIST_POINT_NAME *distPointName = NULL;
        distPointName = d2i_DIST_POINT_NAME(NULL, (const unsigned char **)&octetStr->data, octetStr->length);

        // 遍历 CRL 分发点列表
        for (int i = 0; i < sk_DIST_POINT_num(distPoints); ++i) {
            DIST_POINT *distPoint = sk_DIST_POINT_value(distPoints, i);
            // 处理每个 CRL 分发点，例如打印 URL
            GENERAL_NAMES *fullName = distPoint->distpoint->name.fullname;
            for (int j = 0; j < sk_GENERAL_NAME_num(fullName); ++j) {
                GENERAL_NAME *name = sk_GENERAL_NAME_value(fullName, j);
                if (name->type == GEN_URI) {
                    ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
                    crlStr += QString((char *)uri->data );
                }
            }
        }
        // 释放资源
        sk_DIST_POINT_free(distPoints);
    }

    return crlStr;
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetIssuerName(X509 *x509)
{
    if(!x509)
        return QString();

    QString aiaExtension;
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x509);
    if (exts) {
        int nid = OBJ_txt2nid("authorityInfoAccess");
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
            if (OBJ_obj2nid(X509_EXTENSION_get_object(ext)) == nid) {
                ASN1_OCTET_STRING *str = X509_EXTENSION_get_data(ext);

                aiaExtension = QString::fromUtf8((char *)str->data);
                break;
            }
        }
    }
    return aiaExtension;
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetExtSubjectIdentifier(X509 *x509)
{
    if(!x509)
        return QString();

    QString resStr;
    int crit = 0;
    ASN1_OCTET_STRING *skid = NULL;
    skid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509, NID_subject_key_identifier, &crit, NULL);
    if(!skid)
        return QString();

    for (int i = 0; i < skid->length; i++)
    {
        resStr.append(QString::number(static_cast<unsigned char>(skid->data[i]), 16));
    }

    return resStr.toUpper();
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetExtKeyUsage(X509 *x509)
{
    if(!x509)
        return QString();

    QString resStr;
    ASN1_BIT_STRING* lASN1UsageStr;

    lASN1UsageStr = (ASN1_BIT_STRING *)X509_get_ext_d2i(x509, NID_key_usage, NULL, NULL);
    if (lASN1UsageStr)
    {
        char temp[32] = {0};
        unsigned short usage = lASN1UsageStr->data[0];
        if(lASN1UsageStr->length > 1)
        {
            usage |= lASN1UsageStr->data[1] << 8;
        }

        sprintf_s(temp, 32, "(%x)", usage);

        if (usage & KU_DIGITAL_SIGNATURE)
            resStr += QString("Digital Signature,");
        if (usage & KU_NON_REPUDIATION)
            resStr += QString("Non-Repudiation,");
        if (usage & KU_KEY_ENCIPHERMENT)
            resStr += QString("Key Encipherment,");
        if (usage & KU_DATA_ENCIPHERMENT)
            resStr += QString("Data  Encipherment,");
        if (usage & KU_KEY_AGREEMENT)
            resStr += QString("Key  Agreement,");
        if (usage & KU_KEY_CERT_SIGN)
            resStr += QString("Certificate Signature,");
        if (usage & KU_CRL_SIGN)
            resStr += QString("CRL Signature,");

        if(!resStr.isEmpty())
            resStr.chop(1);
    }

    return resStr;
}

QString Adapts::UKey::SW_DigitalCertificatePrivate::GetHash(X509 *x509)
{
    if(!x509)
        return QString();

    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    unsigned int fingerprintLength = 0;
    const EVP_MD* md = EVP_sha1();  // 指纹算法类型，这里使用SHA-256

    if (X509_digest(x509, md, fingerprint, &fingerprintLength) != 1)
        return QString();

    QString resStr;
    for (int i = 0; i < fingerprintLength; i++)
    {
        resStr.append(QString::number(static_cast<unsigned char>(fingerprint[i]), 16));
    }

    return resStr.toUpper();
}
