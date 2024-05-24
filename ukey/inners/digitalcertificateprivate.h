#ifndef DIGITALCERTIFICATEPRIVATE_H
#define DIGITALCERTIFICATEPRIVATE_H

#include <ukey/at_digitalcertificate.h>
#include <QObject>
#include <QMap>

namespace Adapts {
namespace UKey {

class SW_DigitalCertificatePrivate
{
    Q_DECLARE_PUBLIC(SW_DigitalCertificate)
public:
    SW_DigitalCertificatePrivate(SW_DigitalCertificate *parent) : q_ptr(parent) {}

private:
    QString GetVersion(X509 * x509);        //版本
    QString GetSerialNumber(X509 * x509);   //序列号
    QString GetKeyType(X509 * x509);        //算法
    QString GetSignType(X509 * x509);       //签名算法
    QString GetNotBefore(X509 * x509);      //有效时间起
    QString GetNotAfter(X509 * x509);       //有效时间止
    QString GetIssuer(X509 * x509);         //颁发者
    QString GetSubject(X509 * x509);        //使用者
    QString GetPublicKey(X509 * x509);      //公钥
    QString GetPublicKeyType(X509 * x509);  //公钥参数
    QString GetExtBasicConstraints(X509 * x509);  //基本约束
    QString GetAuthorizationKeyIdentifier(X509 * x509); //授权密钥标识符
    QString GetCRL(X509 * x509);            //CRL分发点
    QString GetIssuerName(X509 * x509);     //颁发机构信息 授权信息访问
    QString GetExtSubjectIdentifier(X509 * x509);   //使用者密钥标识
    QString GetExtKeyUsage(X509 * x509);    //密钥用法
    QString GetHash(X509 * x509);           //指纹

private:
    SW_DigitalCertificate* const q_ptr;
    QMap<QString, QString> m_certificateNamePwdMap;    //名称 密码
};

}
}

#endif // DIGITALCERTIFICATEPRIVATE_H
