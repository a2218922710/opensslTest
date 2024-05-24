#include "at_digitalcertificate.h"

#include "inners/digitalcertificateprivate.h"

#include <QStringList>
#include <QFile>
#include <QDebug>
#include <QDateTime>

namespace Adapts {
namespace UKey {
SW_DigitalCertificate::SW_DigitalCertificate()
    : d_ptr(new SW_DigitalCertificatePrivate(this))
{
}

SW_DigitalCertificate::~SW_DigitalCertificate()
{
}

const QStringList SW_DigitalCertificate::GetCertificateList()
{
    return d_ptr->m_certificateNamePwdMap.keys();
}

bool SW_DigitalCertificate::VerifyCertificate(const QString &certificateName, const QString &password)
{
    QFile certificateFile(certificateName);
    if(!certificateFile.exists()) {
        qDebug() << "certificate file is not exists";
        return false;
    }
    
    certificateFile.open(QIODevice::ReadOnly);
    QByteArray fileArr = certificateFile.readAll();
    char * context = fileArr.data();
    certificateFile.close();

    BIO * bio = BIO_new(BIO_s_mem());
    int rv = BIO_write(bio, context, fileArr.size());

    if(!bio || 0 == rv) {
        qDebug() << "BIO_write||BIO_new error";
        return false;
    }

    PKCS12 *p12 = NULL;
	p12 = d2i_PKCS12_bio(bio, &p12);

	EVP_PKEY* pkey = NULL;
	X509* x509 = NULL;
	STACK_OF(X509)* ca = NULL;

    bool returnRes = false;
    if (!PKCS12_parse(p12, password.toUtf8(), &pkey, &x509, &ca)) {
        qDebug() << "PKCS12_parse error";
        returnRes = false;
    }else{
        d_ptr->m_certificateNamePwdMap.insert(certificateName, password);
        //打印数据
        ShowCertificateInfo(x509);

        returnRes = true;
    }

    X509_free(x509);		
    sk_X509_pop_free(ca, X509_free);
    ca = NULL;	
    PKCS12_free(p12);
    p12 = NULL;

    return returnRes;
}


void SW_DigitalCertificate::ShowCertificateInfo(X509 *cert)
{
    if(!cert) {
        qDebug() << "X509 is null";
        return;
    }

    qDebug() << "GetVersion"<< " :" << d_ptr->GetVersion(cert);
    qDebug() << "GetSerialNumber"<< " :" << d_ptr->GetSerialNumber(cert);
    qDebug() << "GetKeyType"<< " :" << d_ptr->GetKeyType(cert);
    qDebug() << "GetSignType"<< " :" << d_ptr->GetSignType(cert);
    qDebug() << "GetNotBefore"<< " :" << d_ptr->GetNotBefore(cert);
    qDebug() << "GetNotAfter"<< " :" << d_ptr->GetNotAfter(cert);
    qDebug() << "GetIssuer"<< " :" << d_ptr->GetIssuer(cert);
    qDebug() << "GetSubject"<< " :" << d_ptr->GetSubject(cert);
    qDebug() << "GetPublicKey"<< " :" << d_ptr->GetPublicKey(cert);
    qDebug() << "GetPublicKeyType"<< " :" << d_ptr->GetPublicKeyType(cert);
    qDebug() << "GetExtBasicConstraints"<< " :" << d_ptr->GetExtBasicConstraints(cert);
    qDebug() << "GetAuthorizationKeyIdentifier"<< " :" << d_ptr->GetAuthorizationKeyIdentifier(cert);
    qDebug() << "GetCRL"<< " :" << d_ptr->GetCRL(cert);
    qDebug() << "GetIssuerName"<< " :" << d_ptr->GetIssuerName(cert);
    qDebug() << "GetExtSubjectIdentifier"<< " :" << d_ptr->GetExtSubjectIdentifier(cert);
    qDebug() << "GetExtKeyUsage"<< " :" << d_ptr->GetExtKeyUsage(cert);
    qDebug() << "GetHash"<< " :" << d_ptr->GetHash(cert);
}

}
}
